//! `RenewalServer` (RFC-AITP-0013): mounted only at the advertised
//! `rfc-aitp-0005.renew_uri`, replay-guarded, rate limited per source,
//! re-checks revocation and grants, answers with a signed `tct`
//! envelope, and refuses each failure with a signed `error` envelope
//! carrying its own registry code.

use aitp::core::nonce_store::{InMemoryNonceStore, NonceStore};
use aitp::core::{base64url, Aid, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use aitp::tct::{
    sign_revocation_list, RevocationEntry, RevocationList, RevocationListEnvelope, TctBuilder,
};
use aitp::transport::{
    HandshakeServer, ManifestServer, RateLimitConfig, RevocationListProducer, REVOCATION_LIST_PATH,
};
use aitp_experimental::renewal::{
    build_renewal_request, RenewalServer, RenewalServerError, TctRenewalPayload, RENEW_URI_EXT,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use uuid::Uuid;

const ISSUER_SEED: [u8; 32] = [0x42; 32];
const RENEW_PATH: &str = "/custom/renew";

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

struct StaticProducer(RevocationListEnvelope);
impl RevocationListProducer for StaticProducer {
    fn current(
        &self,
    ) -> aitp::core::BoxFuture<'_, Result<RevocationListEnvelope, aitp::transport::RevocationError>>
    {
        Box::pin(std::future::ready(Ok(self.0.clone())))
    }
}

fn issuer() -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&ISSUER_SEED)
}

fn manifest(advertise: bool, manifest_ttl: u64) -> Manifest {
    manifest_at(advertise.then_some(RENEW_PATH), manifest_ttl)
}

fn manifest_at(renew_path: Option<&str>, manifest_ttl: u64) -> Manifest {
    let key = issuer();
    let mut b = ManifestBuilder::new(&key)
        .display_name("issuer")
        .handshake_endpoint("https://example.com/aitp/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityHintKind::PinnedKey, "issuer").with_public_key(
                base64url::encode(&key.verifying_key().try_to_ed25519_bytes().unwrap()),
            ),
        )
        .accept_identity_type(aitp::handshake::IdentityKind::PinnedKey)
        .offer("demo.echo")
        .offer("demo.write")
        .ttl(std::time::Duration::from_secs(manifest_ttl));
    if let Some(path) = renew_path {
        b = b.extension(RENEW_URI_EXT, format!("http://127.0.0.1{path}").into());
    }
    b.build().unwrap()
}

/// An empty revocation list signed by the issuer.
fn empty_list() -> Arc<dyn RevocationListProducer> {
    revoking(&[])
}

/// A revocation list signed by the issuer naming `jtis`.
fn revoking(jtis: &[Uuid]) -> Arc<dyn RevocationListProducer> {
    let key = issuer();
    let now = Timestamp::now();
    let list = sign_revocation_list(
        RevocationList::new(
            key.aid().clone(),
            now,
            Timestamp(now.0 + 3600),
            jtis.iter().map(|j| RevocationEntry::new(*j, now)).collect(),
        ),
        &key,
    )
    .unwrap();
    Arc::new(StaticProducer(list))
}

fn renewal_with(
    manifest: Manifest,
    revocation: Arc<dyn RevocationListProducer>,
    store: Arc<dyn NonceStore>,
) -> RenewalServer {
    RenewalServer::new(Arc::new(issuer()), manifest, revocation, store).unwrap()
}

fn renewal(manifest: Manifest) -> RenewalServer {
    renewal_with(
        manifest,
        empty_list(),
        Arc::new(InMemoryNonceStore::default()),
    )
}

/// Serve the handshake routes, the Manifest and `renewal` on one
/// listener, with connect info.
async fn serve(renewal: RenewalServer) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let manifest = manifest(true, 86_400);
    let app = HandshakeServer::new(
        issuer(),
        manifest.clone(),
        vec!["https://idp.example.com".parse().unwrap()],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    .into_router()
    .merge(ManifestServer::new(manifest).into_router())
    .merge(renewal.router().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    format!("http://127.0.0.1:{port}")
}

/// A TCT this server issued to `holder`.
fn tct(
    signer: &AitpSigningKey,
    holder: &AitpSigningKey,
    grants: &[&str],
    issued_at: Timestamp,
    ttl: u64,
) -> aitp::tct::IssuedTct {
    TctBuilder::new(signer)
        .subject(holder.aid().clone())
        .audience(holder.aid().clone())
        .grants(grants.iter().copied())
        .ttl(std::time::Duration::from_secs(ttl))
        .subject_pubkey(holder.verifying_key())
        .issued_at(issued_at)
        .build()
        .unwrap()
}

fn request(holder: &AitpSigningKey, token: String) -> TctRenewalPayload {
    let nonce = Uuid::new_v4();
    build_renewal_request(holder, token, base64url::encode(nonce.as_bytes())).unwrap()
}

/// POST to the renew path; returns (status, body).
async fn post(base: &str, body: &impl serde::Serialize) -> (u16, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("{base}{RENEW_PATH}"))
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, body)
}

/// The code of a signed `error` envelope from this issuer.
fn code(body: &serde_json::Value) -> &str {
    assert_eq!(body["message_type"], "error", "{body}");
    assert_eq!(
        body["sender"]["agent_id"].as_str(),
        Some(issuer().aid().as_str())
    );
    body["payload"]["code"].as_str().unwrap_or("<none>")
}

#[test]
fn router_errors_without_renew_uri() {
    let err = renewal(manifest(false, 86_400)).router().unwrap_err();
    assert!(matches!(err, RenewalServerError::NotAdvertised), "{err:?}");
}

#[test]
fn router_errors_on_path_collision() {
    for path in [
        "/aitp/handshake/hello",
        "/aitp/handshake/commit",
        REVOCATION_LIST_PATH,
        "/.well-known/aitp-manifest",
    ] {
        let err = renewal(manifest_at(Some(path), 86_400))
            .router()
            .unwrap_err();
        assert!(
            matches!(&err, RenewalServerError::PathCollision(p) if p == path),
            "{path}: {err:?}"
        );
    }
}

#[test]
fn new_rejects_signer_manifest_aid_mismatch() {
    let other = AitpSigningKey::from_ed25519_seed(&[0x43; 32]);
    let err = RenewalServer::new(
        Arc::new(other),
        manifest(true, 86_400),
        empty_list(),
        Arc::new(InMemoryNonceStore::default()),
    )
    .err()
    .expect("signer is not the Manifest key");
    assert!(matches!(err, RenewalServerError::KeyMismatch), "{err:?}");
}

#[tokio::test]
async fn renews_at_advertised_path_and_refuses_replay() {
    let base = serve(renewal(manifest(true, 86_400))).await;
    let holder = AitpSigningKey::from_ed25519_seed(&[0x01; 32]);
    let current = tct(&issuer(), &holder, &["demo.echo"], Timestamp::now(), 600);
    let req = request(&holder, current.token);

    let (status, body) = post(&base, &req).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["message_type"], "tct");
    assert_eq!(
        body["sender"]["agent_id"].as_str(),
        Some(issuer().aid().as_str())
    );
    assert_eq!(
        body["payload"]["pop_nonce_echo"].as_str(),
        Some(req.pop_nonce.as_str())
    );
    assert!(body["payload"]["tct"].is_string());
    assert!(body["payload"]["grant_voucher"].is_string());

    // The old fixed path is not mounted when another is advertised.
    let resp = reqwest::Client::new()
        .post(format!("{base}/aitp/handshake/renew"))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);

    let (status, body) = post(&base, &req).await;
    assert_eq!((status, code(&body)), (400, "REPLAY_DETECTED"), "{body}");
}

#[tokio::test]
async fn revoked_tct_is_refused() {
    let key = issuer();
    let holder = AitpSigningKey::from_ed25519_seed(&[0x02; 32]);
    let now = Timestamp::now();
    let current = tct(&key, &holder, &["demo.echo"], now, 600);
    let base = serve(renewal_with(
        manifest(true, 86_400),
        revoking(&[current.claims.jti]),
        Arc::new(InMemoryNonceStore::default()),
    ))
    .await;
    let (status, body) = post(&base, &request(&holder, current.token)).await;
    assert_eq!((status, code(&body)), (400, "TCT_REVOKED"), "{body}");
}

#[tokio::test]
async fn withdrawn_grants_are_dropped_or_refused() {
    let base = serve(renewal(manifest(true, 86_400))).await;
    let holder = AitpSigningKey::from_ed25519_seed(&[0x03; 32]);

    // "legacy.cap" is no longer offered: dropped, the rest survives.
    let current = tct(
        &issuer(),
        &holder,
        &["demo.echo", "legacy.cap"],
        Timestamp::now(),
        600,
    );
    let (status, body) = post(&base, &request(&holder, current.token)).await;
    assert_eq!(status, 200, "{body}");
    let renewed =
        aitp::crypto::jws::decode_payload_unverified(body["payload"]["tct"].as_str().unwrap())
            .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&renewed).unwrap();
    assert_eq!(claims["grants"], serde_json::json!(["demo.echo"]));

    // Nothing left: refused.
    let current = tct(&issuer(), &holder, &["legacy.cap"], Timestamp::now(), 600);
    let (status, body) = post(&base, &request(&holder, current.token)).await;
    assert_eq!((status, code(&body)), (400, "POLICY_VIOLATION"), "{body}");
}

#[tokio::test]
async fn grant_policy_hook_is_applied() {
    let deny = Arc::new(|_: &Aid, _: &[String]| Vec::new());
    let base = serve(renewal(manifest(true, 86_400)).with_grant_policy(deny)).await;
    let holder = AitpSigningKey::from_ed25519_seed(&[0x04; 32]);
    let current = tct(&issuer(), &holder, &["demo.echo"], Timestamp::now(), 600);
    let (status, body) = post(&base, &request(&holder, current.token)).await;
    assert_eq!((status, code(&body)), (400, "POLICY_VIOLATION"), "{body}");
}

#[tokio::test]
async fn each_failure_maps_to_its_own_code() {
    let base = serve(renewal(manifest(true, 3_000))).await;
    let key = issuer();
    let holder = AitpSigningKey::from_ed25519_seed(&[0x05; 32]);
    let now = Timestamp::now();

    // Expired TCT.
    let expired = tct(&key, &holder, &["demo.echo"], Timestamp(now.0 - 7200), 60);
    let (status, body) = post(&base, &request(&holder, expired.token)).await;
    assert_eq!((status, code(&body)), (400, "TCT_EXPIRED"), "{body}");

    // TCT outliving the issuer's current Manifest (3000 s).
    let long = tct(&key, &holder, &["demo.echo"], now, 7200);
    let (status, body) = post(&base, &request(&holder, long.token)).await;
    assert_eq!(
        (status, code(&body)),
        (400, "TCT_EXPIRES_AFTER_MANIFEST"),
        "{body}"
    );

    let good = tct(&key, &holder, &["demo.echo"], now, 600);

    // PoP signed by a key other than the TCT's subject.
    let attacker = AitpSigningKey::from_ed25519_seed(&[0x06; 32]);
    let (status, body) = post(&base, &request(&attacker, good.token.clone())).await;
    assert_eq!(
        (status, code(&body)),
        (400, "POP_RESPONSE_INVALID"),
        "{body}"
    );

    // pop_nonce of the wrong length.
    let short =
        build_renewal_request(&holder, good.token.clone(), base64url::encode(&[7u8; 8])).unwrap();
    let (status, body) = post(&base, &short).await;
    assert_eq!(
        (status, code(&body)),
        (400, "POP_RESPONSE_INVALID"),
        "{body}"
    );

    // A TCT some other issuer signed.
    let other = AitpSigningKey::from_ed25519_seed(&[0x07; 32]);
    let foreign = tct(&other, &holder, &["demo.echo"], now, 600);
    let (status, body) = post(&base, &request(&holder, foreign.token)).await;
    assert_eq!(
        (status, code(&body)),
        (400, "TCT_SIGNATURE_INVALID"),
        "{body}"
    );

    // Unknown request member.
    let mut extra = serde_json::to_value(request(&holder, good.token.clone())).unwrap();
    extra["surprise"] = serde_json::json!(1);
    let (status, body) = post(&base, &extra).await;
    assert_eq!(
        (status, code(&body)),
        (400, "POP_RESPONSE_INVALID"),
        "{body}"
    );

    // Not a JWS.
    let mut garbage = request(&holder, good.token.clone());
    garbage.current_tct = "not-a-jws".into();
    let (status, body) = post(&base, &garbage).await;
    assert_eq!((status, code(&body)), (400, "INVALID_ENVELOPE"), "{body}");

    // And the good one still renews.
    let (status, body) = post(&base, &request(&holder, good.token)).await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn full_replay_guard_is_a_local_error() {
    let store = Arc::new(InMemoryNonceStore::new(1));
    let base = serve(renewal_with(manifest(true, 86_400), empty_list(), store)).await;
    let holder = AitpSigningKey::from_ed25519_seed(&[0x08; 32]);
    let current = tct(&issuer(), &holder, &["demo.echo"], Timestamp::now(), 600);
    let (status, _) = post(&base, &request(&holder, current.token.clone())).await;
    assert_eq!(status, 200);
    let (status, body) = post(&base, &request(&holder, current.token)).await;
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["message_type"], "error");
    assert_eq!(body["payload"]["retryable"], true);
}

#[tokio::test]
async fn rate_limit_applies_per_source() {
    let base = serve(
        renewal(manifest(true, 86_400))
            .with_rate_limit(RateLimitConfig::default().with_requests_per_source_per_60s(2)),
    )
    .await;
    let holder = AitpSigningKey::from_ed25519_seed(&[0x09; 32]);
    let current = tct(&issuer(), &holder, &["demo.echo"], Timestamp::now(), 600);
    for _ in 0..2 {
        let (status, body) = post(&base, &request(&holder, current.token.clone())).await;
        assert_eq!(status, 200, "{body}");
    }
    let resp = reqwest::Client::new()
        .post(format!("{base}{RENEW_PATH}"))
        .json(&request(&holder, current.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 429);
    assert!(resp.bytes().await.unwrap().is_empty(), "429 has no body");
}

#[tokio::test]
async fn oversized_body_is_refused() {
    let base = serve(renewal(manifest(true, 86_400)).with_request_body_limit(64)).await;
    let holder = AitpSigningKey::from_ed25519_seed(&[0x0a; 32]);
    let current = tct(&issuer(), &holder, &["demo.echo"], Timestamp::now(), 600);
    let (status, body) = post(&base, &request(&holder, current.token)).await;
    assert_eq!((status, code(&body)), (400, "INVALID_ENVELOPE"), "{body}");
}

#[tokio::test]
async fn wrong_content_type_is_refused() {
    let base = serve(renewal(manifest(true, 86_400))).await;
    let resp = reqwest::Client::new()
        .post(format!("{base}{RENEW_PATH}"))
        .header("content-type", "text/plain")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(code(&body), "POP_RESPONSE_INVALID", "{body}");
}

/// A request with no connect info, as from a router served without
/// `into_make_service_with_connect_info`.
fn bare_request(body: &impl serde::Serialize) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::post(RENEW_PATH)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

#[tokio::test]
async fn missing_connect_info_is_internal_error() {
    use tower::ServiceExt;
    let app = renewal(manifest(true, 86_400)).router().unwrap();
    let holder = AitpSigningKey::from_ed25519_seed(&[0x0b; 32]);
    let current = tct(&issuer(), &holder, &["demo.echo"], Timestamp::now(), 600);
    let resp = app
        .oneshot(bare_request(&request(&holder, current.token)))
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 500);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(code(&body), "INVALID_ENVELOPE");
    assert_eq!(body["payload"]["retryable"], true);
}

#[tokio::test]
async fn without_rate_limit_serves_without_connect_info() {
    use tower::ServiceExt;
    let app = renewal(manifest(true, 86_400))
        .without_rate_limit()
        .router()
        .unwrap();
    let holder = AitpSigningKey::from_ed25519_seed(&[0x0c; 32]);
    let current = tct(&issuer(), &holder, &["demo.echo"], Timestamp::now(), 600);
    let resp = app
        .oneshot(bare_request(&request(&holder, current.token)))
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}
