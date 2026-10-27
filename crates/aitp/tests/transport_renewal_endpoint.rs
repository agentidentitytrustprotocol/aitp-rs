//! TCT renewal endpoint (RFC-AITP-0013, issue #196): mounted only at
//! the advertised `rfc-aitp-0005.renew_uri`, replay-guarded, re-checks
//! revocation and grants, answers with a signed `tct` envelope, and
//! refuses each failure with a signed `error` envelope carrying its own
//! registry code.

#![cfg(all(feature = "http-server", feature = "experimental-renewal"))]

use aitp::core::{base64url, Aid, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use aitp::tct::{
    build_renewal_request, sign_revocation_list, RevocationEntry, RevocationList,
    RevocationListEnvelope, TctBuilder, TctRenewalPayload,
};
use aitp::transport::{HandshakeServer, RevocationListProducer, RENEW_URI_EXT};
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
    fn current(&self) -> RevocationListEnvelope {
        self.0.clone()
    }
}

fn issuer() -> AitpSigningKey {
    AitpSigningKey::from_seed(&ISSUER_SEED)
}

fn manifest(advertise: bool, manifest_ttl: i64) -> Manifest {
    let key = issuer();
    let mut b = ManifestBuilder::new(&key)
        .display_name("issuer")
        .handshake_endpoint("https://example.com/aitp/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityHintKind::PinnedKey, "issuer").with_public_key(
                base64url::encode(&key.verifying_key().try_to_ed25519_bytes().unwrap()),
            ),
        )
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .offer("demo.write")
        .ttl_secs(manifest_ttl);
    if advertise {
        b = b.extension(
            RENEW_URI_EXT,
            format!("http://127.0.0.1{RENEW_PATH}").into(),
        );
    }
    b.build().unwrap()
}

fn server(manifest: Manifest) -> HandshakeServer<NoOpResolver> {
    HandshakeServer::new(
        issuer(),
        manifest,
        vec!["https://idp.example.com".parse().unwrap()],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
}

async fn serve(server: HandshakeServer<NoOpResolver>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        server.serve(listener).await.unwrap();
    });
    format!("http://127.0.0.1:{port}")
}

/// A TCT this server issued to `holder`.
fn tct(
    signer: &AitpSigningKey,
    holder: &AitpSigningKey,
    grants: &[&str],
    issued_at: Timestamp,
    ttl: i64,
) -> aitp::tct::IssuedTct {
    TctBuilder::new(signer)
        .subject(holder.aid().clone())
        .audience(holder.aid().clone())
        .grants(grants.iter().copied())
        .ttl_secs(ttl)
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

#[tokio::test]
async fn route_is_absent_without_renew_uri() {
    let base = serve(server(manifest(false, 86_400))).await;
    for path in [RENEW_PATH, "/aitp/handshake/renew"] {
        let resp = reqwest::Client::new()
            .post(format!("{base}{path}"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404, "{path}");
    }
}

#[tokio::test]
async fn renews_at_advertised_path_and_refuses_replay() {
    let base = serve(server(manifest(true, 86_400))).await;
    let holder = AitpSigningKey::from_seed(&[0x01; 32]);
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
    let holder = AitpSigningKey::from_seed(&[0x02; 32]);
    let now = Timestamp::now();
    let current = tct(&key, &holder, &["demo.echo"], now, 600);
    let list = sign_revocation_list(
        RevocationList::new(
            key.aid().clone(),
            now,
            Timestamp(now.0 + 3600),
            vec![RevocationEntry::new(current.claims.jti, now)],
        ),
        &key,
    )
    .unwrap();
    let base = serve(
        server(manifest(true, 86_400)).with_revocation_producer(Arc::new(StaticProducer(list))),
    )
    .await;
    let (status, body) = post(&base, &request(&holder, current.token)).await;
    assert_eq!((status, code(&body)), (400, "TCT_REVOKED"), "{body}");
}

#[tokio::test]
async fn withdrawn_grants_are_dropped_or_refused() {
    let base = serve(server(manifest(true, 86_400))).await;
    let holder = AitpSigningKey::from_seed(&[0x03; 32]);

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
    let base = serve(server(manifest(true, 86_400)).with_renewal_grant_policy(deny)).await;
    let holder = AitpSigningKey::from_seed(&[0x04; 32]);
    let current = tct(&issuer(), &holder, &["demo.echo"], Timestamp::now(), 600);
    let (status, body) = post(&base, &request(&holder, current.token)).await;
    assert_eq!((status, code(&body)), (400, "POLICY_VIOLATION"), "{body}");
}

#[tokio::test]
async fn each_failure_maps_to_its_own_code() {
    let base = serve(server(manifest(true, 3_000))).await;
    let key = issuer();
    let holder = AitpSigningKey::from_seed(&[0x05; 32]);
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
    let attacker = AitpSigningKey::from_seed(&[0x06; 32]);
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
    let other = AitpSigningKey::from_seed(&[0x07; 32]);
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
    let store = Arc::new(aitp::core::nonce_store::InMemoryNonceStore::new(1));
    let base = serve(server(manifest(true, 86_400)).with_renewal_nonce_store(store)).await;
    let holder = AitpSigningKey::from_seed(&[0x08; 32]);
    let current = tct(&issuer(), &holder, &["demo.echo"], Timestamp::now(), 600);
    let (status, _) = post(&base, &request(&holder, current.token.clone())).await;
    assert_eq!(status, 200);
    let (status, body) = post(&base, &request(&holder, current.token)).await;
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["message_type"], "error");
    assert_eq!(body["payload"]["retryable"], true);
}
