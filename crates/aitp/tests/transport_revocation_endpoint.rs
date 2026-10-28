//! P12 — `GET /.well-known/aitp-revocation-list` integration test.
//!
//! Spins up a `HandshakeServer` (with a `RevocationListProducer`, and with
//! none — the default signed empty snapshot of issue #225)
//! and asserts that the wire response is a valid `RevocationListEnvelope`
//! the consuming side can verify against the issuer's AID.

#![cfg(all(feature = "http-client", feature = "http-server"))]

use aitp::core::{BoxFuture, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::handshake::{IdentityKind, JwkPublicKey, JwksResolver, ResolveError};
use aitp::manifest::{IdentityHint, ManifestBuilder};
use aitp::tct::{
    sign_revocation_list, verify_revocation_list, RevocationEntry, RevocationList,
    RevocationListEnvelope, RevocationListVerifyContext, RevocationQuery, RevocationStatus,
};
use aitp::transport::{
    HandshakeServer, RevocationError, RevocationFetcher, RevocationListProducer, RevocationPolicy,
    RevocationProvider, REVOCATION_LIST_PATH,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use uuid::Uuid;

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

struct StaticProducer(RevocationListEnvelope);
impl RevocationListProducer for StaticProducer {
    fn current(&self) -> BoxFuture<'_, Result<RevocationListEnvelope, RevocationError>> {
        Box::pin(std::future::ready(Ok(self.0.clone())))
    }
}

#[tokio::test]
async fn well_known_revocation_list_serves_signed_snapshot() {
    let issuer = AitpSigningKey::from_ed25519_seed(&[0x42; 32]);
    let now = Timestamp::now();
    let revoked_jti = Uuid::new_v4();
    let envelope = sign_revocation_list(
        RevocationList::new(
            issuer.aid().clone(),
            now,
            Timestamp(now.0 + 3600),
            vec![RevocationEntry::new(revoked_jti, now).with_reason("test")],
        ),
        &issuer,
    )
    .unwrap();

    let manifest = ManifestBuilder::new(&issuer)
        .display_name("issuer")
        .handshake_endpoint("https://example.com/aitp/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityKind::PinnedKey, "issuer").with_public_key(
                aitp::core::base64url::encode(
                    &issuer
                        .verifying_key()
                        .try_to_ed25519_bytes()
                        .expect("key was constructed as Ed25519, never P-256"),
                ),
            ),
        )
        .accept_identity_type(aitp::handshake::IdentityKind::PinnedKey)
        .offer("demo.echo")
        .build()
        .unwrap();

    let server_key = AitpSigningKey::from_ed25519_seed(&[0x42; 32]);
    let server = HandshakeServer::new(
        server_key,
        manifest,
        vec!["https://idp.example.com".parse().unwrap()],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    .with_revocation_producer(Arc::new(StaticProducer(envelope.clone())));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        server.serve(listener).await.unwrap();
    });

    let url = format!("http://127.0.0.1:{port}/.well-known/aitp-revocation-list");
    let body: RevocationListEnvelope = reqwest::get(&url).await.unwrap().json().await.unwrap();

    verify_revocation_list(&body, &RevocationListVerifyContext::new(issuer.aid(), now))
        .expect("served snapshot must verify under the issuer's key");
    assert_eq!(body.revocation_list.entries.len(), 1);
    assert_eq!(body.revocation_list.entries[0].jti, revoked_jti);
}

/// The **served bytes** must be signed over the inner artifact body, not
/// over the `{"revocation_list": …}` transport wrapper.
///
/// `well_known_revocation_list_serves_signed_snapshot` above cannot
/// establish this: it signs and verifies with the same implementation,
/// so it passes for any signing input the two sides happen to agree on
/// — which is exactly how the wrapped form survived a full release.
///
/// This test reconstructs the signing input **from the JSON on the
/// wire**, using neither `sign_revocation_list` nor
/// `verify_revocation_list` nor `revocation_signing_bytes`. Flipping the
/// shared helper back to the wrapped form would leave signer and
/// verifier agreeing with each other and still fail here.
#[tokio::test]
async fn served_snapshot_signature_is_over_the_inner_body_not_the_wrapper() {
    let issuer = AitpSigningKey::from_ed25519_seed(&[0x77; 32]);
    let now = Timestamp::now();
    let envelope = sign_revocation_list(
        RevocationList::new(
            issuer.aid().clone(),
            now,
            Timestamp(now.0 + 3600),
            vec![RevocationEntry::new(Uuid::new_v4(), now).with_reason("wire-shape check")],
        ),
        &issuer,
    )
    .unwrap();

    let manifest = ManifestBuilder::new(&issuer)
        .display_name("issuer")
        .handshake_endpoint("https://example.com/aitp/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityKind::PinnedKey, "issuer").with_public_key(
                aitp::core::base64url::encode(
                    &issuer
                        .verifying_key()
                        .try_to_ed25519_bytes()
                        .expect("key was constructed as Ed25519, never P-256"),
                ),
            ),
        )
        .accept_identity_type(aitp::handshake::IdentityKind::PinnedKey)
        .offer("demo.echo")
        .build()
        .unwrap();

    let server = HandshakeServer::new(
        AitpSigningKey::from_ed25519_seed(&[0x77; 32]),
        manifest,
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    .with_revocation_producer(Arc::new(StaticProducer(envelope)));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        server.serve(listener).await.unwrap();
    });

    // Take the response as untyped JSON — the wire, not our own types.
    let url = format!("http://127.0.0.1:{port}/.well-known/aitp-revocation-list");
    let raw: serde_json::Value = reqwest::get(&url).await.unwrap().json().await.unwrap();
    let body = raw
        .get("revocation_list")
        .expect("served envelope carries the transport wrapper");
    let sig = aitp::crypto::Signature::parse(
        raw.get("signature")
            .and_then(serde_json::Value::as_str)
            .expect("served envelope carries a sibling `signature`"),
    )
    .expect("signature parses");
    let pubkey = aitp::crypto::AitpVerifyingKey::from_aid(issuer.aid()).unwrap();

    // Positive: sha256(JCS(inner body)) is the signing input.
    let inner_digest =
        aitp::crypto::Digest32::sha256(&aitp::core::jcs::canonicalize(body).unwrap());
    pubkey
        .verify_jcs(&inner_digest, &sig)
        .expect("served signature must verify over sha256(JCS(inner body)) — RFC-AITP-0001 §5.4.1");

    // Negative: the wrapped form is NOT the signing input. Without this
    // half the test would still pass if the wrapper were reintroduced
    // and `body` happened to be re-read from it.
    let wrapped = serde_json::json!({ "revocation_list": body });
    let wrapped_digest =
        aitp::crypto::Digest32::sha256(&aitp::core::jcs::canonicalize(&wrapped).unwrap());
    assert!(
        pubkey.verify_jcs(&wrapped_digest, &sig).is_err(),
        "served signature must NOT verify over the wrapped \
         {{\"revocation_list\": …}} form — the transport wrapper is not signed"
    );
}

fn advertising_manifest(issuer: &AitpSigningKey, origin: &url::Url) -> aitp::manifest::Manifest {
    ManifestBuilder::new(issuer)
        .display_name("issuer")
        .handshake_endpoint(origin.join("/aitp/handshake").unwrap())
        .identity_hint(
            IdentityHint::new(IdentityKind::Oidc, "issuer")
                .with_issuer("https://idp.example.com".parse().unwrap()),
        )
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .offer("demo.echo")
        .revocation_list_uri(origin.join(REVOCATION_LIST_PATH).unwrap())
        .build()
        .unwrap()
}

async fn serve(server: HandshakeServer<NoOpResolver>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        server.serve(listener).await.unwrap();
    });
    port
}

/// Issue #225 / RFC-AITP-0005 §11: a `HandshakeServer` with no producer
/// still serves `ListRevoked` — a signed **empty** snapshot
/// (RFC-AITP-0008 §1.5 "Empty lists are signed") whose `issuer` is the
/// server's AID and whose signature verifies under that key, through the
/// same wire parser a consumer runs.
#[tokio::test]
async fn list_revoked_is_served_by_default_as_a_signed_empty_snapshot() {
    let issuer = AitpSigningKey::from_ed25519_seed(&[0x51; 32]);
    let origin: url::Url = "https://issuer.example".parse().unwrap();
    let manifest = advertising_manifest(&issuer, &origin);

    // The Manifest advertises the absolute route URL inside its signed
    // body, and a consumer resolves exactly that URL from it.
    aitp::manifest::verify_manifest(&manifest, &aitp::manifest::ManifestVerifyContext::now())
        .unwrap();
    let advertised: url::Url = manifest
        .extensions
        .as_ref()
        .and_then(|ext| ext.get(aitp::manifest::REVOCATION_LIST_URI_EXT))
        .and_then(|v| v.as_str())
        .expect("advertised")
        .parse()
        .unwrap();
    assert_eq!(
        advertised.as_str(),
        "https://issuer.example/.well-known/aitp-revocation-list"
    );

    let server = HandshakeServer::new(
        AitpSigningKey::from_ed25519_seed(&[0x51; 32]),
        manifest,
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    );
    let port = serve(server).await;

    // Poll the advertised path on the local listener.
    let url = format!("http://127.0.0.1:{port}{}", advertised.path());
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), 200, "ListRevoked must be served by default");
    let text = resp.text().await.unwrap();
    let env = aitp::tct::parse_revocation_snapshot_wire(&text.parse().unwrap())
        .expect("default snapshot passes the consumer's wire parser");
    let now = Timestamp::now();
    verify_revocation_list(&env, &RevocationListVerifyContext::new(issuer.aid(), now))
        .expect("default snapshot verifies under the issuer key");
    let list = &env.revocation_list;
    assert_eq!(list.version, "aitp/0.3");
    assert_eq!(&list.issuer, issuer.aid());
    assert!(list.entries.is_empty());
    assert!(list.extensions.is_none());
    assert!(list.published_at.0 <= now.0 && list.published_at.0 > now.0 - 60);
    assert!(list.expires_at.0 > list.published_at.0);

    // A second poll inside the refresh window reuses the snapshot rather
    // than re-signing on every unauthenticated GET.
    let again: RevocationListEnvelope = reqwest::get(&url).await.unwrap().json().await.unwrap();
    assert_eq!(again.signature, env.signature);

    // And a consumer-side fetcher reading that snapshot answers "clear".
    let prepared = RevocationFetcher::new(RevocationPolicy::default())
        .with_provider(Arc::new(StaticSource(env.clone())))
        .prepare(issuer.aid(), Some(advertised.as_str()), now)
        .await;
    let jti = Uuid::new_v4();
    assert_eq!(
        prepared
            .decide(&RevocationQuery::new(issuer.aid(), &jti, now))
            .unwrap(),
        RevocationStatus::Clear
    );
}

struct StaticSource(RevocationListEnvelope);
impl RevocationProvider for StaticSource {
    fn fetch<'a>(
        &'a self,
        _issuer: &'a aitp::core::Aid,
    ) -> BoxFuture<'a, Result<RevocationListEnvelope, RevocationError>> {
        Box::pin(std::future::ready(Ok(self.0.clone())))
    }
}

/// A signing-backend failure on the default snapshot is answered with 503
/// and no body — never an unsigned or mis-signed list. Consumers treat it
/// as an unreachable source and apply their fail mode (RFC-AITP-0008 §3).
#[tokio::test]
async fn default_snapshot_signer_failure_is_503_not_an_unsigned_list() {
    use aitp::crypto::testing::MockKmsSigner;
    let issuer = AitpSigningKey::from_p256_seed(&[0x52; 32]).unwrap();
    let origin: url::Url = "https://issuer.example".parse().unwrap();
    let manifest = advertising_manifest(&issuer, &origin);
    let broken = MockKmsSigner::new(AitpSigningKey::from_p256_seed(&[0x52; 32]).unwrap())
        .sign_with(AitpSigningKey::from_p256_seed(&[0x53; 32]).unwrap());
    let server = HandshakeServer::new(broken, manifest, vec![], NoOpResolver, vec![]);
    let port = serve(server).await;
    let resp = reqwest::get(format!("http://127.0.0.1:{port}{REVOCATION_LIST_PATH}"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
}
