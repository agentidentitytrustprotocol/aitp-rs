//! P12 — `GET /.well-known/aitp-revocation-list` integration test.
//!
//! Spins up a `HandshakeServer` configured with a `RevocationListProducer`
//! and asserts that the wire response is a valid `RevocationListEnvelope`
//! the consuming side can verify against the issuer's AID.

#![cfg(all(feature = "client", feature = "server"))]

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp_tct::{
    sign_revocation_list, verify_revocation_list, RevocationEntry, RevocationList,
    RevocationListEnvelope, VerifyRevocationListContext,
};
use aitp_transport_http::{HandshakeServer, RevocationListProducer};
use sha2::{Digest, Sha256};
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
    fn current(&self) -> RevocationListEnvelope {
        self.0.clone()
    }
}

#[tokio::test]
async fn well_known_revocation_list_serves_signed_snapshot() {
    let issuer = AitpSigningKey::from_seed(&[0x42; 32]);
    let now = Timestamp::now();
    let revoked_jti = Uuid::new_v4();
    let envelope = sign_revocation_list(
        RevocationList {
            version: "aitp/0.2".into(),
            issuer: issuer.aid().clone(),
            published_at: now,
            expires_at: Timestamp(now.0 + 3600),
            entries: vec![RevocationEntry {
                jti: revoked_jti,
                revoked_at: now,
                reason: Some("test".into()),
            }],
        },
        &issuer,
    )
    .unwrap();

    let manifest = ManifestBuilder::new(&issuer)
        .display_name("issuer")
        .handshake_endpoint("https://example.com/aitp/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "issuer".into(),
            issuer: None,
            public_key: Some(aitp_core::base64url::encode(
                &issuer.verifying_key().to_bytes(),
            )),
        })
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .build()
        .unwrap();

    let server_key = AitpSigningKey::from_seed(&[0x42; 32]);
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
        axum::serve(listener, server.router()).await.unwrap();
    });

    let url = format!("http://127.0.0.1:{port}/.well-known/aitp-revocation-list");
    let body: RevocationListEnvelope = reqwest::get(&url).await.unwrap().json().await.unwrap();

    verify_revocation_list(&body, &VerifyRevocationListContext::new(issuer.aid(), now))
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
    let issuer = AitpSigningKey::from_seed(&[0x77; 32]);
    let now = Timestamp::now();
    let envelope = sign_revocation_list(
        RevocationList {
            version: "aitp/0.2".into(),
            issuer: issuer.aid().clone(),
            published_at: now,
            expires_at: Timestamp(now.0 + 3600),
            entries: vec![RevocationEntry {
                jti: Uuid::new_v4(),
                revoked_at: now,
                reason: Some("wire-shape check".into()),
            }],
        },
        &issuer,
    )
    .unwrap();

    let manifest = ManifestBuilder::new(&issuer)
        .display_name("issuer")
        .handshake_endpoint("https://example.com/aitp/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "issuer".into(),
            issuer: None,
            public_key: Some(aitp_core::base64url::encode(
                &issuer.verifying_key().to_bytes(),
            )),
        })
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .build()
        .unwrap();

    let server = HandshakeServer::new(
        AitpSigningKey::from_seed(&[0x77; 32]),
        manifest,
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    .with_revocation_producer(Arc::new(StaticProducer(envelope)));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, server.router()).await.unwrap();
    });

    // Take the response as untyped JSON — the wire, not our own types.
    let url = format!("http://127.0.0.1:{port}/.well-known/aitp-revocation-list");
    let raw: serde_json::Value = reqwest::get(&url).await.unwrap().json().await.unwrap();
    let body = raw
        .get("revocation_list")
        .expect("served envelope carries the transport wrapper");
    let sig = aitp_crypto::Signature::parse(
        raw.get("signature")
            .and_then(serde_json::Value::as_str)
            .expect("served envelope carries a sibling `signature`"),
    )
    .expect("signature parses");
    let pubkey = aitp_crypto::AitpVerifyingKey::from_aid(issuer.aid()).unwrap();

    // Positive: sha256(JCS(inner body)) is the signing input.
    let inner_digest = Sha256::digest(aitp_core::jcs::canonicalize(body).unwrap());
    pubkey
        .verify(&inner_digest, &sig)
        .expect("served signature must verify over sha256(JCS(inner body)) — RFC-AITP-0001 §5.4.1");

    // Negative: the wrapped form is NOT the signing input. Without this
    // half the test would still pass if the wrapper were reintroduced
    // and `body` happened to be re-read from it.
    let wrapped = serde_json::json!({ "revocation_list": body });
    let wrapped_digest = Sha256::digest(aitp_core::jcs::canonicalize(&wrapped).unwrap());
    assert!(
        pubkey.verify(&wrapped_digest, &sig).is_err(),
        "served signature must NOT verify over the wrapped \
         {{\"revocation_list\": …}} form — the transport wrapper is not signed"
    );
}
