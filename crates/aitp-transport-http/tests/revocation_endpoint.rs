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

    verify_revocation_list(
        &body,
        &VerifyRevocationListContext {
            expected_issuer: issuer.aid(),
            now,
        },
    )
    .expect("served snapshot must verify under the issuer's key");
    assert_eq!(body.revocation_list.entries.len(), 1);
    assert_eq!(body.revocation_list.entries[0].jti, revoked_jti);
}
