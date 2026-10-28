//! `handle_commit` rejects a COMMIT that targets no live session.
//!
//! `session_expiry.rs` covers the *expired*-session branch. The two
//! sibling rejections — a COMMIT with no `x-aitp-session-id` header, and
//! one bearing an unknown session id — were untested. Both are reached
//! before payload/signature validation, so a minimal well-formed
//! `MutualCommit` envelope is enough to drive them.

#![cfg(all(feature = "http-client", feature = "http-server"))]

use aitp::core::{MessageType, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::envelope::sign_envelope_with;
use aitp::handshake::{IdentityKind, JwkPublicKey, JwksResolver, ResolveError};
use aitp::manifest::{IdentityHint, ManifestBuilder};
use aitp::transport::HandshakeServer;
use tokio::net::TcpListener;
use uuid::Uuid;

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn manifest_for(key: &AitpSigningKey, name: &str, endpoint: &str) -> aitp::manifest::Manifest {
    ManifestBuilder::new(key)
        .display_name(name)
        .handshake_endpoint(endpoint.parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityKind::PinnedKey, name).with_public_key(
                aitp::core::base64url::encode(
                    &key.verifying_key()
                        .try_to_ed25519_bytes()
                        .expect("key was constructed as Ed25519, never P-256"),
                ),
            ),
        )
        .accept_identity_type(aitp::handshake::IdentityKind::PinnedKey)
        .offer("demo.echo")
        .build()
        .unwrap()
}

async fn spawn_server() -> u16 {
    let bob = AitpSigningKey::from_ed25519_seed(&[0x72; 32]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let manifest = manifest_for(
        &bob,
        "bob",
        &format!("http://localhost:{port}/aitp/handshake/"),
    );
    let server = HandshakeServer::new(
        AitpSigningKey::from_ed25519_seed(&[0x72; 32]),
        manifest,
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    );
    tokio::spawn(async move {
        server.serve(listener).await.ok();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    port
}

/// A well-formed (parseable, fresh-timestamp) `MutualCommit` envelope.
/// Its payload/signature are never validated here — both checks run
/// after the session lookup we are exercising.
fn commit_envelope() -> aitp::core::AitpEnvelope {
    let alice = AitpSigningKey::from_ed25519_seed(&[0x71; 32]);
    sign_envelope_with(
        &alice,
        MessageType::MutualCommit,
        serde_json::json!({}),
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .unwrap()
}

async fn assert_invalid_envelope(resp: reqwest::Response, expect_msg: &str) {
    assert!(
        !resp.status().is_success(),
        "expected a rejection status, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "INVALID_ENVELOPE", "body: {body}");
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains(expect_msg),
        "expected message containing {expect_msg:?}, got {msg:?}"
    );
}

#[tokio::test]
async fn commit_without_session_header_is_rejected() {
    let port = spawn_server().await;
    let resp = reqwest::Client::new()
        .post(format!("http://localhost:{port}/aitp/handshake/commit"))
        .json(&commit_envelope())
        .send()
        .await
        .unwrap();
    assert_invalid_envelope(resp, "session header").await;
}

#[tokio::test]
async fn commit_with_unknown_session_id_is_rejected() {
    let port = spawn_server().await;
    let resp = reqwest::Client::new()
        .post(format!("http://localhost:{port}/aitp/handshake/commit"))
        .header("x-aitp-session-id", Uuid::new_v4().to_string())
        .json(&commit_envelope())
        .send()
        .await
        .unwrap();
    assert_invalid_envelope(resp, "unknown session").await;
}
