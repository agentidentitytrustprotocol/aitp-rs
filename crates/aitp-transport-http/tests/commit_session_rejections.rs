//! `handle_commit` rejects a COMMIT that targets no live session.
//!
//! `session_expiry.rs` covers the *expired*-session branch. The two
//! sibling rejections — a COMMIT with no `x-aitp-session-id` header, and
//! one bearing an unknown session id — were untested. Both are reached
//! before payload/signature validation, so a minimal well-formed
//! `MutualCommit` envelope is enough to drive them.

#![cfg(all(feature = "client", feature = "server"))]

use aitp_core::{MessageType, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp_transport_http::{sign_envelope_with, HandshakeServer};
use tokio::net::TcpListener;
use uuid::Uuid;

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn manifest_for(key: &AitpSigningKey, name: &str, endpoint: &str) -> aitp_manifest::Manifest {
    ManifestBuilder::new(key)
        .display_name(name)
        .handshake_endpoint(endpoint.parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: name.into(),
            issuer: None,
            public_key: Some(aitp_core::base64url::encode(
                &key.verifying_key().to_bytes(),
            )),
        })
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .build()
        .unwrap()
}

async fn spawn_server() -> u16 {
    let bob = AitpSigningKey::from_seed(&[0x72; 32]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let manifest = manifest_for(
        &bob,
        "bob",
        &format!("http://localhost:{port}/aitp/handshake/"),
    );
    let server = HandshakeServer::new(
        AitpSigningKey::from_seed(&[0x72; 32]),
        manifest,
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    );
    let app = server.router();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.ok();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    port
}

/// A well-formed (parseable, fresh-timestamp) `MutualCommit` envelope.
/// Its payload/signature are never validated here — both checks run
/// after the session lookup we are exercising.
fn commit_envelope() -> aitp_core::AitpEnvelope {
    let alice = AitpSigningKey::from_seed(&[0x71; 32]);
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
