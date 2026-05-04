//! P13 — boundary checks on the handshake server.
//!
//! Asserts that wrong Content-Type, malformed JSON, stale timestamp,
//! replayed message_id, and unknown message_type all yield AITP error
//! envelopes (`{ "error": { "code": "...", "message": "..." } }`).

#![cfg(all(feature = "client", feature = "server"))]

use aitp_core::{MessageType, Sender, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp_transport_http::{sign_envelope_with, HandshakeServer};
use serde_json::Value;
use tokio::net::TcpListener;
use uuid::Uuid;

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn manifest_for(key: &AitpSigningKey, name: &str) -> aitp_manifest::Manifest {
    ManifestBuilder::new(key)
        .display_name(name)
        .handshake_endpoint("https://example.com/aitp/handshake".parse().unwrap())
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
    let server_key = AitpSigningKey::from_seed(&[0xCC; 32]);
    let manifest = manifest_for(&server_key, "responder");
    let server = HandshakeServer::new(
        server_key,
        manifest,
        vec!["https://idp.example.com".parse().unwrap()],
        NoOpResolver,
        vec!["demo.echo".into()],
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, server.router()).await.ok();
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    port
}

async fn assert_error_code(resp: reqwest::Response, expected: &str) {
    assert_eq!(resp.status().as_u16(), 400, "expected 400 for {expected}");
    let body: Value = resp.json().await.unwrap();
    let code = body
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str())
        .unwrap_or_default();
    assert_eq!(code, expected, "got body: {body}");
}

#[tokio::test]
async fn wrong_content_type_returns_invalid_envelope() {
    let port = spawn_server().await;
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .header(reqwest::header::CONTENT_TYPE, "text/plain")
        .body("hello")
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "INVALID_ENVELOPE").await;
}

#[tokio::test]
async fn malformed_json_returns_invalid_envelope() {
    let port = spawn_server().await;
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "INVALID_ENVELOPE").await;
}

#[tokio::test]
async fn stale_timestamp_returns_timestamp_expired() {
    let port = spawn_server().await;
    let key = AitpSigningKey::from_seed(&[0xAB; 32]);
    let mut envelope = sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({}),
        Uuid::new_v4(),
        Timestamp(Timestamp::now().0 - 7200), // 2 h in the past
    )
    .unwrap();
    envelope.sender = Sender {
        agent_id: key.aid().clone(),
    };
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .json(&envelope)
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "TIMESTAMP_EXPIRED").await;
}

#[tokio::test]
async fn replayed_message_id_returns_replay_detected() {
    let port = spawn_server().await;
    let key = AitpSigningKey::from_seed(&[0xAD; 32]);
    let mid = Uuid::new_v4();
    let envelope = sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({}),
        mid,
        Timestamp::now(),
    )
    .unwrap();
    let url = format!("http://127.0.0.1:{port}/aitp/handshake/hello");
    let client = reqwest::Client::new();
    // First call: rejected for malformed payload (because we sent {})
    // — but the message_id IS recorded before payload parsing in the
    // boundary path. Re-sending the same envelope should now hit the
    // replay deny list before payload parsing.
    let _ = client.post(&url).json(&envelope).send().await.unwrap();
    let resp = client.post(&url).json(&envelope).send().await.unwrap();
    assert_error_code(resp, "REPLAY_DETECTED").await;
}

#[tokio::test]
async fn unknown_envelope_version_returns_unknown_version() {
    // RFC-AITP-0001 §5.6: "Verifiers receiving an unknown `version`
    // MUST respond with `UNKNOWN_VERSION`." We simulate a forward-
    // version client by hand-rolling the envelope JSON; the server
    // should reject before any payload parsing.
    let port = spawn_server().await;
    let key = AitpSigningKey::from_seed(&[0xCF; 32]);
    let mut envelope = sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({}),
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .unwrap();
    envelope.version = "aitp/9.9".into();
    // The signature won't match the new version — that's OK; the
    // version check fires before signature verification.
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .json(&envelope)
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "UNKNOWN_VERSION").await;
}

#[tokio::test]
async fn unknown_message_type_returns_invalid_envelope() {
    let port = spawn_server().await;
    let key = AitpSigningKey::from_seed(&[0xAE; 32]);
    // Construct a TCT-typed envelope sent to the hello endpoint.
    let envelope = sign_envelope_with(
        &key,
        MessageType::Tct,
        serde_json::json!({}),
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .unwrap();
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .json(&envelope)
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "INVALID_ENVELOPE").await;
}
