//! Verifies that `HandshakeServer` evicts in-progress handshake sessions
//! after `session_ttl` and rejects subsequent COMMIT messages targeting
//! the expired session.

#![cfg(all(feature = "client", feature = "server"))]

use aitp_core::{MessageType, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_handshake::{
    Initiator, JwkPublicKey, JwksResolver, PeerConfig, PresentedIdentity, ResolveError,
};
use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp_transport_http::{sign_envelope_with, HandshakeServer};
use std::time::Duration;
use tokio::net::TcpListener;
use uuid::Uuid;

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn manifest_for(
    key: &AitpSigningKey,
    name: &str,
    handshake_endpoint: &str,
) -> aitp_manifest::Manifest {
    ManifestBuilder::new(key)
        .display_name(name)
        .handshake_endpoint(handshake_endpoint.parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: name.into(),
            issuer: None,
            public_key: Some(aitp_core::base64url::encode(
                &key.verifying_key().to_bytes(),
            )),
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .build()
        .unwrap()
}

#[tokio::test]
async fn commit_after_session_ttl_is_rejected() {
    let alice = AitpSigningKey::from_seed(&[0x71; 32]);
    let bob = AitpSigningKey::from_seed(&[0x72; 32]);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("http://localhost:{port}/aitp/handshake");

    let bob_manifest = manifest_for(&bob, "bob", &endpoint);
    let alice_manifest = manifest_for(&alice, "alice", "http://localhost:0/aitp/handshake");

    // 50ms TTL; the test sleeps 200ms between HELLO and COMMIT.
    let server = HandshakeServer::with_session_ttl(
        AitpSigningKey::from_seed(&[0x72; 32]),
        bob_manifest.clone(),
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
        Duration::from_millis(50),
    );
    let app = server.router();

    let server_task = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. Alice sends a valid HELLO and gets a session_id back.
    let resolver = NoOpResolver;
    let cfg = PeerConfig {
        signing_key: &alice,
        manifest: &alice_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        now: Timestamp::now(),
    };
    let hello_mid = Uuid::new_v4();
    let hello_ts = Timestamp::now();
    let (mut initiator, hello_payload) = Initiator::start(
        &cfg,
        PresentedIdentity::PinnedKey {
            subject: "alice".into(),
        },
        &hello_mid,
        hello_ts,
        vec!["demo.echo".into()],
    )
    .unwrap();
    let hello_envelope = sign_envelope_with(
        &alice,
        MessageType::MutualHello,
        serde_json::to_value(&hello_payload).unwrap(),
        hello_mid,
        hello_ts,
    )
    .unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://localhost:{port}/aitp/handshake/hello"))
        .json(&hello_envelope)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "hello status: {}",
        resp.status()
    );
    let session_id = resp
        .headers()
        .get("x-aitp-session-id")
        .expect("server returns session id")
        .to_str()
        .unwrap()
        .to_string();
    let ack_envelope: aitp_core::AitpEnvelope = resp.json().await.unwrap();
    let ack_payload: aitp_handshake::MutualHelloAckPayload =
        serde_json::from_value(ack_envelope.payload.clone()).unwrap();

    let commit_payload = initiator
        .on_hello_ack(&ack_envelope, &ack_payload, &cfg)
        .unwrap();
    let commit_envelope = sign_envelope_with(
        &alice,
        MessageType::MutualCommit,
        serde_json::to_value(&commit_payload).unwrap(),
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .unwrap();

    // 2. Sleep past the TTL.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 3. COMMIT against the expired session. Expect 400 with body
    //    "session expired".
    let resp = client
        .post(format!("http://localhost:{port}/aitp/handshake/commit"))
        .header("x-aitp-session-id", &session_id)
        .json(&commit_envelope)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("session expired"),
        "expected 'session expired' in body, got: {body}"
    );

    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test]
async fn fresh_session_within_ttl_is_accepted() {
    // Sanity: confirm the same setup completes successfully when the
    // COMMIT comes well within the TTL window. Without this, the
    // expiry test could "pass" because of an unrelated regression.
    let alice = AitpSigningKey::from_seed(&[0x73; 32]);
    let bob = AitpSigningKey::from_seed(&[0x74; 32]);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("http://localhost:{port}/aitp/handshake");

    let bob_manifest = manifest_for(&bob, "bob", &endpoint);
    let alice_manifest = manifest_for(&alice, "alice", "http://localhost:0/aitp/handshake");

    let server = HandshakeServer::with_session_ttl(
        AitpSigningKey::from_seed(&[0x74; 32]),
        bob_manifest.clone(),
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
        Duration::from_secs(60),
    );
    let app = server.router();

    let server_task = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resolver = NoOpResolver;
    let cfg = PeerConfig {
        signing_key: &alice,
        manifest: &alice_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        now: Timestamp::now(),
    };
    let hello_mid = Uuid::new_v4();
    let hello_ts = Timestamp::now();
    let (mut initiator, hello_payload) = Initiator::start(
        &cfg,
        PresentedIdentity::PinnedKey {
            subject: "alice".into(),
        },
        &hello_mid,
        hello_ts,
        vec!["demo.echo".into()],
    )
    .unwrap();
    let hello_envelope = sign_envelope_with(
        &alice,
        MessageType::MutualHello,
        serde_json::to_value(&hello_payload).unwrap(),
        hello_mid,
        hello_ts,
    )
    .unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://localhost:{port}/aitp/handshake/hello"))
        .json(&hello_envelope)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let session_id = resp
        .headers()
        .get("x-aitp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let ack_envelope: aitp_core::AitpEnvelope = resp.json().await.unwrap();
    let ack_payload: aitp_handshake::MutualHelloAckPayload =
        serde_json::from_value(ack_envelope.payload.clone()).unwrap();

    let commit_payload = initiator
        .on_hello_ack(&ack_envelope, &ack_payload, &cfg)
        .unwrap();
    let commit_envelope = sign_envelope_with(
        &alice,
        MessageType::MutualCommit,
        serde_json::to_value(&commit_payload).unwrap(),
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .unwrap();

    let resp = client
        .post(format!("http://localhost:{port}/aitp/handshake/commit"))
        .header("x-aitp-session-id", &session_id)
        .json(&commit_envelope)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "commit status: {}, body: {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );

    server_task.abort();
    let _ = server_task.await;
}
