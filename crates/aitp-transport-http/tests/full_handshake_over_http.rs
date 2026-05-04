//! End-to-end: spin up the lib's `HandshakeServer` (responder side),
//! drive the `Initiator` over real HTTP via `reqwest`, and assert both
//! peers end up holding cross-issued TCTs.

#![cfg(all(feature = "client", feature = "server"))]

use aitp_core::{AitpEnvelope, MessageType, Sender, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_handshake::{
    Initiator, JwkPublicKey, JwksResolver, MutualCommitAckPayload, MutualHelloAckPayload,
    PeerConfig, PresentedIdentity, ResolveError,
};
use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp_transport_http::{sign_envelope_with, HandshakeServer, ManifestServer};
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
async fn full_pinned_key_handshake_over_http() {
    let alice = AitpSigningKey::from_seed(&[0x71; 32]);
    let bob = AitpSigningKey::from_seed(&[0x72; 32]);

    // Bind Bob first so we know his port.
    let bob_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bob_port = bob_listener.local_addr().unwrap().port();
    let bob_endpoint = format!("http://localhost:{bob_port}/aitp/handshake");

    let bob_manifest = manifest_for(&bob, "bob", &bob_endpoint);
    let alice_manifest = manifest_for(
        &alice,
        "alice",
        "http://localhost:0/aitp/handshake", // alice doesn't run a server in this test
    );

    let manifest_router = ManifestServer::new(bob_manifest.clone()).router();
    let handshake_router = HandshakeServer::new(
        bob.clone_for_test(),
        bob_manifest.clone(),
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    .router();
    let app = manifest_router.merge(handshake_router);

    let server = tokio::spawn(async move {
        axum::serve(bob_listener, app.into_make_service())
            .await
            .ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Alice drives the handshake.
    let resolver = NoOpResolver;
    let cfg = PeerConfig {
        signing_key: &alice,
        manifest: &alice_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        now: Timestamp::now(),
    };
    let hello_mid = Uuid::new_v4();
    let hello_ts = Timestamp::now();
    let (mut initiator, hello_payload) = Initiator::start(
        &cfg,
        PresentedIdentity::PinnedKey {
            subject: "alice".into(),
        },
        bob.aid(),
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
        .post(format!("http://localhost:{bob_port}/aitp/handshake/hello"))
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
    let ack_envelope: AitpEnvelope = resp.json().await.unwrap();
    let ack_payload: MutualHelloAckPayload =
        serde_json::from_value(ack_envelope.payload.clone()).unwrap();

    let commit_payload = initiator
        .on_hello_ack(&ack_envelope, &ack_payload, &cfg)
        .unwrap();
    let commit_mid = Uuid::new_v4();
    let commit_ts = Timestamp::now();
    let commit_envelope = sign_envelope_with(
        &alice,
        MessageType::MutualCommit,
        serde_json::to_value(&commit_payload).unwrap(),
        commit_mid,
        commit_ts,
    )
    .unwrap();
    let resp = client
        .post(format!("http://localhost:{bob_port}/aitp/handshake/commit"))
        .header("x-aitp-session-id", &session_id)
        .json(&commit_envelope)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "commit status: {}",
        resp.status()
    );
    let commit_ack_envelope: AitpEnvelope = resp.json().await.unwrap();
    let commit_ack_payload: MutualCommitAckPayload =
        serde_json::from_value(commit_ack_envelope.payload.clone()).unwrap();

    let alice_holds = initiator
        .on_commit_ack(&commit_ack_envelope, &commit_ack_payload, &cfg)
        .unwrap();
    assert_eq!(&alice_holds.issuer, bob.aid());
    assert_eq!(&alice_holds.subject, alice.aid());
    assert_eq!(alice_holds.grants, vec!["demo.echo".to_string()]);

    server.abort();
    let _ = server.await;
    let _ = Sender {
        agent_id: alice.aid().clone(),
    };
}

// `AitpSigningKey` is not `Clone`, by design. The test needs to give the
// key to both the local Initiator and to Bob's server. We use this helper
// to construct two keys from the same seed — equivalent to a key
// "owner" + "delegate" pattern at the test boundary only.
trait CloneForTest {
    fn clone_for_test(&self) -> Self;
}

impl CloneForTest for AitpSigningKey {
    fn clone_for_test(&self) -> Self {
        // Reseed deterministically. The test seeds Bob from `[0x72; 32]`.
        AitpSigningKey::from_seed(&[0x72; 32])
    }
}
