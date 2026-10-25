//! End-to-end: spin up the lib's `HandshakeServer` (responder side),
//! drive the `Initiator` over real HTTP via `reqwest`, and assert both
//! peers end up holding cross-issued TCTs.

#![cfg(all(feature = "client", feature = "server"))]

use aitp_core::{AitpEnvelope, MessageType, Sender, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_handshake::{
    Initiator, JwkPublicKey, JwksResolver, MutualCommitAckPayload, MutualHelloAckPayload,
    PeerConfig, PresentedIdentity, ResolveError, StaticPinnedKeyStore,
};
use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp_transport_http::{sign_envelope_with, HandshakeServer, ManifestServer};
use std::sync::Arc;
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
            // 32 bytes for Ed25519, 33-byte SEC1 compressed for P-256:
            // the AID identifier bytes (RFC-AITP-0002 §3.2 step 2).
            public_key: Some(aitp_core::base64url::encode(
                &key.verifying_key().to_compressed(),
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
    run_pinned_handshake(AitpSigningKey::from_seed(&[0x71; 32]), || {
        AitpSigningKey::from_seed(&[0x72; 32])
    })
    .await;
}

/// Item 1 of the 2026-10 proposal: a P-256 pinned key is a first-class
/// identity. Both peers P-256, over real HTTP, each pinning the other.
#[tokio::test]
async fn full_p256_pinned_key_handshake_over_http() {
    run_pinned_handshake(AitpSigningKey::from_p256_seed(&[0x73; 32]).unwrap(), || {
        AitpSigningKey::from_p256_seed(&[0x74; 32]).unwrap()
    })
    .await;
}

/// Mixed suites: a P-256 initiator against an Ed25519 responder.
#[tokio::test]
async fn mixed_p256_initiator_ed25519_responder_over_http() {
    run_pinned_handshake(AitpSigningKey::from_p256_seed(&[0x75; 32]).unwrap(), || {
        AitpSigningKey::from_seed(&[0x76; 32])
    })
    .await;
}

/// `make_bob` is called twice: `AitpSigningKey` is deliberately not
/// `Clone`, and both the local verifier and Bob's server need his key.
async fn run_pinned_handshake(alice: AitpSigningKey, make_bob: impl Fn() -> AitpSigningKey) {
    let bob = make_bob();

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
        make_bob(),
        bob_manifest.clone(),
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    .with_pinned_key_store(Arc::new(StaticPinnedKeyStore::new([alice.verifying_key()])))
    .router();
    let app = manifest_router.merge(handshake_router);

    let server = tokio::spawn(async move {
        axum::serve(bob_listener, app.into_make_service())
            .await
            .ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Alice drives the handshake. PeerConfig is rebuilt before each
    // verify step so `now` advances with the wall clock — otherwise on
    // slow runners Bob's TCT `issued_at` (his Timestamp::now() in handle
    // hello-ack) lands strictly after a stale startup `now` and Alice's
    // verifier rejects it as `Tct(Expired)`.
    let resolver = NoOpResolver;
    let alice_trusts = StaticPinnedKeyStore::new([bob.verifying_key()]);
    let make_cfg = || {
        PeerConfig::new(
            &alice,
            &alice_manifest,
            &resolver,
            &alice_trusts,
            Timestamp::now(),
        )
    };
    let cfg = make_cfg();
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

    let cfg = make_cfg();
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

    let cfg = make_cfg();
    let alice_holds = initiator
        .on_commit_ack(&commit_ack_envelope, &commit_ack_payload, &cfg)
        .unwrap();
    assert_eq!(&alice_holds.tct.claims.iss, bob.aid());
    assert_eq!(&alice_holds.tct.claims.sub, alice.aid());
    assert_eq!(alice_holds.tct.claims.grants, vec!["demo.echo".to_string()]);

    server.abort();
    let _ = server.await;
    let _ = Sender {
        agent_id: alice.aid().clone(),
    };
}

/// GAP-3: a `HandshakeServer` configured with a pinned-key trust store
/// rejects an initiator whose Ed25519 key is absent from the store with
/// `IDENTITY_FAILED` (RFC-AITP-0002 §3.2 step 1). Before rc.2 the
/// handlers hardcoded `pinned_key_store: None`, so any key-possessing
/// peer was accepted regardless of the server's trust configuration.
#[tokio::test]
async fn pinned_key_store_rejects_untrusted_initiator() {
    let alice = AitpSigningKey::from_seed(&[0x81; 32]);
    let bob = AitpSigningKey::from_seed(&[0x82; 32]);

    let bob_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bob_port = bob_listener.local_addr().unwrap().port();
    let bob_endpoint = format!("http://localhost:{bob_port}/aitp/handshake");
    let bob_manifest = manifest_for(&bob, "bob", &bob_endpoint);
    let alice_manifest = manifest_for(&alice, "alice", "http://localhost:0/aitp/handshake");

    // Bob's pinned-key store trusts a stranger — NOT Alice.
    let stranger = AitpSigningKey::from_seed(&[0x99; 32]);
    let store = StaticPinnedKeyStore::new([stranger.verifying_key()]);
    let handshake_router = HandshakeServer::new(
        AitpSigningKey::from_seed(&[0x82; 32]),
        bob_manifest.clone(),
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    .with_pinned_key_store(Arc::new(store))
    .router();
    let server = tokio::spawn(async move {
        axum::serve(bob_listener, handshake_router.into_make_service())
            .await
            .ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resolver = NoOpResolver;
    let cfg_pinned = aitp_handshake::StaticPinnedKeyStore::new([bob.verifying_key()]);
    let cfg = PeerConfig::new(
        &alice,
        &alice_manifest,
        &resolver,
        &cfg_pinned,
        Timestamp::now(),
    );
    let hello_mid = Uuid::new_v4();
    let hello_ts = Timestamp::now();
    let (_initiator, hello_payload) = Initiator::start(
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

    let resp = reqwest::Client::new()
        .post(format!("http://localhost:{bob_port}/aitp/handshake/hello"))
        .json(&hello_envelope)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "an untrusted pinned key must be rejected"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    let code = body
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str());
    assert_eq!(code, Some("IDENTITY_FAILED"), "got body: {body}");

    server.abort();
    let _ = server.await;
}
