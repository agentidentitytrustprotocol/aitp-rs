//! End-to-end: spin up the lib's `HandshakeServer` (responder side),
//! drive the `Initiator` over real HTTP via `reqwest`, and assert both
//! peers end up holding cross-issued TCTs.

#![cfg(all(feature = "http-client", feature = "http-server"))]

use aitp::core::{AitpEnvelope, MessageType, Sender, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::handshake::{
    Initiator, JwkPublicKey, JwksResolver, MutualCommitAckPayload, MutualHelloAckPayload,
    PeerConfig, PresentedIdentity, ResolveError, StaticPinnedKeyStore,
};
use aitp::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp::transport::{
    sign_envelope_with, HandshakeServer, RevocationFailMode, RevocationFetcher, RevocationPolicy,
    REVOCATION_LIST_PATH,
};
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
) -> aitp::manifest::Manifest {
    manifest_with_revocation(key, name, handshake_endpoint, None)
}

fn manifest_with_revocation(
    key: &AitpSigningKey,
    name: &str,
    handshake_endpoint: &str,
    revocation_list_uri: Option<String>,
) -> aitp::manifest::Manifest {
    let mut builder = ManifestBuilder::new(key);
    if let Some(uri) = revocation_list_uri {
        builder = builder.revocation_list_uri(uri.parse().unwrap());
    }
    builder
        .display_name(name)
        .handshake_endpoint(handshake_endpoint.parse().unwrap())
        // 32 bytes for Ed25519, 33-byte SEC1 compressed for P-256: the
        // AID identifier bytes (RFC-AITP-0002 §3.2 step 2).
        .identity_hint(
            IdentityHint::new(IdentityHintKind::PinnedKey, name).with_public_key(
                aitp::core::base64url::encode(&key.verifying_key().to_compressed()),
            ),
        )
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .build()
        .unwrap()
}

/// How the initiator (Alice) handles revocation in a test run.
#[derive(Clone, Copy, PartialEq)]
enum AliceRevocation {
    /// Alice serves a signed snapshot and advertises it; both sides run
    /// the default `fail_closed` policy.
    Published,
    /// Alice advertises no `ListRevoked` URL; Bob runs `fail_closed`.
    UnadvertisedFailClosed,
    /// Alice advertises no `ListRevoked` URL; Bob opts into `fail_open`.
    UnadvertisedFailOpen,
}

#[tokio::test]
async fn full_pinned_key_handshake_over_http() {
    run_pinned_handshake(
        AitpSigningKey::from_seed(&[0x71; 32]),
        || AitpSigningKey::from_seed(&[0x72; 32]),
        AliceRevocation::Published,
    )
    .await;
}

/// RS1.2: the default responder policy is `fail_closed`, so an initiator
/// with no advertised revocation list is refused at COMMIT with
/// `TCT_REVOKED`, and the message says the source was unavailable
/// rather than that the TCT is revoked.
#[tokio::test]
async fn unadvertised_revocation_list_fails_closed_at_commit() {
    run_pinned_handshake(
        AitpSigningKey::from_seed(&[0x77; 32]),
        || AitpSigningKey::from_seed(&[0x78; 32]),
        AliceRevocation::UnadvertisedFailClosed,
    )
    .await;
}

/// The explicit `fail_open` opt-out admits the same initiator.
#[tokio::test]
async fn unadvertised_revocation_list_admitted_under_fail_open() {
    run_pinned_handshake(
        AitpSigningKey::from_seed(&[0x79; 32]),
        || AitpSigningKey::from_seed(&[0x7a; 32]),
        AliceRevocation::UnadvertisedFailOpen,
    )
    .await;
}

/// Item 1 of the 2026-10 proposal: a P-256 pinned key is a first-class
/// identity. Both peers P-256, over real HTTP, each pinning the other.
#[tokio::test]
async fn full_p256_pinned_key_handshake_over_http() {
    run_pinned_handshake(
        AitpSigningKey::from_p256_seed(&[0x73; 32]).unwrap(),
        || AitpSigningKey::from_p256_seed(&[0x74; 32]).unwrap(),
        AliceRevocation::Published,
    )
    .await;
}

/// Mixed suites: a P-256 initiator against an Ed25519 responder.
#[tokio::test]
async fn mixed_p256_initiator_ed25519_responder_over_http() {
    run_pinned_handshake(
        AitpSigningKey::from_p256_seed(&[0x75; 32]).unwrap(),
        || AitpSigningKey::from_seed(&[0x76; 32]),
        AliceRevocation::Published,
    )
    .await;
}

/// `make_bob` is called twice: `AitpSigningKey` is deliberately not
/// `Clone`, and both the local verifier and Bob's server need his key.
async fn run_pinned_handshake(
    alice: AitpSigningKey,
    make_bob: impl Fn() -> AitpSigningKey,
    revocation: AliceRevocation,
) {
    let bob = make_bob();

    // Bind Bob first so we know his port.
    let bob_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bob_port = bob_listener.local_addr().unwrap().port();
    let bob_endpoint = format!("http://localhost:{bob_port}/aitp/handshake");

    // Alice runs no handshake server, only her `ListRevoked` endpoint,
    // serving a signed empty snapshot.
    let alice_list_uri = if revocation == AliceRevocation::Published {
        let snapshot = aitp::tct::sign_revocation_list(
            aitp::tct::RevocationList::new(
                alice.aid().clone(),
                Timestamp::now(),
                Timestamp(Timestamp::now().0 + 3600),
                vec![],
            ),
            &alice,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new().route(
            "/revocations",
            axum::routing::get(move || {
                let snapshot = snapshot.clone();
                async move { axum::Json(snapshot) }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service()).await.ok();
        });
        Some(format!("http://localhost:{port}/revocations"))
    } else {
        None
    };

    // Bob's own `HandshakeServer` serves his list at REVOCATION_LIST_PATH.
    let bob_manifest = manifest_with_revocation(
        &bob,
        "bob",
        &bob_endpoint,
        Some(format!("http://localhost:{bob_port}{REVOCATION_LIST_PATH}")),
    );
    let alice_manifest = manifest_with_revocation(
        &alice,
        "alice",
        "http://localhost:0/aitp/handshake", // alice doesn't run a server in this test
        alice_list_uri,
    );

    let bob_policy = RevocationPolicy::default().with_fail_mode(
        if revocation == AliceRevocation::UnadvertisedFailOpen {
            RevocationFailMode::FailOpen
        } else {
            RevocationFailMode::FailClosed
        },
    );
    // `serve` also serves the Manifest.
    let bob_server = HandshakeServer::new(
        make_bob(),
        bob_manifest.clone(),
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    .with_pinned_key_store(Arc::new(StaticPinnedKeyStore::new([alice.verifying_key()])))
    .with_revocation_fetcher(Arc::new(
        RevocationFetcher::new(bob_policy).with_insecure_localhost(true),
    ));

    let server = tokio::spawn(async move {
        bob_server.serve(bob_listener).await.ok();
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
            aitp::handshake::RevocationSource::FailOpen,
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
    if revocation == AliceRevocation::UnadvertisedFailClosed {
        assert_eq!(resp.status().as_u16(), 400);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["error"]["code"], "TCT_REVOKED", "got body: {body}");
        let message = body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("revocation source unavailable"),
            "got body: {body}"
        );
        server.abort();
        return;
    }
    assert!(
        resp.status().is_success(),
        "commit status: {}",
        resp.status()
    );
    let commit_ack_envelope: AitpEnvelope = resp.json().await.unwrap();
    let commit_ack_payload: MutualCommitAckPayload =
        serde_json::from_value(commit_ack_envelope.payload.clone()).unwrap();

    // Alice checks Bob's TCT against his served snapshot, fail_closed.
    let prepared = RevocationFetcher::default()
        .with_insecure_localhost(true)
        .prepare(
            initiator.peer_aid().unwrap(),
            initiator.peer_revocation_list_uri(),
            Timestamp::now(),
        )
        .await;
    assert!(prepared.is_available(), "Bob's snapshot must be fetched");
    let check = move |iss: &aitp::core::Aid, jti: &Uuid| prepared.decide(iss, jti);
    let cfg = PeerConfig::new(
        &alice,
        &alice_manifest,
        &resolver,
        &alice_trusts,
        aitp::handshake::RevocationSource::Check(&check),
        Timestamp::now(),
    );
    let alice_holds = initiator
        .on_commit_ack(&commit_ack_envelope, &commit_ack_payload, &cfg)
        .unwrap();
    assert_eq!(&alice_holds.tct.claims.iss, bob.aid());
    assert_eq!(&alice_holds.tct.claims.sub, alice.aid());
    assert_eq!(alice_holds.tct.claims.grants, vec!["demo.echo".to_string()]);

    server.abort();
    let _ = server.await;
    let _ = Sender::new(alice.aid().clone());
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
    let bob_server = HandshakeServer::new(
        AitpSigningKey::from_seed(&[0x82; 32]),
        bob_manifest.clone(),
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    .with_pinned_key_store(Arc::new(store));
    let server = tokio::spawn(async move {
        bob_server.serve(bob_listener).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resolver = NoOpResolver;
    let cfg_pinned = aitp::handshake::StaticPinnedKeyStore::new([bob.verifying_key()]);
    let cfg = PeerConfig::new(
        &alice,
        &alice_manifest,
        &resolver,
        &cfg_pinned,
        aitp::handshake::RevocationSource::FailOpen,
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
