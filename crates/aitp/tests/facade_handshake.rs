//! Integration test for the facade's one-call initiator driver.
//!
//! `aitp::facade::run_initiator_handshake` is the primary public entry
//! point, but its HTTP orchestration (Manifest fetch, session-header
//! propagation, HELLO → COMMIT sequencing, response validation) was
//! exercised only by an out-of-workspace example binary. This drives it
//! against a real `aitp::transport::HandshakeServer` over loopback HTTP:
//! once for the happy path, once for a server-side rejection (which must
//! surface as `FacadeError::Protocol`, distinct from a transport fault).

#![cfg(all(feature = "http-client", feature = "http-server"))]

use aitp::crypto::AitpSigningKey;
use aitp::facade::{
    run_initiator_handshake, FacadeError, IdentityMode, InitiatorConfig, TrustMode,
};
use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError, StaticPinnedKeyStore};
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use aitp::transport::{HandshakeServer, ManifestServer};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn manifest_for(key: &AitpSigningKey, name: &str, handshake_endpoint: &str) -> Manifest {
    ManifestBuilder::new(key)
        .display_name(name)
        .handshake_endpoint(handshake_endpoint.parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: name.into(),
            issuer: None,
            public_key: Some(aitp::core::base64url::encode(
                &key.verifying_key().to_bytes(),
            )),
        })
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .build()
        .unwrap()
}

/// Spawn Bob's server (Manifest + handshake routes). `pin_initiator`
/// controls the pinned-key store: `None` accepts any peer; `Some(false)`
/// installs an empty store that rejects the (untrusted) initiator.
async fn spawn_bob(seed: u8, reject_initiator: bool) -> (AitpSigningKey, url::Url) {
    let bob = AitpSigningKey::from_seed(&[seed; 32]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Trailing slash: the facade resolves routes via endpoint.join("hello").
    let endpoint = format!("http://localhost:{port}/aitp/handshake/");
    let manifest = manifest_for(&bob, "bob", &endpoint);

    let bob_server_key = AitpSigningKey::from_seed(&[seed; 32]); // same identity
    let mut handshake = HandshakeServer::new(
        bob_server_key,
        manifest.clone(),
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    );
    if reject_initiator {
        // Empty pinned store ⇒ no pinned-key peer is trusted ⇒ reject.
        handshake = handshake.with_pinned_key_store(Arc::new(StaticPinnedKeyStore::new(vec![])));
    }
    let app = ManifestServer::new(manifest)
        .router()
        .merge(handshake.router());

    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.ok();
    });
    // Give the listener a beat to start accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let origin: url::Url = format!("http://localhost:{port}").parse().unwrap();
    (bob, origin)
}

#[tokio::test]
async fn facade_drives_full_handshake_and_returns_peer_tct() {
    let (bob, bob_origin) = spawn_bob(0x71, false).await;

    let alice = AitpSigningKey::from_seed(&[0x70; 32]);
    let alice_manifest = manifest_for(&alice, "alice", "http://localhost:1/aitp/handshake/");

    let session = run_initiator_handshake(InitiatorConfig {
        signing_key: &alice,
        own_manifest: &alice_manifest,
        peer_origin: bob_origin,
        trust_mode: TrustMode::UnsafeNoTrustEnforcement,
        identity_mode: IdentityMode::PinnedKey {
            subject: "alice".into(),
        },
        requested_grants: vec!["demo.echo".into()],
    })
    .await
    .expect("facade handshake succeeds");

    assert_eq!(
        &session.peer_aid,
        bob.aid(),
        "peer AID is Bob's (the TCT issuer)"
    );
    assert_eq!(&session.held_tct.claims.iss, bob.aid());
    assert!(
        session
            .held_tct
            .claims
            .grants
            .iter()
            .any(|g| g == "demo.echo"),
        "held TCT carries the requested grant"
    );
}

#[tokio::test]
async fn facade_surfaces_peer_protocol_rejection() {
    // Bob installs an empty pinned-key store, so he rejects Alice's
    // pinned-key identity during the HELLO. The facade must classify
    // this as a protocol rejection (an AITP error envelope), not a
    // transport fault.
    let (_bob, bob_origin) = spawn_bob(0x73, true).await;

    let alice = AitpSigningKey::from_seed(&[0x70; 32]);
    let alice_manifest = manifest_for(&alice, "alice", "http://localhost:1/aitp/handshake/");

    let err = run_initiator_handshake(InitiatorConfig {
        signing_key: &alice,
        own_manifest: &alice_manifest,
        peer_origin: bob_origin,
        trust_mode: TrustMode::UnsafeNoTrustEnforcement,
        identity_mode: IdentityMode::PinnedKey {
            subject: "alice".into(),
        },
        requested_grants: vec!["demo.echo".into()],
    })
    .await
    .expect_err("untrusted initiator must be rejected");

    match err {
        FacadeError::Protocol { code, .. } => {
            assert!(
                !code.is_empty(),
                "protocol rejection carries the peer's error code (got {code:?})"
            );
        }
        other => panic!("expected FacadeError::Protocol, got {other:?}"),
    }
}
