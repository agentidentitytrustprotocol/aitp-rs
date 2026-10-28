//! Integration test for the facade's one-call initiator driver.
//!
//! `aitp::facade::run_initiator_handshake` is the primary public entry
//! point, but its HTTP orchestration (Manifest fetch, session-header
//! propagation, HELLO → COMMIT sequencing, response validation) was
//! exercised only by an out-of-workspace example binary. This drives it
//! against a real `aitp::transport::HandshakeServer` over loopback HTTP:
//! once for the happy path, once for a server-side rejection (which must
//! surface as `FacadeError::Protocol`, distinct from a transport fault),
//! and once to check the plain-HTTP loopback origin is refused unless
//! the config opts in.

#![cfg(all(feature = "http-client", feature = "http-server"))]

use aitp::crypto::AitpSigningKey;
use aitp::facade::{
    run_initiator_handshake, FacadeError, IdentityMode, InitiatorConfig, TrustMode,
};
use aitp::handshake::{
    GrantPolicyFn, JwkPublicKey, JwksResolver, ResolveError, StaticPinnedKeyStore,
};
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use aitp::transport::{HandshakeServer, RevocationFailMode, RevocationPolicy};
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
    manifest_with_revocation(key, name, handshake_endpoint, None)
}

fn manifest_with_revocation(
    key: &AitpSigningKey,
    name: &str,
    handshake_endpoint: &str,
    revocation_list_uri: Option<String>,
) -> Manifest {
    let mut builder = ManifestBuilder::new(key);
    if let Some(uri) = revocation_list_uri {
        builder = builder.revocation_list_uri(uri.parse().unwrap());
    }
    builder
        .display_name(name)
        .handshake_endpoint(handshake_endpoint.parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityHintKind::PinnedKey, name).with_public_key(
                aitp::core::base64url::encode(
                    &key.verifying_key()
                        .try_to_ed25519_bytes()
                        .expect("key was constructed as Ed25519, never P-256"),
                ),
            ),
        )
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .build()
        .unwrap()
}

/// Spawn Bob's server (Manifest + handshake routes). `pin_initiator`
/// controls the pinned-key store: `None` accepts any peer; `Some(false)`
/// installs an empty store that rejects the (untrusted) initiator.
/// Bob advertises the revocation list his `HandshakeServer` serves; he
/// runs `fail_open` because Alice, who runs no server, publishes none.
async fn spawn_bob(seed: u8, reject_initiator: bool) -> (AitpSigningKey, url::Url) {
    spawn_bob_with(seed, reject_initiator, true, None).await
}

async fn spawn_bob_with(
    seed: u8,
    reject_initiator: bool,
    advertise_revocation: bool,
    grant_policy: Option<Arc<GrantPolicyFn>>,
) -> (AitpSigningKey, url::Url) {
    let bob = AitpSigningKey::from_seed(&[seed; 32]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Trailing slash: the facade resolves routes via endpoint.join("hello").
    let endpoint = format!("http://localhost:{port}/aitp/handshake/");
    let list_uri = advertise_revocation.then(|| {
        format!(
            "http://localhost:{port}{}",
            aitp::transport::REVOCATION_LIST_PATH
        )
    });
    let manifest = manifest_with_revocation(&bob, "bob", &endpoint, list_uri);

    let bob_server_key = AitpSigningKey::from_seed(&[seed; 32]); // same identity
    let mut handshake = HandshakeServer::new(
        bob_server_key,
        manifest.clone(),
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    .with_revocation_policy(
        RevocationPolicy::default().with_fail_mode(RevocationFailMode::FailOpen),
    );
    if reject_initiator {
        // Empty pinned store ⇒ no pinned-key peer is trusted ⇒ reject.
        handshake = handshake.with_pinned_key_store(Arc::new(StaticPinnedKeyStore::default()));
    } else {
        // Bob trusts Alice's pinned key (seed 0x70).
        handshake = handshake.with_pinned_key_store(Arc::new(StaticPinnedKeyStore::new([
            AitpSigningKey::from_seed(&[0x70; 32]).verifying_key(),
        ])));
    }
    if let Some(policy) = grant_policy {
        handshake = handshake.with_grant_policy(policy);
    }
    // `serve` also serves the Manifest.
    tokio::spawn(async move {
        handshake.serve(listener).await.ok();
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

    let trusted = StaticPinnedKeyStore::new([bob.verifying_key()]);
    let session = run_initiator_handshake(
        InitiatorConfig::new(
            &alice,
            &alice_manifest,
            bob_origin,
            TrustMode::PinnedKeys(&trusted),
            IdentityMode::PinnedKey {
                subject: "alice".into(),
            },
            vec!["demo.echo".into()],
        )
        .with_insecure_localhost_dangerous(),
    )
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

/// RS1.2: the facade's default revocation policy is `fail_closed`, so a
/// peer whose Manifest advertises no revocation list is refused after
/// COMMIT_ACK with `RevocationUnavailable` (`TCT_REVOKED` on the wire),
/// distinct from a revoked TCT. `fail_open` admits the same peer.
#[tokio::test]
async fn facade_fails_closed_without_peer_revocation_list() {
    let (bob, bob_origin) = spawn_bob_with(0x77, false, false, None).await;

    let alice = AitpSigningKey::from_seed(&[0x70; 32]);
    let alice_manifest = manifest_for(&alice, "alice", "http://localhost:1/aitp/handshake/");
    let trusted = StaticPinnedKeyStore::new([bob.verifying_key()]);
    let config = || {
        InitiatorConfig::new(
            &alice,
            &alice_manifest,
            bob_origin.clone(),
            TrustMode::PinnedKeys(&trusted),
            IdentityMode::PinnedKey {
                subject: "alice".into(),
            },
            vec!["demo.echo".into()],
        )
        .with_insecure_localhost_dangerous()
    };

    let err = run_initiator_handshake(config())
        .await
        .expect_err("no revocation list under fail_closed must be refused");
    assert!(
        matches!(
            err,
            FacadeError::Handshake(aitp::handshake::HandshakeError::Tct(
                aitp::tct::TctError::RevocationUnavailable(_)
            ))
        ),
        "got {err:?}"
    );

    run_initiator_handshake(config().with_revocation_policy(
        RevocationPolicy::default().with_fail_mode(RevocationFailMode::FailOpen),
    ))
    .await
    .expect("fail_open admits the peer");
}

#[tokio::test]
async fn the_server_grant_policy_narrows_the_issued_tct() {
    let deny_all: Arc<GrantPolicyFn> = Arc::new(|ctx| {
        assert_eq!(ctx.candidate_grants, ["demo.echo"]);
        Ok(vec![])
    });
    let (bob, bob_origin) = spawn_bob_with(0x74, false, true, Some(deny_all)).await;

    let alice = AitpSigningKey::from_seed(&[0x70; 32]);
    let alice_manifest = manifest_for(&alice, "alice", "http://localhost:1/aitp/handshake/");
    let trusted = StaticPinnedKeyStore::new([bob.verifying_key()]);
    let err = run_initiator_handshake(
        InitiatorConfig::new(
            &alice,
            &alice_manifest,
            bob_origin,
            TrustMode::PinnedKeys(&trusted),
            IdentityMode::PinnedKey {
                subject: "alice".into(),
            },
            vec!["demo.echo".into()],
        )
        .with_insecure_localhost_dangerous(),
    )
    .await
    .expect_err("a server policy granting nothing refuses the handshake");
    match err {
        FacadeError::Protocol { code, .. } => assert_eq!(code, "POLICY_VIOLATION"),
        other => panic!("expected FacadeError::Protocol, got {other:?}"),
    }
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

    let trusted = aitp::handshake::NoPinnedKeys;
    let err = run_initiator_handshake(
        InitiatorConfig::new(
            &alice,
            &alice_manifest,
            bob_origin,
            TrustMode::PinnedKeys(&trusted),
            IdentityMode::PinnedKey {
                subject: "alice".into(),
            },
            vec!["demo.echo".into()],
        )
        .with_insecure_localhost_dangerous(),
    )
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

#[tokio::test]
async fn facade_refuses_http_localhost_peer_by_default() {
    // #198: without `with_insecure_localhost_dangerous()` the plain-HTTP
    // loopback origin is refused at the Manifest fetch (RFC-AITP-0003
    // §4.1), before any handshake traffic.
    let (bob, bob_origin) = spawn_bob(0x75, false).await;

    let alice = AitpSigningKey::from_seed(&[0x70; 32]);
    let alice_manifest = manifest_for(&alice, "alice", "http://localhost:1/aitp/handshake/");

    let trusted = StaticPinnedKeyStore::new([bob.verifying_key()]);
    let err = run_initiator_handshake(InitiatorConfig::new(
        &alice,
        &alice_manifest,
        bob_origin,
        TrustMode::PinnedKeys(&trusted),
        IdentityMode::PinnedKey {
            subject: "alice".into(),
        },
        vec!["demo.echo".into()],
    ))
    .await
    .expect_err("http://localhost peer must be refused by default");

    assert!(
        matches!(
            err,
            FacadeError::Manifest(aitp::transport::FetchError::InsecureUrl)
        ),
        "expected FacadeError::Manifest(InsecureUrl), got {err:?}"
    );
}
