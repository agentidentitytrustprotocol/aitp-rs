//! Handshake-time revocation enforcement (BUG-3).
//!
//! Pre-rc.1, `verify_received_tct` always passed `revocation_check:
//! None` to `verify_tct`, so a revoked peer-issued TCT was silently
//! accepted during the Mutual Handshake. RFC-AITP-0008 §1 requires
//! handshake verifiers to consult revocation state for every TCT they
//! receive.
//!
//! These tests exercise the new `PeerConfig::revocation_check` hook
//! end-to-end: a TCT whose JTI is reported revoked must fail
//! `MUTUAL_COMMIT` with `TctError::Revoked`, and a fail-closed lookup
//! error from the hook must propagate as a `HandshakeError`.

use aitp_core::{Aid, AitpEnvelope, MessageType, Sender, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_handshake::error::HandshakeError;
use aitp_handshake::state_machine::RevocationCheckFn;
use aitp_handshake::{
    Initiator, JwkPublicKey, JwksResolver, PeerConfig, PresentedIdentity, ResolveError, Responder,
};
use aitp_manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use aitp_tct::TctError;
use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn manifest_for(key: &AitpSigningKey, name: &str) -> Manifest {
    ManifestBuilder::new(key)
        .display_name(name)
        .handshake_endpoint(
            format!("https://{}.example.com/handshake", name)
                .parse()
                .unwrap(),
        )
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
        .published_at(NOW)
        .build()
        .unwrap()
}

fn envelope_with(
    sender: &AitpSigningKey,
    mt: MessageType,
    payload: serde_json::Value,
    message_id: Uuid,
    timestamp: Timestamp,
) -> AitpEnvelope {
    let digest =
        aitp_core::envelope_signing_digest(&message_id, timestamp, sender.aid(), &payload).unwrap();
    let sig = sender.sign(&digest);
    AitpEnvelope {
        version: "aitp/0.1".into(),
        message_type: mt,
        message_id,
        timestamp,
        sender: Sender {
            agent_id: sender.aid().clone(),
        },
        payload,
        signature: sig.into_string(),
    }
}

/// Helper: drive HELLO + HELLO_ACK + COMMIT setup so each test can
/// plug a different `revocation_check` into Bob's commit-time config.
struct StagedCommit {
    bob_resp: Responder,
    commit_envelope: AitpEnvelope,
    commit_payload: aitp_handshake::MutualCommitPayload,
    bob: AitpSigningKey,
    bob_manifest: Manifest,
}

fn stage_through_commit() -> StagedCommit {
    let alice = AitpSigningKey::from_seed(&[0xAA; 32]);
    let bob = AitpSigningKey::from_seed(&[0xBB; 32]);
    let alice_manifest = manifest_for(&alice, "alice");
    let bob_manifest = manifest_for(&bob, "bob");
    let resolver = NoOpResolver;

    let alice_cfg = PeerConfig {
        signing_key: &alice,
        manifest: &alice_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: NOW,
    };
    let bob_cfg = PeerConfig {
        signing_key: &bob,
        manifest: &bob_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: NOW,
    };

    let hello_mid = Uuid::new_v4();
    let (mut alice_init, hello_payload) = Initiator::start(
        &alice_cfg,
        PresentedIdentity::PinnedKey {
            subject: "alice".into(),
        },
        bob.aid(),
        &hello_mid,
        NOW,
        vec!["demo.echo".into()],
    )
    .unwrap();
    let hello_envelope = envelope_with(
        &alice,
        MessageType::MutualHello,
        serde_json::to_value(&hello_payload).unwrap(),
        hello_mid,
        NOW,
    );
    let ack_mid = Uuid::new_v4();
    let (bob_resp, ack_payload) = Responder::on_hello(
        &hello_envelope,
        &hello_payload,
        PresentedIdentity::PinnedKey {
            subject: "bob".into(),
        },
        &ack_mid,
        NOW,
        &bob_cfg,
        vec!["demo.echo".into()],
    )
    .unwrap();
    let ack_envelope = envelope_with(
        &bob,
        MessageType::MutualHelloAck,
        serde_json::to_value(&ack_payload).unwrap(),
        ack_mid,
        NOW,
    );
    let commit_payload = alice_init
        .on_hello_ack(&ack_envelope, &ack_payload, &alice_cfg)
        .unwrap();
    let commit_mid = Uuid::new_v4();
    let commit_envelope = envelope_with(
        &alice,
        MessageType::MutualCommit,
        serde_json::to_value(&commit_payload).unwrap(),
        commit_mid,
        NOW,
    );

    StagedCommit {
        bob_resp,
        commit_envelope,
        commit_payload,
        bob,
        bob_manifest,
    }
}

/// A revocation hook reporting `Ok(true)` for the JTI carried in the
/// MUTUAL_COMMIT TCT must abort the handshake with
/// `HandshakeError::Tct(TctError::Revoked)`.
#[test]
fn revoked_tct_in_mutual_commit_aborts_handshake() {
    // The trait object behind `revocation_check: Option<&dyn Fn(...)>`
    // is `Send + Sync + 'static`, so it can't borrow stack state.
    // Use a static counter instead.
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    CALLS.store(0, Ordering::Relaxed);
    let mut staged = stage_through_commit();
    let resolver = NoOpResolver;
    let hook: Box<RevocationCheckFn> = Box::new(|_issuer: &Aid, _jti: &Uuid| {
        CALLS.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    });
    let hook_ref: &RevocationCheckFn = &*hook;

    let bob_cfg = PeerConfig {
        signing_key: &staged.bob,
        manifest: &staged.bob_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: Some(hook_ref),
        now: NOW,
    };
    let err = staged
        .bob_resp
        .on_commit(&staged.commit_envelope, &staged.commit_payload, &bob_cfg)
        .expect_err("revoked TCT must fail commit");
    assert!(
        matches!(err, HandshakeError::Tct(TctError::Revoked)),
        "expected Tct(Revoked), got {err:?}"
    );
    assert_eq!(
        CALLS.load(Ordering::Relaxed),
        1,
        "revocation hook should be called exactly once per received TCT"
    );
}

/// A revocation hook returning `Err` (e.g. fail-closed when the
/// snapshot source is unreachable) must propagate the error
/// untranslated, so callers can map provider-level diagnostics to
/// their own error surface.
#[test]
fn revocation_provider_failure_propagates() {
    let mut staged = stage_through_commit();
    let resolver = NoOpResolver;
    let hook: Box<RevocationCheckFn> = Box::new(|_issuer: &Aid, _jti: &Uuid| {
        Err(HandshakeError::InvalidEnvelope(
            "revocation provider unreachable".into(),
        ))
    });
    let hook_ref: &RevocationCheckFn = &*hook;

    let bob_cfg = PeerConfig {
        signing_key: &staged.bob,
        manifest: &staged.bob_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: Some(hook_ref),
        now: NOW,
    };
    let err = staged
        .bob_resp
        .on_commit(&staged.commit_envelope, &staged.commit_payload, &bob_cfg)
        .expect_err("hook error must propagate");
    assert!(
        matches!(err, HandshakeError::InvalidEnvelope(ref s) if s.contains("unreachable")),
        "expected InvalidEnvelope from hook, got {err:?}"
    );
}

/// Sanity: with `revocation_check: None` (the default), the hook is
/// skipped and the handshake proceeds as it did before rc.1.
#[test]
fn missing_hook_preserves_default_acceptance() {
    let mut staged = stage_through_commit();
    let resolver = NoOpResolver;
    let bob_cfg = PeerConfig {
        signing_key: &staged.bob,
        manifest: &staged.bob_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: NOW,
    };
    let _ = staged
        .bob_resp
        .on_commit(&staged.commit_envelope, &staged.commit_payload, &bob_cfg)
        .expect("commit succeeds without revocation hook");
}
