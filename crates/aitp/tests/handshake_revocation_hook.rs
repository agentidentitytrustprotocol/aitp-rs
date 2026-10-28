//! Handshake-time revocation enforcement (BUG-3).
//!
//! Pre-rc.1, `verify_received_tct` always passed `revocation_check:
//! None` to `verify_tct`, so a revoked peer-issued TCT was silently
//! accepted during the Mutual Handshake. RFC-AITP-0008 §1 requires
//! handshake verifiers to consult revocation state for every TCT they
//! receive.
//!
//! These tests exercise the `PeerConfig::revocation` hook
//! end-to-end: a TCT whose JTI is reported revoked must fail
//! `MUTUAL_COMMIT` with `TctError::Revoked`, and a fail-closed lookup
//! error from the hook must propagate as a `HandshakeError`.
//!
//! They also pin the RFC-AITP-0008 §3.3 ordering requirement: the TCT
//! signature MUST be verified before the revocation hook is consulted,
//! so a tampered, wrong-audience, or expired TCT never triggers a
//! revocation lookup. Those tests install a hook that panics if called.

use aitp::core::{AitpEnvelope, MessageType, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::handshake::error::HandshakeError;
use aitp::handshake::{
    Initiator, JwkPublicKey, JwksResolver, PeerConfig, PresentedIdentity, ResolveError, Responder,
};
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use aitp::tct::{
    RevocationCheckFn, RevocationQuery, RevocationStatus, RevocationUnavailable, TctError,
};
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
        .identity_hint(
            IdentityHint::new(IdentityHintKind::PinnedKey, name).with_public_key(
                aitp::core::base64url::encode(
                    &key.verifying_key()
                        .try_to_ed25519_bytes()
                        .expect("key was constructed as Ed25519, never P-256"),
                ),
            ),
        )
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
    let mut envelope =
        AitpEnvelope::unsigned(sender.aid().clone(), mt, payload, message_id, timestamp);
    let digest = aitp::core::envelope_signing_digest(&envelope).unwrap();
    envelope.signature = sender
        .sign_jcs(&aitp::crypto::Digest32::from(digest))
        .into_string();
    envelope
}

/// Re-sign the staged commit's TCT after mutating its decoded claims —
/// the JWS analogue of the old struct-field tampering. Signed with
/// alice's (the issuer's) fixed-seed key so the signature stays valid
/// and the mutated claim is what trips the verifier.
fn resign_commit_tct(
    payload: &mut aitp::handshake::MutualCommitPayload,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let alice = AitpSigningKey::from_ed25519_seed(&[0xAA; 32]);
    let bytes = aitp::crypto::jws::decode_payload_unverified(&payload.tct).unwrap();
    let mut claims: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    mutate(&mut claims);
    payload.tct =
        aitp::crypto::jws::sign_compact(&alice, aitp::crypto::jws::TYP_TCT, &claims).unwrap();
}

/// Helper: drive HELLO + HELLO_ACK + COMMIT setup so each test can
/// plug a different `revocation_check` into Bob's commit-time config.
struct StagedCommit {
    bob_resp: Responder,
    commit_envelope: AitpEnvelope,
    commit_payload: aitp::handshake::MutualCommitPayload,
    bob: AitpSigningKey,
    bob_manifest: Manifest,
}

fn stage_through_commit() -> StagedCommit {
    let alice = AitpSigningKey::from_ed25519_seed(&[0xAA; 32]);
    let bob = AitpSigningKey::from_ed25519_seed(&[0xBB; 32]);
    let alice_manifest = manifest_for(&alice, "alice");
    let bob_manifest = manifest_for(&bob, "bob");
    let resolver = NoOpResolver;

    let alice_cfg_pinned = aitp::handshake::StaticPinnedKeyStore::new([bob.verifying_key()]);
    let alice_cfg = PeerConfig::new(
        &alice,
        &alice_manifest,
        &resolver,
        &alice_cfg_pinned,
        aitp::tct::RevocationSource::FailOpen,
        NOW,
    );
    let bob_cfg_pinned = aitp::handshake::StaticPinnedKeyStore::new([alice.verifying_key()]);
    let bob_cfg = PeerConfig::new(
        &bob,
        &bob_manifest,
        &resolver,
        &bob_cfg_pinned,
        aitp::tct::RevocationSource::FailOpen,
        NOW,
    );

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

/// A revocation hook reporting `Revoked` for the JTI carried in the
/// MUTUAL_COMMIT TCT must abort the handshake with
/// `HandshakeError::Tct(TctError::Revoked)`.
#[test]
fn revoked_tct_in_mutual_commit_aborts_handshake() {
    // A static counter keeps the boxed hook `'static`.
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    CALLS.store(0, Ordering::Relaxed);
    let mut staged = stage_through_commit();
    let resolver = NoOpResolver;
    let hook: Box<RevocationCheckFn<'static>> = Box::new(|_q: &RevocationQuery<'_>| {
        CALLS.fetch_add(1, Ordering::Relaxed);
        Ok(RevocationStatus::Revoked)
    });
    let hook_ref: &RevocationCheckFn<'_> = &*hook;

    let bob_cfg = PeerConfig::new(
        &staged.bob,
        &staged.bob_manifest,
        &resolver,
        &aitp::handshake::NoPinnedKeys,
        aitp::tct::RevocationSource::Check(hook_ref),
        NOW,
    );
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
/// snapshot source is unreachable) surfaces as
/// `Tct(RevocationUnavailable)` carrying the hook's reason.
#[test]
fn revocation_provider_failure_propagates() {
    let mut staged = stage_through_commit();
    let resolver = NoOpResolver;
    let hook: Box<RevocationCheckFn<'static>> = Box::new(|_q: &RevocationQuery<'_>| {
        Err(RevocationUnavailable::new(
            "revocation provider unreachable",
        ))
    });
    let hook_ref: &RevocationCheckFn<'_> = &*hook;

    let bob_cfg = PeerConfig::new(
        &staged.bob,
        &staged.bob_manifest,
        &resolver,
        &aitp::handshake::NoPinnedKeys,
        aitp::tct::RevocationSource::Check(hook_ref),
        NOW,
    );
    let err = staged
        .bob_resp
        .on_commit(&staged.commit_envelope, &staged.commit_payload, &bob_cfg)
        .expect_err("hook error must propagate");
    assert!(
        matches!(
            err,
            HandshakeError::Tct(TctError::RevocationUnavailable(ref e))
                if e.to_string().contains("unreachable")
        ),
        "expected Tct(RevocationUnavailable) from hook, got {err:?}"
    );
}

/// The explicit `RevocationSource::FailOpen` opt-out skips the lookup and
/// the handshake proceeds without a revocation hook.
#[test]
fn fail_open_opt_out_skips_the_hook() {
    let mut staged = stage_through_commit();
    let resolver = NoOpResolver;
    let bob_cfg = PeerConfig::new(
        &staged.bob,
        &staged.bob_manifest,
        &resolver,
        &aitp::handshake::NoPinnedKeys,
        aitp::tct::RevocationSource::FailOpen,
        NOW,
    );
    let _ = staged
        .bob_resp
        .on_commit(&staged.commit_envelope, &staged.commit_payload, &bob_cfg)
        .expect("commit succeeds without revocation hook");
}

/// SoftFailSafeSubset whose `safe_grants` overlaps the received TCT's
/// `grants` must let the handshake proceed (degraded — local enforcement
/// restricts the session to the intersection).
#[test]
fn soft_fail_safe_subset_with_intersection_accepts() {
    let mut staged = stage_through_commit();
    let resolver = NoOpResolver;
    let hook: Box<RevocationCheckFn<'static>> = Box::new(|_q: &RevocationQuery<'_>| {
        Ok(RevocationStatus::soft_fail_safe_subset(vec![
            "demo.echo".into()
        ]))
    });
    let hook_ref: &RevocationCheckFn<'_> = &*hook;
    let bob_cfg = PeerConfig::new(
        &staged.bob,
        &staged.bob_manifest,
        &resolver,
        &aitp::handshake::NoPinnedKeys,
        aitp::tct::RevocationSource::Check(hook_ref),
        NOW,
    );
    let (_ack, completed) = staged
        .bob_resp
        .on_commit(&staged.commit_envelope, &staged.commit_payload, &bob_cfg)
        .expect("soft-fail with overlapping safe_grants must accept");
    assert_eq!(completed.effective_grants(), ["demo.echo"]);
    assert_eq!(completed.tct().effective_grants(), ["demo.echo"]);
}

/// RFC-AITP-0008 §3.3: a TCT whose signature does not validate MUST be
/// rejected *before* any remote revocation lookup. The hook here panics
/// if invoked — the test passes only if the handshake fails at
/// signature verification without the revocation source ever being
/// consulted (no panic).
#[test]
fn invalid_tct_signature_skips_revocation_lookup() {
    let mut staged = stage_through_commit();
    let resolver = NoOpResolver;
    // Tamper the signature on the TCT carried in MUTUAL_COMMIT. It
    // still parses as a 64-byte Ed25519 signature but cannot verify.
    {
        let parts: Vec<&str> = staged.commit_payload.tct.split('.').collect();
        staged.commit_payload.tct = format!(
            "{}.{}.{}",
            parts[0],
            parts[1],
            aitp::core::base64url::encode(&[0u8; 64])
        );
    }
    let hook: Box<RevocationCheckFn<'static>> = Box::new(|_q: &RevocationQuery<'_>| {
        panic!("revocation hook called before TCT signature verification");
    });
    let hook_ref: &RevocationCheckFn<'_> = &*hook;
    let bob_cfg = PeerConfig::new(
        &staged.bob,
        &staged.bob_manifest,
        &resolver,
        &aitp::handshake::NoPinnedKeys,
        aitp::tct::RevocationSource::Check(hook_ref),
        NOW,
    );
    let err = staged
        .bob_resp
        .on_commit(&staged.commit_envelope, &staged.commit_payload, &bob_cfg)
        .expect_err("tampered TCT signature must fail commit");
    assert!(
        matches!(
            err,
            HandshakeError::Tct(TctError::Crypto(
                aitp::crypto::CryptoError::SignatureInvalid
            ))
        ),
        "expected Tct(Crypto(SignatureInvalid)), got {err:?}"
    );
}

/// A TCT whose `audience` does not match the verifier MUST be rejected
/// before revocation — `verify_tct` checks audience ahead of both the
/// signature and the revocation hook (RFC-AITP-0005 §9 + RFC-AITP-0008
/// §3.3). The panicking hook proves the lookup never runs.
#[test]
fn wrong_audience_skips_revocation_lookup() {
    let mut staged = stage_through_commit();
    let resolver = NoOpResolver;
    let stranger = AitpSigningKey::from_ed25519_seed(&[0xCC; 32]);
    let stranger_aid = stranger.aid().clone();
    resign_commit_tct(&mut staged.commit_payload, |claims| {
        claims["aud"] = serde_json::to_value(&stranger_aid).unwrap();
    });
    let hook: Box<RevocationCheckFn<'static>> = Box::new(|_q: &RevocationQuery<'_>| {
        panic!("revocation hook called for a TCT with the wrong audience");
    });
    let hook_ref: &RevocationCheckFn<'_> = &*hook;
    let bob_cfg = PeerConfig::new(
        &staged.bob,
        &staged.bob_manifest,
        &resolver,
        &aitp::handshake::NoPinnedKeys,
        aitp::tct::RevocationSource::Check(hook_ref),
        NOW,
    );
    let err = staged
        .bob_resp
        .on_commit(&staged.commit_envelope, &staged.commit_payload, &bob_cfg)
        .expect_err("wrong audience must fail commit");
    assert!(
        matches!(err, HandshakeError::Tct(TctError::AudienceMismatch)),
        "expected Tct(AudienceMismatch), got {err:?}"
    );
}

/// An expired TCT MUST be rejected before revocation — `verify_tct`
/// checks expiry ahead of the revocation hook (RFC-AITP-0008 §3.3).
#[test]
fn expired_tct_skips_revocation_lookup() {
    let mut staged = stage_through_commit();
    let resolver = NoOpResolver;
    resign_commit_tct(&mut staged.commit_payload, |claims| {
        claims["exp"] = serde_json::json!(NOW.0 - 100);
    });
    let hook: Box<RevocationCheckFn<'static>> = Box::new(|_q: &RevocationQuery<'_>| {
        panic!("revocation hook called for an expired TCT");
    });
    let hook_ref: &RevocationCheckFn<'_> = &*hook;
    let bob_cfg = PeerConfig::new(
        &staged.bob,
        &staged.bob_manifest,
        &resolver,
        &aitp::handshake::NoPinnedKeys,
        aitp::tct::RevocationSource::Check(hook_ref),
        NOW,
    );
    let err = staged
        .bob_resp
        .on_commit(&staged.commit_envelope, &staged.commit_payload, &bob_cfg)
        .expect_err("expired TCT must fail commit");
    assert!(
        matches!(err, HandshakeError::Tct(TctError::Expired)),
        "expected Tct(Expired), got {err:?}"
    );
}

/// SoftFailSafeSubset whose `safe_grants` is disjoint from the
/// received TCT's `grants` must fail with `PolicyViolation` —
/// degrading to a zero-grant session is not useful.
#[test]
fn soft_fail_safe_subset_with_empty_intersection_rejects() {
    let mut staged = stage_through_commit();
    let resolver = NoOpResolver;
    let hook: Box<RevocationCheckFn<'static>> = Box::new(|_q: &RevocationQuery<'_>| {
        Ok(RevocationStatus::soft_fail_safe_subset(vec![
            "unrelated.cap".into(),
        ]))
    });
    let hook_ref: &RevocationCheckFn<'_> = &*hook;
    let bob_cfg = PeerConfig::new(
        &staged.bob,
        &staged.bob_manifest,
        &resolver,
        &aitp::handshake::NoPinnedKeys,
        aitp::tct::RevocationSource::Check(hook_ref),
        NOW,
    );
    let err = staged
        .bob_resp
        .on_commit(&staged.commit_envelope, &staged.commit_payload, &bob_cfg)
        .expect_err("empty safe-grants intersection must fail");
    assert!(
        matches!(err, HandshakeError::PolicyViolation),
        "expected PolicyViolation, got {err:?}"
    );
}
