//! Isolated rejection tests for the TCT verifier's early guards and the
//! downstream PoP check.
//!
//! `round_trip.rs` proves the happy paths plus a few rejections, but the
//! `VersionUnknown` guard, the Ed25519 `CnfMalformed` branch (in
//! isolation, not collapsed with `SignatureInvalid`), and the two
//! cryptographic PoP-failure branches (`PopFailed` on a forged signature,
//! `PopChallengeExpired` past the challenge window) had no negative test.
//! Each mutation here trips exactly one guard because `verify_tct` checks
//! version → audience → expiry → grants → cnf **before** the signature.

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_tct::{
    sign_pop_response, verify_pop_response, verify_tct, PopChallenge, Tct, TctBuilder, TctError,
    TctVerifyContext,
};

const NOW: Timestamp = Timestamp(1_700_000_000);

fn issuer_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xA0; 32])
}
fn subject_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xB0; 32])
}

fn build_tct() -> Tct {
    TctBuilder::new(&issuer_key())
        .subject(subject_key().aid().clone())
        .audience(subject_key().aid().clone())
        .grants(["demo.echo"])
        .ttl_secs(3600)
        .subject_pubkey(subject_key().verifying_key())
        .issued_at(NOW)
        .build()
        .expect("builder ok")
}

#[test]
fn unknown_version_rejected() {
    let issuer = issuer_key();
    let subject = subject_key();
    let mut tct = build_tct();
    tct.version = "aitp/9.9".into();
    let pk = issuer.verifying_key();
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer_pubkey: &pk,
        now: NOW,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    assert!(matches!(
        verify_tct(&tct, &ctx).unwrap_err(),
        TctError::VersionUnknown
    ));
}

#[test]
fn non_base64url_cnf_rejected() {
    let issuer = issuer_key();
    let subject = subject_key();
    let mut tct = build_tct();
    tct.binding.cnf = "not base64url!!".into();
    let pk = issuer.verifying_key();
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer_pubkey: &pk,
        now: NOW,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    assert!(matches!(
        verify_tct(&tct, &ctx).unwrap_err(),
        TctError::CnfMalformed
    ));
}

#[test]
fn cnf_not_matching_subject_key_rejected() {
    // A well-formed 43-char base64url cnf (decodes to 32 bytes) that is
    // NOT the subject's pubkey. The cnf-binding check runs before the
    // signature check, so this is `CnfMalformed`, not `SignatureInvalid`.
    let issuer = issuer_key();
    let subject = subject_key();
    let mut tct = build_tct();
    tct.binding.cnf = "A".repeat(43); // 32 zero bytes ≠ subject key
    let pk = issuer.verifying_key();
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer_pubkey: &pk,
        now: NOW,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    assert!(matches!(
        verify_tct(&tct, &ctx).unwrap_err(),
        TctError::CnfMalformed
    ));
}

#[test]
fn pop_with_forged_signature_rejected() {
    // Valid jti + nonce echo, but the response is signed by a key that is
    // NOT the TCT subject. The cryptographic PoP check must reject it.
    let subject = subject_key();
    let rogue = AitpSigningKey::from_seed(&[0xEE; 32]);
    let tct = build_tct();
    let challenge = PopChallenge {
        tct_jti: tct.jti,
        nonce: "A".repeat(22),
        expires_at: Timestamp(NOW.0 + 300),
    };
    // Sign with the rogue key; jti/nonce_echo still come from `challenge`.
    let response = sign_pop_response(&challenge, &rogue).unwrap();
    assert_ne!(rogue.aid(), subject.aid());
    let err = verify_pop_response(&challenge, &response, &tct, Timestamp(NOW.0 + 100)).unwrap_err();
    assert!(
        matches!(err, TctError::PopFailed),
        "expected PopFailed, got {err:?}"
    );
}

#[test]
fn pop_past_challenge_expiry_rejected() {
    let subject = subject_key();
    let tct = build_tct();
    let challenge = PopChallenge {
        tct_jti: tct.jti,
        nonce: "A".repeat(22),
        expires_at: Timestamp(NOW.0 + 50),
    };
    let response = sign_pop_response(&challenge, &subject).unwrap();
    // Verify strictly after the challenge window closes.
    let err = verify_pop_response(&challenge, &response, &tct, Timestamp(NOW.0 + 100)).unwrap_err();
    assert!(
        matches!(err, TctError::PopChallengeExpired),
        "expected PopChallengeExpired, got {err:?}"
    );
}
