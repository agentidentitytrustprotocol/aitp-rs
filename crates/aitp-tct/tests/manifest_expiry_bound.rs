//! TCT verifier MUST cap `expires_at` at the issuer Manifest's
//! `expires_at` (BUG-5).
//!
//! RFC-AITP-0004 §4.3 / RFC-AITP-0005 §9: a peer-issued TCT MUST NOT
//! outlive the issuer Manifest's expiry, because the issuer's keys
//! could legitimately rotate at that point. Issuance already enforces
//! this; pre-rc.1 the verifier had no way to (callers couldn't pass
//! the bound). `TctVerifyContext::issuer_manifest_expires_at` closes
//! the gap.

use aitp_core::Timestamp;
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp_tct::{verify_tct, TctBuilder, TctError, TctVerifyContext};

const NOW: Timestamp = Timestamp(1_700_000_000);

/// TCT expiring exactly at the issuer Manifest's expiry verifies.
#[test]
fn tct_expires_at_manifest_boundary_passes() {
    let issuer = AitpSigningKey::from_seed(&[0xC1; 32]);
    let subject = AitpSigningKey::from_seed(&[0xC2; 32]);
    let manifest_exp = Timestamp(NOW.0 + 3600);
    let tct = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["demo.echo"])
        .ttl_secs(3600) // expires_at = NOW + 3600 = manifest_exp
        .subject_pubkey(subject.verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap();
    let issuer_pk = AitpVerifyingKey::from_aid(issuer.aid()).unwrap();
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer_pubkey: &issuer_pk,
        now: NOW,
        issuer_manifest_expires_at: Some(manifest_exp),
        revocation_check: None,
    };
    verify_tct(&tct, &ctx).expect("TCT at the boundary verifies");
}

/// TCT expiring AFTER the issuer Manifest's expiry is rejected.
#[test]
fn tct_expires_after_manifest_is_rejected() {
    let issuer = AitpSigningKey::from_seed(&[0xC3; 32]);
    let subject = AitpSigningKey::from_seed(&[0xC4; 32]);
    let manifest_exp = Timestamp(NOW.0 + 1800); // 30 min
    let tct = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["demo.echo"])
        .ttl_secs(3600) // 60 min > 30 min manifest
        .subject_pubkey(subject.verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap();
    let issuer_pk = AitpVerifyingKey::from_aid(issuer.aid()).unwrap();
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer_pubkey: &issuer_pk,
        now: NOW,
        issuer_manifest_expires_at: Some(manifest_exp),
        revocation_check: None,
    };
    let err = verify_tct(&tct, &ctx).expect_err("TCT past manifest must fail");
    assert!(
        matches!(err, TctError::ExpiresAfterManifest),
        "expected ExpiresAfterManifest, got {err:?}"
    );
}

/// `issuer_manifest_expires_at: None` skips the check, preserving
/// pre-rc.1 behavior for callers that don't have the issuer's
/// Manifest in hand (RFC-AITP-0005 §9: MAY skip when unavailable).
#[test]
fn manifest_expiry_check_is_optional() {
    let issuer = AitpSigningKey::from_seed(&[0xC5; 32]);
    let subject = AitpSigningKey::from_seed(&[0xC6; 32]);
    let tct = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["demo.echo"])
        .ttl_secs(86_400) // 24 hours — no manifest bound, so accepted
        .subject_pubkey(subject.verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap();
    let issuer_pk = AitpVerifyingKey::from_aid(issuer.aid()).unwrap();
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer_pubkey: &issuer_pk,
        now: NOW,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    verify_tct(&tct, &ctx).expect("no manifest-bound check when caller passes None");
}
