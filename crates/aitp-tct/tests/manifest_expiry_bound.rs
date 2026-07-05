//! TCT verifier MUST cap `exp` at the issuer Manifest's `expires_at`.
//!
//! RFC-AITP-0004 §4.3 / RFC-AITP-0005 §10.4: a peer-issued TCT MUST NOT
//! outlive the issuer Manifest's expiry, because the issuer's keys
//! could legitimately rotate at that point.
//! `TctVerifyContext::issuer_manifest_expires_at` carries the bound.

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_tct::{verify_tct, TctBuilder, TctError, TctVerifyContext};

const NOW: Timestamp = Timestamp(1_700_000_000);

fn issue(issuer: &AitpSigningKey, subject: &AitpSigningKey, ttl: i64) -> String {
    TctBuilder::new(issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["demo.echo"])
        .ttl_secs(ttl)
        .subject_pubkey(subject.verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
        .token
}

/// TCT expiring exactly at the issuer Manifest's expiry verifies.
#[test]
fn tct_expires_at_manifest_boundary_passes() {
    let issuer = AitpSigningKey::from_seed(&[0xC1; 32]);
    let subject = AitpSigningKey::from_seed(&[0xC2; 32]);
    let manifest_exp = Timestamp(NOW.0 + 3600);
    let token = issue(&issuer, &subject, 3600); // exp = NOW + 3600 = manifest_exp
    let ctx = TctVerifyContext::builder(subject.aid(), issuer.aid(), NOW)
        .issuer_manifest_expires_at(manifest_exp)
        .accept_unchecked_revocation_dangerous()
        .build()
        .unwrap();
    verify_tct(&token, &ctx).expect("TCT at the boundary verifies");
}

/// TCT expiring AFTER the issuer Manifest's expiry is rejected.
#[test]
fn tct_expires_after_manifest_is_rejected() {
    let issuer = AitpSigningKey::from_seed(&[0xC3; 32]);
    let subject = AitpSigningKey::from_seed(&[0xC4; 32]);
    let manifest_exp = Timestamp(NOW.0 + 1800); // 30 min
    let token = issue(&issuer, &subject, 3600); // 60 min > 30 min manifest
    let ctx = TctVerifyContext::builder(subject.aid(), issuer.aid(), NOW)
        .issuer_manifest_expires_at(manifest_exp)
        .accept_unchecked_revocation_dangerous()
        .build()
        .unwrap();
    let err = verify_tct(&token, &ctx).expect_err("TCT past manifest must fail");
    assert!(
        matches!(err, TctError::ExpiresAfterManifest),
        "expected ExpiresAfterManifest, got {err:?}"
    );
}

/// `issuer_manifest_expires_at: None` skips the check for callers that
/// don't have the issuer's Manifest in hand (RFC-AITP-0005 §10.4: MAY
/// skip when unavailable).
#[test]
fn manifest_expiry_check_is_optional() {
    let issuer = AitpSigningKey::from_seed(&[0xC5; 32]);
    let subject = AitpSigningKey::from_seed(&[0xC6; 32]);
    let token = issue(&issuer, &subject, 86_400); // 24 hours, no bound
    let ctx = TctVerifyContext::permissive_at(subject.aid(), issuer.aid(), NOW);
    verify_tct(&token, &ctx).expect("no manifest-bound check when caller passes None");
}
