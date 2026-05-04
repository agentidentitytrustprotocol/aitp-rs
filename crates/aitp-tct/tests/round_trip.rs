//! End-to-end TCT issue + verify + tamper-detection.

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_tct::{
    sign_pop_response, verify_pop_response, verify_tct, PopChallenge, TctBuilder, TctError,
    TctVerifyContext,
};
use uuid::Uuid;

fn issuer_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xA0; 32])
}

fn subject_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xB0; 32])
}

fn build_tct_at(now: Timestamp) -> aitp_tct::Tct {
    let issuer = issuer_key();
    let subject = subject_key();
    TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["demo.echo"])
        .ttl_secs(3600)
        .subject_pubkey(subject.verifying_key())
        .issued_at(now)
        .build()
        .expect("builder ok")
}

#[test]
fn happy_path_round_trip() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let tct = build_tct_at(now);
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer_pubkey: &issuer.verifying_key(),
        now,
        revocation_check: None,
    };
    verify_tct(&tct, &ctx).expect("fresh TCT verifies");
}

#[test]
fn wrong_audience_rejected() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let _subject = subject_key();
    let tct = build_tct_at(now);
    let other = AitpSigningKey::from_seed(&[0xCC; 32]);
    let ctx = TctVerifyContext {
        expected_audience: other.aid(),
        issuer_pubkey: &issuer.verifying_key(),
        now,
        revocation_check: None,
    };
    let err = verify_tct(&tct, &ctx).unwrap_err();
    assert!(matches!(err, TctError::AudienceMismatch));
}

#[test]
fn audience_subject_mismatch_rejected() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    // Forge a TCT where audience != subject.
    let mut tct = build_tct_at(now);
    let evil = AitpSigningKey::from_seed(&[0xEE; 32]);
    tct.audience = evil.aid().clone();
    let ctx = TctVerifyContext {
        // Use the forged audience as expected so the first audience check
        // passes and we hit the "audience must equal subject" branch.
        expected_audience: evil.aid(),
        issuer_pubkey: &issuer.verifying_key(),
        now,
        revocation_check: None,
    };
    let err = verify_tct(&tct, &ctx).unwrap_err();
    assert!(matches!(err, TctError::AudienceMismatch));
    let _ = subject; // silence unused
}

#[test]
fn tampered_signature_rejected() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let mut tct = build_tct_at(now);
    let mut s = tct.signature.clone();
    let last = s.pop().unwrap();
    s.push(if last == 'A' { 'B' } else { 'A' });
    tct.signature = s;
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer_pubkey: &issuer.verifying_key(),
        now,
        revocation_check: None,
    };
    let err = verify_tct(&tct, &ctx).unwrap_err();
    assert!(matches!(err, TctError::SignatureInvalid));
}

#[test]
fn tampered_grants_rejected() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let mut tct = build_tct_at(now);
    tct.grants.push("demo.evil".into());
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer_pubkey: &issuer.verifying_key(),
        now,
        revocation_check: None,
    };
    let err = verify_tct(&tct, &ctx).unwrap_err();
    assert!(matches!(err, TctError::SignatureInvalid));
}

#[test]
fn expired_rejected() {
    let issued = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let tct = build_tct_at(issued);
    let later = Timestamp(1_700_000_000 + 7200);
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer_pubkey: &issuer.verifying_key(),
        now: later,
        revocation_check: None,
    };
    assert!(matches!(
        verify_tct(&tct, &ctx).unwrap_err(),
        TctError::Expired
    ));
}

#[test]
fn future_issued_rejected() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let tct = build_tct_at(now);
    let earlier = Timestamp(1_699_999_900);
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer_pubkey: &issuer.verifying_key(),
        now: earlier,
        revocation_check: None,
    };
    assert!(matches!(
        verify_tct(&tct, &ctx).unwrap_err(),
        TctError::Expired
    ));
}

#[test]
fn revoked_rejected() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let tct = build_tct_at(now);
    let target = tct.jti;
    let revoked = move |jti: &Uuid| *jti == target;
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer_pubkey: &issuer.verifying_key(),
        now,
        revocation_check: Some(&revoked),
    };
    assert!(matches!(
        verify_tct(&tct, &ctx).unwrap_err(),
        TctError::Revoked
    ));
}

#[test]
fn pop_challenge_response_round_trip() {
    let subject = subject_key();
    let tct = build_tct_at(Timestamp(1_700_000_000));
    let challenge = PopChallenge {
        tct_jti: tct.jti,
        nonce: "A".repeat(22),
        expires_at: Timestamp(1_700_000_300),
    };
    let response = sign_pop_response(&challenge, &subject).unwrap();
    verify_pop_response(&challenge, &response, &tct, Timestamp(1_700_000_100)).unwrap();
}

#[test]
fn pop_response_with_wrong_nonce_fails() {
    let subject = subject_key();
    let tct = build_tct_at(Timestamp(1_700_000_000));
    let challenge = PopChallenge {
        tct_jti: tct.jti,
        nonce: "A".repeat(22),
        expires_at: Timestamp(1_700_000_300),
    };
    let mut response = sign_pop_response(&challenge, &subject).unwrap();
    response.nonce_echo = "B".repeat(22);
    let err =
        verify_pop_response(&challenge, &response, &tct, Timestamp(1_700_000_100)).unwrap_err();
    assert!(matches!(err, TctError::PopNonceMismatch));
}

#[test]
fn pop_response_with_wrong_jti_fails() {
    let subject = subject_key();
    let tct = build_tct_at(Timestamp(1_700_000_000));
    let challenge = PopChallenge {
        tct_jti: Uuid::new_v4(),
        nonce: "A".repeat(22),
        expires_at: Timestamp(1_700_000_300),
    };
    let response = sign_pop_response(&challenge, &subject).unwrap();
    let err =
        verify_pop_response(&challenge, &response, &tct, Timestamp(1_700_000_100)).unwrap_err();
    assert!(matches!(err, TctError::PopJtiMismatch));
}

#[test]
fn builder_rejects_empty_grants() {
    let issuer = issuer_key();
    let subject = subject_key();
    let err = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .subject_pubkey(subject.verifying_key())
        .build()
        .unwrap_err();
    assert!(matches!(err, TctError::EmptyGrants));
}

#[test]
fn builder_rejects_audience_neq_subject() {
    let issuer = issuer_key();
    let subject = subject_key();
    let other = AitpSigningKey::from_seed(&[0x77; 32]);
    let err = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(other.aid().clone())
        .grants(["x"])
        .subject_pubkey(subject.verifying_key())
        .build()
        .unwrap_err();
    assert!(matches!(err, TctError::AudienceMismatch));
}

#[test]
fn builder_rejects_grant_with_whitespace() {
    // RFC-AITP-0005 §4.2: "Grants MUST NOT contain whitespace."
    let issuer = issuer_key();
    let subject = subject_key();
    let err = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["bad grant"])
        .subject_pubkey(subject.verifying_key())
        .build()
        .unwrap_err();
    assert!(matches!(err, TctError::GrantWhitespace(_)), "got {err:?}");
}

#[test]
fn builder_rejects_grant_with_tab() {
    let issuer = issuer_key();
    let subject = subject_key();
    let err = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["one\ttwo"])
        .subject_pubkey(subject.verifying_key())
        .build()
        .unwrap_err();
    assert!(matches!(err, TctError::GrantWhitespace(_)));
}
