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
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    verify_tct(&tct, &ctx).expect("fresh TCT verifies");
}

#[test]
fn spoofed_issuer_rejected_before_signature() {
    // RFC-AITP-0008 §3.3 issuer-key binding: a TCT genuinely signed by
    // one key MUST NOT pass verification while claiming a different
    // `issuer` AID. This is the revocation-evasion / DoS-reflection
    // vector — the per-issuer revocation lookup is keyed on `tct.issuer`.
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let mut tct = build_tct_at(now);
    // Splice the issuer field to an unrelated AID while leaving the
    // signature (made by `issuer`) intact.
    let victim = AitpSigningKey::from_seed(&[0xDD; 32]);
    tct.issuer = victim.aid().clone();
    let subject = subject_key();
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer_pubkey: &issuer.verifying_key(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    let err = verify_tct(&tct, &ctx).unwrap_err();
    // MUST be IssuerMismatch (binding checked before signature), not
    // SignatureInvalid — proving the binding holds unconditionally.
    assert!(matches!(err, TctError::IssuerMismatch), "got {err:?}");
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
        issuer_manifest_expires_at: None,
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
        issuer_manifest_expires_at: None,
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
        issuer_manifest_expires_at: None,
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
        issuer_manifest_expires_at: None,
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
        issuer_manifest_expires_at: None,
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
        issuer_manifest_expires_at: None,
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
        issuer_manifest_expires_at: None,
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

#[test]
fn p256_subject_round_trip_and_pop() {
    // Algorithm-agile round-trip: P-256 issuer + P-256 subject.
    // cnf encodes the subject as 33-byte SEC1-compressed (44 b64u chars);
    // verifier accepts on the length-dispatched algorithm-agile path;
    // PoP signature is tagged `p256.<86b64u>`.
    use aitp_core::base64url;

    let now = Timestamp(1_700_000_000);
    let issuer = AitpSigningKey::generate_p256();
    let subject = AitpSigningKey::generate_p256();
    let tct = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["demo.echo"])
        .ttl_secs(3600)
        .subject_pubkey(subject.verifying_key())
        .issued_at(now)
        .build()
        .expect("p256 builder ok");

    // cnf is 33-byte SEC1-compressed encoded → 44 b64u characters.
    assert_eq!(tct.binding.cnf.len(), 44);

    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer_pubkey: &issuer.verifying_key(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    verify_tct(&tct, &ctx).expect("p256 TCT verifies");

    // PoP round-trips: holder signs with P-256, verifier decodes the
    // cnf via the algorithm-agile from_compressed path.
    let nonce_bytes = [0x55u8; 32];
    let challenge = PopChallenge {
        tct_jti: tct.jti,
        nonce: base64url::encode(&nonce_bytes),
        expires_at: Timestamp(now.0 + 60),
    };
    let response = sign_pop_response(&challenge, &subject).expect("p256 pop sign ok");
    verify_pop_response(&challenge, &response, &tct, now).expect("p256 pop verifies");
}

#[test]
fn p256_subject_rejects_tampered_cnf_length() {
    // A TCT with a P-256 subject MUST NOT verify if cnf is reshaped
    // to the 32-byte Ed25519 form — guards against algorithm
    // confusion in the cnf channel.
    use aitp_core::base64url;

    let now = Timestamp(1_700_000_000);
    let issuer = AitpSigningKey::generate_p256();
    let subject = AitpSigningKey::generate_p256();
    let mut tct = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["demo.echo"])
        .ttl_secs(3600)
        .subject_pubkey(subject.verifying_key())
        .issued_at(now)
        .build()
        .unwrap();

    // Tamper: replace cnf with the 32-byte Ed25519 form of arbitrary key.
    let bogus = [0x77u8; 32];
    tct.binding.cnf = base64url::encode(&bogus);

    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer_pubkey: &issuer.verifying_key(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    let err = verify_tct(&tct, &ctx).unwrap_err();
    // Length-mismatched cnf may be rejected as CnfMalformed OR
    // SignatureInvalid (since the signed body covers the cnf field) —
    // both are correct refusals; assert it's one of those, not Ok.
    assert!(
        matches!(err, TctError::CnfMalformed | TctError::SignatureInvalid),
        "got {err:?}"
    );
}
