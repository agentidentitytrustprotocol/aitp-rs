//! End-to-end TCT issue + verify + tamper-detection (compact JWS).

use aitp_core::{base64url, Timestamp, PROTOCOL_VERSION};
use aitp_crypto::{jws, AitpSigningKey, CryptoError};
use aitp_tct::{
    sign_pop_response, verify_pop_response, verify_tct, verify_voucher, IssuedTct, PopChallenge,
    TctBuilder, TctError, TctVerifyContext,
};
use uuid::Uuid;

fn issuer_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xA0; 32])
}

fn subject_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xB0; 32])
}

fn issue_at(now: Timestamp) -> IssuedTct {
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

/// Re-sign `claims` (a JSON object) as a TCT under `key` — used to mint
/// deliberately malformed tokens the builder refuses to produce.
fn forge(key: &AitpSigningKey, claims: &serde_json::Value) -> String {
    jws::sign_compact(key, jws::TYP_TCT, claims).unwrap()
}

#[test]
fn happy_path_round_trip() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let issued = issue_at(now);
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer: issuer.aid(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    let verified = verify_tct(&issued.token, &ctx).expect("fresh TCT verifies");
    assert_eq!(verified.token, issued.token);
    assert_eq!(verified.claims, issued.claims);
    assert_eq!(verified.claims.ver, PROTOCOL_VERSION);
}

#[test]
fn companion_voucher_mirrors_tct_and_verifies() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let issued = issue_at(now);
    let voucher_token = issued
        .voucher
        .as_deref()
        .expect("voucher minted by default");
    let voucher = verify_voucher(voucher_token, issuer.aid()).expect("voucher verifies");
    // §8.2: voucher claims mirror the companion TCT exactly.
    assert_eq!(voucher.iss, issued.claims.iss);
    assert_eq!(voucher.sub, issued.claims.sub);
    assert_eq!(voucher.grants, issued.claims.grants);
    assert_eq!(voucher.iat, issued.claims.iat);
    assert_eq!(voucher.exp, issued.claims.exp);
    assert_eq!(voucher.src_jti, issued.claims.jti);
}

#[test]
fn without_voucher_omits_voucher() {
    let issuer = issuer_key();
    let subject = subject_key();
    let issued = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["demo.echo"])
        .subject_pubkey(subject.verifying_key())
        .without_voucher()
        .build()
        .unwrap();
    assert!(issued.voucher.is_none());
}

#[test]
fn voucher_presented_as_tct_dies_on_typ() {
    // Cross-type confusion: a valid voucher must never verify in a TCT
    // context (RFC 8725 explicit typing).
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let issued = issue_at(now);
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer: issuer.aid(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    let err = verify_tct(issued.voucher.as_deref().unwrap(), &ctx).unwrap_err();
    assert!(
        matches!(err, TctError::Crypto(CryptoError::TypMismatch { .. })),
        "got {err:?}"
    );
}

#[test]
fn spoofed_issuer_claim_rejected() {
    // A TCT genuinely signed by one key MUST NOT pass while claiming a
    // different `iss` AID (revocation lookups are keyed on iss).
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let issued = issue_at(now);
    let mut claims = serde_json::to_value(&issued.claims).unwrap();
    let victim = AitpSigningKey::from_seed(&[0xDD; 32]);
    claims["iss"] = serde_json::to_value(victim.aid()).unwrap();
    let forged = forge(&issuer, &claims); // really signed by `issuer`
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer: issuer.aid(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    let err = verify_tct(&forged, &ctx).unwrap_err();
    assert!(matches!(err, TctError::IssuerMismatch), "got {err:?}");

    // And verifying under the victim's AID dies on the signature.
    let ctx_victim = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer: victim.aid(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    let err = verify_tct(&forged, &ctx_victim).unwrap_err();
    assert!(
        matches!(err, TctError::Crypto(CryptoError::SignatureInvalid)),
        "got {err:?}"
    );
}

#[test]
fn wrong_audience_rejected() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let issued = issue_at(now);
    let other = AitpSigningKey::from_seed(&[0xCC; 32]);
    let ctx = TctVerifyContext {
        expected_audience: other.aid(),
        issuer: issuer.aid(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    assert!(matches!(
        verify_tct(&issued.token, &ctx).unwrap_err(),
        TctError::AudienceMismatch
    ));
}

#[test]
fn audience_subject_mismatch_rejected() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let issued = issue_at(now);
    let evil = AitpSigningKey::from_seed(&[0xEE; 32]);
    let mut claims = serde_json::to_value(&issued.claims).unwrap();
    claims["aud"] = serde_json::to_value(evil.aid()).unwrap();
    let forged = forge(&issuer, &claims);
    let ctx = TctVerifyContext {
        // Use the forged audience as expected so the first audience
        // check passes and we hit the "aud == sub" invariant.
        expected_audience: evil.aid(),
        issuer: issuer.aid(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    assert!(matches!(
        verify_tct(&forged, &ctx).unwrap_err(),
        TctError::AudienceMismatch
    ));
}

#[test]
fn tampered_signature_rejected() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let issued = issue_at(now);
    // Flip the FIRST character of the signature segment, not the last.
    // The last base64url char of an 86-char (64-byte) Ed25519 signature
    // carries trailing padding bits that MUST be zero; flipping it can
    // make the segment non-canonical, which strict decode rejects as
    // `JwsMalformed` rather than `SignatureInvalid` — and since the
    // `jti` is random per run, which of the two fires would be flaky.
    // The first char never touches padding bits, so the segment stays a
    // canonical-but-wrong 64-byte signature → deterministically
    // `SignatureInvalid`, which is exactly what this test asserts.
    let (head, sig) = issued.token.rsplit_once('.').unwrap();
    let mut sig_chars: Vec<char> = sig.chars().collect();
    sig_chars[0] = if sig_chars[0] == 'A' { 'B' } else { 'A' };
    let token = format!("{head}.{}", sig_chars.into_iter().collect::<String>());
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer: issuer.aid(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    assert!(matches!(
        verify_tct(&token, &ctx).unwrap_err(),
        TctError::Crypto(CryptoError::SignatureInvalid)
    ));
}

#[test]
fn tampered_grants_rejected() {
    // Splice a grants escalation into the payload segment while keeping
    // the original signature: dies on the signature over exact bytes.
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let issued = issue_at(now);
    let mut claims = serde_json::to_value(&issued.claims).unwrap();
    claims["grants"]
        .as_array_mut()
        .unwrap()
        .push("demo.evil".into());
    let (header, rest) = issued.token.split_once('.').unwrap();
    let (_, sig) = rest.split_once('.').unwrap();
    let evil_payload =
        base64url::encode(&aitp_core::jcs::canonicalize_serializable(&claims).unwrap());
    let tampered = format!("{header}.{evil_payload}.{sig}");
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer: issuer.aid(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    assert!(matches!(
        verify_tct(&tampered, &ctx).unwrap_err(),
        TctError::Crypto(CryptoError::SignatureInvalid)
    ));
}

#[test]
fn unknown_claim_rejected() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let issued = issue_at(now);
    let mut claims = serde_json::to_value(&issued.claims).unwrap();
    claims["rogue"] = serde_json::json!("x");
    let forged = forge(&issuer, &claims);
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer: issuer.aid(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    assert!(matches!(
        verify_tct(&forged, &ctx).unwrap_err(),
        TctError::ClaimsMalformed(_)
    ));
}

#[test]
fn unknown_version_rejected() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let issued = issue_at(now);
    let mut claims = serde_json::to_value(&issued.claims).unwrap();
    claims["ver"] = serde_json::json!("aitp/9.9");
    let forged = forge(&issuer, &claims);
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer: issuer.aid(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    assert!(matches!(
        verify_tct(&forged, &ctx).unwrap_err(),
        TctError::VersionUnknown
    ));
}

#[test]
fn expired_rejected() {
    let issued_at = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let issued = issue_at(issued_at);
    let later = Timestamp(1_700_000_000 + 7200);
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer: issuer.aid(),
        now: later,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    assert!(matches!(
        verify_tct(&issued.token, &ctx).unwrap_err(),
        TctError::Expired
    ));
}

#[test]
fn future_issued_rejected() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let issued = issue_at(now);
    let earlier = Timestamp(1_699_999_900);
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer: issuer.aid(),
        now: earlier,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    assert!(matches!(
        verify_tct(&issued.token, &ctx).unwrap_err(),
        TctError::Expired
    ));
}

#[test]
fn revoked_rejected() {
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let issued = issue_at(now);
    let target = issued.claims.jti;
    let revoked = move |jti: &Uuid| *jti == target;
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer: issuer.aid(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: Some(&revoked),
    };
    assert!(matches!(
        verify_tct(&issued.token, &ctx).unwrap_err(),
        TctError::Revoked
    ));
}

#[test]
fn pop_challenge_response_round_trip() {
    let subject = subject_key();
    let issued = issue_at(Timestamp(1_700_000_000));
    let challenge = PopChallenge {
        tct_jti: issued.claims.jti,
        nonce: "A".repeat(22),
        expires_at: Timestamp(1_700_000_300),
    };
    let response = sign_pop_response(&challenge, &subject).unwrap();
    verify_pop_response(
        &challenge,
        &response,
        &issued.claims,
        Timestamp(1_700_000_100),
    )
    .unwrap();
}

#[test]
fn pop_response_with_wrong_nonce_fails() {
    let subject = subject_key();
    let issued = issue_at(Timestamp(1_700_000_000));
    let challenge = PopChallenge {
        tct_jti: issued.claims.jti,
        nonce: "A".repeat(22),
        expires_at: Timestamp(1_700_000_300),
    };
    let mut response = sign_pop_response(&challenge, &subject).unwrap();
    response.nonce_echo = "B".repeat(22);
    let err = verify_pop_response(
        &challenge,
        &response,
        &issued.claims,
        Timestamp(1_700_000_100),
    )
    .unwrap_err();
    assert!(matches!(err, TctError::PopNonceMismatch));
}

#[test]
fn pop_response_with_wrong_jti_fails() {
    let subject = subject_key();
    let issued = issue_at(Timestamp(1_700_000_000));
    let challenge = PopChallenge {
        tct_jti: Uuid::new_v4(),
        nonce: "A".repeat(22),
        expires_at: Timestamp(1_700_000_300),
    };
    let response = sign_pop_response(&challenge, &subject).unwrap();
    let err = verify_pop_response(
        &challenge,
        &response,
        &issued.claims,
        Timestamp(1_700_000_100),
    )
    .unwrap_err();
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
fn builder_rejects_subject_pubkey_aid_mismatch() {
    // §3: cnf binds the subject's key; the builder refuses to bind a
    // key other than the one the subject AID encodes.
    let issuer = issuer_key();
    let subject = subject_key();
    let other = AitpSigningKey::from_seed(&[0x78; 32]);
    let err = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["x"])
        .subject_pubkey(other.verifying_key())
        .build()
        .unwrap_err();
    assert!(matches!(err, TctError::CnfMalformed), "got {err:?}");
}

#[test]
fn forged_cnf_jkt_rejected() {
    // An issuer-signed TCT whose cnf.jkt doesn't match the sub AID's
    // key must be rejected by consumers (§3).
    let now = Timestamp(1_700_000_000);
    let issuer = issuer_key();
    let subject = subject_key();
    let issued = issue_at(now);
    let mut claims = serde_json::to_value(&issued.claims).unwrap();
    claims["cnf"]["jkt"] = serde_json::json!("A".repeat(43));
    let forged = forge(&issuer, &claims);
    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer: issuer.aid(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    assert!(matches!(
        verify_tct(&forged, &ctx).unwrap_err(),
        TctError::CnfMalformed
    ));
}

#[test]
fn p256_issuer_and_subject_round_trip_and_pop() {
    // Algorithm-agile round-trip: P-256 issuer (ES256 JWS) + P-256
    // subject (EC-form cnf.jkt + p256-tagged PoP signature).
    let now = Timestamp(1_700_000_000);
    let issuer = AitpSigningKey::generate_p256();
    let subject = AitpSigningKey::generate_p256();
    let issued = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["demo.echo"])
        .ttl_secs(3600)
        .subject_pubkey(subject.verifying_key())
        .issued_at(now)
        .build()
        .expect("p256 builder ok");

    // ES256 header on the wire.
    let header = base64url::decode_strict(issued.token.split('.').next().unwrap()).unwrap();
    assert!(String::from_utf8(header).unwrap().contains("\"ES256\""));

    let ctx = TctVerifyContext {
        expected_audience: subject.aid(),
        issuer: issuer.aid(),
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    verify_tct(&issued.token, &ctx).expect("p256 TCT verifies");

    let challenge = PopChallenge {
        tct_jti: issued.claims.jti,
        nonce: base64url::encode(&[0x55u8; 16]),
        expires_at: Timestamp(now.0 + 60),
    };
    let response = sign_pop_response(&challenge, &subject).expect("p256 pop sign ok");
    verify_pop_response(&challenge, &response, &issued.claims, now).expect("p256 pop verifies");
}
