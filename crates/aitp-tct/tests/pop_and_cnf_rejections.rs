//! Isolated rejection tests for the TCT verifier's claim guards and the
//! downstream PoP check.
//!
//! `round_trip.rs` proves the happy paths plus structural rejections;
//! here each mutation trips exactly one guard: the `cnf.jkt` binding in
//! isolation, and the two cryptographic PoP-failure branches
//! (`PopFailed` on a forged signature, `PopChallengeExpired` past the
//! challenge window).

use aitp_core::Timestamp;
use aitp_crypto::{jws, AitpSigningKey};
use aitp_tct::{
    sign_pop_response, verify_pop_response, verify_tct, IssuedTct, PopChallenge, TctBuilder,
    TctError, TctVerifyContext,
};

const NOW: Timestamp = Timestamp(1_700_000_000);

fn issuer_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xA0; 32])
}
fn subject_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xB0; 32])
}

fn issue() -> IssuedTct {
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
fn malformed_jkt_shape_rejected() {
    // A cnf.jkt that isn't even base64url-shaped fails the typed-claims
    // jkt comparison (CnfMalformed), proving the guard doesn't rely on
    // schema validation upstream.
    let issuer = issuer_key();
    let subject = subject_key();
    let issued = issue();
    let mut claims = serde_json::to_value(&issued.claims).unwrap();
    claims["cnf"]["jkt"] = serde_json::json!("not base64url!!");
    let forged = jws::sign_compact(&issuer, jws::TYP_TCT, &claims).unwrap();
    let ctx = TctVerifyContext::permissive_at(subject.aid(), issuer.aid(), NOW);
    assert!(matches!(
        verify_tct(&forged, &ctx).unwrap_err(),
        TctError::CnfMalformed
    ));
}

#[test]
fn jkt_of_wrong_key_rejected() {
    // A well-formed jkt that is the thumbprint of a DIFFERENT key than
    // the sub AID encodes: §3 requires rejection.
    let issuer = issuer_key();
    let subject = subject_key();
    let rogue = AitpSigningKey::from_seed(&[0xEE; 32]);
    let issued = issue();
    let mut claims = serde_json::to_value(&issued.claims).unwrap();
    claims["cnf"]["jkt"] = serde_json::json!(rogue.verifying_key().to_jwk_thumbprint().unwrap());
    let forged = jws::sign_compact(&issuer, jws::TYP_TCT, &claims).unwrap();
    let ctx = TctVerifyContext::permissive_at(subject.aid(), issuer.aid(), NOW);
    assert!(matches!(
        verify_tct(&forged, &ctx).unwrap_err(),
        TctError::CnfMalformed
    ));
}

#[test]
fn pop_with_forged_signature_rejected() {
    // Valid jti + nonce echo, but the response is signed by a key that
    // is NOT the TCT subject. The cryptographic PoP check must reject.
    let subject = subject_key();
    let rogue = AitpSigningKey::from_seed(&[0xEE; 32]);
    let issued = issue();
    let challenge = PopChallenge {
        tct_jti: issued.claims.jti,
        nonce: "A".repeat(22),
        expires_at: Timestamp(NOW.0 + 300),
    };
    // Sign with the rogue key; jti/nonce_echo still come from `challenge`.
    let response = sign_pop_response(&challenge, &rogue).unwrap();
    assert_ne!(rogue.aid(), subject.aid());
    let err = verify_pop_response(
        &challenge,
        &response,
        &issued.claims,
        Timestamp(NOW.0 + 100),
    )
    .unwrap_err();
    assert!(
        matches!(err, TctError::PopFailed),
        "expected PopFailed, got {err:?}"
    );
}

#[test]
fn pop_past_challenge_expiry_rejected() {
    let subject = subject_key();
    let issued = issue();
    let challenge = PopChallenge {
        tct_jti: issued.claims.jti,
        nonce: "A".repeat(22),
        expires_at: Timestamp(NOW.0 + 50),
    };
    let response = sign_pop_response(&challenge, &subject).unwrap();
    // Verify strictly after the challenge window closes.
    let err = verify_pop_response(
        &challenge,
        &response,
        &issued.claims,
        Timestamp(NOW.0 + 100),
    )
    .unwrap_err();
    assert!(
        matches!(err, TctError::PopChallengeExpired),
        "expected PopChallengeExpired, got {err:?}"
    );
}
