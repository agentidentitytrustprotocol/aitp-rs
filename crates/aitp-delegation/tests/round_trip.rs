//! End-to-end single-hop delegation: A issues B a TCT + voucher; B
//! delegates a subset to C; A verifies — plus the RFC-AITP-0006 §4
//! rejection matrix.

use aitp_core::{Timestamp, PROTOCOL_VERSION};
use aitp_crypto::{jws, AitpSigningKey, CryptoError};
use aitp_delegation::{
    verify_delegation, DelegationBuilder, DelegationError, VerifyDelegationContext,
};
use aitp_tct::TctBuilder;
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

fn a() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xA1; 32])
}
fn b() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xB1; 32])
}
fn c() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xC1; 32])
}

/// A → B: TCT + voucher with two grants, 2h TTL.
fn voucher_for_b() -> String {
    TctBuilder::new(&a())
        .subject(b().aid().clone())
        .audience(b().aid().clone())
        .grants(["read_data", "write_data"])
        .ttl_secs(7200)
        .subject_pubkey(b().verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
        .voucher
        .unwrap()
}

/// B → C: delegate `read_data`, 1h TTL.
fn delegate_to_c(voucher: &str) -> String {
    DelegationBuilder::new(&b(), voucher)
        .unwrap()
        .delegatee(c().aid().clone())
        .scope(["read_data"])
        .ttl_secs(3600)
        .now(NOW)
        .build()
        .unwrap()
}

#[test]
fn happy_path_round_trip() {
    let token = delegate_to_c(&voucher_for_b());
    let a_key = a();
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    let verified = verify_delegation(&token, &ctx).expect("delegation verifies");
    assert_eq!(verified.claims.iss, *b().aid());
    assert_eq!(verified.claims.sub, *c().aid());
    assert_eq!(verified.claims.scope, vec!["read_data".to_string()]);
    assert_eq!(verified.claims.ver, PROTOCOL_VERSION);
    assert_eq!(verified.voucher.sub, *b().aid());
    assert_eq!(verified.voucher.grants.len(), 2);
}

#[test]
fn builder_rejects_voucher_for_someone_else() {
    // C cannot delegate against B's voucher.
    let voucher = voucher_for_b();
    let b_key = c();
    let err = match DelegationBuilder::new(&b_key, &voucher) {
        Err(e) => e,
        Ok(_) => panic!("voucher for B must not be usable by C"),
    };
    assert!(matches!(err, DelegationError::InvalidVoucher));
}

#[test]
fn builder_rejects_scope_outside_voucher() {
    let err = DelegationBuilder::new(&b(), &voucher_for_b())
        .unwrap()
        .delegatee(c().aid().clone())
        .scope(["admin"])
        .now(NOW)
        .build()
        .unwrap_err();
    assert!(matches!(err, DelegationError::ScopeExceeded));
}

#[test]
fn builder_rejects_self_delegation() {
    let err = DelegationBuilder::new(&b(), &voucher_for_b())
        .unwrap()
        .delegatee(b().aid().clone())
        .scope(["read_data"])
        .now(NOW)
        .build()
        .unwrap_err();
    assert!(matches!(err, DelegationError::SelfDelegation));
}

#[test]
fn builder_caps_expiry_at_voucher() {
    let token = DelegationBuilder::new(&b(), &voucher_for_b())
        .unwrap()
        .delegatee(c().aid().clone())
        .scope(["read_data"])
        .ttl_secs(999_999) // way past the voucher's 2h
        .now(NOW)
        .build()
        .unwrap();
    let a_key = a();
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    let verified = verify_delegation(&token, &ctx).unwrap();
    assert_eq!(verified.claims.exp.0, NOW.0 + 7200, "capped at voucher exp");
}

#[test]
fn missing_voucher_rejected() {
    // Hand-mint a single-hop token with no voucher claim.
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 3600,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint().unwrap() },
    });
    let token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::InvalidVoucher
    ));
}

#[test]
fn voucher_issued_by_third_party_rejected() {
    // B embeds a voucher minted by some other agent (not the verifier):
    // verification under A's own key fails.
    let mallory = AitpSigningKey::from_seed(&[0xD1; 32]);
    let foreign_voucher = TctBuilder::new(&mallory)
        .subject(b().aid().clone())
        .audience(b().aid().clone())
        .grants(["read_data"])
        .ttl_secs(7200)
        .subject_pubkey(b().verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
        .voucher
        .unwrap();
    // Hand-mint with aud = A (the builder would derive aud from the
    // foreign voucher's issuer and die on the audience check instead).
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 600,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint().unwrap() },
        "voucher": foreign_voucher,
    });
    let token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    let err = verify_delegation(&token, &ctx).unwrap_err();
    // Dies verifying the voucher signature under A's own key.
    assert!(
        matches!(
            err,
            DelegationError::InvalidVoucher
                | DelegationError::Crypto(CryptoError::SignatureInvalid)
        ),
        "got {err:?}"
    );
}

#[test]
fn voucher_subject_mismatch_rejected() {
    // B's voucher embedded in a token issued by Mallory:
    // voucher.sub != outer iss (RFC-AITP-0006 §4 step 4).
    let mallory = AitpSigningKey::from_seed(&[0xD2; 32]);
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": mallory.aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 600,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint().unwrap() },
        "voucher": voucher_for_b(),
    });
    let token = jws::sign_compact(&mallory, jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::InvalidVoucher
    ));
}

#[test]
fn audience_mismatch_rejected() {
    let token = delegate_to_c(&voucher_for_b());
    let other = AitpSigningKey::from_seed(&[0xD3; 32]);
    let ctx = VerifyDelegationContext::new(other.aid(), Timestamp(NOW.0 + 60));
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::AudienceMismatch
    ));
}

#[test]
fn expired_delegation_rejected() {
    let token = delegate_to_c(&voucher_for_b());
    let a_key = a();
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 4000));
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::Expired
    ));
}

#[test]
fn exp_beyond_voucher_rejected() {
    // Hand-mint exp > voucher.exp (the builder would cap it).
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 7200 + 1,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint().unwrap() },
        "voucher": voucher_for_b(),
    });
    let token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::Expired
    ));
}

#[test]
fn scope_exceeding_voucher_rejected() {
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data", "admin"],
        "exp": NOW.0 + 600,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint().unwrap() },
        "voucher": voucher_for_b(),
    });
    let token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::ScopeExceeded
    ));
}

#[test]
fn forged_cnf_jkt_rejected() {
    let rogue = AitpSigningKey::from_seed(&[0xD4; 32]);
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 600,
        // jkt of a different key than sub encodes
        "cnf": { "jkt": rogue.verifying_key().to_jwk_thumbprint().unwrap() },
        "voucher": voucher_for_b(),
    });
    let token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::CnfMalformed
    ));
}

#[test]
fn revoked_source_tct_rejected() {
    let voucher = voucher_for_b();
    let payload = jws::decode_payload_unverified(&voucher).unwrap();
    let voucher_claims: aitp_tct::GrantVoucherClaims = serde_json::from_slice(&payload).unwrap();
    let src = voucher_claims.src_jti;
    let token = delegate_to_c(&voucher);
    let revoked = move |jti: &Uuid| *jti == src;
    let a_key = a();
    let mut ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    ctx.revocation_check = Some(&revoked);
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::SourceTctRevoked
    ));
}

#[test]
fn tampered_token_rejected() {
    let mut token = delegate_to_c(&voucher_for_b());
    let last = token.pop().unwrap();
    token.push(if last == 'A' { 'B' } else { 'A' });
    let a_key = a();
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    let err = verify_delegation(&token, &ctx).unwrap_err();
    // A flipped final character fails either as a bad signature or as
    // non-canonical base64 in the signature segment — both refusals.
    assert!(
        matches!(
            err,
            DelegationError::InvalidSignature
                | DelegationError::Crypto(CryptoError::JwsMalformed(_))
        ),
        "got {err:?}"
    );
}

#[test]
fn tct_presented_as_delegation_rejected() {
    let issued = TctBuilder::new(&a())
        .subject(b().aid().clone())
        .audience(b().aid().clone())
        .grants(["read_data"])
        .ttl_secs(7200)
        .subject_pubkey(b().verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap();
    let a_key = a();
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    let err = verify_delegation(&issued.token, &ctx).unwrap_err();
    // The TCT's claims don't deserialize as delegation claims (peek
    // fails) — and even if they did, the typ check would fire.
    assert!(
        matches!(
            err,
            DelegationError::ClaimsMalformed(_)
                | DelegationError::Crypto(CryptoError::TypMismatch { .. })
        ),
        "got {err:?}"
    );
}

#[test]
fn jti_without_multihop_opt_in_rejected() {
    // RFC-AITP-0011 §1.1: strict-claims rejection for non-opted-in
    // verifiers; the same token verifies under the opt-in.
    let token = DelegationBuilder::new(&b(), &voucher_for_b())
        .unwrap()
        .delegatee(c().aid().clone())
        .scope(["read_data"])
        .now(NOW)
        .jti(Uuid::new_v4()) // minted as chain-extensible
        .build()
        .unwrap();
    let a_key = a();
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::ClaimsMalformed(_)
    ));
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60)).with_max_hops(3);
    verify_delegation(&token, &ctx).expect("jti-bearing single-hop verifies under opt-in");
}
