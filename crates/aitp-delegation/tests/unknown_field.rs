//! §7 unknown-member rejection for delegation tokens (issue #140,
//! Phase 6b). No spec fixture pins any of this — it is gated entirely
//! by the tests in this file.

use aitp_core::{Timestamp, PROTOCOL_VERSION};
use aitp_crypto::{jws, AitpSigningKey};
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

/// Acceptance criterion 1 (library half): an outer delegation token
/// with an unknown top-level claim reports `DelegationError::UnknownField`
/// through `verify_delegation`, not `ClaimsMalformed`/`INVALID_ENVELOPE`.
/// The adapter-level assertion of `delegation_error_code` lives in
/// `aitp-rs-adapter`.
#[test]
fn outer_claims_unknown_member_rejected_via_verify_delegation() {
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 600,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint().unwrap() },
        "voucher": voucher_for_b(),
        "rogue": "nope",
    });
    let token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    let err = verify_delegation(&token, &ctx).unwrap_err();
    match err {
        DelegationError::UnknownField(field) => assert_eq!(field, "rogue"),
        other => panic!("expected UnknownField(\"rogue\"), got {other:?}"),
    }
}

/// RFC-AITP-0001 §5.4.5 / issue #140: an outer delegation token whose
/// (unverified) payload carries a duplicate top-level key must be
/// rejected as `ClaimsMalformed`, not silently accepted with the key's
/// last occurrence winning. Raw-text tampering of an otherwise-validly-
/// signed token's payload segment — a defect no `serde_json::Value` can
/// even represent, which is exactly why the JWS-payload "peek" in
/// `peek_claims` must run [`aitp_core::reject_duplicate_keys`] against
/// the raw decoded bytes before ever building a `Value` from them.
#[test]
fn outer_claims_duplicate_member_rejected_via_verify_delegation() {
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 600,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint().unwrap() },
        "voucher": voucher_for_b(),
    });
    let token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &claims).unwrap();

    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload_bytes = aitp_core::base64url::decode_strict(parts[1]).unwrap();
    let payload_str = std::str::from_utf8(&payload_bytes).unwrap();
    assert!(payload_str.starts_with('{'));
    let dup_payload = format!("{{\"ver\":\"{PROTOCOL_VERSION}\",{}", &payload_str[1..]);
    let dup_token = format!(
        "{}.{}.{}",
        parts[0],
        aitp_core::base64url::encode(dup_payload.as_bytes()),
        parts[2]
    );

    let a_key = a();
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    let err = verify_delegation(&dup_token, &ctx).unwrap_err();
    assert!(
        matches!(&err, DelegationError::ClaimsMalformed(m) if m.contains("duplicate field `ver`")),
        "expected ClaimsMalformed(duplicate field `ver`), got {err:?}"
    );
}

/// Acceptance criterion 2, verify-time half: an unknown claim on the
/// *embedded* grant voucher must surface as `UnknownField` through
/// `verify_delegation`, not be swallowed into `InvalidVoucher` by
/// `verify_root_voucher`'s `TctError` -> `DelegationError` mapping.
#[test]
fn embedded_voucher_unknown_member_rejected_not_invalid_voucher() {
    let a_key = a();
    let voucher_claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": a_key.aid(),
        "sub": b().aid(),
        "grants": ["read_data"],
        "iat": NOW.0,
        "exp": NOW.0 + 7200,
        "src_jti": Uuid::new_v4(),
        "rogue": "nope",
    });
    let voucher_token = jws::sign_compact(&a_key, jws::TYP_GRANT_VOUCHER, &voucher_claims).unwrap();
    let outer_claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a_key.aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 600,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint().unwrap() },
        "voucher": voucher_token,
    });
    let token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &outer_claims).unwrap();
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    let err = verify_delegation(&token, &ctx).unwrap_err();
    match err {
        DelegationError::UnknownField(field) => assert_eq!(field, "rogue"),
        other => panic!(
            "expected UnknownField(\"rogue\"), not DELEGATION_INVALID_VOUCHER; got {other:?}"
        ),
    }
}

/// Acceptance criterion 2, build-time half: `DelegationBuilder::new`'s
/// voucher peek must reject an unknown voucher claim as `UnknownField`,
/// not `InvalidVoucher`/`ClaimsMalformed`.
#[test]
fn builder_new_rejects_voucher_with_unknown_member() {
    let a_key = a();
    let voucher_claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": a_key.aid(),
        "sub": b().aid(),
        "grants": ["read_data"],
        "iat": NOW.0,
        "exp": NOW.0 + 7200,
        "src_jti": Uuid::new_v4(),
        "extra_junk": true,
    });
    let voucher_token = jws::sign_compact(&a_key, jws::TYP_GRANT_VOUCHER, &voucher_claims).unwrap();
    let err = match DelegationBuilder::new(&b(), &voucher_token) {
        Err(e) => e,
        Ok(_) => panic!("voucher with an unknown claim must not build"),
    };
    match err {
        DelegationError::UnknownField(field) => assert_eq!(field, "extra_junk"),
        other => panic!("expected UnknownField(\"extra_junk\"), got {other:?}"),
    }
}

/// Same treatment for `DelegationBuilder::extending`'s prior-hop peek.
#[test]
fn builder_extending_rejects_prior_hop_with_unknown_member() {
    let prior_claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 3600,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint().unwrap() },
        "jti": Uuid::new_v4(),
        "surprise": 1,
    });
    let prior_token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &prior_claims).unwrap();
    let err = match DelegationBuilder::extending(&c(), &prior_token) {
        Err(e) => e,
        Ok(_) => panic!("prior hop with an unknown claim must not extend"),
    };
    match err {
        DelegationError::UnknownField(field) => assert_eq!(field, "surprise"),
        other => panic!("expected UnknownField(\"surprise\"), got {other:?}"),
    }
}

fn inject_duplicate_ver(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload_bytes = aitp_core::base64url::decode_strict(parts[1]).unwrap();
    let payload_str = std::str::from_utf8(&payload_bytes).unwrap();
    assert!(payload_str.starts_with('{'));
    let dup_payload = format!("{{\"ver\":\"{PROTOCOL_VERSION}\",{}", &payload_str[1..]);
    format!(
        "{}.{}.{}",
        parts[0],
        aitp_core::base64url::encode(dup_payload.as_bytes()),
        parts[2]
    )
}

/// RFC-AITP-0001 §5.4.5 / issue #140: same duplicate-key rejection as
/// `outer_claims_duplicate_member_rejected_via_verify_delegation`, but for
/// `DelegationBuilder::new`'s embedded-voucher peek.
#[test]
fn builder_new_rejects_voucher_with_duplicate_member() {
    let a_key = a();
    let voucher_claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": a_key.aid(),
        "sub": b().aid(),
        "grants": ["read_data"],
        "iat": NOW.0,
        "exp": NOW.0 + 7200,
        "src_jti": Uuid::new_v4(),
    });
    let voucher_token = jws::sign_compact(&a_key, jws::TYP_GRANT_VOUCHER, &voucher_claims).unwrap();
    let dup_token = inject_duplicate_ver(&voucher_token);
    let err = match DelegationBuilder::new(&b(), &dup_token) {
        Err(e) => e,
        Ok(_) => panic!("voucher with a duplicate claim must not build"),
    };
    assert!(
        matches!(&err, DelegationError::ClaimsMalformed(m) if m.contains("duplicate field `ver`")),
        "expected ClaimsMalformed(duplicate field `ver`), got {err:?}"
    );
}

/// Same treatment for `DelegationBuilder::extending`'s prior-hop peek.
#[test]
fn builder_extending_rejects_prior_hop_with_duplicate_member() {
    let prior_claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 3600,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint().unwrap() },
        "jti": Uuid::new_v4(),
    });
    let prior_token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &prior_claims).unwrap();
    let dup_token = inject_duplicate_ver(&prior_token);
    let err = match DelegationBuilder::extending(&c(), &dup_token) {
        Err(e) => e,
        Ok(_) => panic!("prior hop with a duplicate claim must not extend"),
    };
    assert!(
        matches!(&err, DelegationError::ClaimsMalformed(m) if m.contains("duplicate field `ver`")),
        "expected ClaimsMalformed(duplicate field `ver`), got {err:?}"
    );
}
