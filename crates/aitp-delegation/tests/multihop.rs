//! Multi-hop delegation (RFC-AITP-0011): happy path, the rejection
//! matrix, and reproduction of the spec's pinned chain vectors.
//!
//! Topology mirrors the spec's worked example and KAT:
//! A (kat-keypair-001) grants B (-002); B delegates to C (-003) as
//! `chain[0]`; C extends to D (-004) as the outer token D presents
//! to A. Total hops = 3.

use aitp_core::{Timestamp, PROTOCOL_VERSION};
use aitp_crypto::{jws, AitpSigningKey};
use aitp_delegation::{
    compute_chain_hash, verify_delegation, DelegationBuilder, DelegationError,
    VerifyDelegationContext, DEFAULT_MAX_HOPS,
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
fn d() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xD1; 32])
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

/// B → C (chain[0]): jti-bearing, both grants, 100 min.
fn hop1() -> String {
    DelegationBuilder::new(&b(), &voucher_for_b())
        .unwrap()
        .delegatee(c().aid().clone())
        .scope(["read_data", "write_data"])
        .ttl_secs(6000)
        .now(NOW)
        .jti(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440011").unwrap())
        .build()
        .unwrap()
}

/// C → D (outer): narrowed scope, 50 min.
fn outer(h1: &str) -> String {
    DelegationBuilder::extending(&c(), h1)
        .unwrap()
        .delegatee(d().aid().clone())
        .scope(["read_data"])
        .ttl_secs(3000)
        .now(NOW)
        .jti(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440012").unwrap())
        .build()
        .unwrap()
}

fn multihop_ctx(verifier: &aitp_core::Aid) -> VerifyDelegationContext<'_> {
    VerifyDelegationContext::new(verifier, Timestamp(NOW.0 + 60)).with_max_hops(DEFAULT_MAX_HOPS)
}

#[test]
fn three_hop_chain_round_trip() {
    let h1 = hop1();
    let token = outer(&h1);
    let a_key = a();
    let verified = verify_delegation(&token, &multihop_ctx(a_key.aid())).expect("chain verifies");
    assert_eq!(verified.claims.iss, *c().aid());
    assert_eq!(verified.claims.sub, *d().aid());
    assert_eq!(verified.claims.scope, vec!["read_data".to_string()]);
    assert_eq!(verified.claims.chain.as_ref().unwrap().len(), 1);
    assert_eq!(verified.claims.chain.as_ref().unwrap()[0], h1);
    // The root authority surfaced to the caller is A's voucher to B.
    assert_eq!(verified.voucher.sub, *b().aid());
}

#[test]
fn chain_rejected_without_opt_in() {
    let token = outer(&hop1());
    let a_key = a();
    // Single-hop-only context: structural rejection.
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::MultihopNotSupported
    ));
}

#[test]
fn hop_limit_enforced_before_signatures() {
    let token = outer(&hop1());
    let a_key = a();
    // total_hops = chain(1) + 2 = 3 > max_hops 2.
    let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60)).with_max_hops(2);
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::HopLimitExceeded
    ));
}

#[test]
fn scope_inflation_across_hops_rejected() {
    // C tries to delegate `write_data` to D after B granted C only
    // `read_data` — adjacent-pair subsetting must catch it.
    let narrow_h1 = DelegationBuilder::new(&b(), &voucher_for_b())
        .unwrap()
        .delegatee(c().aid().clone())
        .scope(["read_data"])
        .ttl_secs(6000)
        .now(NOW)
        .jti(Uuid::new_v4())
        .build()
        .unwrap();
    // The builder itself refuses scope inflation…
    assert!(matches!(
        DelegationBuilder::extending(&c(), &narrow_h1)
            .unwrap()
            .delegatee(d().aid().clone())
            .scope(["write_data"])
            .now(NOW)
            .build()
            .unwrap_err(),
        DelegationError::ScopeExceeded
    ));
    // …so hand-mint the inflated outer token to prove the verifier
    // catches it independently.
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": c().aid(),
        "sub": d().aid(),
        "aud": a().aid(),
        "scope": ["write_data"],
        "exp": NOW.0 + 600,
        "cnf": { "jkt": d().verifying_key().to_jwk_thumbprint().unwrap() },
        "jti": Uuid::new_v4(),
        "chain": [narrow_h1.clone()],
        "chain_hash": compute_chain_hash(std::slice::from_ref(&narrow_h1)).unwrap(),
    });
    let token = jws::sign_compact(&c(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    assert!(matches!(
        verify_delegation(&token, &multihop_ctx(a_key.aid())).unwrap_err(),
        DelegationError::ScopeExceeded
    ));
}

#[test]
fn truncated_chain_rejected() {
    // Four-hop topology A→B→C→D→E so a *mid-chain* truncation is
    // expressible: the outer (D→E) carries chain [h1, h2]; dropping h1
    // (the most restrictive hop) while keeping chain_hash must die on
    // the digest-array commitment.
    let e = AitpSigningKey::from_seed(&[0xE7; 32]);
    let h1 = hop1(); // B→C, chain-extensible
    let h2 = DelegationBuilder::extending(&c(), &h1)
        .unwrap()
        .delegatee(d().aid().clone())
        .scope(["read_data"])
        .ttl_secs(2500)
        .now(NOW)
        .jti(Uuid::new_v4())
        .build()
        .unwrap();
    let outer4 = DelegationBuilder::extending(&d(), &h2)
        .unwrap()
        .delegatee(e.aid().clone())
        .scope(["read_data"])
        .ttl_secs(2000)
        .now(NOW)
        .jti(Uuid::new_v4())
        .build()
        .unwrap();
    let a_key = a();
    let full_ctx =
        VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60)).with_max_hops(4);
    verify_delegation(&outer4, &full_ctx).expect("4-hop chain verifies under max_hops=4");

    // Truncate: drop h1, keep the original chain_hash.
    let payload = jws::decode_payload_unverified(&outer4).unwrap();
    let mut claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    claims["chain"] = serde_json::json!([h2]);
    let forged = jws::sign_compact(&d(), jws::TYP_DELEGATION, &claims).unwrap();
    let err = verify_delegation(&forged, &full_ctx).unwrap_err();
    assert!(
        matches!(err, DelegationError::ChainHashMismatch),
        "got {err:?}"
    );
}

#[test]
fn chain_hash_missing_rejected() {
    let h1 = hop1();
    let token = outer(&h1);
    let payload = jws::decode_payload_unverified(&token).unwrap();
    let mut claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    claims.as_object_mut().unwrap().remove("chain_hash");
    let forged = jws::sign_compact(&c(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    assert!(matches!(
        verify_delegation(&forged, &multihop_ctx(a_key.aid())).unwrap_err(),
        DelegationError::ChainHashMismatch
    ));
}

#[test]
fn voucher_on_chained_outer_token_rejected() {
    // Exactly one root of authority: a chain-bearing outer token MUST
    // NOT also carry a voucher.
    let h1 = hop1();
    let token = outer(&h1);
    let payload = jws::decode_payload_unverified(&token).unwrap();
    let mut claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    claims
        .as_object_mut()
        .unwrap()
        .insert("voucher".into(), serde_json::json!(voucher_for_b()));
    let forged = jws::sign_compact(&c(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    assert!(matches!(
        verify_delegation(&forged, &multihop_ctx(a_key.aid())).unwrap_err(),
        DelegationError::InvalidVoucher
    ));
}

#[test]
fn continuity_break_rejected() {
    // Outer token issued by an agent that is NOT chain[0].sub.
    let mallory = AitpSigningKey::from_seed(&[0xE1; 32]);
    let h1 = hop1();
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": mallory.aid(), // not C
        "sub": d().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 600,
        "cnf": { "jkt": d().verifying_key().to_jwk_thumbprint().unwrap() },
        "jti": Uuid::new_v4(),
        "chain": [h1.clone()],
        "chain_hash": compute_chain_hash(std::slice::from_ref(&h1)).unwrap(),
    });
    let token = jws::sign_compact(&mallory, jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    assert!(matches!(
        verify_delegation(&token, &multihop_ctx(a_key.aid())).unwrap_err(),
        DelegationError::InvalidVoucher
    ));
}

#[test]
fn expiry_inflation_across_hops_rejected() {
    // Outer exp > chain[0].exp.
    let h1 = hop1(); // exp = NOW + 6000
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": c().aid(),
        "sub": d().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 6001,
        "cnf": { "jkt": d().verifying_key().to_jwk_thumbprint().unwrap() },
        "jti": Uuid::new_v4(),
        "chain": [h1.clone()],
        "chain_hash": compute_chain_hash(std::slice::from_ref(&h1)).unwrap(),
    });
    let token = jws::sign_compact(&c(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    assert!(matches!(
        verify_delegation(&token, &multihop_ctx(a_key.aid())).unwrap_err(),
        DelegationError::Expired
    ));
}

#[test]
fn duplicate_hop_jti_rejected() {
    // Outer token reuses chain[0]'s jti.
    let h1 = hop1();
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": c().aid(),
        "sub": d().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 600,
        "cnf": { "jkt": d().verifying_key().to_jwk_thumbprint().unwrap() },
        "jti": "550e8400-e29b-41d4-a716-446655440011", // == h1's jti
        "chain": [h1.clone()],
        "chain_hash": compute_chain_hash(std::slice::from_ref(&h1)).unwrap(),
    });
    let token = jws::sign_compact(&c(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    assert!(matches!(
        verify_delegation(&token, &multihop_ctx(a_key.aid())).unwrap_err(),
        DelegationError::InvalidVoucher
    ));
}

#[test]
fn revoked_mid_chain_hop_rejected() {
    let h1 = hop1();
    let token = outer(&h1);
    let b_aid = b().aid().clone();
    let h1_jti = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440011").unwrap();
    // B revokes the hop it issued (B→C): everything downstream dies.
    let hop_revoked = move |issuer: &aitp_core::Aid, jti: &Uuid| *issuer == b_aid && *jti == h1_jti;
    let a_key = a();
    let mut ctx = multihop_ctx(a_key.aid());
    ctx.hop_revocation_check = Some(&hop_revoked);
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::SourceTctRevoked
    ));
}

// ───────────────────────── spec KAT vectors ─────────────────────────

fn kat_vectors() -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("tests/schemas/known-answer/jcs-sha256.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn kat(id: &str) -> serde_json::Value {
    kat_vectors()["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
        .unwrap_or_else(|| panic!("KAT {id} missing"))
        .clone()
}

#[test]
fn spec_multihop_chain_kat_verifies_end_to_end() {
    let v = kat("kat-multihop-chain-001");
    let outer_token = v["outer_delegation_jws"].as_str().unwrap();
    let verifier = AitpSigningKey::from_seed(&[0u8; 32]); // kat-keypair-001 (A)

    // chain_hash recomputation matches the pinned value.
    let chain: Vec<String> = v["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        compute_chain_hash(&chain).unwrap(),
        v["chain_hash"].as_str().unwrap()
    );

    // Full multi-hop verification at a time inside every hop's window.
    let ctx = VerifyDelegationContext {
        verifier: verifier.aid(),
        now: Timestamp(1_711_900_100),
        max_hops: DEFAULT_MAX_HOPS,
        revocation_check: None,
        hop_revocation_check: None,
    };
    let verified = verify_delegation(outer_token, &ctx).expect("spec chain KAT verifies");
    assert_eq!(verified.claims.scope, vec!["macp.mode.task.v1".to_string()]);
    assert_eq!(
        verified.voucher.src_jti,
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap()
    );
}

#[test]
fn spec_truncation_kat_detects_mismatch() {
    let v = kat("kat-multihop-truncation-001");
    let truncated: Vec<String> = v["chain_truncated"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect();
    let recomputed = compute_chain_hash(&truncated).unwrap();
    assert_eq!(recomputed, v["chain_hash_truncated"].as_str().unwrap());
    assert_ne!(
        recomputed,
        v["chain_hash_full"].as_str().unwrap(),
        "truncation MUST change the chain hash"
    );
}

#[test]
fn builder_reproduces_spec_outer_delegation() {
    // DelegationBuilder::extending re-mints the KAT's outer token
    // byte-for-byte from the pinned seeds and the carried chain entry.
    let v = kat("kat-multihop-chain-001");
    let h1 = v["chain"][0].as_str().unwrap();
    let c_key = AitpSigningKey::from_seed(&[0xffu8; 32]); // kat-keypair-003 (C)
    let d_key = AitpSigningKey::from_seed(&[0x01u8; 32]); // kat-keypair-004 (D)

    // Outer exp is 1711902000; drive the ttl to land exactly there.
    let now = Timestamp(1_711_900_000);
    let token = DelegationBuilder::extending(&c_key, h1)
        .unwrap()
        .delegatee(d_key.aid().clone())
        .scope(["macp.mode.task.v1"])
        .ttl_secs(2000)
        .now(now)
        .jti(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440012").unwrap())
        .build()
        .unwrap();
    assert_eq!(
        token,
        v["outer_delegation_jws"].as_str().unwrap(),
        "builder-minted outer token diverges from the spec KAT"
    );
}
