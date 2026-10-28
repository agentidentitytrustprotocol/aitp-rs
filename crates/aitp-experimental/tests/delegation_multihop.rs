//! Multi-hop delegation (RFC-AITP-0011): happy path, the rejection
//! matrix, and reproduction of the spec's pinned chain vectors.
//!
//! Topology mirrors the spec's worked example and KAT:
//! A (kat-keypair-001) grants B (-002); B delegates to C (-003) as
//! `chain[0]`; C extends to D (-004) as the outer token D presents
//! to A. Total hops = 3.

use aitp::core::{Aid, Timestamp, PROTOCOL_VERSION};
use aitp::crypto::{jws, AitpSigningKey};
use aitp::delegation::DelegationError;
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder, ManifestError};
use aitp::tct::TctBuilder;
use aitp::tct::{RevocationQuery, RevocationSource, RevocationStatus};
use aitp_experimental::delegation::{
    compute_chain_hash, verify_chained_delegation, ChainedDelegationBuilder,
    ChainedDelegationError, VerifyChainContext, DEFAULT_MAX_DELEGATION_HOPS,
};
use std::collections::HashMap;
use std::sync::OnceLock;
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

fn a() -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&[0xA1; 32])
}
fn b() -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&[0xB1; 32])
}
fn c() -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&[0xC1; 32])
}
fn d() -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&[0xD1; 32])
}

fn voucher_for_b() -> String {
    TctBuilder::new(&a())
        .subject(b().aid().clone())
        .audience(b().aid().clone())
        .grants(["read_data", "write_data"])
        .ttl(std::time::Duration::from_secs(7200))
        .subject_pubkey(b().verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
        .voucher
        .unwrap()
}

/// B → C (chain[0]): jti-bearing, both grants, 100 min.
fn hop1() -> String {
    ChainedDelegationBuilder::new(&b(), &voucher_for_b())
        .unwrap()
        .delegatee(c().aid().clone())
        .scope(["read_data", "write_data"])
        .ttl(std::time::Duration::from_secs(6000))
        .now(NOW)
        .jti(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440011").unwrap())
        .build()
        .unwrap()
}

/// C → D (outer): narrowed scope, 50 min.
fn outer(h1: &str) -> String {
    ChainedDelegationBuilder::extending(&c(), h1)
        .unwrap()
        .delegatee(d().aid().clone())
        .scope(["read_data"])
        .ttl(std::time::Duration::from_secs(3000))
        .now(NOW)
        .jti(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440012").unwrap())
        .build()
        .unwrap()
}

fn mallory() -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&[0xE1; 32])
}
fn e() -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&[0xE7; 32])
}

/// `key`'s published Manifest, valid for `ttl_secs` from `published_at`.
fn manifest_with_ttl(key: &AitpSigningKey, published_at: Timestamp, ttl_secs: u64) -> Manifest {
    ManifestBuilder::new(key)
        .handshake_endpoint("https://agent.example.com/aitp/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityHintKind::Oidc, "agent")
                .with_issuer("https://idp.example.com".parse().unwrap()),
        )
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .published_at(published_at)
        .ttl(std::time::Duration::from_secs(ttl_secs))
        .build()
        .unwrap()
}

fn manifest_for(key: &AitpSigningKey, published_at: Timestamp) -> Manifest {
    manifest_with_ttl(key, published_at, 86_400)
}

/// Every potential hop issuer's Manifest (RFC-AITP-0011 §3 step 1),
/// including the off-path keys some rejection tests sign with, so each
/// test still reaches the check it targets.
fn issuer_manifests() -> &'static Vec<Manifest> {
    static MANIFESTS: OnceLock<Vec<Manifest>> = OnceLock::new();
    MANIFESTS.get_or_init(|| {
        [b(), c(), d(), mallory(), e()]
            .iter()
            .map(|k| manifest_for(k, NOW))
            .collect()
    })
}

fn multihop_ctx(verifier: &aitp::core::Aid) -> VerifyChainContext<'_> {
    VerifyChainContext::new(verifier, Timestamp(NOW.0 + 60), RevocationSource::FailOpen)
        .with_max_delegation_hops(DEFAULT_MAX_DELEGATION_HOPS)
        .with_issuer_manifests(issuer_manifests())
}

#[test]
fn three_hop_chain_round_trip() {
    let h1 = hop1();
    let token = outer(&h1);
    let a_key = a();
    let verified =
        verify_chained_delegation(&token, &multihop_ctx(a_key.aid())).expect("chain verifies");
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
    // A hop budget of 0: structural rejection.
    let ctx = VerifyChainContext::new(
        a_key.aid(),
        Timestamp(NOW.0 + 60),
        RevocationSource::FailOpen,
    )
    .with_max_delegation_hops(0);
    assert!(matches!(
        verify_chained_delegation(&token, &ctx).unwrap_err(),
        ChainedDelegationError::Delegation(DelegationError::MultihopNotSupported)
    ));
}

#[test]
fn hop_limit_enforced_before_signatures() {
    let token = outer(&hop1());
    let a_key = a();
    // total_hops = chain(1) + 2 = 3 > max_delegation_hops 2.
    let ctx = VerifyChainContext::new(
        a_key.aid(),
        Timestamp(NOW.0 + 60),
        RevocationSource::FailOpen,
    )
    .with_max_delegation_hops(2);
    assert!(matches!(
        verify_chained_delegation(&token, &ctx).unwrap_err(),
        ChainedDelegationError::HopLimitExceeded
    ));
}

#[test]
fn scope_inflation_across_hops_rejected() {
    // C tries to delegate `write_data` to D after B granted C only
    // `read_data` — adjacent-pair subsetting must catch it.
    let narrow_h1 = ChainedDelegationBuilder::new(&b(), &voucher_for_b())
        .unwrap()
        .delegatee(c().aid().clone())
        .scope(["read_data"])
        .ttl(std::time::Duration::from_secs(6000))
        .now(NOW)
        .jti(Uuid::new_v4())
        .build()
        .unwrap();
    // The builder itself refuses scope inflation…
    assert!(matches!(
        ChainedDelegationBuilder::extending(&c(), &narrow_h1)
            .unwrap()
            .delegatee(d().aid().clone())
            .scope(["write_data"])
            .now(NOW)
            .build()
            .unwrap_err(),
        ChainedDelegationError::Delegation(DelegationError::ScopeExceeded)
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
        "cnf": { "jkt": d().verifying_key().to_jwk_thumbprint_sha256().unwrap() },
        "jti": Uuid::new_v4(),
        "chain": [narrow_h1.clone()],
        "chain_hash": compute_chain_hash(std::slice::from_ref(&narrow_h1)).unwrap(),
    });
    let token = jws::sign_compact(&c(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    assert!(matches!(
        verify_chained_delegation(&token, &multihop_ctx(a_key.aid())).unwrap_err(),
        ChainedDelegationError::Delegation(DelegationError::ScopeExceeded)
    ));
}

#[test]
fn truncated_chain_rejected() {
    // Four-hop topology A→B→C→D→E so a *mid-chain* truncation is
    // expressible: the outer (D→E) carries chain [h1, h2]; dropping h1
    // (the most restrictive hop) while keeping chain_hash must die on
    // the digest-array commitment.
    let e = e();
    let h1 = hop1(); // B→C, chain-extensible
    let h2 = ChainedDelegationBuilder::extending(&c(), &h1)
        .unwrap()
        .delegatee(d().aid().clone())
        .scope(["read_data"])
        .ttl(std::time::Duration::from_secs(2500))
        .now(NOW)
        .jti(Uuid::new_v4())
        .build()
        .unwrap();
    let outer4 = ChainedDelegationBuilder::extending(&d(), &h2)
        .unwrap()
        .delegatee(e.aid().clone())
        .scope(["read_data"])
        .ttl(std::time::Duration::from_secs(2000))
        .now(NOW)
        .jti(Uuid::new_v4())
        .build()
        .unwrap();
    let a_key = a();
    let full_ctx = VerifyChainContext::new(
        a_key.aid(),
        Timestamp(NOW.0 + 60),
        RevocationSource::FailOpen,
    )
    .with_max_delegation_hops(4)
    .with_issuer_manifests(issuer_manifests());
    verify_chained_delegation(&outer4, &full_ctx)
        .expect("4-hop chain verifies under max_delegation_hops=4");

    // Truncate: drop h1, keep the original chain_hash.
    let payload = jws::decode_payload_unverified(&outer4).unwrap();
    let mut claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    claims["chain"] = serde_json::json!([h2]);
    let forged = jws::sign_compact(&d(), jws::TYP_DELEGATION, &claims).unwrap();
    let err = verify_chained_delegation(&forged, &full_ctx).unwrap_err();
    assert!(
        matches!(err, ChainedDelegationError::ChainHashMismatch),
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
        verify_chained_delegation(&forged, &multihop_ctx(a_key.aid())).unwrap_err(),
        ChainedDelegationError::ChainHashMismatch
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
        verify_chained_delegation(&forged, &multihop_ctx(a_key.aid())).unwrap_err(),
        ChainedDelegationError::Delegation(DelegationError::InvalidVoucher)
    ));
}

#[test]
fn continuity_break_rejected() {
    // Outer token issued by an agent that is NOT chain[0].sub.
    let mallory = mallory();
    let h1 = hop1();
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": mallory.aid(), // not C
        "sub": d().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 600,
        "cnf": { "jkt": d().verifying_key().to_jwk_thumbprint_sha256().unwrap() },
        "jti": Uuid::new_v4(),
        "chain": [h1.clone()],
        "chain_hash": compute_chain_hash(std::slice::from_ref(&h1)).unwrap(),
    });
    let token = jws::sign_compact(&mallory, jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    assert!(matches!(
        verify_chained_delegation(&token, &multihop_ctx(a_key.aid())).unwrap_err(),
        ChainedDelegationError::Delegation(DelegationError::InvalidVoucher)
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
        "cnf": { "jkt": d().verifying_key().to_jwk_thumbprint_sha256().unwrap() },
        "jti": Uuid::new_v4(),
        "chain": [h1.clone()],
        "chain_hash": compute_chain_hash(std::slice::from_ref(&h1)).unwrap(),
    });
    let token = jws::sign_compact(&c(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    assert!(matches!(
        verify_chained_delegation(&token, &multihop_ctx(a_key.aid())).unwrap_err(),
        ChainedDelegationError::Delegation(DelegationError::Expired)
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
        "cnf": { "jkt": d().verifying_key().to_jwk_thumbprint_sha256().unwrap() },
        "jti": "550e8400-e29b-41d4-a716-446655440011", // == h1's jti
        "chain": [h1.clone()],
        "chain_hash": compute_chain_hash(std::slice::from_ref(&h1)).unwrap(),
    });
    let token = jws::sign_compact(&c(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    assert!(matches!(
        verify_chained_delegation(&token, &multihop_ctx(a_key.aid())).unwrap_err(),
        ChainedDelegationError::Delegation(DelegationError::InvalidVoucher)
    ));
}

#[test]
fn revoked_mid_chain_hop_rejected() {
    let h1 = hop1();
    let token = outer(&h1);
    let b_aid = b().aid().clone();
    let h1_jti = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440011").unwrap();
    // B revokes the hop it issued (B→C): everything downstream dies.
    let hop_revoked = move |q: &RevocationQuery<'_>| {
        Ok(if *q.issuer == b_aid && *q.jti == h1_jti {
            RevocationStatus::Revoked
        } else {
            RevocationStatus::Clear
        })
    };
    let not_revoked = |_: &RevocationQuery<'_>| Ok(RevocationStatus::Clear);
    let a_key = a();
    let mut ctx = multihop_ctx(a_key.aid());
    ctx.revocation = RevocationSource::Check(&not_revoked);
    ctx.hop_revocation_check = Some(&hop_revoked);
    assert!(matches!(
        verify_chained_delegation(&token, &ctx).unwrap_err(),
        ChainedDelegationError::Delegation(DelegationError::SourceTctRevoked)
    ));
}

/// RS1.2: under `Check`, a multi-hop chain with no per-hop source fails
/// closed rather than skipping the per-hop lookups.
#[test]
fn multihop_without_hop_source_fails_closed() {
    let token = outer(&hop1());
    let not_revoked = |_: &RevocationQuery<'_>| Ok(RevocationStatus::Clear);
    let a_key = a();
    let mut ctx = multihop_ctx(a_key.aid());
    ctx.revocation = RevocationSource::Check(&not_revoked);
    assert!(matches!(
        verify_chained_delegation(&token, &ctx).unwrap_err(),
        ChainedDelegationError::Delegation(DelegationError::RevocationUnavailable(_))
    ));
}

// ─────────────── issuer key from the issuer's Manifest ───────────────
// RFC-AITP-0011 §3 step 1: each hop verifies under `h.iss`'s public key
// "resolved from that issuer's Manifest", not merely the key the AID
// encodes.

fn ctx_with<'a>(
    verifier: &'a Aid,
    resolver: &'a dyn aitp::manifest::ManifestResolver,
) -> VerifyChainContext<'a> {
    VerifyChainContext::new(verifier, Timestamp(NOW.0 + 60), RevocationSource::FailOpen)
        .with_max_delegation_hops(DEFAULT_MAX_DELEGATION_HOPS)
        .with_issuer_manifests(resolver)
}

/// Unwrap a `KeyResolutionFailed` for `issuer` and return its cause.
fn key_resolution_cause(err: ChainedDelegationError, issuer: &Aid) -> ManifestError {
    match err {
        ChainedDelegationError::Delegation(DelegationError::KeyResolutionFailed {
            issuer: got,
            source,
        }) => {
            assert_eq!(&got, issuer);
            source
        }
        other => panic!("expected KeyResolutionFailed, got {other:?}"),
    }
}

#[test]
fn multihop_without_manifest_source_rejected() {
    let token = outer(&hop1());
    let a_key = a();
    let ctx = VerifyChainContext::new(
        a_key.aid(),
        Timestamp(NOW.0 + 60),
        RevocationSource::FailOpen,
    )
    .with_max_delegation_hops(DEFAULT_MAX_DELEGATION_HOPS);
    // chain[0] is verified first; its issuer is B.
    let cause = key_resolution_cause(
        verify_chained_delegation(&token, &ctx).unwrap_err(),
        b().aid(),
    );
    assert!(matches!(cause, ManifestError::NotFound), "got {cause:?}");
}

#[test]
fn hop_issuer_manifest_unavailable_rejected() {
    // B's Manifest is available; C's (the outer token's issuer) is not.
    let token = outer(&hop1());
    let only_b = vec![manifest_for(&b(), NOW)];
    let a_key = a();
    let err = verify_chained_delegation(&token, &ctx_with(a_key.aid(), &only_b)).unwrap_err();
    let cause = key_resolution_cause(err, c().aid());
    assert!(matches!(cause, ManifestError::NotFound), "got {cause:?}");
}

#[test]
fn hop_key_not_designated_by_issuer_manifest_rejected() {
    // chain[0] is signed by the key B's AID encodes, but the Manifest
    // served for B designates a different (rotated, RFC-AITP-0003 §8.1)
    // key. The AID-embedded key alone MUST NOT verify the hop.
    let token = outer(&hop1());
    let rotated_b = AitpSigningKey::from_ed25519_seed(&[0xB2; 32]);
    let resolver: HashMap<Aid, Manifest> = HashMap::from([
        (b().aid().clone(), manifest_for(&rotated_b, NOW)),
        (c().aid().clone(), manifest_for(&c(), NOW)),
    ]);
    let a_key = a();
    let err = verify_chained_delegation(&token, &ctx_with(a_key.aid(), &resolver)).unwrap_err();
    let cause = key_resolution_cause(err, b().aid());
    assert!(matches!(cause, ManifestError::AidMismatch), "got {cause:?}");
}

#[test]
fn hop_issuer_manifest_must_verify() {
    let token = outer(&hop1());
    let a_key = a();

    // Expired: C's Manifest lapsed before the verification time.
    let stale_c = manifest_with_ttl(&c(), Timestamp(NOW.0 - 120), 60);
    let manifests = vec![manifest_for(&b(), NOW), stale_c];
    let err = verify_chained_delegation(&token, &ctx_with(a_key.aid(), &manifests)).unwrap_err();
    let cause = key_resolution_cause(err, c().aid());
    assert!(matches!(cause, ManifestError::Expired), "got {cause:?}");

    // Forged: B's Manifest body altered after signing.
    let mut forged_b = manifest_for(&b(), NOW);
    forged_b.display_name = Some("not what B signed".into());
    let manifests = vec![forged_b, manifest_for(&c(), NOW)];
    let err = verify_chained_delegation(&token, &ctx_with(a_key.aid(), &manifests)).unwrap_err();
    let cause = key_resolution_cause(err, b().aid());
    assert!(
        matches!(cause, ManifestError::SignatureInvalid),
        "got {cause:?}"
    );
}

#[test]
fn hop_signed_by_other_key_is_invalid_signature() {
    // C's Manifest resolves, but the outer token claiming `iss = C` was
    // signed by someone else: DELEGATION_INVALID_SIGNATURE.
    let payload = jws::decode_payload_unverified(&outer(&hop1())).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    let forged = jws::sign_compact(&mallory(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    let err = verify_chained_delegation(&forged, &multihop_ctx(a_key.aid())).unwrap_err();
    assert!(
        matches!(
            err,
            ChainedDelegationError::Delegation(DelegationError::InvalidSignature)
        ),
        "got {err:?}"
    );
}

#[test]
fn single_hop_under_opt_in_resolves_issuer_manifest() {
    // A plain B → C delegation takes the single-hop path under multi-hop
    // opt-in too, and verifies under B's Manifest key (RFC-AITP-0006 §4
    // step 1) exactly as it does under the strict default.
    let token = ChainedDelegationBuilder::new(&b(), &voucher_for_b())
        .unwrap()
        .delegatee(c().aid().clone())
        .scope(["read_data"])
        .ttl(std::time::Duration::from_secs(600))
        .now(NOW)
        .build()
        .unwrap();
    let a_key = a();
    verify_chained_delegation(&token, &multihop_ctx(a_key.aid()))
        .expect("single-hop verifies under B's Manifest key");
    let none: Vec<Manifest> = Vec::new();
    let err = verify_chained_delegation(&token, &ctx_with(a_key.aid(), &none)).unwrap_err();
    let cause = key_resolution_cause(err, b().aid());
    assert!(matches!(cause, ManifestError::NotFound), "got {cause:?}");
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
    let verifier = AitpSigningKey::from_ed25519_seed(&[0u8; 32]); // kat-keypair-001 (A)

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
    // The hop issuers B (kat-keypair-002) and C (kat-keypair-003) each
    // publish a Manifest (RFC-AITP-0011 §3 step 1).
    let mut kat_002_seed = [0u8; 32];
    for (i, byte) in kat_002_seed.iter_mut().enumerate() {
        *byte = i as u8;
    }
    let published = Timestamp(1_711_900_000);
    let manifests = vec![
        manifest_for(&AitpSigningKey::from_ed25519_seed(&kat_002_seed), published),
        manifest_for(&AitpSigningKey::from_ed25519_seed(&[0xffu8; 32]), published),
    ];
    let ctx = VerifyChainContext::new(
        verifier.aid(),
        Timestamp(1_711_900_100),
        RevocationSource::FailOpen,
    )
    .with_max_delegation_hops(DEFAULT_MAX_DELEGATION_HOPS)
    .with_issuer_manifests(&manifests);
    let verified = verify_chained_delegation(outer_token, &ctx).expect("spec chain KAT verifies");
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
    // ChainedDelegationBuilder::extending re-mints the KAT's outer token
    // byte-for-byte from the pinned seeds and the carried chain entry.
    let v = kat("kat-multihop-chain-001");
    let h1 = v["chain"][0].as_str().unwrap();
    let c_key = AitpSigningKey::from_ed25519_seed(&[0xffu8; 32]); // kat-keypair-003 (C)
    let d_key = AitpSigningKey::from_ed25519_seed(&[0x01u8; 32]); // kat-keypair-004 (D)

    // Outer exp is 1711902000; drive the ttl to land exactly there.
    let now = Timestamp(1_711_900_000);
    let token = ChainedDelegationBuilder::extending(&c_key, h1)
        .unwrap()
        .delegatee(d_key.aid().clone())
        .scope(["macp.mode.task.v1"])
        .ttl(std::time::Duration::from_secs(2000))
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

/// Outer claims for C → D over `h1`, carrying `jti` verbatim.
fn outer_claims_with_jti(h1: &str, jti: &str) -> serde_json::Value {
    serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": c().aid(),
        "sub": d().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 600,
        "cnf": { "jkt": d().verifying_key().to_jwk_thumbprint_sha256().unwrap() },
        "jti": jti,
        "chain": [h1],
        "chain_hash": compute_chain_hash(&[h1.to_string()]).unwrap(),
    })
}

/// Spec PR C (RFC-AITP-0011 §1.1, RFC-AITP-0005 §2 v4 rule): a hop
/// `jti` outside the strict lowercase UUID v4 layout is rejected
/// before signature verification, with wire code
/// `DELEGATION_INVALID_SIGNATURE`.
#[test]
fn non_v4_outer_hop_jti_rejected_before_signature() {
    let h1 = hop1();
    let a_key = a();
    for bad in [
        "0190f8a8-5b7e-7a3c-8d2e-1f4a5b6c7d8e", // v7
        "550e8400-e29b-41d4-c716-446655440012", // v4, variant bits 110
        "550E8400-E29B-41D4-A716-446655440012", // uppercase
    ] {
        let claims = outer_claims_with_jti(&h1, bad);
        let token = jws::sign_compact(&c(), jws::TYP_DELEGATION, &claims).unwrap();
        assert!(
            matches!(
                verify_chained_delegation(&token, &multihop_ctx(a_key.aid())).unwrap_err(),
                ChainedDelegationError::JtiNotV4(_)
            ),
            "{bad}"
        );
        // Signed by the wrong key: the layout check still fires first.
        let forged = jws::sign_compact(&d(), jws::TYP_DELEGATION, &claims).unwrap();
        assert!(
            matches!(
                verify_chained_delegation(&forged, &multihop_ctx(a_key.aid())).unwrap_err(),
                ChainedDelegationError::JtiNotV4(_)
            ),
            "{bad} (forged)"
        );
    }
}

#[test]
fn non_v4_chain_hop_jti_rejected() {
    let v = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 3000,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint_sha256().unwrap() },
        "voucher": voucher_for_b(),
        "jti": "0190f8a8-5b7e-7a3c-8d2e-1f4a5b6c7d8e",
    });
    let h1 = jws::sign_compact(&b(), jws::TYP_DELEGATION, &v).unwrap();
    let token = jws::sign_compact(
        &c(),
        jws::TYP_DELEGATION,
        &outer_claims_with_jti(&h1, "550e8400-e29b-41d4-a716-446655440012"),
    )
    .unwrap();
    let a_key = a();
    assert!(matches!(
        verify_chained_delegation(&token, &multihop_ctx(a_key.aid())).unwrap_err(),
        ChainedDelegationError::JtiNotV4(_)
    ));
}

#[test]
fn builder_rejects_non_v4_jti() {
    let err = ChainedDelegationBuilder::new(&b(), &voucher_for_b())
        .unwrap()
        .delegatee(c().aid().clone())
        .scope(["read_data"])
        .ttl(std::time::Duration::from_secs(600))
        .now(NOW)
        .jti(Uuid::parse_str("0190f8a8-5b7e-7a3c-8d2e-1f4a5b6c7d8e").unwrap())
        .build()
        .unwrap_err();
    assert!(
        matches!(err, ChainedDelegationError::JtiNotV4(_)),
        "{err:?}"
    );
}

// ───────────────────────── async signers ─────────────────────────

/// Sync and async chain extensions are byte identical for deterministic
/// keys (Ed25519; P-256 via RFC 6979 through the mock's Raw and Der
/// outputs).
#[tokio::test]
async fn async_extensions_are_byte_identical_to_sync() {
    use aitp::crypto::testing::{MockKmsSigner, MockOutput};
    type MakeKey = fn(u8) -> AitpSigningKey;
    fn p256(seed: u8) -> AitpSigningKey {
        AitpSigningKey::from_p256_seed(&[seed; 32]).expect("valid P-256 scalar")
    }
    let jti1 = Uuid::parse_str("770e8400-e29b-41d4-a716-446655440901").unwrap();
    let jti2 = Uuid::parse_str("770e8400-e29b-41d4-a716-446655440902").unwrap();
    let cases: [(MakeKey, MockOutput); 3] = [
        (
            |s| AitpSigningKey::from_ed25519_seed(&[s; 32]),
            MockOutput::Raw,
        ),
        (p256, MockOutput::Raw),
        (p256, MockOutput::Der),
    ];
    for (make, output) in cases {
        let (a, b, c) = (make(0xA3), make(0xB4), make(0xC4));
        let d = AitpSigningKey::from_ed25519_seed(&[0xD4; 32]);
        let voucher = TctBuilder::new(&a)
            .subject(b.aid().clone())
            .audience(b.aid().clone())
            .grants(["read_data"])
            .ttl(std::time::Duration::from_secs(7200))
            .subject_pubkey(b.verifying_key())
            .issued_at(NOW)
            .build()
            .unwrap()
            .voucher
            .unwrap();
        let hop1 = ChainedDelegationBuilder::new(&b, &voucher)
            .unwrap()
            .delegatee(c.aid().clone())
            .scope(["read_data"])
            .now(NOW)
            .jti(jti1)
            .build()
            .unwrap();
        let b_kms = MockKmsSigner::new(make(0xB4)).output(output);
        let async_hop1 = ChainedDelegationBuilder::new_async(&b_kms, &voucher)
            .unwrap()
            .delegatee(c.aid().clone())
            .scope(["read_data"])
            .now(NOW)
            .jti(jti1)
            .build_async()
            .await
            .unwrap();
        assert_eq!(hop1, async_hop1);

        let sync2 = ChainedDelegationBuilder::extending(&c, &hop1)
            .unwrap()
            .delegatee(d.aid().clone())
            .scope(["read_data"])
            .now(NOW)
            .jti(jti2)
            .build()
            .unwrap();
        let c_kms = MockKmsSigner::new(make(0xC4)).output(output);
        let async2 = ChainedDelegationBuilder::extending_async(&c_kms, &hop1)
            .unwrap()
            .delegatee(d.aid().clone())
            .scope(["read_data"])
            .now(NOW)
            .jti(jti2)
            .build_async()
            .await
            .unwrap();
        assert_eq!(sync2, async2);
    }
    let stranger = MockKmsSigner::new(AitpSigningKey::from_ed25519_seed(&[0xE5; 32]));
    assert!(matches!(
        ChainedDelegationBuilder::extending_async(&stranger, "not.a.jws").err(),
        Some(ChainedDelegationError::Delegation(DelegationError::Crypto(
            _
        )))
    ));
}

// ──────────────────── prior-hop peek in `extending` ────────────────────

fn prior_hop_claims() -> serde_json::Value {
    serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 3600,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint_sha256().unwrap() },
        "jti": Uuid::new_v4(),
    })
}

/// RFC-AITP-0001 §7: an unknown member on the prior hop is UNKNOWN_FIELD.
#[test]
fn builder_extending_rejects_prior_hop_with_unknown_member() {
    let mut prior_claims = prior_hop_claims();
    prior_claims["surprise"] = serde_json::json!(1);
    let prior_token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &prior_claims).unwrap();
    match ChainedDelegationBuilder::extending(&c(), &prior_token) {
        Err(ChainedDelegationError::Delegation(DelegationError::UnknownField(field))) => {
            assert_eq!(field, "surprise")
        }
        Err(other) => panic!("expected UnknownField(\"surprise\"), got {other:?}"),
        Ok(_) => panic!("prior hop with an unknown claim must not extend"),
    }
}

/// RFC-AITP-0001 §5.4.5: a duplicate member on the prior hop is rejected.
#[test]
fn builder_extending_rejects_prior_hop_with_duplicate_member() {
    let prior_token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &prior_hop_claims()).unwrap();
    let parts: Vec<&str> = prior_token.split('.').collect();
    let payload = aitp::core::base64url::decode_strict(parts[1]).unwrap();
    let payload = std::str::from_utf8(&payload).unwrap();
    let dup_payload = format!("{{\"ver\":\"{PROTOCOL_VERSION}\",{}", &payload[1..]);
    let dup_token = format!(
        "{}.{}.{}",
        parts[0],
        aitp::core::base64url::encode(dup_payload.as_bytes()),
        parts[2]
    );
    match ChainedDelegationBuilder::extending(&c(), &dup_token) {
        Err(ChainedDelegationError::Delegation(DelegationError::ClaimsMalformed(m))) => {
            assert!(m.contains("duplicate field `ver`"), "{m}")
        }
        Err(other) => panic!("expected ClaimsMalformed(duplicate field `ver`), got {other:?}"),
        Ok(_) => panic!("prior hop with a duplicate claim must not extend"),
    }
}

#[test]
fn new_defaults_to_three_hops() {
    let a_key = a();
    let ctx = VerifyChainContext::new(
        a_key.aid(),
        Timestamp(NOW.0 + 60),
        RevocationSource::FailOpen,
    );
    assert_eq!(ctx.max_delegation_hops, DEFAULT_MAX_DELEGATION_HOPS);
    assert_eq!(DEFAULT_MAX_DELEGATION_HOPS, 3);
}
