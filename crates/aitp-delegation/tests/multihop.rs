//! End-to-end multi-hop delegation verification (RFC-AITP-0011).
//!
//! Topology: A → B → C → D, then C issues delegation to E (the
//! delegatee). Total chain hops = 3 (chain length 2 + grant_proof).
//!
//! - chain[0] = A → B  (TCT projection, signature reused from A's TCT)
//! - chain[1] = B → C  (DelegationStep, signed by B)
//! - grant_proof = C → D (DelegationStep, signed by C)
//! - delegation.issued_by = D (signs outer delegation to E)
//! - delegation.delegatee = E
//! - verifier = A
//!
//! The cryptographic invariants RFC-AITP-0011 §3-§5 require:
//! 1. Per-hop signature dispatch (TCT projection at hop 0; step body
//!    JCS at hops > 0).
//! 2. Audience continuity through the chain.
//! 3. Issuer-of-first-hop equals delegator (A).
//! 4. Per-hop expiry monotonically non-increasing.
//! 5. Transitive scope subsetting.
//! 6. `chain_hash` over all chain JTIs binds the chain into the outer
//!    signature.

use aitp_core::{base64url, jcs, Aid, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_delegation::{
    compute_chain_hash, verify_delegation, DelegationError, DelegationStep, DelegationToken,
    GrantProof, VerifyDelegationContext, DEFAULT_MAX_HOPS,
};
use aitp_tct::{Tct, TctBuilder};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

fn key(seed: u8) -> AitpSigningKey {
    AitpSigningKey::from_seed(&[seed; 32])
}

/// JCS canonicalization view for a multi-hop step (matches the verifier's
/// internal `StepSigningView`). Used in tests to mint hops i > 0.
#[derive(Serialize)]
struct StepSigningView<'a> {
    issuer: &'a Aid,
    subject: &'a Aid,
    capabilities: &'a [String],
    issued_at: &'a Timestamp,
    expires_at: &'a Timestamp,
    source_tct_jti: &'a Uuid,
}

/// Mint a chain step (hop > 0): issuer signs the canonical JCS body
/// of the step (excluding `signature`).
fn mint_step(
    issuer_key: &AitpSigningKey,
    subject: Aid,
    capabilities: Vec<String>,
    expires_at: Timestamp,
) -> DelegationStep {
    let issued_at = NOW;
    let source_tct_jti = Uuid::new_v4();
    let view = StepSigningView {
        issuer: issuer_key.aid(),
        subject: &subject,
        capabilities: &capabilities,
        issued_at: &issued_at,
        expires_at: &expires_at,
        source_tct_jti: &source_tct_jti,
    };
    let canonical = jcs::canonicalize_serializable(&view).unwrap();
    let digest = Sha256::digest(&canonical);
    let signature = issuer_key.sign(&digest);
    GrantProof {
        issuer: issuer_key.aid().clone(),
        subject,
        capabilities,
        issued_at,
        expires_at,
        source_tct_jti,
        signature: signature.into_string(),
    }
}

/// JCS canonicalization view for the outer delegation (matches the
/// verifier's internal `DelegationSigningView`). For multi-hop, this
/// covers `chain` and `chain_hash`.
#[derive(Serialize)]
struct OuterSigningView<'a> {
    delegator: &'a Aid,
    delegatee: &'a Aid,
    issued_by: &'a Aid,
    audience: &'a Aid,
    scope: &'a [String],
    expires_at: &'a Timestamp,
    cnf: &'a str,
    grant_proof: &'a GrantProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain: Option<&'a [DelegationStep]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_hash: Option<&'a str>,
}

fn make_3hop_token() -> (DelegationToken, AitpSigningKey) {
    // 3-hop A → B → C → D delegation. RFC-AITP-0011 §3 line 130:
    // total_hops = chain.length + 1, where the +1 is the top-level
    // grant_proof. So a 3-hop chain has chain[0..1] plus a grant_proof
    // that IS the final hop. The outer delegation's `issued_by`
    // equals `grant_proof.issuer`, and `delegatee` equals
    // `grant_proof.subject`.
    let alice = key(0xA0);
    let bob = key(0xB0);
    let carol = key(0xC0);
    let dave = key(0xD0);

    // chain[0]: A → B (TCT projection). Signature reused from a real
    // peer-issued TCT minted by A.
    let tct_b: Tct = TctBuilder::new(&alice)
        .subject(bob.aid().clone())
        .audience(bob.aid().clone())
        .grants(["read", "write", "admin"])
        .ttl_secs(3600)
        .subject_pubkey(bob.verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap();
    let step_ab = GrantProof {
        issuer: alice.aid().clone(),
        subject: bob.aid().clone(),
        capabilities: tct_b.grants.clone(),
        issued_at: tct_b.issued_at,
        expires_at: tct_b.expires_at,
        source_tct_jti: tct_b.jti,
        signature: tct_b.signature.clone(),
    };

    // chain[1]: B → C, signed by B, narrower scope.
    let step_bc = mint_step(
        &bob,
        carol.aid().clone(),
        vec!["read".into(), "write".into()],
        Timestamp(tct_b.expires_at.0 - 60),
    );

    // grant_proof = final hop C → D, signed by C, narrowest scope.
    // C is `issued_by` (signs the outer delegation); D is the
    // `delegatee` (recipient).
    let step_cd = mint_step(
        &carol,
        dave.aid().clone(),
        vec!["read".into()],
        Timestamp(step_bc.expires_at.0 - 60),
    );

    // Chain held in delegation token: oldest first; most-recent stays
    // in grant_proof.
    let chain = vec![step_ab, step_bc];
    let chain_hash = compute_chain_hash(&chain).unwrap();

    let delegator = alice.aid().clone(); // A
    let audience = delegator.clone();
    let scope = vec!["read".into()];
    let expires_at = Timestamp(step_cd.expires_at.0 - 60);
    let cnf = base64url::encode(&dave.verifying_key().to_bytes());

    let outer = OuterSigningView {
        delegator: &delegator,
        delegatee: dave.aid(),
        issued_by: carol.aid(),
        audience: &audience,
        scope: &scope,
        expires_at: &expires_at,
        cnf: &cnf,
        grant_proof: &step_cd,
        chain: Some(&chain),
        chain_hash: Some(&chain_hash),
    };
    let canonical = jcs::canonicalize_serializable(&outer).unwrap();
    let digest = Sha256::digest(&canonical);
    let signature = carol.sign(&digest);

    let token = DelegationToken {
        delegator,
        delegatee: dave.aid().clone(),
        issued_by: carol.aid().clone(),
        audience,
        scope,
        expires_at,
        cnf,
        grant_proof: step_cd,
        chain: Some(chain),
        chain_hash: Some(chain_hash),
        signature: signature.into_string(),
    };
    (token, alice)
}

#[test]
fn three_hop_happy_path() {
    let (token, alice) = make_3hop_token();
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
        max_hops: DEFAULT_MAX_HOPS,
    };
    verify_delegation(&token, &ctx).expect("3-hop chain verifies");
}

#[test]
fn hop_limit_exceeded() {
    let (token, alice) = make_3hop_token();
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
        max_hops: 2, // total_hops = 3 > 2
    };
    let err = verify_delegation(&token, &ctx).unwrap_err();
    assert!(matches!(err, DelegationError::HopLimitExceeded));
}

#[test]
fn multihop_not_supported_when_max_zero() {
    let (token, alice) = make_3hop_token();
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
        max_hops: 0,
    };
    let err = verify_delegation(&token, &ctx).unwrap_err();
    assert!(matches!(err, DelegationError::MultihopNotSupported));
}

#[test]
fn chain_hash_tampered() {
    let (mut token, alice) = make_3hop_token();
    // Tamper: replace chain_hash with a different valid base64url string.
    let mut h = token.chain_hash.unwrap().into_bytes();
    h[0] ^= 0x01;
    // Ensure result is still 43 chars of base64url alphabet.
    let mut tampered = String::from_utf8(h).unwrap();
    if !tampered
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        // Fallback: just reverse it.
        tampered = tampered.chars().rev().collect();
    }
    token.chain_hash = Some(tampered);
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
        max_hops: DEFAULT_MAX_HOPS,
    };
    let err = verify_delegation(&token, &ctx).unwrap_err();
    // ChainHashMismatch OR InvalidSignature are both acceptable —
    // the recompute fails, but a malformed hash also breaks the outer
    // signature. We accept either.
    assert!(
        matches!(err, DelegationError::ChainHashMismatch)
            || matches!(err, DelegationError::InvalidSignature),
        "unexpected error: {err:?}"
    );
}

#[test]
fn chain_truncation_rejected() {
    let (mut token, alice) = make_3hop_token();
    // Drop chain[1]; recomputed chain_hash now mismatches and outer
    // signature fails too. The outer signer covered the full chain;
    // truncating breaks the signing input regardless.
    let mut chain = token.chain.clone().unwrap();
    chain.pop();
    token.chain = Some(chain);
    // Don't update chain_hash — the truncation must be detected.
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
        max_hops: DEFAULT_MAX_HOPS,
    };
    let err = verify_delegation(&token, &ctx).unwrap_err();
    // After dropping chain[1], the audience-continuity check catches
    // it before the chain_hash recompute (chain[0].subject was B,
    // grant_proof.issuer is C). InvalidGrantProof is the canonical
    // outcome.
    assert!(
        matches!(err, DelegationError::InvalidGrantProof)
            || matches!(err, DelegationError::ChainHashMismatch),
        "unexpected error: {err:?}"
    );
}

#[test]
fn scope_inflation_in_outer() {
    let (mut token, alice) = make_3hop_token();
    // Grant_proof.capabilities = ["read"]; outer scope adds "admin".
    token.scope.push("admin".into());
    // Don't re-sign — but the verifier checks scope before signature,
    // so we'll see ScopeExceeded.
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
        max_hops: DEFAULT_MAX_HOPS,
    };
    let err = verify_delegation(&token, &ctx).unwrap_err();
    assert!(matches!(err, DelegationError::ScopeExceeded));
}

#[test]
fn revoked_hop_rejected() {
    let (token, alice) = make_3hop_token();
    let revoked_jti = token.chain.as_ref().unwrap()[1].source_tct_jti;
    let check = |jti: &Uuid| *jti == revoked_jti;
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: Some(&check),
        max_hops: DEFAULT_MAX_HOPS,
    };
    let err = verify_delegation(&token, &ctx).unwrap_err();
    assert!(matches!(err, DelegationError::SourceTctRevoked));
}

#[test]
fn duplicate_jti_in_chain_rejected() {
    let (mut token, alice) = make_3hop_token();
    // Force chain[0].source_tct_jti == chain[1].source_tct_jti.
    let mut chain = token.chain.clone().unwrap();
    let dup = chain[0].source_tct_jti;
    chain[1].source_tct_jti = dup;
    token.chain = Some(chain);
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
        max_hops: DEFAULT_MAX_HOPS,
    };
    let err = verify_delegation(&token, &ctx).unwrap_err();
    assert!(matches!(err, DelegationError::ChainHashMismatch));
}

#[test]
fn singlehop_unchanged_with_chain_field_absent() {
    // Existing single-hop tests (in round_trip.rs) cover this path,
    // but assert here too: a token with no `chain` field still
    // exercises the v0.1 verifier and is byte-equivalent at the wire.
    use aitp_delegation::DelegationBuilder;
    let alice = key(0xA0);
    let bob = key(0xB0);
    let carol = key(0xC0);
    let tct_b = TctBuilder::new(&alice)
        .subject(bob.aid().clone())
        .audience(bob.aid().clone())
        .grants(["read"])
        .ttl_secs(3600)
        .subject_pubkey(bob.verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap();
    let token = DelegationBuilder::new(&bob, &tct_b)
        .delegatee(carol.aid().clone())
        .delegatee_pubkey(carol.verifying_key())
        .scope(["read"])
        .now(NOW)
        .build()
        .unwrap();
    assert!(token.chain.is_none(), "single-hop must not emit chain");
    assert!(
        token.chain_hash.is_none(),
        "single-hop must not emit chain_hash"
    );
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
        max_hops: DEFAULT_MAX_HOPS,
    };
    verify_delegation(&token, &ctx).unwrap();
}
