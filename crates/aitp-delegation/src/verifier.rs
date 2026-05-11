//! Delegation token verification (RFC-AITP-0006 §4 single-hop;
//! RFC-AITP-0011 multi-hop).

use crate::builder::DelegationSigningView;
use crate::types::{DelegationStep, DelegationToken, GrantProof};
use crate::DelegationError;
use aitp_core::{base64url, jcs, Aid, Timestamp};
use aitp_crypto::{AitpVerifyingKey, Signature};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Default `max_hops` cap from RFC-AITP-0011 §2: orchestrator → planner →
/// executor. Configurable per [`VerifyDelegationContext`].
pub const DEFAULT_MAX_HOPS: u32 = 3;

/// Inputs for verifying a delegation token.
pub struct VerifyDelegationContext<'a> {
    /// The verifier's own AID (A).
    pub verifier_aid: &'a Aid,
    /// Current time, for expiry checks.
    pub now: Timestamp,
    /// Optional revocation lookup against the verifier's deny list.
    /// Returns `true` if the JTI is revoked. For multi-hop tokens
    /// every hop's `source_tct_jti` (including the top-level
    /// `grant_proof`) is consulted (RFC-AITP-0011 §6).
    pub revocation_check: Option<&'a dyn Fn(&Uuid) -> bool>,
    /// Maximum total hop count permitted (RFC-AITP-0011 §2). The
    /// total hop count is `chain.len() + 1`. Setting `0` rejects any
    /// non-empty chain with `MultihopNotSupported` (the strict v0.1
    /// posture). Default: 3.
    pub max_hops: u32,
}

impl<'a> VerifyDelegationContext<'a> {
    /// Default context for verifier `verifier_aid` at time `now`. No
    /// revocation lookup; `max_hops = 3`.
    pub fn new(verifier_aid: &'a Aid, now: Timestamp) -> Self {
        Self {
            verifier_aid,
            now,
            revocation_check: None,
            max_hops: DEFAULT_MAX_HOPS,
        }
    }
}

/// Verify a delegation token (RFC-AITP-0006 §4).
///
/// Order of checks:
///
/// 1. `audience == verifier_aid` and `delegator == verifier_aid`.
/// 2. `expires_at` and `grant_proof.expires_at` in the future.
/// 3. `delegation.expires_at <= grant_proof.expires_at`.
/// 4. `grant_proof.issuer == verifier_aid` and `grant_proof.subject ==
///    delegation.issued_by`.
/// 5. Reject self-delegation (`issued_by == delegatee`).
/// 6. Verify `grant_proof.signature` against the verifier's public key
///    over the reconstructed source-TCT body. Failure ⇒ `InvalidGrantProof`.
/// 7. `scope ⊆ grant_proof.capabilities`. Else `ScopeExceeded`.
/// 8. Revocation check on `grant_proof.source_tct_jti`.
/// 9. Verify outer `delegation.signature` against `delegation.issued_by`'s
///    public key.
/// 10. `cnf` decodes to a valid 32-byte pubkey. (Downstream PoP — proving
///     C controls that key — is the caller's responsibility.)
pub fn verify_delegation<'a>(
    token: &'a DelegationToken,
    ctx: &VerifyDelegationContext<'_>,
) -> Result<&'a DelegationToken, DelegationError> {
    let chain = token.chain.as_deref().filter(|c| !c.is_empty());

    if let Some(chain) = chain {
        verify_multihop(token, chain, ctx)
    } else {
        verify_singlehop(token, ctx)
    }
}

/// v0.1 single-hop verification. The pre-rc.1 logic, unchanged. The
/// outer signing view emits no `chain`/`chain_hash` (skip-if-none)
/// so single-hop signing input bytes are byte-identical to pre-rc.1.
fn verify_singlehop<'a>(
    token: &'a DelegationToken,
    ctx: &VerifyDelegationContext<'_>,
) -> Result<&'a DelegationToken, DelegationError> {
    // 1. Audience / delegator binding.
    if &token.audience != ctx.verifier_aid {
        return Err(DelegationError::AudienceMismatch);
    }
    if &token.delegator != ctx.verifier_aid {
        return Err(DelegationError::AudienceMismatch);
    }

    // 2 + 3. Expiry checks.
    if token.expires_at.is_in_the_past(ctx.now) {
        return Err(DelegationError::Expired);
    }
    if token.grant_proof.expires_at.is_in_the_past(ctx.now) {
        return Err(DelegationError::Expired);
    }
    if token.expires_at.0 > token.grant_proof.expires_at.0 {
        return Err(DelegationError::Expired);
    }

    // 4. grant_proof identity binding.
    if &token.grant_proof.issuer != ctx.verifier_aid {
        return Err(DelegationError::InvalidGrantProof);
    }
    if token.grant_proof.subject != token.issued_by {
        return Err(DelegationError::InvalidGrantProof);
    }

    // 5. Self-delegation check.
    if token.issued_by == token.delegatee {
        return Err(DelegationError::SelfDelegation);
    }

    // 6. Reconstruct source TCT body and verify A's signature.
    verify_source_tct_projection(&token.grant_proof, &token.issued_by)?;

    // 7. Scope ⊆ grant_proof.capabilities.
    for cap in &token.scope {
        if !token.grant_proof.capabilities.contains(cap) {
            return Err(DelegationError::ScopeExceeded);
        }
    }

    // 8. Revocation lookup.
    if let Some(check) = ctx.revocation_check {
        if check(&token.grant_proof.source_tct_jti) {
            return Err(DelegationError::SourceTctRevoked);
        }
    }

    // 9. Outer signature.
    let issued_by_pubkey = AitpVerifyingKey::from_aid(&token.issued_by)?;
    let outer_view = DelegationSigningView {
        delegator: &token.delegator,
        delegatee: &token.delegatee,
        issued_by: &token.issued_by,
        audience: &token.audience,
        scope: &token.scope,
        expires_at: &token.expires_at,
        cnf: &token.cnf,
        grant_proof: &token.grant_proof,
        chain: None,
        chain_hash: None,
    };
    let canonical = jcs::canonicalize_serializable(&outer_view)
        .map_err(|e| DelegationError::Canonicalization(e.to_string()))?;
    let digest = Sha256::digest(&canonical);
    let outer_sig =
        Signature::parse(&token.signature).map_err(|_| DelegationError::InvalidSignature)?;
    issued_by_pubkey
        .verify(&digest, &outer_sig)
        .map_err(|_| DelegationError::InvalidSignature)?;

    // 10. cnf well-formedness.
    let cnf_bytes =
        base64url::decode_strict(&token.cnf).map_err(|_| DelegationError::CnfMalformed)?;
    if cnf_bytes.len() != 32 {
        return Err(DelegationError::CnfMalformed);
    }

    Ok(token)
}

/// Multi-hop verification (RFC-AITP-0011). `chain` is non-empty.
fn verify_multihop<'a>(
    token: &'a DelegationToken,
    chain: &'a [DelegationStep],
    ctx: &VerifyDelegationContext<'_>,
) -> Result<&'a DelegationToken, DelegationError> {
    // §2: hop limit. total_hops = chain.len() + 1.
    if ctx.max_hops == 0 {
        return Err(DelegationError::MultihopNotSupported);
    }
    let total_hops = chain.len() as u32 + 1;
    if total_hops > ctx.max_hops {
        return Err(DelegationError::HopLimitExceeded);
    }

    // §1.4: the audience/delegator pair still binds to the verifier.
    if &token.audience != ctx.verifier_aid {
        return Err(DelegationError::AudienceMismatch);
    }
    if &token.delegator != ctx.verifier_aid {
        return Err(DelegationError::AudienceMismatch);
    }

    // §3 step 3: chain[0].issuer MUST equal delegator (A).
    if &chain[0].issuer != ctx.verifier_aid {
        return Err(DelegationError::InvalidGrantProof);
    }

    // §3 step 5: JTI uniqueness within `chain` (collision-space defense).
    {
        let mut seen = std::collections::HashSet::new();
        for step in chain {
            if !seen.insert(step.source_tct_jti) {
                return Err(DelegationError::ChainHashMismatch);
            }
        }
    }

    // Token expiry; outer expires_at is in the future and bounded by
    // grant_proof (the most-recent hop).
    if token.expires_at.is_in_the_past(ctx.now) {
        return Err(DelegationError::Expired);
    }

    // §3 step 4: per-hop expiry monotonicity. expires_at MUST be in
    // the future at every hop and MUST be non-increasing across hops.
    let mut prior_expires = chain[0].expires_at;
    if chain[0].expires_at.is_in_the_past(ctx.now) {
        return Err(DelegationError::Expired);
    }
    for step in &chain[1..] {
        if step.expires_at.is_in_the_past(ctx.now) {
            return Err(DelegationError::Expired);
        }
        if step.expires_at.0 > prior_expires.0 {
            return Err(DelegationError::Expired);
        }
        prior_expires = step.expires_at;
    }
    if token.grant_proof.expires_at.is_in_the_past(ctx.now) {
        return Err(DelegationError::Expired);
    }
    if token.grant_proof.expires_at.0 > prior_expires.0 {
        return Err(DelegationError::Expired);
    }
    if token.expires_at.0 > token.grant_proof.expires_at.0 {
        return Err(DelegationError::Expired);
    }

    // §3 step 2: audience continuity. The chain forms an unbroken
    // authority lineage from the delegator (chain[0].issuer) to the
    // outer signer (chain[n-2].subject). The top-level grant_proof
    // is the *final* hop — the step where issued_by authorizes the
    // delegatee to exercise the granted scope. So:
    //
    //   - chain[i].subject == chain[i+1].issuer for i < n-2
    //   - chain[n-2].subject == grant_proof.issuer == token.issued_by
    //   - grant_proof.subject == token.delegatee
    //
    // Note: this differs from single-hop, where grant_proof IS the
    // peer-issued source TCT and grant_proof.subject == issued_by
    // (RFC-AITP-0006). For multi-hop, grant_proof is a
    // DelegationStep that carries the *final* hop, so its `subject`
    // is the delegatee, not the issued_by.
    for w in chain.windows(2) {
        if w[0].subject != w[1].issuer {
            return Err(DelegationError::InvalidGrantProof);
        }
    }
    if chain[chain.len() - 1].subject != token.grant_proof.issuer {
        return Err(DelegationError::InvalidGrantProof);
    }
    if token.grant_proof.issuer != token.issued_by {
        return Err(DelegationError::InvalidGrantProof);
    }
    if token.grant_proof.subject != token.delegatee {
        return Err(DelegationError::InvalidGrantProof);
    }

    // Self-delegation forbidden at the outer hop.
    if token.issued_by == token.delegatee {
        return Err(DelegationError::SelfDelegation);
    }

    // §3 step 1: per-hop signature verification.
    // Hop 0: source TCT projection (same as v0.1 single-hop).
    verify_source_tct_projection(&chain[0], &chain[0].subject)?;
    // Hops 1..n-2 (== chain[1..]): signed step body.
    for step in &chain[1..] {
        verify_step_signature(step)?;
    }
    // Most-recent hop (top-level grant_proof): signed step body.
    verify_step_signature(&token.grant_proof)?;

    // §4: transitive scope subsetting.
    // chain[0].capabilities ⊇ chain[1].capabilities ⊇ ... ⊇
    // grant_proof.capabilities ⊇ token.scope.
    let mut prior_caps: &[String] = &chain[0].capabilities;
    for step in &chain[1..] {
        if !is_subset(&step.capabilities, prior_caps) {
            return Err(DelegationError::ScopeExceeded);
        }
        prior_caps = &step.capabilities;
    }
    if !is_subset(&token.grant_proof.capabilities, prior_caps) {
        return Err(DelegationError::ScopeExceeded);
    }
    if !is_subset(&token.scope, &token.grant_proof.capabilities) {
        return Err(DelegationError::ScopeExceeded);
    }

    // §6: per-hop revocation. Every hop's source_tct_jti (chain[*] +
    // grant_proof) is consulted.
    if let Some(check) = ctx.revocation_check {
        for step in chain {
            if check(&step.source_tct_jti) {
                return Err(DelegationError::SourceTctRevoked);
            }
        }
        if check(&token.grant_proof.source_tct_jti) {
            return Err(DelegationError::SourceTctRevoked);
        }
    }

    // §5: chain_hash truncation defense. Recompute and compare.
    let stated_hash = token
        .chain_hash
        .as_deref()
        .ok_or(DelegationError::ChainHashMismatch)?;
    let recomputed = compute_chain_hash(chain)?;
    if recomputed != stated_hash {
        return Err(DelegationError::ChainHashMismatch);
    }

    // Outer signature covers chain_hash via the signing view.
    let issued_by_pubkey = AitpVerifyingKey::from_aid(&token.issued_by)?;
    let outer_view = DelegationSigningView {
        delegator: &token.delegator,
        delegatee: &token.delegatee,
        issued_by: &token.issued_by,
        audience: &token.audience,
        scope: &token.scope,
        expires_at: &token.expires_at,
        cnf: &token.cnf,
        grant_proof: &token.grant_proof,
        chain: Some(chain),
        chain_hash: Some(stated_hash),
    };
    let canonical = jcs::canonicalize_serializable(&outer_view)
        .map_err(|e| DelegationError::Canonicalization(e.to_string()))?;
    let digest = Sha256::digest(&canonical);
    let outer_sig =
        Signature::parse(&token.signature).map_err(|_| DelegationError::InvalidSignature)?;
    issued_by_pubkey
        .verify(&digest, &outer_sig)
        .map_err(|_| DelegationError::InvalidSignature)?;

    // cnf well-formedness.
    let cnf_bytes =
        base64url::decode_strict(&token.cnf).map_err(|_| DelegationError::CnfMalformed)?;
    if cnf_bytes.len() != 32 {
        return Err(DelegationError::CnfMalformed);
    }

    Ok(token)
}

fn is_subset(needle: &[String], haystack: &[String]) -> bool {
    needle.iter().all(|c| haystack.contains(c))
}

/// Hop-0 / single-hop case: the step is a projection of a source TCT,
/// and `step.signature` is reused verbatim from the source TCT. The
/// verifier reconstructs the source TCT body and checks the signature
/// against the issuer's pubkey.
///
/// `subject_for_binding` is the AID whose pubkey appears as the source
/// TCT's `binding.cnf` — for single-hop this is `delegation.issued_by`,
/// for multi-hop hop 0 it is `chain[0].subject`.
fn verify_source_tct_projection(
    proj: &GrantProof,
    subject_for_binding: &Aid,
) -> Result<(), DelegationError> {
    let issuer_pubkey = AitpVerifyingKey::from_aid(&proj.issuer)?;
    let cnf_bytes = subject_for_binding.to_ed25519_bytes();
    let cnf = base64url::encode(&cnf_bytes);
    let source_view = SourceTctView {
        version: "aitp/0.1",
        jti: &proj.source_tct_jti,
        issuer: &proj.issuer,
        subject: &proj.subject,
        // v0.1: TCT.audience == TCT.subject.
        audience: &proj.subject,
        issued_at: &proj.issued_at,
        expires_at: &proj.expires_at,
        grants: &proj.capabilities,
        binding: SourceTctBinding { cnf: &cnf },
    };
    let canonical = jcs::canonicalize_serializable(&source_view)
        .map_err(|e| DelegationError::Canonicalization(e.to_string()))?;
    let digest = Sha256::digest(&canonical);
    let sig = Signature::parse(&proj.signature).map_err(|_| DelegationError::InvalidGrantProof)?;
    issuer_pubkey
        .verify(&digest, &sig)
        .map_err(|_| DelegationError::InvalidGrantProof)?;
    Ok(())
}

/// Hops i > 0 / top-level grant_proof in multi-hop: the step signature
/// is the issuer's signature over the canonical step body excluding
/// `signature`.
fn verify_step_signature(step: &DelegationStep) -> Result<(), DelegationError> {
    let issuer_pubkey = AitpVerifyingKey::from_aid(&step.issuer)?;
    let view = StepSigningView {
        issuer: &step.issuer,
        subject: &step.subject,
        capabilities: &step.capabilities,
        issued_at: &step.issued_at,
        expires_at: &step.expires_at,
        source_tct_jti: &step.source_tct_jti,
    };
    let canonical = jcs::canonicalize_serializable(&view)
        .map_err(|e| DelegationError::Canonicalization(e.to_string()))?;
    let digest = Sha256::digest(&canonical);
    let sig = Signature::parse(&step.signature).map_err(|_| DelegationError::InvalidGrantProof)?;
    issuer_pubkey
        .verify(&digest, &sig)
        .map_err(|_| DelegationError::InvalidGrantProof)?;
    Ok(())
}

/// `base64url(sha256(canonical_json([chain[i].source_tct_jti for i in
/// 0..chain.len()])))`. RFC-AITP-0011 §5.
pub fn compute_chain_hash(chain: &[DelegationStep]) -> Result<String, DelegationError> {
    let jtis: Vec<String> = chain.iter().map(|s| s.source_tct_jti.to_string()).collect();
    let canonical = jcs::canonicalize_serializable(&jtis)
        .map_err(|e| DelegationError::Canonicalization(e.to_string()))?;
    let digest = Sha256::digest(&canonical);
    Ok(base64url::encode(&digest))
}

/// JCS canonicalization view for hops i > 0 (RFC-AITP-0011 §3 step 1
/// second bullet). The body is the DelegationStep excluding `signature`.
#[derive(Serialize)]
struct StepSigningView<'a> {
    issuer: &'a Aid,
    subject: &'a Aid,
    capabilities: &'a [String],
    issued_at: &'a Timestamp,
    expires_at: &'a Timestamp,
    source_tct_jti: &'a Uuid,
}

/// View struct for reconstructing the source TCT body so we can verify
/// A's `grant_proof.signature` against the same JCS bytes A originally
/// signed.
#[derive(Serialize)]
struct SourceTctView<'a> {
    version: &'a str,
    jti: &'a Uuid,
    issuer: &'a Aid,
    subject: &'a Aid,
    audience: &'a Aid,
    issued_at: &'a Timestamp,
    expires_at: &'a Timestamp,
    grants: &'a [String],
    binding: SourceTctBinding<'a>,
}

#[derive(Serialize)]
struct SourceTctBinding<'a> {
    cnf: &'a str,
}

#[allow(dead_code)] // re-exported via lib.rs for consumers.
fn _gp_unused(_: &GrantProof) {}
