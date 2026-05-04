//! Delegation token verification (RFC-AITP-0006 §4).

use crate::builder::DelegationSigningView;
use crate::types::{DelegationToken, GrantProof};
use crate::DelegationError;
use aitp_core::{base64url, jcs, Aid, Timestamp};
use aitp_crypto::{AitpVerifyingKey, Signature};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Inputs for verifying a delegation token.
pub struct VerifyDelegationContext<'a> {
    /// The verifier's own AID (A).
    pub verifier_aid: &'a Aid,
    /// Current time, for expiry checks.
    pub now: Timestamp,
    /// Optional revocation lookup against the verifier's deny list. Returns
    /// `true` if the source TCT is revoked.
    pub revocation_check: Option<&'a dyn Fn(&Uuid) -> bool>,
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
    let issuer_pubkey = AitpVerifyingKey::from_aid(ctx.verifier_aid)?;
    let source_view = SourceTctView {
        version: "aitp/0.1",
        jti: &token.grant_proof.source_tct_jti,
        issuer: &token.grant_proof.issuer,
        subject: &token.grant_proof.subject,
        // v0.1: TCT.audience == TCT.subject.
        audience: &token.grant_proof.subject,
        // RFC-AITP-0006 §3.1 (rc.2): `issued_at` is REQUIRED on
        // grant_proof and copied verbatim from the source TCT, so the
        // verifier can reconstruct A's exact signing input without
        // guessing the TTL.
        issued_at: &token.grant_proof.issued_at,
        expires_at: &token.grant_proof.expires_at,
        grants: &token.grant_proof.capabilities,
        binding: SourceTctBinding {
            cnf: &binding_cnf_for_source(token)?,
        },
    };
    let canonical = jcs::canonicalize_serializable(&source_view)
        .map_err(|e| DelegationError::Canonicalization(e.to_string()))?;
    let digest = Sha256::digest(&canonical);
    let gp_sig = Signature::parse(&token.grant_proof.signature)
        .map_err(|_| DelegationError::InvalidGrantProof)?;
    issuer_pubkey
        .verify(&digest, &gp_sig)
        .map_err(|_| DelegationError::InvalidGrantProof)?;

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

fn binding_cnf_for_source(token: &DelegationToken) -> Result<String, DelegationError> {
    // The `binding.cnf` of A's source TCT to B is the base64url-encoding of
    // B's public key. B is `delegation.issued_by`, so we read its pubkey
    // from the AID.
    let pk_bytes = token.issued_by.to_ed25519_bytes();
    Ok(base64url::encode(&pk_bytes))
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
