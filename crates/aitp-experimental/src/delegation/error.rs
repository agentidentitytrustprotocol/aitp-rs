//! Multi-hop delegation error type.

use aitp::delegation::DelegationError;

/// Errors from multi-hop delegation issuance and verification.
///
/// Every check shared with single-hop delegation reports through
/// [`ChainedDelegationError::Delegation`]; the variants here are the
/// RFC-AITP-0011 checks single-hop does not have.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChainedDelegationError {
    /// A check shared with single-hop delegation (RFC-AITP-0006 §4).
    #[error(transparent)]
    Delegation(#[from] DelegationError),
    /// `total_hops = chain.len() + 2` exceeds the verifier's configured
    /// `max_delegation_hops` (RFC-AITP-0011 §2). Wire code
    /// `DELEGATION_HOP_LIMIT_EXCEEDED`.
    #[error("delegation hop limit exceeded")]
    HopLimitExceeded,
    /// `chain` is non-empty but `chain_hash` was missing or did not
    /// match the recomputed hash over `chain` (RFC-AITP-0011 §5). Wire
    /// code `DELEGATION_CHAIN_HASH_MISMATCH`.
    #[error("delegation chain_hash mismatch")]
    ChainHashMismatch,
    /// A hop's `jti` (the outer token's, or any `chain[]` entry's) is
    /// not in the strict lowercase hyphenated UUID v4 layout
    /// (RFC-AITP-0011 §1.1, RFC-AITP-0005 §2). Checked on the unverified
    /// payload, before signature verification, and also raised by the
    /// builder. Wire code `DELEGATION_INVALID_SIGNATURE`.
    #[error("delegation hop jti is not a UUID v4: {0}")]
    JtiNotV4(aitp::core::ids::V4Error),
    /// JCS canonicalization of the chain digests failed.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
}
