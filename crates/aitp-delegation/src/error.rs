//! Delegation error type.

/// Errors from delegation token issuance and verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DelegationError {
    /// `audience` did not equal verifier's AID, or `delegator` did not
    /// equal verifier's AID.
    #[error("delegation audience mismatch")]
    AudienceMismatch,
    /// `scope` contains capabilities outside `grant_proof.capabilities`.
    #[error("delegation scope exceeds grant proof capabilities")]
    ScopeExceeded,
    /// Embedded voucher JWS invalid, `voucher.iss` ≠ verifier's AID,
    /// `voucher.sub` ≠ the delegator-of-record, a missing/duplicate
    /// per-hop `jti`, a continuity break, or a nested-chain prefix
    /// inconsistency. Wire code `DELEGATION_INVALID_VOUCHER` (renamed
    /// in v0.2 from `DELEGATION_INVALID_GRANT_PROOF`).
    #[error("delegation voucher is invalid")]
    InvalidVoucher,
    /// `voucher.src_jti` (or a hop's `jti`) is in the relevant issuer's
    /// deny list.
    #[error("source TCT has been revoked")]
    SourceTctRevoked,
    /// Outer signature did not verify.
    #[error("delegation signature is invalid")]
    InvalidSignature,
    /// Token or grant proof has expired.
    #[error("delegation token or grant proof has expired")]
    Expired,
    /// Proof-of-possession verification failed.
    #[error("delegation PoP verification failed")]
    PopFailed,
    /// `cnf.jkt` does not equal the RFC 7638 thumbprint of the key
    /// encoded in the delegatee (`sub`) AID.
    #[error("delegation cnf is malformed")]
    CnfMalformed,
    /// `ver` claim is not a supported protocol version.
    #[error("delegation token version is not supported")]
    VersionUnknown,
    /// Decoded JWS payload did not deserialize as delegation claims —
    /// unknown claim outside `ext`, duplicate claim, missing required
    /// claim, or a claim not permitted in the current mode (e.g. `jti`
    /// without multi-hop opt-in).
    #[error("delegation claims malformed: {0}")]
    ClaimsMalformed(String),
    /// Token attempts multi-hop but the verifier was constructed with
    /// `max_hops = 0` (single-hop only).
    #[error("multi-hop delegation is not supported")]
    MultihopNotSupported,
    /// Chain length + 1 exceeds the verifier's configured `max_hops`
    /// (RFC-AITP-0011 §2). Default cap is 3.
    #[error("delegation hop limit exceeded")]
    HopLimitExceeded,
    /// `chain` is non-empty but `chain_hash` was missing or did not
    /// match the recomputed hash over `chain` (RFC-AITP-0011 §5,
    /// truncation defense).
    #[error("delegation chain_hash mismatch")]
    ChainHashMismatch,
    /// Self-delegation attempt (`issued_by == delegatee`).
    #[error("self-delegation is forbidden")]
    SelfDelegation,
    /// Empty scope (forbidden by schema `minItems: 1`).
    #[error("delegation scope must be non-empty")]
    EmptyScope,
    /// Builder was missing a required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// Canonicalization failed.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
    /// Crypto error.
    #[error(transparent)]
    Crypto(#[from] aitp_crypto::CryptoError),
}
