//! Delegation error type.

/// Errors from delegation token issuance and verification.
#[derive(Debug, thiserror::Error)]
pub enum DelegationError {
    /// `audience` did not equal verifier's AID, or `delegator` did not
    /// equal verifier's AID.
    #[error("delegation audience mismatch")]
    AudienceMismatch,
    /// `scope` contains capabilities outside `grant_proof.capabilities`.
    #[error("delegation scope exceeds grant proof capabilities")]
    ScopeExceeded,
    /// `grant_proof.signature` invalid, or `grant_proof.subject !=
    /// delegation.issued_by`, or `grant_proof.issuer != verifier_aid`.
    #[error("grant proof is invalid")]
    InvalidGrantProof,
    /// `grant_proof.source_tct_jti` is in the issuer's deny list.
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
    /// `cnf` is not valid base64url, does not decode to the algorithm-
    /// agile compressed pubkey shape (32 B Ed25519 raw or 33 B SEC1-
    /// compressed P-256), or does not match the pubkey bytes embedded
    /// in the delegatee AID.
    #[error("delegation cnf is malformed")]
    CnfMalformed,
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
