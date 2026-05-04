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
    /// `binding.cnf` malformed (not 43-char base64url decoding to 32 bytes).
    #[error("delegation cnf is malformed")]
    CnfMalformed,
    /// Token attempts multi-hop, which v0.1 does not support.
    #[error("multi-hop delegation is not supported in v0.1")]
    MultihopNotSupported,
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
