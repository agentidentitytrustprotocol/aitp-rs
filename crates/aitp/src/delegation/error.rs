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
    /// Revocation status could not be determined and the source fails
    /// closed (RFC-AITP-0008 §3.1). Same wire code as
    /// [`Self::SourceTctRevoked`], but the reason says the source was
    /// unavailable, not that the token was revoked.
    #[error("revocation source unavailable: {0}")]
    RevocationUnavailable(String),
    /// Outer signature did not verify.
    #[error("delegation signature is invalid")]
    InvalidSignature,
    /// A delegation issuer's key could not be resolved from its Manifest
    /// (RFC-AITP-0006 §4 step 1 for the single-hop token, RFC-AITP-0011
    /// §3 step 1 for every multi-hop hop): no Manifest source configured
    /// or none for this issuer ([`crate::manifest::ManifestError::NotFound`]),
    /// the Manifest failed RFC-AITP-0003 §5 verification, or it does not
    /// designate the hop's `iss` ([`crate::manifest::ManifestError::AidMismatch`]).
    /// Wire code `KEY_RESOLUTION_FAILED` (RFC-AITP-0007 §1), retryable.
    #[error("key resolution failed for delegation issuer {issuer}: {source}")]
    KeyResolutionFailed {
        /// The token's (or hop's) claimed issuer.
        issuer: crate::core::Aid,
        /// Why no usable Manifest was obtained.
        source: crate::manifest::ManifestError,
    },
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
    /// claim, or an RFC-AITP-0011 `jti` or `chain_hash` claim.
    #[error("delegation claims malformed: {0}")]
    ClaimsMalformed(String),
    /// Token carries a `chain` claim (RFC-AITP-0011 multi-hop), which
    /// single-hop verification rejects structurally (RFC-AITP-0006 §4).
    #[error("multi-hop delegation is not supported")]
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
    /// Crypto error.
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
    /// A member outside the schema-declared member set was found on a
    /// closed object — the outer delegation claims, or the embedded
    /// grant voucher's claims, carried a field neither schema defines
    /// and which is not inside `ext` (RFC-AITP-0001 §7). Checked on the
    /// unverified payload peek, ahead of AID-pinned `alg` checking and
    /// signature verification. Maps to the **core** `UNKNOWN_FIELD`
    /// code, not `DELEGATION_INVALID_VOUCHER` / an `INVALID_ENVELOPE`
    /// draft code, even though delegation itself is a draft-RFC surface.
    #[error("unknown field: {0}")]
    UnknownField(String),
}
