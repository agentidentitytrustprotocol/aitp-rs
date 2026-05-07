//! Session Trust Bundle errors (RFC-AITP-0010 §7 / `BUNDLE_*` codes
//! tracked in `agentidentitytrustprotocol/plans/v0.2-conformance-followups.md`).

/// Errors from session-bundle construction and verification.
#[derive(Debug, thiserror::Error)]
pub enum SessionBundleError {
    /// `version` field was not `"aitp/0.1"`.
    #[error("bundle version mismatch")]
    VersionMismatch,
    /// Outer bundle signature failed to verify against the
    /// coordinator's pubkey.
    #[error("bundle signature is invalid")]
    InvalidSignature,
    /// Bundle's `expires_at` is in the past.
    #[error("bundle has expired")]
    Expired,
    /// `expires_at` did not equal `min(participants[*].tct.expires_at)`
    /// (RFC-AITP-0010 §6).
    #[error("bundle expires_at does not equal min(participant TCT expiries)")]
    ExpiryWindowInvariant,
    /// At least one participant TCT had a different `issuer` from the
    /// bundle's `coordinator`.
    #[error("participant TCT issuer does not match coordinator")]
    CoordinatorIssuerMismatch,
    /// At least one participant TCT had `audience` ≠ the entry's
    /// declared `aid` (the bundle distributes participants' OWN TCTs
    /// back to them, so audience and entry.aid must match).
    #[error("participant TCT audience does not match entry AID")]
    AudienceMismatch,
    /// Verifier's AID is not present in `participants[]`.
    #[error("verifier is not a member of this bundle")]
    NotMember,
    /// Builder was missing a required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// Empty participants array — RFC-AITP-0010 §3 requires at least
    /// one entry.
    #[error("participants array is empty")]
    EmptyParticipants,
    /// JCS canonicalization failed.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
    /// TCT verification of an embedded participant TCT failed.
    #[error("participant TCT verification failed: {0}")]
    TctVerification(#[from] aitp_tct::TctError),
    /// Crypto error (e.g. malformed AID-derived key).
    #[error(transparent)]
    Crypto(#[from] aitp_crypto::CryptoError),
}
