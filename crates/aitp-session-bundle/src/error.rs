//! Session Trust Bundle errors (RFC-AITP-0010 §7 / `BUNDLE_*` codes
//! tracked in `agentidentitytrustprotocol/plans/v0.2-conformance-followups.md`).

/// Errors from session-bundle construction and verification.
#[derive(Debug, thiserror::Error)]
pub enum SessionBundleError {
    /// `version` field was not `"aitp/0.2"`.
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
    /// The wire form was structurally invalid before any cryptographic
    /// check could run: the `{"session_bundle": …}` transport wrapper
    /// carried a member besides `session_bundle` (the pre-erratum shape
    /// where `signature` sat as a SIBLING of the wrapper), or the inner
    /// body did not deserialize as a `SessionTrustBundle`.
    ///
    /// RFC-AITP-0010 §3 fixes `signature` as a member of the signed body,
    /// never a sibling of the wrapper, precisely because a bundle is
    /// redistributable and must carry its own proof across any hop that
    /// strips the transport wrapper (RFC-AITP-0001 §5.4.1). Maps to
    /// `SESSION_BUNDLE_INVALID`.
    #[error("session bundle wire form is invalid: {0}")]
    WireFormInvalid(String),
    /// A member outside the schema-declared member set was found on a
    /// closed object — the wrapper's shape was fine, but the object
    /// itself (the inner `session_bundle` body, or a nested closed
    /// object such as a `participants[]` entry) carries a field the
    /// schema does not define and which is not inside `extensions`.
    ///
    /// Distinct from [`SessionBundleError::WireFormInvalid`]: that
    /// variant is for the wrapper-level defect where `signature` sits
    /// beside `{"session_bundle": …}` instead of inside it
    /// (RFC-AITP-0010 §3). This variant is the RFC-AITP-0001 §7 /
    /// RFC-AITP-0010 §5 body-level check — checked ahead of any
    /// cryptographic work, including the coordinator key resolution used
    /// to verify the outer signature — and maps to the **core**
    /// `UNKNOWN_FIELD` code rather than a `BUNDLE_*` draft code, even
    /// though the session bundle artifact itself is draft.
    #[error("unknown field: {0}")]
    UnknownField(String),
}
