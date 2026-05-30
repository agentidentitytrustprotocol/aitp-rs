//! Manifest error type.

/// Errors from Manifest issuance and verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestError {
    /// `expires_at` is in the past.
    #[error("manifest has expired")]
    Expired,
    /// Outer signature failed verification.
    #[error("manifest signature is invalid")]
    SignatureInvalid,
    /// PoP signature failed verification.
    #[error("manifest proof-of-possession failed")]
    PopFailed,
    /// `aid` field does not match the key used to sign.
    #[error("manifest aid does not match signing key")]
    AidMismatch,
    /// Peer's `accepted_identity_types` does not include the type we
    /// would present (RFC-AITP-0003 §3.2 / §5 step 5). Surfaces as
    /// `INCOMPATIBLE_IDENTITY_TYPE` to the caller. An absent field
    /// defaults to `["oidc"]`; an explicitly empty list rejects every
    /// peer (RFC clarification, post-rc.1).
    #[error("manifest does not accept identity type `{0}`")]
    IncompatibleIdentityType(&'static str),
    /// Version is not supported by this implementation.
    #[error("manifest version is not supported")]
    VersionUnknown,
    /// `identity_hint` shape is wrong (missing `issuer` for OIDC, missing
    /// `public_key` for pinned, etc.).
    #[error("identity_hint malformed: {0}")]
    IdentityHintMalformed(&'static str),
    /// Builder was missing a required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// Canonicalization failed.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
    /// Crypto error.
    #[error(transparent)]
    Crypto(#[from] aitp_crypto::CryptoError),
    /// Source of randomness for the PoP challenge failed.
    #[error("rng failure: {0}")]
    Rng(String),
}
