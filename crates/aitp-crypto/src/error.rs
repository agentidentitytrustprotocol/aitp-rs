//! Crypto error type.

/// Errors returned by signing, verifying, and key parsing operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// Signature verification returned a cryptographic failure.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// Signature string was not valid base64url or wrong length.
    #[error("signature parsing failed: {0}")]
    SignatureMalformed(String),

    /// Public key bytes could not be parsed as an Ed25519 key.
    #[error("public key parsing failed: {0}")]
    KeyParseFailed(String),

    /// AID identifier did not decode to a valid 32-byte Ed25519 key.
    #[error("AID does not yield a valid Ed25519 public key: {0}")]
    AidNotEd25519(String),

    /// Compact-JWS header `alg` is not the sole value derived from the
    /// signer's AID (RFC-AITP-0001 §5.4.5). Includes `none` in any
    /// capitalization and unknown algorithms. Wire code:
    /// `TOKEN_ALG_MISMATCH`.
    #[error("JWS alg header does not match the signer AID's algorithm: {0}")]
    AlgMismatch(String),

    /// Compact-JWS header `typ` does not exactly match the value
    /// expected for the verification context (RFC-AITP-0001 §5.4.5).
    /// Wire code: `TOKEN_TYP_MISMATCH`.
    #[error("JWS typ header mismatch: expected {expected}, got {got}")]
    TypMismatch {
        /// The `typ` value required by the verification context.
        expected: String,
        /// The `typ` value found in the protected header.
        got: String,
    },

    /// Compact JWS failed strict parsing (RFC-AITP-0001 §5.4.5):
    /// wrong segment count, empty segment, non-base64url characters,
    /// padding, or a malformed protected header.
    #[error("compact JWS malformed: {0}")]
    JwsMalformed(String),
}
