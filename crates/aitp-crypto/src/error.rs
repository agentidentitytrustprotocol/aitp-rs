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
}
