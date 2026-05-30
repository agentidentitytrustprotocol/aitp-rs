//! Handshake error type.

/// Errors from running the Mutual Handshake.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HandshakeError {
    /// Envelope-level rejection (sender mismatch, bad timestamp, replay).
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
    /// Envelope signature did not verify.
    #[error("envelope signature invalid")]
    InvalidSignature,
    /// Peer's identity issuer is not in own `trust_anchors`.
    #[error("incompatible trust anchors")]
    IncompatibleTrustAnchors,
    /// Peer's Manifest could not be verified.
    #[error("manifest verification failed: {0}")]
    Manifest(#[from] aitp_manifest::ManifestError),
    /// Peer's identity proof did not verify.
    #[error("identity verification failed: {0}")]
    Identity(String),
    /// `pop_nonce_echo` did not match own previously sent nonce.
    #[error("nonce mismatch")]
    NonceMismatch,
    /// Peer's PoP signature did not verify.
    #[error("pop signature verification failed")]
    PopVerificationFailed,
    /// Peer-issued TCT did not satisfy own `required_peer_capabilities`.
    #[error("insufficient grants in peer-issued TCT")]
    InsufficientGrants,
    /// Peer-issued TCT failed verification.
    #[error("TCT verification failed: {0}")]
    Tct(#[from] aitp_tct::TctError),
    /// Crypto failure.
    #[error(transparent)]
    Crypto(#[from] aitp_crypto::CryptoError),
    /// State-machine ordering violation (e.g. `on_commit_ack` called before
    /// `on_hello_ack`).
    #[error("handshake state error: {0}")]
    State(&'static str),
    /// Source of randomness for nonces failed.
    #[error("rng failure: {0}")]
    Rng(String),
    /// Empty grant intersection — RFC-AITP-0004 §4.1 forbids issuing.
    #[error("policy denies handshake (empty grant intersection)")]
    PolicyViolation,
    /// JCS canonicalization failure.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
}
