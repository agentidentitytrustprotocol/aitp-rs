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
    ///
    /// This covers proof-shaped failures: a malformed/expired JWT, a
    /// `kid` that doesn't match any resolved candidate key, an `alg`
    /// mismatch against the resolved key, an invalid signature, or any
    /// other claim check. It does NOT cover the issuer's key being
    /// unresolvable in the first place — see [`Self::KeyResolutionFailed`]
    /// for that distinct, retryable case.
    #[error("identity verification failed: {0}")]
    Identity(String),
    /// The issuer's signing key could not be resolved at all — the JWKS
    /// endpoint was unreachable or returned malformed data, or
    /// resolution otherwise produced zero candidate keys for the
    /// issuer. Distinct from [`Self::Identity`] per RFC-AITP-0001 §5.4.3
    /// and RFC-AITP-0007 §3 (`fail_closed`): this failure is in
    /// *reaching/resolving* the key material, which may clear on retry,
    /// so it reports the retryable `KEY_RESOLUTION_FAILED` wire code
    /// rather than the non-retryable `IDENTITY_FAILED` family. Once
    /// candidate keys DO exist for the issuer, a `kid`/`alg` mismatch or
    /// bad signature is a proof defect that will never succeed on
    /// retry, and stays `Identity`.
    #[error("issuer key resolution failed for {issuer}: {reason}")]
    KeyResolutionFailed {
        /// The OIDC issuer whose key(s) could not be resolved.
        issuer: String,
        /// The underlying resolution failure (e.g. the [`ResolveError`]
        /// display string).
        ///
        /// [`ResolveError`]: crate::identity_oidc::ResolveError
        reason: String,
    },
    /// `pop_nonce_echo` did not match own previously sent nonce.
    #[error("nonce mismatch")]
    NonceMismatch,
    /// Peer's PoP signature did not verify.
    #[error("pop signature verification failed")]
    PopVerificationFailed,
    /// Peer-issued TCT did not satisfy own `required_peer_capabilities`.
    #[error("insufficient grants in peer-issued TCT")]
    InsufficientGrants,
    /// Peer-issued TCT grants a capability outside the issuer's own
    /// `offered_capabilities` (RFC-AITP-0004 §5.3/§5.4 step 4 ⇒
    /// `GRANT_OVERFLOW`). The TCT claims more authority than the issuing
    /// peer's Manifest advertises.
    #[error("peer-issued TCT grants exceed the issuer's offered_capabilities")]
    GrantOverflow,
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
    /// A JSON member outside a handshake payload's declared member set
    /// (RFC-AITP-0001 §7), or inside a nested closed object (e.g.
    /// `identity`) recovered via `aitp_core::from_serde_error`.
    #[error("unknown field: {0}")]
    UnknownField(String),
}
