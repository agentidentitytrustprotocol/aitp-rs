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
    Manifest(#[from] crate::manifest::ManifestError),
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
        /// [`ResolveError`]: crate::handshake::identity_oidc::ResolveError
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
    Tct(#[from] crate::tct::TctError),
    /// Crypto failure.
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
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
    /// `identity`) recovered via `crate::core::from_serde_error`.
    #[error("unknown field: {0}")]
    UnknownField(String),
}

impl HandshakeError {
    /// The closest registered AITP wire error code for this failure, as
    /// the HTTP transport and the language bindings report it.
    pub fn error_code(&self) -> crate::core::ErrorCode {
        use crate::core::ErrorCode;
        use crate::tct::TctError;
        match self {
            Self::Identity(_) => ErrorCode::IdentityFailed,
            // RFC-AITP-0001 §5.4.3 / RFC-AITP-0007 §3: an unresolvable
            // issuer key is retryable and gets its own code, distinct from
            // a bad proof.
            Self::KeyResolutionFailed { .. } => ErrorCode::KeyResolutionFailed,
            // RFC-AITP-0005 §9: a peer-issued TCT can fail for distinct,
            // separately-registered reasons. Collapsing every TctError to
            // TCT_SIGNATURE_INVALID misreports a revoked or expired TCT to
            // the peer as a signature failure.
            Self::Tct(tct_err) => match tct_err {
                TctError::Revoked | TctError::RevocationUnavailable(_) => ErrorCode::TctRevoked,
                TctError::Expired => ErrorCode::TctExpired,
                TctError::ExpiresAfterManifest => ErrorCode::TctExpiresAfterManifest,
                _ => ErrorCode::TctSignatureInvalid,
            },
            // RFC-AITP-0003 §5 / issue #144: a wrapped ManifestError can fail
            // for distinct, separately-registered reasons. Collapsing every
            // variant to MANIFEST_SIGNATURE_INVALID misreports an expired,
            // PoP-failed, version-mismatched, or structurally-invalid
            // manifest as a signature failure. Mirrors the Self::Tct arm above.
            Self::Manifest(m) => {
                use crate::manifest::ManifestError;
                match m {
                    ManifestError::Expired => ErrorCode::ManifestExpired,
                    ManifestError::PopFailed => ErrorCode::ManifestPopFailed,
                    ManifestError::VersionUnknown => ErrorCode::ManifestVersionUnknown,
                    ManifestError::UnknownField(_) => ErrorCode::UnknownField,
                    ManifestError::Malformed(_) => ErrorCode::ManifestInvalid,
                    ManifestError::IncompatibleIdentityType(_) => {
                        ErrorCode::IncompatibleIdentityType
                    }
                    // A malformed Manifest `identity_hint` is a Manifest
                    // structural rejection (RFC-AITP-0003 §3.1, `man-006` /
                    // `man-007`), matching the conformance adapter (issue #179).
                    ManifestError::IdentityHintMalformed(_) => ErrorCode::ManifestInvalid,
                    // SignatureInvalid, AidMismatch, Crypto, Canonicalization,
                    // Rng, MissingField (builder-side only, unreachable from
                    // wire parsing) — and any future #[non_exhaustive] variant.
                    _ => ErrorCode::ManifestSignatureInvalid,
                }
            }
            Self::GrantOverflow => ErrorCode::GrantOverflow,
            Self::PolicyViolation => ErrorCode::PolicyViolation,
            Self::PopVerificationFailed => ErrorCode::PopVerificationFailed,
            Self::NonceMismatch => ErrorCode::NonceMismatch,
            Self::InsufficientGrants => ErrorCode::InsufficientGrants,
            Self::IncompatibleTrustAnchors => ErrorCode::IncompatibleTrustAnchors,
            Self::InvalidSignature => ErrorCode::InvalidSignature,
            Self::InvalidEnvelope(_)
            | Self::State(_)
            | Self::Rng(_)
            | Self::Canonicalization(_) => ErrorCode::InvalidEnvelope,
            // Our own signing backend failed: a local fault, never blamed on
            // the peer as a bad signature (`aitp::transport` also turns it
            // into HTTP 500).
            Self::Crypto(crate::crypto::CryptoError::Signer(_)) => ErrorCode::InvalidEnvelope,
            Self::Crypto(_) => ErrorCode::InvalidSignature,
            // RFC-AITP-0001 §7 / issue #140 Phase 7b: a dedicated core code.
            Self::UnknownField(_) => ErrorCode::UnknownField,
        }
    }
}
