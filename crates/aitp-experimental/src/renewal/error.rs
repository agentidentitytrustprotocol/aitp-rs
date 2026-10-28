//! TCT renewal error types.

use aitp::core::nonce_store::NonceStoreError;
use aitp::core::ErrorCode;
use aitp::crypto::CryptoError;
use aitp::tct::TctError;

/// Why the issuer refused a renewal request, or the holder could not
/// build one (RFC-AITP-0013 §3, §4).
///
/// Every check shared with TCT verification reports through
/// [`RenewalError::Tct`]; the variants here are the renewal checks.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RenewalError {
    /// The request body is not a JSON object with exactly
    /// `current_tct`, `pop_nonce` and `pop_signature`, each a string
    /// (§4 step 1). Wire code `POP_RESPONSE_INVALID`.
    #[error("renewal request malformed: {0}")]
    RequestMalformed(String),
    /// `pop_nonce` is not 22 unpadded base64url characters decoding to
    /// 16 bytes (§4 step 1). Wire code `POP_RESPONSE_INVALID`.
    #[error("renewal pop_nonce malformed: {0}")]
    NonceMalformed(String),
    /// `pop_nonce` was already used to renew a TCT from this issuer.
    /// Wire code `REPLAY_DETECTED`.
    #[error("renewal pop_nonce already used (replay)")]
    Replayed,
    /// No grant survives the grant-policy re-evaluation (§4 step 6).
    /// Wire code `POLICY_VIOLATION`.
    #[error("no grant survives renewal policy re-evaluation")]
    GrantsWithdrawn,
    /// The replay guard's nonce store refused or failed. A local fault
    /// ([`Self::is_local_fault`]).
    #[error("renewal nonce store: {0}")]
    NonceStore(#[source] NonceStoreError),
    /// A TCT check: the presented TCT failed verification (§4 step 2),
    /// the PoP failed ([`TctError::PopFailed`]), the TCT is revoked
    /// ([`TctError::Revoked`]), or signing failed.
    #[error(transparent)]
    Tct(#[from] TctError),
    /// The issuer could not sign its response envelope.
    #[error("renewal response envelope: {0}")]
    Envelope(#[from] aitp::envelope::EnvelopeError),
}

impl RenewalError {
    /// The registered code (RFC-AITP-0013 §4, §8). A local fault
    /// ([`Self::is_local_fault`]) is answered with a retryable error,
    /// not this code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::RequestMalformed(_) | Self::NonceMalformed(_) => ErrorCode::PopResponseInvalid,
            Self::Replayed => ErrorCode::ReplayDetected,
            Self::GrantsWithdrawn => ErrorCode::PolicyViolation,
            Self::NonceStore(_) => ErrorCode::InvalidEnvelope,
            Self::Tct(e) => tct_error_code(e),
            Self::Envelope(_) => ErrorCode::InvalidEnvelope,
        }
    }

    /// Whether this is the issuer's own fault: its nonce store, its
    /// signer or its response envelope failing.
    pub fn is_local_fault(&self) -> bool {
        matches!(
            self,
            Self::NonceStore(_)
                | Self::Envelope(_)
                | Self::Tct(TctError::Crypto(CryptoError::Signer(_)))
        )
    }
}

/// The registered code for a TCT check failing during renewal.
pub(crate) fn tct_error_code(err: &TctError) -> ErrorCode {
    match err {
        TctError::PopFailed => ErrorCode::PopResponseInvalid,
        TctError::Revoked | TctError::RevocationUnavailable(_) => ErrorCode::TctRevoked,
        TctError::SafeSubsetEmpty => ErrorCode::PolicyViolation,
        TctError::Expired => ErrorCode::TctExpired,
        TctError::ExpiresAfterManifest => ErrorCode::TctExpiresAfterManifest,
        TctError::UnknownField(_) => ErrorCode::UnknownField,
        TctError::VersionUnknown => ErrorCode::UnknownVersion,
        TctError::ClaimsMalformed(_)
        | TctError::MissingField(_)
        | TctError::CnfMalformed
        | TctError::EmptyGrants
        | TctError::GrantWhitespace(_)
        | TctError::Crypto(CryptoError::JwsMalformed(_)) => ErrorCode::InvalidEnvelope,
        TctError::Crypto(CryptoError::AlgMismatch(_)) => ErrorCode::TokenAlgMismatch,
        TctError::Crypto(CryptoError::TypMismatch { .. }) => ErrorCode::TokenTypMismatch,
        // Signature, issuer pin (a TCT this issuer did not sign), `aud`
        // other than `sub`, `jti` layout, self-issued or attestation
        // marker: not a TCT this issuer issued (§4 step 2).
        _ => ErrorCode::TctSignatureInvalid,
    }
}

/// Why the holder rejected a renewal response (RFC-AITP-0013 §6.1).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RenewalResponseError {
    /// Step 1: the envelope or its payload is malformed, or its
    /// `message_type` is neither `tct` nor `error`.
    #[error("invalid renewal response envelope: {0}")]
    InvalidEnvelope(String),
    /// Step 1: the payload carries a member outside its schema.
    #[error("unknown field: {0}")]
    UnknownField(String),
    /// Step 1: the envelope timestamp is outside the window.
    #[error("renewal response timestamp outside the window")]
    TimestampExpired,
    /// Step 1: the envelope signature does not verify under its sender.
    #[error("renewal response signature invalid")]
    InvalidSignature,
    /// Step 2: the sender is not the current TCT's issuer.
    #[error("renewal response sender is not the current TCT's issuer")]
    PeerMismatch,
    /// Step 3: `pop_nonce_echo` is not the nonce the holder sent.
    #[error("renewal response pop_nonce_echo does not match the request")]
    NonceMismatch,
    /// Step 4: the renewed TCT fails RFC-AITP-0005 §7.2, or the current
    /// TCT the holder supplied cannot be read.
    #[error("renewed TCT: {0}")]
    Tct(#[source] TctError),
    /// Step 5: the renewed TCT's `sub` or `cnf.jkt` is not the holder's.
    #[error("renewed TCT subject is not the holder")]
    AudienceMismatch,
    /// Step 6: the renewed TCT carries a grant the current one does not.
    #[error("renewed TCT carries a grant the current TCT does not")]
    GrantOverflow,
    /// The issuer refused the renewal with an `error` envelope that
    /// passed steps 1 and 2.
    #[error("issuer refused renewal: {code:?}: {reason}")]
    Refused {
        /// The code the issuer sent.
        code: ErrorCode,
        /// The issuer's informational text.
        reason: String,
        /// Whether the issuer marked the failure retryable.
        retryable: bool,
    },
}

impl RenewalResponseError {
    /// The registered code (RFC-AITP-0013 §8). For [`Self::Refused`],
    /// the issuer's code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidEnvelope(_) => ErrorCode::InvalidEnvelope,
            Self::UnknownField(_) => ErrorCode::UnknownField,
            Self::TimestampExpired => ErrorCode::TimestampExpired,
            Self::InvalidSignature => ErrorCode::InvalidSignature,
            Self::PeerMismatch => ErrorCode::PeerMismatch,
            Self::NonceMismatch => ErrorCode::NonceMismatch,
            Self::Tct(TctError::AudienceMismatch) => ErrorCode::AudienceMismatch,
            Self::Tct(e) => tct_error_code(e),
            Self::AudienceMismatch => ErrorCode::AudienceMismatch,
            Self::GrantOverflow => ErrorCode::GrantOverflow,
            Self::Refused { code, .. } => *code,
        }
    }
}
