//! TCT-specific error type.

/// Errors from TCT issuance and verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TctError {
    /// Version is not supported by this implementation.
    #[error("TCT version is not supported")]
    VersionUnknown,
    /// Signature did not verify against issuer's public key.
    #[error("TCT signature is invalid")]
    SignatureInvalid,
    /// The verifying key supplied by the caller does not correspond to
    /// the key embedded in `tct.issuer`. RFC-AITP-0008 §3.3 requires
    /// verifiers to establish this issuer-key binding before consulting
    /// any revocation source; without it `tct.issuer` stays
    /// attacker-controlled even after a valid signature, enabling
    /// revocation evasion and steering of per-issuer revocation lookups.
    #[error("TCT issuer does not match the verifying key")]
    IssuerMismatch,
    /// `audience` did not equal expected audience or did not equal subject.
    #[error("TCT audience does not match")]
    AudienceMismatch,
    /// `expires_at` is in the past, or `issued_at` is in the future.
    #[error("TCT has expired or is not yet valid")]
    Expired,
    /// `expires_at` exceeds the issuer Manifest's `expires_at`.
    /// RFC-AITP-0004 §4.3 / RFC-AITP-0005 §9: a peer-issued TCT MUST
    /// NOT outlive the issuer's published Manifest. Verifiers that
    /// have resolved the issuer's Manifest MUST reject TCTs whose
    /// `expires_at` exceeds the Manifest's.
    #[error("TCT expires_at exceeds issuer Manifest expires_at")]
    ExpiresAfterManifest,
    /// `jti` appears in the issuer's deny list.
    #[error("TCT jti is revoked")]
    Revoked,
    /// `grants` is empty (forbidden by RFC-AITP-0004 §4.1).
    #[error("TCT grants must be non-empty")]
    EmptyGrants,
    /// One or more grant strings contain whitespace
    /// (forbidden by RFC-AITP-0005 §4.2).
    #[error("TCT grant must not contain whitespace: `{0}`")]
    GrantWhitespace(String),
    /// `binding.cnf` is not valid base64url, does not decode to the
    /// algorithm-agile compressed pubkey shape (32 B Ed25519 raw or
    /// 33 B SEC1-compressed P-256), or does not match the pubkey
    /// bytes embedded in the subject AID.
    #[error("TCT binding.cnf is malformed")]
    CnfMalformed,
    /// Builder was missing a required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// Canonicalization failed.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
    /// PoP nonce echo mismatch (RFC-AITP-0005 §6.2 step 2).
    #[error("PoP nonce echo mismatch")]
    PopNonceMismatch,
    /// PoP signature failed verification.
    #[error("PoP signature failed")]
    PopFailed,
    /// PoP challenge expired.
    #[error("PoP challenge expired")]
    PopChallengeExpired,
    /// PoP response references a different jti than the challenge.
    #[error("PoP response jti mismatch")]
    PopJtiMismatch,
    /// Crypto error.
    #[error(transparent)]
    Crypto(#[from] aitp_crypto::CryptoError),
}
