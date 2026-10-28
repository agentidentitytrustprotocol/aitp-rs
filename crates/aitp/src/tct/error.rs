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
    /// The issuer's revocation status could not be determined (no
    /// revocation source, endpoint unreachable, or snapshot discarded
    /// per RFC-AITP-0008 §1.5) and the policy is `fail_closed`. Same
    /// `TCT_REVOKED` wire code as [`Self::Revoked`] (RFC-AITP-0008
    /// §3.1), but the detail says the `jti` was not found on a list.
    #[error(transparent)]
    RevocationUnavailable(crate::tct::RevocationUnavailable),
    /// `grants` is empty (forbidden by RFC-AITP-0004 §4.1).
    #[error("TCT grants must be non-empty")]
    EmptyGrants,
    /// One or more grant strings contain whitespace
    /// (forbidden by RFC-AITP-0005 §4.2).
    #[error("TCT grant must not contain whitespace: `{0}`")]
    GrantWhitespace(String),
    /// `cnf.jkt` does not equal the RFC 7638 thumbprint of the key
    /// encoded in the subject AID (RFC-AITP-0005 §3).
    #[error("TCT cnf.jkt does not match the subject key")]
    CnfMalformed,
    /// Decoded JWS payload did not deserialize as the artifact's claims
    /// object — unknown claim outside `ext`, duplicate claim, missing
    /// required claim, or a type mismatch (RFC-AITP-0001 §5.4.5 strict
    /// parsing). Also raised by
    /// [`crate::tct::parse_revocation_snapshot_wire`] for a
    /// residual deserialize failure on the JCS-profile revocation
    /// snapshot body (missing/mistyped member other than an unknown
    /// one) — the name predates that artifact, but the shape is the
    /// same: a body that doesn't match its declared schema.
    #[error("claims malformed: {0}")]
    ClaimsMalformed(String),
    /// A JSON member outside the artifact's schema-declared member set was
    /// present (RFC-AITP-0001 §7). Carries the offending member's name.
    /// Raised by [`crate::tct::parse_revocation_snapshot_wire`] for
    /// both the envelope and the inner `revocation_list` body.
    #[error("unknown field: {0}")]
    UnknownField(String),
    /// Builder was missing a required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// Canonicalization failed.
    #[error("canonicalization failed: {0}")]
    Canonicalization(#[source] crate::core::jcs::JcsError),
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
    /// `jti` (TCT) or `src_jti` (grant voucher) is not in the strict
    /// lowercase hyphenated UUID v4 layout (RFC-AITP-0005 §2, proposal
    /// #72 Item 6b). Wire code: `TCT_SIGNATURE_INVALID` for a TCT,
    /// `DELEGATION_INVALID_VOUCHER` for a voucher. Raised before
    /// signature verification. Also raised by
    /// [`crate::tct::parse_revocation_snapshot_wire`] for a
    /// non-v4 `entries[].jti`.
    #[error("jti is not a UUID v4: {0}")]
    JtiNotV4(crate::core::ids::V4Error),
    /// [`crate::tct::TctBuilder::derived_jti`] was given a domain tag outside
    /// printable ASCII `0x21..=0x7E`.
    #[error("jti derivation tag must be non-empty printable ASCII")]
    InvalidJtiTag,
    /// A TCT with `iss == sub` presented (or minted) in a grant context.
    /// Self-issued TCTs are attestations and confer no capability
    /// (RFC-AITP-0005 §5.3, proposal #72 Item 5). Wire code
    /// `TCT_SIGNATURE_INVALID`.
    #[error("self-issued TCT (iss == sub) confers no grants")]
    SelfIssued,
    /// The reserved [`crate::tct::ATTESTATION_GRANT`] marker appeared in a
    /// grant context, with `iss != sub`, or next to other grants. Wire
    /// code `TCT_SIGNATURE_INVALID`.
    #[error("`aitp.attestation` marker grant misused")]
    AttestationMarker,
    /// [`crate::tct::verify_attestation`] was given a TCT that is not a
    /// self-attestation (`iss == sub == aud`, `grants ==
    /// ["aitp.attestation"]`).
    #[error("TCT is not a self-attestation")]
    NotAttestation,
    /// The attestation's `ext` lacks the statement key the relying party
    /// consumes (RFC-AITP-0005 §5.3: MUST reject). Carries the key.
    #[error("attestation ext lacks statement key `{0}`")]
    AttestationStatementMissing(String),
    /// Crypto error.
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
    /// The revocation source answered
    /// [`crate::tct::RevocationStatus::SoftFailSafeSubset`] and none of
    /// the token's grants is in the safe subset (RFC-AITP-0008 §3.1).
    /// Wire code `POLICY_VIOLATION`.
    #[error("no granted capability is in the revocation soft-fail safe subset")]
    SafeSubsetEmpty,
}

#[cfg(test)]
mod revocation_unavailable_tests {
    use crate::delegation::DelegationError;
    use crate::tct::{RevocationUnavailable, TctError};
    use std::error::Error as _;

    /// The variants are transparent: the message appears once, and the
    /// source chain does not repeat it.
    #[test]
    fn revocation_unavailable_prints_its_message_once() {
        let want = "revocation source unavailable: endpoint down";
        let tct = TctError::RevocationUnavailable(RevocationUnavailable::new("endpoint down"));
        assert_eq!(tct.to_string(), want);
        assert!(tct.source().is_none());
        let del =
            DelegationError::RevocationUnavailable(RevocationUnavailable::new("endpoint down"));
        assert_eq!(del.to_string(), want);
        assert!(del.source().is_none());
    }
}
