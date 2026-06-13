//! AITP error codes from the registry.
//!
//! See `agentidentitytrustprotocol/registries/error-codes.md` for the
//! authoritative list.

use serde::{Deserialize, Serialize};

/// Top-level error type for AITP operations.
///
/// Each variant maps to one or more wire-level [`ErrorCode`] values.
/// Protocol-specific crates have their own narrower error types
/// (e.g. `TctError`, `ManifestError`) that flatten into this with
/// `From` impls.
///
/// Marked `#[non_exhaustive]` so future error categories can be added
/// without a semver-major bump. Downstream matches must include a
/// fall-through arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AitpError {
    /// Replay-protection or envelope-level rejection.
    #[error("envelope rejected: {0}")]
    Envelope(String),

    /// Identity proof was invalid (OIDC, pinned key, etc.).
    #[error("identity verification failed: {0}")]
    Identity(String),

    /// Manifest-level error (signature, PoP, expiry).
    #[error("manifest error: {0}")]
    Manifest(String),

    /// TCT-level error (signature, audience, expiry, grants).
    #[error("TCT error: {0}")]
    Tct(String),

    /// Delegation-token error.
    #[error("delegation error: {0}")]
    Delegation(String),

    /// Cryptographic failure (signature, key parsing).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Other / catch-all.
    #[error("AITP error: {0}")]
    Other(String),
}

/// Wire-level error code as it appears on the protocol.
///
/// Serialized as `SCREAMING_SNAKE_CASE` strings matching the registry.
///
/// Marked `#[non_exhaustive]` so new codes added to the spec's error
/// registry can ship in a future minor version without breaking
/// downstream `match` statements. Downstream matches must include a
/// fall-through arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ErrorCode {
    // ── Envelope-level ──────────────────────────────────────────────────
    /// Envelope JSON failed schema validation.
    InvalidEnvelope,
    /// Envelope signature did not verify.
    InvalidSignature,
    /// Duplicate message_id seen.
    ReplayDetected,
    /// Timestamp outside ±300s tolerance.
    TimestampExpired,
    /// Protocol version not supported.
    UnknownVersion,

    // ── Identity / Manifest ─────────────────────────────────────────────
    /// Identity binding could not be verified.
    IdentityFailed,
    /// Manifest expires_at is in the past.
    ManifestExpired,
    /// Manifest signature did not verify.
    ManifestSignatureInvalid,
    /// Manifest proof-of-possession did not verify.
    ManifestPopFailed,
    /// Manifest version not supported by this implementation.
    ManifestVersionUnknown,

    // ── Trust ───────────────────────────────────────────────────────────
    /// Trust evaluation failed for an unspecified policy reason.
    TrustFailed,
    /// Requested capability not granted.
    PolicyViolation,
    /// Issuer's keys could not be resolved.
    KeyResolutionFailed,
    /// Peer's identity issuer is not in this peer's trust anchors.
    IncompatibleTrustAnchors,

    // ── Mutual handshake ────────────────────────────────────────────────
    /// PoP signature in MUTUAL_COMMIT/_ACK did not verify.
    PopVerificationFailed,
    /// pop_nonce_echo did not match the previously sent nonce.
    NonceMismatch,
    /// Peer-issued TCT audience did not equal own AID.
    AudienceMismatch,
    /// Peer-issued TCT grants exceed peer's offered_capabilities.
    GrantOverflow,
    /// Received TCT did not include required peer capabilities.
    InsufficientGrants,
    /// Proposed handshake_mode not supported.
    HandshakeModeUnsupported,

    // ── TCT-specific ────────────────────────────────────────────────────
    /// TCT expires_at is in the past.
    TctExpired,

    // ── PoP ─────────────────────────────────────────────────────────────
    /// Downstream PoP challenge was malformed or stale.
    PopChallengeInvalid,
    /// Downstream PoP response did not verify.
    PopResponseInvalid,

    // ── Delegation ──────────────────────────────────────────────────────
    /// Delegation token: audience did not match self AID.
    DelegationAudienceMismatch,
    /// Delegation token: scope contained capabilities outside grant_proof.
    DelegationScopeExceeded,
    /// Delegation token: grant_proof signature or subject binding invalid.
    DelegationInvalidGrantProof,
    /// Delegation token: source TCT has been revoked.
    DelegationSourceTctRevoked,
    /// Delegation token: signature did not verify.
    DelegationInvalidSignature,
    /// Delegation token: token or grant proof has expired.
    DelegationExpired,
    /// Delegation token: PoP binding (cnf) verification failed.
    DelegationPopFailed,
    /// Delegation token: chain length exceeds v0.1 single-hop limit.
    DelegationMultihopNotSupported,
    /// Multi-hop delegation: chain length exceeds `max_delegation_hops`
    /// (RFC-AITP-0011).
    DelegationHopLimitExceeded,
    /// Multi-hop delegation: `chain_hash` does not match the `chain`
    /// array contents (truncation or tampering detected — RFC-AITP-0011).
    DelegationChainHashMismatch,
    /// Manifest service: no manifest for the requested AID.
    ManifestNotFound,
    /// TCT verification: signature did not validate under issuer's key.
    TctSignatureInvalid,
    /// TCT verification: jti is in issuer's deny list.
    TctRevoked,
    /// TCT verification: TCT `expires_at` exceeds the issuing peer's
    /// Manifest `expires_at` (RFC-AITP-0004 §4.3).
    TctExpiresAfterManifest,

    // ── Session Bundle (RFC-AITP-0010, Draft) ───────────────────────────
    /// Coordinator's outer bundle signature failed verification under
    /// the coordinator's Manifest key.
    BundleInvalidSignature,
    /// `version` is not `"aitp/0.1"` (or a later supported version).
    BundleVersionMismatch,
    /// Bundle `expires_at` is in the past at verification time.
    BundleExpired,
    /// `expires_at` is greater than
    /// `min(participants[*].tct.expires_at)` (RFC-AITP-0010 §6).
    BundleExpiryWindowInvariant,
    /// One or more `participants[*].tct.issuer` values do not equal
    /// `coordinator`.
    BundleCoordinatorIssuerMismatch,
    /// A `participants[i].tct.audience` does not equal
    /// `participants[i].aid`.
    BundleAudienceMismatch,
    /// `participants` array is empty.
    BundleEmptyParticipants,
    /// At least one embedded participant TCT failed standard TCT
    /// verification.
    BundleParticipantTctInvalid,
    /// Receiver's AID is not in `participants[*].aid`.
    BundleNotMember,
    /// Aggregate fallback — implementations MAY return this when a
    /// deployment policy requires a single-error surface for bundles,
    /// in lieu of the specific BUNDLE_* codes above.
    SessionBundleInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned wire strings — the contract with the AITP error-code registry.
    /// Drift here would silently break interop with other implementations.
    #[test]
    fn pinned_wire_strings() {
        let cases: &[(ErrorCode, &str)] = &[
            (ErrorCode::AudienceMismatch, "AUDIENCE_MISMATCH"),
            (ErrorCode::TctExpired, "TCT_EXPIRED"),
            (
                ErrorCode::ManifestSignatureInvalid,
                "MANIFEST_SIGNATURE_INVALID",
            ),
            (ErrorCode::ReplayDetected, "REPLAY_DETECTED"),
            (
                ErrorCode::DelegationSourceTctRevoked,
                "DELEGATION_SOURCE_TCT_REVOKED",
            ),
            (ErrorCode::InvalidEnvelope, "INVALID_ENVELOPE"),
            (ErrorCode::InvalidSignature, "INVALID_SIGNATURE"),
            (ErrorCode::TimestampExpired, "TIMESTAMP_EXPIRED"),
            (ErrorCode::UnknownVersion, "UNKNOWN_VERSION"),
            (ErrorCode::IdentityFailed, "IDENTITY_FAILED"),
            (ErrorCode::PolicyViolation, "POLICY_VIOLATION"),
            (ErrorCode::GrantOverflow, "GRANT_OVERFLOW"),
            (ErrorCode::InsufficientGrants, "INSUFFICIENT_GRANTS"),
            (ErrorCode::KeyResolutionFailed, "KEY_RESOLUTION_FAILED"),
            (ErrorCode::ManifestExpired, "MANIFEST_EXPIRED"),
            (ErrorCode::ManifestPopFailed, "MANIFEST_POP_FAILED"),
            (
                ErrorCode::ManifestVersionUnknown,
                "MANIFEST_VERSION_UNKNOWN",
            ),
            (
                ErrorCode::IncompatibleTrustAnchors,
                "INCOMPATIBLE_TRUST_ANCHORS",
            ),
            (ErrorCode::PopVerificationFailed, "POP_VERIFICATION_FAILED"),
            (ErrorCode::NonceMismatch, "NONCE_MISMATCH"),
            (ErrorCode::PopChallengeInvalid, "POP_CHALLENGE_INVALID"),
            (ErrorCode::PopResponseInvalid, "POP_RESPONSE_INVALID"),
            (
                ErrorCode::DelegationAudienceMismatch,
                "DELEGATION_AUDIENCE_MISMATCH",
            ),
            (
                ErrorCode::DelegationScopeExceeded,
                "DELEGATION_SCOPE_EXCEEDED",
            ),
            (
                ErrorCode::DelegationInvalidGrantProof,
                "DELEGATION_INVALID_GRANT_PROOF",
            ),
            (
                ErrorCode::DelegationInvalidSignature,
                "DELEGATION_INVALID_SIGNATURE",
            ),
            (ErrorCode::DelegationExpired, "DELEGATION_EXPIRED"),
            (ErrorCode::DelegationPopFailed, "DELEGATION_POP_FAILED"),
            (
                ErrorCode::DelegationMultihopNotSupported,
                "DELEGATION_MULTIHOP_NOT_SUPPORTED",
            ),
            (
                ErrorCode::DelegationHopLimitExceeded,
                "DELEGATION_HOP_LIMIT_EXCEEDED",
            ),
            (
                ErrorCode::DelegationChainHashMismatch,
                "DELEGATION_CHAIN_HASH_MISMATCH",
            ),
            (ErrorCode::ManifestNotFound, "MANIFEST_NOT_FOUND"),
            (ErrorCode::TrustFailed, "TRUST_FAILED"),
            (
                ErrorCode::HandshakeModeUnsupported,
                "HANDSHAKE_MODE_UNSUPPORTED",
            ),
            (ErrorCode::TctSignatureInvalid, "TCT_SIGNATURE_INVALID"),
            (ErrorCode::TctRevoked, "TCT_REVOKED"),
            (
                ErrorCode::TctExpiresAfterManifest,
                "TCT_EXPIRES_AFTER_MANIFEST",
            ),
            // Session Bundle (RFC-AITP-0010, Draft)
            (
                ErrorCode::BundleInvalidSignature,
                "BUNDLE_INVALID_SIGNATURE",
            ),
            (ErrorCode::BundleVersionMismatch, "BUNDLE_VERSION_MISMATCH"),
            (ErrorCode::BundleExpired, "BUNDLE_EXPIRED"),
            (
                ErrorCode::BundleExpiryWindowInvariant,
                "BUNDLE_EXPIRY_WINDOW_INVARIANT",
            ),
            (
                ErrorCode::BundleCoordinatorIssuerMismatch,
                "BUNDLE_COORDINATOR_ISSUER_MISMATCH",
            ),
            (
                ErrorCode::BundleAudienceMismatch,
                "BUNDLE_AUDIENCE_MISMATCH",
            ),
            (
                ErrorCode::BundleEmptyParticipants,
                "BUNDLE_EMPTY_PARTICIPANTS",
            ),
            (
                ErrorCode::BundleParticipantTctInvalid,
                "BUNDLE_PARTICIPANT_TCT_INVALID",
            ),
            (ErrorCode::BundleNotMember, "BUNDLE_NOT_MEMBER"),
            (ErrorCode::SessionBundleInvalid, "SESSION_BUNDLE_INVALID"),
        ];
        for (code, wire) in cases {
            let v = serde_json::to_value(code).unwrap();
            assert_eq!(v.as_str().unwrap(), *wire, "encode {:?}", code);
            let back: ErrorCode = serde_json::from_value(v).unwrap();
            assert_eq!(back, *code, "decode {}", wire);
        }
    }

    #[test]
    fn round_trip_through_json_string() {
        let s = serde_json::to_string(&ErrorCode::PopVerificationFailed).unwrap();
        assert_eq!(s, "\"POP_VERIFICATION_FAILED\"");
        let back: ErrorCode = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ErrorCode::PopVerificationFailed);
    }

    #[test]
    fn rejects_unknown_wire_strings() {
        assert!(serde_json::from_str::<ErrorCode>("\"NOT_A_REAL_CODE\"").is_err());
        assert!(serde_json::from_str::<ErrorCode>("\"audience_mismatch\"").is_err());
    }
}
