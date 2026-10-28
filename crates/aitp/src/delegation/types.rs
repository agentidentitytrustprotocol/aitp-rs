//! Delegation-token claim types (RFC-AITP-0006,
//! `schemas/json/aitp-delegation.schema.json`).
//!
//! On the wire a delegation token is an **opaque compact JWS string**
//! (`typ: aitp-delegation+jwt`, RFC-AITP-0001 §5.4.5); this type models
//! the decoded payload claims. The embedded grant voucher is carried
//! **verbatim** as a string — nothing is ever
//! decoded-and-re-encoded, and verification never reconstructs bytes.

use crate::core::{Aid, Timestamp};
use crate::tct::{Cnf, GrantVoucherClaims};
use serde::{Deserialize, Serialize};

/// Decoded claims of a delegation token.
///
/// Issued by B (who holds a TCT + voucher from A) to authorize C to act
/// with a subset of B's grants. Verified by A.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct DelegationClaims {
    /// Protocol version private claim. MUST be `"aitp/0.3"`.
    pub ver: String,
    /// Delegator-of-record (B for a single hop) — signs this token.
    pub iss: Aid,
    /// Delegatee (C).
    pub sub: Aid,
    /// The verifier the token is presentable to (A — the original
    /// grantor and voucher issuer). MUST equal the verifier's own AID.
    pub aud: Aid,
    /// Subset of capabilities being delegated. Non-empty;
    /// `scope ⊆ voucher.grants`.
    pub scope: Vec<String>,
    /// Expiry. MUST NOT exceed the voucher's `exp`.
    pub exp: Timestamp,
    /// PoP binding to the delegatee's key (RFC-AITP-0001 §5.4.4).
    pub cnf: Cnf,
    /// A's grant voucher, embedded verbatim (RFC-AITP-0005 §8). REQUIRED.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voucher: Option<String>,
    /// OPTIONAL extensions slot (RFC-AITP-0012); unknown keys inside
    /// `ext` MUST be ignored, unknown claims outside it rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<crate::core::ExtensionsMap>,
}

/// Full set of top-level members `aitp-delegation.schema.json` declares,
/// including the `ext` namespace key itself and the RFC-AITP-0011
/// members `jti`, `chain` and `chain_hash`, which
/// [`crate::delegation::verify_delegation`] rejects after this check. Used by the claim-set check
/// (RFC-AITP-0001 §7 / RFC-AITP-0005 §7.2) performed on the decoded JWS
/// payload — before AID-pinned `alg` checking and signature verification
/// — by [`crate::delegation::verify_delegation`]'s unverified peek.
///
/// Anchored to the vendored schema by `crates/aitp/tests/delegation_schema.rs`,
/// which asserts this list equals the schema's top-level `properties`
/// keys — so this cannot silently drift from the spec.
pub const DELEGATION_CLAIMS_MEMBERS: &[&str] = &[
    "ver",
    "iss",
    "sub",
    "aud",
    "scope",
    "exp",
    "cnf",
    "voucher",
    "jti",
    "chain",
    "chain_hash",
    "ext",
];

/// A delegation token that passed [`crate::delegation::verify_delegation`]: the
/// verbatim token, its trusted claims, and the embedded voucher's claims.
///
/// Only this crate constructs it, and its fields are read-only:
/// [`Self::into_parts`] hands out the owned pieces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelegation {
    pub(crate) token: String,
    pub(crate) claims: DelegationClaims,
    pub(crate) voucher: GrantVoucherClaims,
    pub(crate) effective_grants: Vec<String>,
}

impl VerifiedDelegation {
    /// The compact JWS, byte-for-byte as presented.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Decoded outer claims, trusted after verification.
    pub fn claims(&self) -> &DelegationClaims {
        &self.claims
    }

    /// Claims of the embedded grant voucher.
    pub fn voucher(&self) -> &GrantVoucherClaims {
        &self.voucher
    }

    /// The capabilities this delegation may exercise: `claims.scope`,
    /// narrowed to the safe subset when the revocation source answered
    /// [`crate::tct::RevocationStatus::SoftFailSafeSubset`].
    pub fn effective_grants(&self) -> &[String] {
        &self.effective_grants
    }

    /// The owned pieces.
    pub fn into_parts(self) -> VerifiedDelegationParts {
        VerifiedDelegationParts {
            token: self.token,
            claims: self.claims,
            voucher: self.voucher,
            effective_grants: self.effective_grants,
        }
    }
}

/// The owned pieces of a [`VerifiedDelegation`], from [`VerifiedDelegation::into_parts`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedDelegationParts {
    /// See [`VerifiedDelegation::token`].
    pub token: String,
    /// See [`VerifiedDelegation::claims`].
    pub claims: DelegationClaims,
    /// See [`VerifiedDelegation::voucher`].
    pub voucher: GrantVoucherClaims,
    /// See [`VerifiedDelegation::effective_grants`].
    pub effective_grants: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_claims_json() -> serde_json::Value {
        json!({
            "ver": "aitp/0.3",
            "iss": "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
            "sub": "aid:pubkey:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU",
            "aud": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "scope": ["macp.mode.task.v1"],
            "exp": 1_711_901_800,
            "cnf": { "jkt": "LlsmkXmHJuXWkRZLv_FKl_mprfIV5aYVnXqCgsebsdU" },
            "voucher": "eyJh.eyJl.c2ln",
        })
    }

    #[test]
    fn claims_round_trip() {
        let claims: DelegationClaims = serde_json::from_value(sample_claims_json()).unwrap();
        assert_eq!(serde_json::to_value(&claims).unwrap(), sample_claims_json());
    }

    #[test]
    fn unknown_claim_rejected() {
        let mut v = sample_claims_json();
        v.as_object_mut().unwrap().insert("rogue".into(), json!(1));
        assert!(serde_json::from_value::<DelegationClaims>(v).is_err());
    }

    /// Acceptance criterion 4 (Phase 6b): RFC-AITP-0001 §7's asymmetry —
    /// an unknown sibling claim is rejected (`unknown_claim_rejected`
    /// above), but an arbitrary key *inside* `ext` MUST be accepted.
    /// Library-level, independent of any conformance fixture.
    #[test]
    fn junk_key_inside_ext_accepted() {
        let mut v = sample_claims_json();
        v.as_object_mut().unwrap().insert(
            "ext".into(),
            json!({"any_junk_key_at_all": {"deeply": ["nested", 1, true]}}),
        );
        let claims: DelegationClaims =
            serde_json::from_value(v).expect("junk key inside ext must be accepted");
        assert!(claims.ext.is_some());
    }
}
