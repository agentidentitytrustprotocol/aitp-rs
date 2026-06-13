//! Delegation-token claim types (RFC-AITP-0006 single-hop;
//! RFC-AITP-0011 multi-hop / `schemas/json/aitp-delegation.schema.json`).
//!
//! On the wire a delegation token is an **opaque compact JWS string**
//! (`typ: aitp-delegation+jwt`, RFC-AITP-0001 §5.4.5); this type models
//! the decoded payload claims. The embedded grant voucher and every
//! chain entry are carried **verbatim** as strings — nothing is ever
//! decoded-and-re-encoded, and verification never reconstructs bytes.

use aitp_core::{Aid, Timestamp};
use aitp_tct::{Cnf, GrantVoucherClaims};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Decoded claims of a delegation token.
///
/// Single-hop (RFC-AITP-0006): `voucher` is REQUIRED; `jti`, `chain`,
/// and `chain_hash` are absent. Issued by B (who holds a TCT + voucher
/// from A) to authorize C to act with a subset of B's grants. Verified
/// by A.
///
/// Multi-hop (RFC-AITP-0011, opt-in): `chain` is non-empty and is the
/// opt-in marker; `chain_hash` and a per-hop `jti` are REQUIRED;
/// `voucher` lives only on `chain[0]` (exactly one root of authority)
/// and MUST be absent on the outer token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelegationClaims {
    /// Protocol version private claim. MUST be `"aitp/0.2"`.
    pub ver: String,
    /// Delegator-of-record (B for a single hop) — signs this token.
    pub iss: Aid,
    /// Delegatee (C).
    pub sub: Aid,
    /// The verifier the token is presentable to (A — the original
    /// grantor and voucher issuer). MUST equal the verifier's own AID.
    pub aud: Aid,
    /// Subset of capabilities being delegated. Non-empty;
    /// `scope ⊆ voucher.grants` (transitively, for chains).
    pub scope: Vec<String>,
    /// Expiry. MUST NOT exceed the voucher's `exp` (nor, per hop, the
    /// preceding hop's `exp`).
    pub exp: Timestamp,
    /// PoP binding to the delegatee's key (RFC-AITP-0001 §5.4.4).
    pub cnf: Cnf,
    /// A's grant voucher, embedded verbatim (RFC-AITP-0005 §8).
    /// REQUIRED on single-hop tokens and on `chain[0]`; MUST be absent
    /// on every later hop and on a chain-bearing outer token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voucher: Option<String>,
    /// Per-hop revocation handle (RFC-AITP-0011 §1.1). REQUIRED on
    /// every hop of a chain; not part of the single-hop claims set —
    /// non-opted-in verifiers reject `jti`-bearing tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<Uuid>,
    /// Prior hops, oldest first, each a verbatim delegation compact
    /// JWS (RFC-AITP-0011). Presence (non-empty) is the multi-hop
    /// opt-in marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<String>>,
    /// Digest-array commitment over `chain` (RFC-AITP-0011 §5).
    /// REQUIRED whenever `chain` is non-empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_hash: Option<String>,
    /// OPTIONAL extensions slot (RFC-AITP-0012); unknown keys inside
    /// `ext` MUST be ignored, unknown claims outside it rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<serde_json::Map<String, serde_json::Value>>,
}

/// A delegation token that passed [`crate::verify_delegation`]: the
/// verbatim outer token, its trusted claims, and the root voucher's
/// claims (the authority the chain bottomed out in).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelegation {
    /// The outer compact JWS, byte-for-byte as presented.
    pub token: String,
    /// Decoded outer claims, trusted after verification.
    pub claims: DelegationClaims,
    /// Claims of the root grant voucher (embedded in the token itself
    /// for single-hop, or in `chain[0]` for multi-hop).
    pub voucher: GrantVoucherClaims,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_claims_json() -> serde_json::Value {
        json!({
            "ver": "aitp/0.2",
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

    #[test]
    fn multihop_claims_round_trip() {
        let mut v = sample_claims_json();
        let obj = v.as_object_mut().unwrap();
        obj.remove("voucher");
        obj.insert("jti".into(), json!("550e8400-e29b-41d4-a716-446655440011"));
        obj.insert("chain".into(), json!(["eyJh.eyJl.c2ln"]));
        obj.insert("chain_hash".into(), json!("A".repeat(43)));
        let claims: DelegationClaims = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(serde_json::to_value(&claims).unwrap(), v);
    }
}
