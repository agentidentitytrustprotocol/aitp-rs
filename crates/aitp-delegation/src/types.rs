//! Wire types for delegation tokens (RFC-AITP-0006 single-hop;
//! RFC-AITP-0011 multi-hop).

use aitp_core::{Aid, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A delegation token.
///
/// Single-hop (RFC-AITP-0006): `chain` is absent or empty. Issued by B
/// (who holds a TCT from A) to authorize C to act with a subset of B's
/// grants. Verified by A.
///
/// Multi-hop (RFC-AITP-0011): `chain` is non-empty and `chain_hash` is
/// REQUIRED. The chain holds the first n-1 steps oldest-first; the
/// most-recent step lives in the top-level `grant_proof`. Total hop
/// count is `chain.len() + 1`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelegationToken {
    /// Original grantor — A.
    pub delegator: Aid,
    /// Recipient of delegation — C.
    pub delegatee: Aid,
    /// Issuer of this delegation — B.
    pub issued_by: Aid,
    /// MUST equal `delegator` (A's AID).
    pub audience: Aid,
    /// Subset of capabilities B is delegating to C.
    pub scope: Vec<String>,
    /// When this delegation expires.
    pub expires_at: Timestamp,
    /// C's raw 32-byte Ed25519 public key (43-char base64url) for PoP.
    pub cnf: String,
    /// Most-recent hop's projection. For single-hop tokens this is A's
    /// original signed grant to B. For multi-hop (RFC-AITP-0011) this
    /// is the last DelegationStep, which authorizes `issued_by` to
    /// issue the outer delegation.
    pub grant_proof: GrantProof,
    /// Multi-hop chain (RFC-AITP-0011). Absent or empty means single-hop
    /// (the v0.1 case). Ordered oldest hop first; `chain[0].issuer`
    /// MUST equal `delegator` (A) and is what roots the chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<DelegationStep>>,
    /// Truncation-defense binding (RFC-AITP-0011 §5). REQUIRED whenever
    /// `chain` is non-empty. `base64url(sha256(canonical_json([
    /// chain[0].source_tct_jti, ..., chain[n-2].source_tct_jti])))`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_hash: Option<String>,
    /// B's signature over the JCS canonicalization of this token minus
    /// `signature`.
    pub signature: String,
}

/// One link in a multi-hop delegation chain (RFC-AITP-0011 §1.1).
///
/// Same wire shape as [`GrantProof`]. The semantics differ: `chain[0]`
/// references A's original peer-issued TCT (`source_tct_jti` is the
/// JTI of that TCT and the signature is reused verbatim from it). For
/// `chain[i > 0]` the `signature` is the issuer's signature over the
/// canonical step body (excluding `signature`); `source_tct_jti` is a
/// fresh UUIDv4 the issuer assigned at minting time and only ever
/// participates in `chain_hash` and per-hop revocation.
pub type DelegationStep = GrantProof;

/// Minimized record of A's original TCT issued to B.
///
/// Carries only the fields needed for scope-subset verification, plus
/// `source_tct_jti` for revocation linkage. Reconstruction of the source
/// TCT body for signature verification uses these fields plus the
/// constants from RFC-AITP-0005 (`version = "aitp/0.1"`, audience equals
/// subject in v0.1, the `binding.cnf` taken from the *delegation*'s
/// `cnf` field).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantProof {
    /// AID of the original grantor (A).
    pub issuer: Aid,
    /// AID of the original grantee (B). MUST equal `delegation.issued_by`.
    pub subject: Aid,
    /// Capabilities A originally granted to B.
    pub capabilities: Vec<String>,
    /// Issuance time of A's original grant. Per RFC-AITP-0006 §3.1
    /// (rc.2), copied verbatim from the source TCT so the source TCT
    /// signing input can be reconstructed byte-for-byte without TTL
    /// guessing.
    pub issued_at: Timestamp,
    /// Expiry of A's original grant.
    pub expires_at: Timestamp,
    /// JTI of A's original TCT to B. Used for revocation linkage.
    pub source_tct_jti: Uuid,
    /// A's signature over the source TCT body (reused verbatim).
    pub signature: String,
}

/// HTTP-wrapped delegation token (the `{"delegation": {...}}` form).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelegationEnvelope {
    /// The signed inner token.
    pub delegation: DelegationToken,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_aid() -> Aid {
        Aid::from_ed25519(&[0u8; 32])
    }

    fn sample_token() -> DelegationToken {
        DelegationToken {
            delegator: sample_aid(),
            delegatee: sample_aid(),
            issued_by: sample_aid(),
            audience: sample_aid(),
            scope: vec!["x".into()],
            expires_at: Timestamp(1_700_000_000),
            cnf: "A".repeat(43),
            grant_proof: GrantProof {
                issuer: sample_aid(),
                subject: sample_aid(),
                capabilities: vec!["x".into(), "y".into()],
                issued_at: Timestamp(1_700_006_400),
                expires_at: Timestamp(1_700_010_000),
                source_tct_jti: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
                signature: "A".repeat(86),
            },
            chain: None,
            chain_hash: None,
            signature: "A".repeat(86),
        }
    }

    #[test]
    fn round_trip() {
        let t = sample_token();
        let s = serde_json::to_string(&t).unwrap();
        let back: DelegationToken = serde_json::from_str(&s).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn rejects_unknown_top_field() {
        let mut v = serde_json::to_value(sample_token()).unwrap();
        v.as_object_mut().unwrap().insert("rogue".into(), json!(1));
        assert!(serde_json::from_value::<DelegationToken>(v).is_err());
    }

    #[test]
    fn rejects_unknown_grant_proof_field() {
        let mut v = serde_json::to_value(sample_token()).unwrap();
        v["grant_proof"]
            .as_object_mut()
            .unwrap()
            .insert("rogue".into(), json!(1));
        assert!(serde_json::from_value::<DelegationToken>(v).is_err());
    }

    #[test]
    fn rejects_extensions_field() {
        let mut v = serde_json::to_value(sample_token()).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("extensions".into(), json!({}));
        assert!(serde_json::from_value::<DelegationToken>(v).is_err());
    }

    #[test]
    fn delegation_envelope_round_trips() {
        let env = DelegationEnvelope {
            delegation: sample_token(),
        };
        let s = serde_json::to_string(&env).unwrap();
        let back: DelegationEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back, env);
    }
}
