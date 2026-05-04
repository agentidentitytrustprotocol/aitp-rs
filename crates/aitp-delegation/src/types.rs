//! Wire types for delegation tokens (RFC-AITP-0006).

use aitp_core::{Aid, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single-hop delegation token.
///
/// Issued by B (who holds a TCT from A) to authorize C to act with a
/// subset of B's grants. Verified by A.
///
/// Schema is `additionalProperties: false`; v0.1 has no `extensions`
/// slot on the delegation token.
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
    /// A's original signed grant to B, used for stateless scope-subset
    /// checks.
    pub grant_proof: GrantProof,
    /// B's signature over the JCS canonicalization of this token minus
    /// `signature`.
    pub signature: String,
}

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
