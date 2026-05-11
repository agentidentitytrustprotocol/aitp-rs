//! Wire types for the TCT (RFC-AITP-0005 §1 / `schemas/json/aitp-tct.schema.json`).

use aitp_core::{Aid, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Trust Context Token — a signed, peer-issued capability grant.
///
/// Build with [`crate::TctBuilder`]. Verify with [`crate::verify_tct`].
///
/// The schema is `additionalProperties: false`. The TCT does **not** have
/// `extensions` or `evidence_ref` in v0.1 — every byte that gets signed
/// is enumerated by this struct.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tct {
    /// MUST be `"aitp/0.1"`.
    pub version: String,
    /// Unique token ID for revocation.
    pub jti: Uuid,
    /// Issuing peer's AID.
    pub issuer: Aid,
    /// Subject peer's AID.
    pub subject: Aid,
    /// Audience peer's AID. In v0.1 audience MUST equal subject (Model 1,
    /// holder receipt).
    pub audience: Aid,
    /// When this TCT was signed.
    pub issued_at: Timestamp,
    /// When this TCT becomes invalid.
    pub expires_at: Timestamp,
    /// Capability strings granted by issuer to subject. MUST be non-empty
    /// (RFC-AITP-0004 §4.1).
    pub grants: Vec<String>,
    /// Proof-of-possession binding to subject's key.
    pub binding: TctBinding,
    /// Issuer's signature over the JCS canonicalization of the TCT minus
    /// this field.
    pub signature: String,
}

/// PoP binding for a TCT.
///
/// Per RFC-AITP-0005 §1 / §6.2 step 4 the schema field `cnf` carries the
/// **subject's raw 32-byte Ed25519 public key** as 43-char base64url —
/// not the JWK thumbprint. Downstream PoP verifiers use this key directly
/// to validate the holder's signature over a challenge nonce.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TctBinding {
    /// Subject's raw Ed25519 public key, base64url-unpadded (43 chars).
    pub cnf: String,
}

/// TCT renewal request body. Gated behind the
/// `experimental-renewal` Cargo feature (post-v0.1, RFC-AITP-0004 §8.1).
///
/// A holder asks the issuer to mint a fresh TCT (new JTI, fresh
/// `expires_at`) by presenting:
/// - the existing TCT it currently holds, as proof the original
///   handshake completed;
/// - a fresh `pop_nonce` the issuer's response will echo;
/// - a `pop_signature` over `sha256(decoded(pop_nonce))` using the
///   subject's key, proving the renewal request comes from the
///   original holder rather than someone replaying the existing TCT.
///
/// The issuer returns a new `TctEnvelope` with a fresh `jti` and TTL
/// bounded by the issuing peer's current Manifest `expires_at`
/// (RFC-AITP-0004 §4.3).
#[cfg(feature = "experimental-renewal")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TctRenewalPayload {
    /// The currently-held TCT being renewed. Issuer re-verifies
    /// signature + audience + non-expired before honoring the renewal.
    pub current_tct: TctEnvelope,
    /// Holder-supplied fresh nonce (22-char base64url, 16 bytes).
    pub pop_nonce: String,
    /// `sign(holder_key, sha256(base64url_decode(pop_nonce)))`.
    pub pop_signature: String,
}

/// HTTP-wrapped TCT (the `{"tct": {...}}` form).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TctEnvelope {
    /// The signed inner TCT.
    pub tct: Tct,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_aid() -> Aid {
        Aid::from_ed25519(&[0u8; 32])
    }

    fn sample_tct() -> Tct {
        Tct {
            version: "aitp/0.1".into(),
            jti: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            issuer: sample_aid(),
            subject: sample_aid(),
            audience: sample_aid(),
            issued_at: Timestamp(1_700_000_000),
            expires_at: Timestamp(1_700_003_600),
            grants: vec!["demo.echo".into()],
            binding: TctBinding {
                cnf: "A".repeat(43),
            },
            signature: "A".repeat(86),
        }
    }

    #[test]
    fn round_trip_minimal_tct() {
        let t = sample_tct();
        let s = serde_json::to_string(&t).unwrap();
        let back: Tct = serde_json::from_str(&s).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let mut v = serde_json::to_value(sample_tct()).unwrap();
        v.as_object_mut().unwrap().insert("rogue".into(), json!(1));
        let err = serde_json::from_value::<Tct>(v).unwrap_err();
        assert!(err.to_string().contains("rogue"), "got: {}", err);
    }

    #[test]
    fn rejects_unknown_binding_field() {
        let mut v = serde_json::to_value(sample_tct()).unwrap();
        v["binding"]
            .as_object_mut()
            .unwrap()
            .insert("rogue".into(), json!(1));
        let err = serde_json::from_value::<Tct>(v).unwrap_err();
        assert!(err.to_string().contains("rogue"), "got: {}", err);
    }

    #[test]
    fn extensions_and_evidence_ref_are_not_fields() {
        // Schema is additionalProperties: false. Trying either rejects.
        let mut v = serde_json::to_value(sample_tct()).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("extensions".into(), json!({}));
        assert!(serde_json::from_value::<Tct>(v.clone()).is_err());

        let mut v = serde_json::to_value(sample_tct()).unwrap();
        v.as_object_mut().unwrap().insert(
            "evidence_ref".into(),
            json!({"sha256": "x", "description": "y"}),
        );
        assert!(serde_json::from_value::<Tct>(v).is_err());
    }

    #[test]
    fn tct_envelope_round_trips() {
        let env = TctEnvelope { tct: sample_tct() };
        let s = serde_json::to_string(&env).unwrap();
        let back: TctEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back, env);
    }
}
