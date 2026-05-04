//! Wire types for the Manifest (RFC-AITP-0003 §2 / `schemas/json/aitp-manifest.schema.json`).

use aitp_core::{Aid, ExtensionsMap, Timestamp};
use serde::{Deserialize, Serialize};
use url::Url;

/// A signed self-description published by every A2A agent.
///
/// Construct with [`crate::ManifestBuilder`]. Verify with
/// [`crate::verify_manifest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// MUST be `"aitp/0.1"`.
    pub version: String,
    /// The agent's AID.
    pub aid: Aid,
    /// Optional human-readable name. Not used in trust decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Static identity metadata. NOT a verifiable JWT.
    pub identity_hint: IdentityHint,
    /// HTTPS endpoint where peers initiate the handshake.
    pub handshake_endpoint: Url,
    /// OIDC issuer URIs this peer accepts from incoming peers.
    pub accepted_trust_anchors: Vec<Url>,
    /// Identity types this peer accepts. Default: `["oidc"]` when absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_identity_types: Vec<String>,
    /// Capabilities this peer is willing to grant.
    pub offered_capabilities: Vec<String>,
    /// Capabilities this peer requires of any peer that connects to it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_peer_capabilities: Vec<String>,
    /// Proof-of-possession over the Manifest signing key.
    pub proof_of_possession: ManifestPop,
    /// When this Manifest was signed.
    pub published_at: Timestamp,
    /// When this Manifest stops being valid.
    pub expires_at: Timestamp,
    /// Forward-compatible extensions.
    #[serde(default, skip_serializing_if = "ExtensionsMap::is_empty")]
    pub extensions: ExtensionsMap,
    /// Signature over JCS-canonicalized Manifest minus this field.
    pub signature: String,
}

/// HTTP-wrapped Manifest as published at `/.well-known/aitp-manifest`.
///
/// RFC-AITP-0003 §6.1: the `{"manifest": {...}}` form is the HTTP transport
/// envelope only. The signed object is the inner [`Manifest`]. Verifiers
/// MUST unwrap before computing the signing input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestEnvelope {
    /// The signed inner Manifest.
    pub manifest: Manifest,
}

/// Static identity metadata (RFC-AITP-0003 §3.1).
///
/// This carries only `type`, `subject`, and either an `issuer` (OIDC) or a
/// `public_key` (pinned key). It MUST NOT contain a verifiable proof — the
/// fresh JWT or pinned-key signature is exchanged in the Mutual Handshake
/// where it can be bound to a per-handshake nonce.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityHint {
    /// `oidc` or `pinned_key`.
    #[serde(rename = "type")]
    pub kind: IdentityHintKind,
    /// Subject identifier at the identity provider.
    pub subject: String,
    /// OIDC issuer URI (required when type=oidc).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Url>,
    /// Pinned 32-byte raw public key, base64url-unpadded
    /// (required when type=pinned_key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

/// Identity provider type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityHintKind {
    /// OIDC OpenID Connect issuer.
    Oidc,
    /// Pinned Ed25519 public key.
    PinnedKey,
}

/// Manifest PoP block (RFC-AITP-0003 §3.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestPop {
    /// Random 128-bit base64url-unpadded challenge (22 chars).
    pub challenge: String,
    /// Signature over `sha256(challenge)` using the AID's private key.
    pub signature: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_aid() -> Aid {
        Aid::from_ed25519(&[0u8; 32])
    }

    fn build_minimal_manifest() -> Manifest {
        Manifest {
            version: "aitp/0.1".into(),
            aid: sample_aid(),
            display_name: None,
            identity_hint: IdentityHint {
                kind: IdentityHintKind::Oidc,
                subject: "agent-a".into(),
                issuer: Some("https://idp.example.com".parse().unwrap()),
                public_key: None,
            },
            handshake_endpoint: "https://a.example.com/handshake".parse().unwrap(),
            accepted_trust_anchors: vec!["https://idp.example.com".parse().unwrap()],
            accepted_identity_types: vec![],
            offered_capabilities: vec!["demo.echo".into()],
            required_peer_capabilities: vec![],
            proof_of_possession: ManifestPop {
                challenge: "A".repeat(22),
                signature: "A".repeat(86),
            },
            published_at: Timestamp(1_711_900_000),
            expires_at: Timestamp(1_711_986_400),
            extensions: ExtensionsMap::new(),
            signature: "A".repeat(86),
        }
    }

    #[test]
    fn round_trip_oidc_manifest() {
        let m = build_minimal_manifest();
        let s = serde_json::to_string(&m).unwrap();
        assert!(!s.contains("\"display_name\":"));
        assert!(!s.contains("\"extensions\":"));
        assert!(!s.contains("\"required_peer_capabilities\":"));
        let back: Manifest = serde_json::from_str(&s).unwrap();
        assert_eq!(back, m);
    }

    /// Manifest schema is `additionalProperties: false`; the previously-
    /// supported `description` field was not in RFC-AITP-0003 §3.1/§3.2,
    /// so a Manifest carrying it MUST now fail to deserialize. Guards
    /// against the field silently coming back.
    #[test]
    fn rejects_legacy_description_field() {
        let mut v = serde_json::to_value(build_minimal_manifest()).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("description".into(), json!("legacy human description"));
        let err = serde_json::from_value::<Manifest>(v).unwrap_err();
        assert!(err.to_string().contains("description"), "got: {}", err);
    }

    #[test]
    fn round_trip_pinned_key_manifest() {
        let mut m = build_minimal_manifest();
        m.identity_hint = IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "internal-1".into(),
            issuer: None,
            public_key: Some("A".repeat(43)),
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: Manifest = serde_json::from_str(&s).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn extensions_when_present_serializes() {
        let mut m = build_minimal_manifest();
        m.extensions.insert("vendor.example/foo", json!({"x": 1}));
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("vendor.example/foo"));
        let back: Manifest = serde_json::from_str(&s).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let mut v = serde_json::to_value(build_minimal_manifest()).unwrap();
        v.as_object_mut().unwrap().insert("rogue".into(), json!(1));
        let err = serde_json::from_value::<Manifest>(v).unwrap_err();
        assert!(err.to_string().contains("rogue"), "got: {}", err);
    }

    #[test]
    fn rejects_unknown_pop_field() {
        let mut v = serde_json::to_value(build_minimal_manifest()).unwrap();
        v["proof_of_possession"]
            .as_object_mut()
            .unwrap()
            .insert("rogue".into(), json!(1));
        let err = serde_json::from_value::<Manifest>(v).unwrap_err();
        assert!(err.to_string().contains("rogue"), "got: {}", err);
    }

    #[test]
    fn manifest_envelope_round_trips() {
        let env = ManifestEnvelope {
            manifest: build_minimal_manifest(),
        };
        let s = serde_json::to_string(&env).unwrap();
        let back: ManifestEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back, env);
    }
}
