//! Wire types for the Manifest (RFC-AITP-0003 §2 / `schemas/json/aitp-manifest.schema.json`).

use aitp_core::{Aid, ExtensionsMap, RawUrl, Timestamp};
use serde::{Deserialize, Serialize};

/// A signed self-description published by every A2A agent.
///
/// Construct with [`crate::ManifestBuilder`]. Verify with
/// [`crate::verify_manifest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// MUST be `"aitp/0.2"`.
    pub version: String,
    /// The agent's AID.
    pub aid: Aid,
    /// Optional human-readable name. Not used in trust decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Static identity metadata. NOT a verifiable JWT.
    pub identity_hint: IdentityHint,
    /// HTTPS endpoint where peers initiate the handshake. Stored
    /// as a [`RawUrl`] so the wire bytes are preserved verbatim
    /// for canonical-form signing — `url::Url` normalizes (adds
    /// trailing slash, lowercases scheme) which would diverge from
    /// the issuer's signed input.
    pub handshake_endpoint: RawUrl,
    /// OIDC issuer URIs this peer accepts from incoming peers.
    /// `RawUrl` for the same canonical-form-preservation reason as
    /// [`Self::handshake_endpoint`].
    pub accepted_trust_anchors: Vec<RawUrl>,
    /// Identity types this peer accepts.
    ///
    /// **Presence-sensitive:** RFC-AITP-0003 §3.2 distinguishes
    /// absent (= defaults to `["oidc"]`) from explicit `[]`
    /// (= reject every peer). Modeled as `Option<Vec<String>>` so
    /// the canonical signing bytes preserve the on-the-wire shape:
    /// `None` → field absent, `Some(_)` → field serialized verbatim
    /// (including `Some(vec![])`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_identity_types: Option<Vec<String>>,
    /// Capabilities this peer is willing to grant.
    pub offered_capabilities: Vec<String>,
    /// Capabilities this peer requires of any peer that connects to it.
    ///
    /// **Presence-sensitive** for the same canonical-form reason as
    /// [`Self::accepted_identity_types`]: spec fixtures vary in
    /// whether they include the field as explicit `[]` or omit it,
    /// and the canonical signing bytes differ. Modeling as
    /// `Option<Vec<String>>` preserves the wire form through
    /// deserialize→re-serialize.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_peer_capabilities: Option<Vec<String>>,
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
    /// OIDC issuer URI (required when type=oidc). `RawUrl` so the
    /// canonical-form bytes match the issuer-signed input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<RawUrl>,
    /// Pinned 32-byte raw public key, base64url-unpadded
    /// (required when type=pinned_key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

/// Identity provider type.
///
/// Marked `#[non_exhaustive]` so future identity-hint kinds (e.g.
/// did, mtls) added to the spec can ship without a major bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
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
            version: "aitp/0.2".into(),
            aid: sample_aid(),
            display_name: None,
            identity_hint: IdentityHint {
                kind: IdentityHintKind::Oidc,
                subject: "agent-a".into(),
                issuer: Some(RawUrl::new("https://idp.example.com")),
                public_key: None,
            },
            handshake_endpoint: RawUrl::new("https://a.example.com/handshake"),
            accepted_trust_anchors: vec![RawUrl::new("https://idp.example.com")],
            accepted_identity_types: None,
            offered_capabilities: vec!["demo.echo".into()],
            required_peer_capabilities: None,
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
        // Optional fields modeled as `Option` round-trip absent
        // → absent. `display_name`, `extensions`,
        // `accepted_identity_types`, and `required_peer_capabilities`
        // are all skip-on-none / skip-on-empty, so they're missing
        // from the wire form when the builder didn't set them.
        // (Preserving the absent-vs-explicit-empty distinction
        // through a serde round-trip is what keeps issuer and
        // verifier signing inputs in sync — see RFC-AITP-0001 §5.4.)
        assert!(!s.contains("\"display_name\":"));
        assert!(!s.contains("\"extensions\":"));
        assert!(!s.contains("\"accepted_identity_types\":"));
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
