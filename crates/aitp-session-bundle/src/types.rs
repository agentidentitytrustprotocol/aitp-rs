//! Wire types for Session Trust Bundle (RFC-AITP-0010 §3).

use aitp_core::{Aid, ExtensionsMap, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Coordinator-attested session membership artifact (RFC-AITP-0010 §3).
///
/// The schema is `additionalProperties: false`, with an explicit
/// `extensions` slot reserved per RFC-AITP-0001 §7.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionTrustBundle {
    /// MUST be `"aitp/0.2"` for this RFC.
    pub version: String,
    /// UUID v4 unique to this session. Used as a replay-binding scope.
    pub session_id: Uuid,
    /// Coordinator's AID. MUST match the `issuer` of every embedded TCT.
    pub coordinator: Aid,
    /// When this bundle was signed.
    pub issued_at: Timestamp,
    /// When the bundle MUST NOT be used after. MUST equal
    /// `min(participants[*].tct.expires_at)` (RFC-AITP-0010 §6).
    pub expires_at: Timestamp,
    /// One entry per session participant.
    pub participants: Vec<ParticipantEntry>,
    /// Forward-compatible extension namespace (RFC-AITP-0001 §7).
    ///
    /// **Presence-sensitive**, deliberately modeled as `Option<ExtensionsMap>`
    /// rather than a defaulted empty map with `skip_serializing_if =
    /// "is_empty"`. Under RFC 8785 canonicalization, absent (`None`) emits
    /// no `extensions` key at all, while present-but-empty
    /// (`Some(ExtensionsMap::new())`) emits `"extensions":{}` — different
    /// bytes, different digest, different signature. Silently normalizing
    /// one into the other would change the signing input and break
    /// verification against a conformant peer (RFC-AITP-0001 §5.4.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionsMap>,
    /// Coordinator's signature over the canonical bundle JSON
    /// excluding `signature`. JCS rules per RFC-AITP-0001 §5.4.1.
    pub signature: String,
}

/// One participant in a [`SessionTrustBundle`]: their AID + the
/// coordinator-issued TCT they received during their bilateral
/// handshake.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ParticipantEntry {
    /// Participant's AID. MUST equal the embedded TCT's `aud` claim.
    pub aid: Aid,
    /// Coordinator → participant TCT as an **opaque compact JWS
    /// string** (`typ: aitp-tct+jwt`, RFC-AITP-0001 §5.4.5), carried
    /// verbatim — the outer bundle signature covers it byte-for-byte.
    pub tct: String,
}

/// HTTP/transport-wrapped form (the `{"session_bundle": {...}}` shape
/// that matches the JSON Schema `$id`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionBundleEnvelope {
    /// The signed inner bundle.
    pub session_bundle: SessionTrustBundle,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_unknown_top_field() {
        let v = json!({
            "version": "aitp/0.2",
            "session_id": "00000000-0000-4000-8000-000000000000",
            "coordinator": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "issued_at": 1_700_000_000,
            "expires_at": 1_700_010_000,
            "participants": [],
            "signature": "A".repeat(86),
            "rogue": 1,
        });
        assert!(serde_json::from_value::<SessionTrustBundle>(v).is_err());
    }
}
