//! Identity descriptors and proof verifiers (RFC-AITP-0002).
//!
//! AITP carries a single `IdentityDescriptor` shape at the wire level:
//!
//! ```json
//! {
//!   "type":       "oidc" | "pinned_key",
//!   "issuer":     "...",      // required when type=oidc
//!   "subject":    "...",
//!   "proof":      "...",      // JWT for oidc; base64url sig for pinned_key
//!   "public_key": "..."       // required when type=pinned_key
//! }
//! ```
//!
//! This module defines the wire struct, plus helper enums/methods to make
//! the type-vs-shape distinction ergonomic in Rust.

use aitp_core::RawUrl;
use serde::{Deserialize, Serialize};

/// Identity descriptor carried in handshake payloads (`payload.identity`).
///
/// Structurally a single object with a `type` discriminator; we keep it
/// flat rather than a tagged enum to mirror the wire format. Use
/// [`IdentityDescriptor::kind`] to branch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityDescriptor {
    /// Identity mechanism: `oidc` or `pinned_key`.
    #[serde(rename = "type")]
    pub kind: IdentityKind,
    /// OIDC issuer URI (required when type=oidc). [`RawUrl`] so the
    /// canonical-form bytes match what the issuer signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<RawUrl>,
    /// Agent subject identifier.
    pub subject: String,
    /// JWT (oidc) or base64url signature (pinned_key).
    pub proof: String,
    /// Pinned 32-byte raw public key, base64url-unpadded (required when
    /// type=pinned_key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

/// Identity mechanism discriminator.
///
/// Marked `#[non_exhaustive]` (matches [`aitp_manifest::IdentityHintKind`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IdentityKind {
    /// OIDC OpenID Connect provider.
    Oidc,
    /// Pinned Ed25519 public key.
    PinnedKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trip_oidc() {
        let v = json!({
            "type": "oidc",
            "issuer": "https://idp.example.com/",
            "subject": "agent-a",
            "proof": "eyJhbGc..."
        });
        let i: IdentityDescriptor = serde_json::from_value(v).unwrap();
        assert_eq!(i.kind, IdentityKind::Oidc);
        assert!(i.issuer.is_some());
        assert!(i.public_key.is_none());
    }

    #[test]
    fn round_trip_pinned() {
        let v = json!({
            "type": "pinned_key",
            "subject": "internal-1",
            "proof": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        });
        let i: IdentityDescriptor = serde_json::from_value(v).unwrap();
        assert_eq!(i.kind, IdentityKind::PinnedKey);
        assert!(i.public_key.is_some());
        assert!(i.issuer.is_none());
    }

    #[test]
    fn rejects_unknown_field() {
        let v = json!({"type": "oidc", "subject": "x", "proof": "y", "rogue": 1});
        assert!(serde_json::from_value::<IdentityDescriptor>(v).is_err());
    }

    #[test]
    fn rejects_unknown_kind() {
        let v = json!({"type": "x509", "subject": "x", "proof": "y"});
        assert!(serde_json::from_value::<IdentityDescriptor>(v).is_err());
    }
}
