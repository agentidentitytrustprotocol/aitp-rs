//! Identity descriptors and proof verifiers (RFC-AITP-0002).
//!
//! AITP carries a single `IdentityDescriptor` shape at the wire level:
//!
//! ```json
//! {
//!   "type":       "oidc" | "pinned_key" | "spiffe",
//!   "issuer":     "...",      // required when type=oidc
//!   "subject":    "...",
//!   "svid_type":  "...",      // required when type=spiffe
//!   "proof":      "...",      // JWT (oidc, jwt-svid) or base64url sig
//!   "x5c":        ["..."],    // required when svid_type=x509-svid
//!   "public_key": "...",      // required when type=pinned_key
//!   "extensions": { ... }     // optional (RFC-AITP-0002 §1)
//! }
//! ```
//!
//! This module defines the wire struct, plus helper enums/methods to make
//! the type-vs-shape distinction ergonomic in Rust.

use crate::core::{ExtensionsMap, RawUrl};
use serde::{Deserialize, Serialize};

/// Identity descriptor carried in handshake payloads (`payload.identity`).
///
/// Structurally a single object with a `type` discriminator; we keep it
/// flat rather than a tagged enum to mirror the wire format. Use
/// [`IdentityDescriptor::kind`] to branch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct IdentityDescriptor {
    /// Identity mechanism: `oidc`, `pinned_key` or `spiffe`.
    #[serde(rename = "type")]
    pub kind: IdentityKind,
    /// OIDC issuer URI (required when type=oidc). [`RawUrl`] so the
    /// canonical-form bytes match what the issuer signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<RawUrl>,
    /// Agent subject identifier (a SPIFFE ID when type=spiffe).
    pub subject: String,
    // SVID form (type=spiffe only). Read by `aitp-experimental`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) svid_type: Option<SvidType>,
    /// The identity proof: a JWT (oidc) or a base64url signature
    /// (pinned_key).
    pub proof: String,
    // Certificate chain (type=spiffe only). Read by `aitp-experimental`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) x5c: Option<Vec<String>>,
    /// Pinned 32-byte raw public key, base64url-unpadded (required when
    /// type=pinned_key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Optional extension namespace (RFC-AITP-0001 §7 / RFC-AITP-0002 §1).
    ///
    /// **Presence-sensitive**, deliberately modeled as `Option<ExtensionsMap>`
    /// rather than a defaulted empty map — absence (`None`) omits the key
    /// entirely on the wire, matching the shared convention used
    /// throughout this codebase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionsMap>,
}

impl IdentityDescriptor {
    /// A `pinned_key` descriptor (RFC-AITP-0002 §3). `public_key` is the
    /// sender's raw public key, base64url-unpadded, and `proof` the output
    /// of [`sign_pinned_key_proof`](crate::handshake::sign_pinned_key_proof).
    pub fn pinned_key(
        subject: impl Into<String>,
        public_key: impl Into<String>,
        proof: impl Into<String>,
    ) -> Self {
        Self {
            kind: IdentityKind::PinnedKey,
            issuer: None,
            subject: subject.into(),
            svid_type: None,
            proof: proof.into(),
            x5c: None,
            public_key: Some(public_key.into()),
            extensions: None,
        }
    }

    /// An `oidc` descriptor (RFC-AITP-0002 §2). `proof` is the ID token.
    pub fn oidc(issuer: RawUrl, subject: impl Into<String>, proof: impl Into<String>) -> Self {
        Self {
            kind: IdentityKind::Oidc,
            issuer: Some(issuer),
            subject: subject.into(),
            svid_type: None,
            proof: proof.into(),
            x5c: None,
            public_key: None,
            extensions: None,
        }
    }
}

/// Identity mechanism discriminator.
///
/// Marked `#[non_exhaustive]` (matches [`crate::manifest::IdentityHintKind`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IdentityKind {
    /// OIDC OpenID Connect provider.
    Oidc,
    /// Pinned Ed25519 public key.
    PinnedKey,
    /// SPIFFE workload identity (RFC-AITP-0002 §6, registry status
    /// Proposed). `aitp` does not verify it; a
    /// [`crate::handshake::IdentityVerifier`] can.
    Spiffe,
}

impl IdentityKind {
    /// The RFC-AITP-0002 wire name (`oidc`, `pinned_key`, `spiffe`), as
    /// listed in a Manifest's `accepted_identity_types`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::PinnedKey => "pinned_key",
            Self::Spiffe => "spiffe",
        }
    }
}

pub(crate) use svid::SvidType;

pub(crate) mod svid {
    use serde::{Deserialize, Serialize};

    /// SPIFFE SVID form of a `spiffe` descriptor (RFC-AITP-0002 §6.1).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[non_exhaustive]
    pub enum SvidType {
        /// `proof` is a JWT-SVID (RFC-AITP-0002 §6.3).
        #[serde(rename = "jwt-svid")]
        JwtSvid,
        /// `proof` is a signature by the X509-SVID key and `x5c` carries
        /// the chain (RFC-AITP-0002 §6.4).
        #[serde(rename = "x509-svid")]
        X509Svid,
    }
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
    fn round_trip_spiffe_x509() {
        let v = json!({
            "type": "spiffe",
            "subject": "spiffe://prod.example.com/ns/payments/sa/agent",
            "svid_type": "x509-svid",
            "proof": "sig",
            "x5c": ["MIIB"]
        });
        let i: IdentityDescriptor = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(i.kind, IdentityKind::Spiffe);
        assert_eq!(i.svid_type, Some(SvidType::X509Svid));
        assert_eq!(serde_json::to_value(&i).unwrap(), v);
    }

    #[test]
    fn rejects_unknown_svid_type() {
        let v = json!({"type": "spiffe", "subject": "x", "svid_type": "cwt-svid", "proof": "y"});
        assert!(serde_json::from_value::<IdentityDescriptor>(v).is_err());
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
