//! Manifest builder.
//!
//! Builds a fully-signed [`Manifest`] from the issuer's signing key plus
//! configuration, following RFC-AITP-0003 §3 and §6.

use crate::types::{IdentityHint, IdentityHintKind, Manifest, ManifestPop};
use crate::ManifestError;
use aitp_core::{base64url, jcs, ExtensionsMap, Timestamp};
use aitp_crypto::AitpSigningKey;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use url::Url;

/// Default Manifest TTL (24 hours).
pub const DEFAULT_MANIFEST_TTL_SECS: i64 = 24 * 3600;

/// Fluent builder for issuing a Manifest.
///
/// ```ignore
/// use aitp_manifest::{ManifestBuilder, IdentityHint, IdentityHintKind};
/// let manifest = ManifestBuilder::new(&signing_key)
///     .handshake_endpoint("https://a.example.com/handshake".parse()?)
///     .identity_hint(IdentityHint {
///         kind: IdentityHintKind::Oidc,
///         subject: "agent-a".into(),
///         issuer: Some("https://idp.example.com".parse()?),
///         public_key: None,
///     })
///     .accept_trust_anchor("https://idp.example.com".parse()?)
///     .offer("demo.echo")
///     .ttl_secs(3600)
///     .build()?;
/// ```
pub struct ManifestBuilder<'a> {
    signing_key: &'a AitpSigningKey,
    handshake_endpoint: Option<Url>,
    accepted_trust_anchors: Vec<Url>,
    accepted_identity_types: Vec<String>,
    offered_capabilities: Vec<String>,
    required_peer_capabilities: Vec<String>,
    identity_hint: Option<IdentityHint>,
    ttl_secs: i64,
    display_name: Option<String>,
    extensions: ExtensionsMap,
    /// Override `published_at` for tests / fixed-clock scenarios.
    now_override: Option<Timestamp>,
}

impl<'a> ManifestBuilder<'a> {
    /// Begin a new Manifest, signed by `signing_key`.
    pub fn new(signing_key: &'a AitpSigningKey) -> Self {
        Self {
            signing_key,
            handshake_endpoint: None,
            accepted_trust_anchors: Vec::new(),
            accepted_identity_types: Vec::new(),
            offered_capabilities: Vec::new(),
            required_peer_capabilities: Vec::new(),
            identity_hint: None,
            ttl_secs: DEFAULT_MANIFEST_TTL_SECS,
            display_name: None,
            extensions: ExtensionsMap::new(),
            now_override: None,
        }
    }

    /// Set the handshake endpoint URL.
    pub fn handshake_endpoint(mut self, url: Url) -> Self {
        self.handshake_endpoint = Some(url);
        self
    }

    /// Set the identity hint block.
    pub fn identity_hint(mut self, hint: IdentityHint) -> Self {
        self.identity_hint = Some(hint);
        self
    }

    /// Append a capability to `offered_capabilities`.
    pub fn offer(mut self, capability: impl Into<String>) -> Self {
        self.offered_capabilities.push(capability.into());
        self
    }

    /// Append a capability to `required_peer_capabilities`.
    pub fn require(mut self, capability: impl Into<String>) -> Self {
        self.required_peer_capabilities.push(capability.into());
        self
    }

    /// Append an issuer URI to `accepted_trust_anchors`.
    pub fn accept_trust_anchor(mut self, issuer: Url) -> Self {
        self.accepted_trust_anchors.push(issuer);
        self
    }

    /// Append an identity type (`"oidc"`, `"pinned_key"`).
    pub fn accept_identity_type(mut self, ty: impl Into<String>) -> Self {
        self.accepted_identity_types.push(ty.into());
        self
    }

    /// Override the default Manifest TTL.
    pub fn ttl_secs(mut self, secs: i64) -> Self {
        self.ttl_secs = secs;
        self
    }

    /// Set the human-readable display name.
    pub fn display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Insert a forward-compatible extension key.
    pub fn extension(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.extensions.insert(key, value);
        self
    }

    /// Override `published_at`. Used by tests and fixture issuers; production
    /// callers should leave this unset and let the builder use
    /// `Timestamp::now()`.
    pub fn published_at(mut self, ts: Timestamp) -> Self {
        self.now_override = Some(ts);
        self
    }

    /// Construct, sign, and return the Manifest.
    pub fn build(self) -> Result<Manifest, ManifestError> {
        // 1. Required-field validation.
        let handshake_endpoint = self
            .handshake_endpoint
            .ok_or(ManifestError::MissingField("handshake_endpoint"))?;
        let identity_hint = self
            .identity_hint
            .ok_or(ManifestError::MissingField("identity_hint"))?;
        validate_identity_hint(&identity_hint)?;

        // 2. Generate a 128-bit (16-byte) random PoP challenge.
        let mut challenge_bytes = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut challenge_bytes)
            .map_err(|e| ManifestError::Rng(e.to_string()))?;
        let challenge = base64url::encode(&challenge_bytes);
        debug_assert_eq!(
            challenge.len(),
            22,
            "16 bytes encode to 22 base64url-unpadded chars"
        );

        // 3. Sign `sha256(base64url_decode(challenge))` per RFC-AITP-0001
        //    §5.4.2 (unified PoP signing-input convention) and RFC-AITP-0003
        //    §3 — the hash input is the 16 raw decoded bytes, NOT the ASCII
        //    bytes of the base64url-encoded string. Pinned by KAT
        //    `kat-manifest-pop-001` in `jcs-sha256.json`.
        let pop_input = Sha256::digest(challenge_bytes);
        let pop_signature = self.signing_key.sign(&pop_input);

        // 4. Compose published_at / expires_at.
        let published_at = self.now_override.unwrap_or_else(Timestamp::now);
        let expires_at = published_at.plus_secs(self.ttl_secs);

        // 5. Assemble the unsigned Manifest body for JCS canonicalization.
        let aid = self.signing_key.aid().clone();
        let pop = ManifestPop {
            challenge,
            signature: pop_signature.into_string(),
        };

        let unsigned = ManifestSigningView {
            version: "aitp/0.1",
            aid: &aid,
            display_name: self.display_name.as_deref(),
            identity_hint: &identity_hint,
            handshake_endpoint: &handshake_endpoint,
            accepted_trust_anchors: &self.accepted_trust_anchors,
            accepted_identity_types: &self.accepted_identity_types,
            offered_capabilities: &self.offered_capabilities,
            required_peer_capabilities: &self.required_peer_capabilities,
            proof_of_possession: &pop,
            published_at: &published_at,
            expires_at: &expires_at,
            extensions: &self.extensions,
        };
        let canonical = jcs::canonicalize_serializable(&unsigned)
            .map_err(|e| ManifestError::Canonicalization(e.to_string()))?;
        let digest = Sha256::digest(&canonical);
        let signature = self.signing_key.sign(&digest);

        Ok(Manifest {
            version: "aitp/0.1".into(),
            aid,
            display_name: self.display_name,
            identity_hint,
            handshake_endpoint,
            accepted_trust_anchors: self.accepted_trust_anchors,
            accepted_identity_types: self.accepted_identity_types,
            offered_capabilities: self.offered_capabilities,
            required_peer_capabilities: self.required_peer_capabilities,
            proof_of_possession: pop,
            published_at,
            expires_at,
            extensions: self.extensions,
            signature: signature.into_string(),
        })
    }
}

fn validate_identity_hint(hint: &IdentityHint) -> Result<(), ManifestError> {
    match hint.kind {
        IdentityHintKind::Oidc => {
            if hint.issuer.is_none() {
                return Err(ManifestError::IdentityHintMalformed(
                    "oidc requires `issuer`",
                ));
            }
            if hint.public_key.is_some() {
                return Err(ManifestError::IdentityHintMalformed(
                    "oidc must not include `public_key`",
                ));
            }
        }
        IdentityHintKind::PinnedKey => {
            if hint.public_key.is_none() {
                return Err(ManifestError::IdentityHintMalformed(
                    "pinned_key requires `public_key`",
                ));
            }
        }
    }
    Ok(())
}

/// Serialization view of a Manifest with the `signature` field elided.
///
/// The exact field order, names, and skip-when-empty rules MUST mirror
/// `Manifest` so that the bytes hashed at issuance are byte-identical to
/// the bytes hashed at verification.
#[derive(Serialize)]
pub(crate) struct ManifestSigningView<'a> {
    pub version: &'a str,
    pub aid: &'a aitp_core::Aid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<&'a str>,
    pub identity_hint: &'a IdentityHint,
    pub handshake_endpoint: &'a Url,
    pub accepted_trust_anchors: &'a [Url],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    pub accepted_identity_types: &'a [String],
    pub offered_capabilities: &'a [String],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    pub required_peer_capabilities: &'a [String],
    pub proof_of_possession: &'a ManifestPop,
    pub published_at: &'a Timestamp,
    pub expires_at: &'a Timestamp,
    #[serde(skip_serializing_if = "ExtensionsMap::is_empty")]
    pub extensions: &'a ExtensionsMap,
}

impl Default for ManifestBuilder<'_> {
    fn default() -> Self {
        // No reasonable default key; consumers must call `new`.
        // We provide `Default` only via this stub that panics so we don't
        // accidentally encourage default-initialised builders.
        panic!("ManifestBuilder requires an issuer signing key; use ManifestBuilder::new")
    }
}
