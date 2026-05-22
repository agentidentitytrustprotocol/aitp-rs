//! `AitpAgent` — an Ed25519 identity plus its published Manifest.

use std::sync::Arc;

use aitp_crypto::AitpSigningKey;
use aitp_manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder, ManifestEnvelope};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::session::{JsInitiatorSession, JsResponderSession};
use crate::tct::{js_verify_tct, JsTctIdentity};

/// Options for `buildManifest`.
#[napi(object)]
pub struct ManifestOpts {
    /// Human-readable agent name; also the pinned-key identity subject.
    pub display_name: String,
    /// Absolute URL of this agent's handshake endpoint.
    pub handshake_endpoint: String,
    /// Capabilities this agent offers to peers.
    pub offered_caps: Vec<String>,
    /// Capabilities a peer must grant back (optional).
    pub required_caps: Option<Vec<String>>,
    /// Manifest TTL in seconds (optional; defaults to 3600).
    pub ttl_secs: Option<i32>,
}

/// An AITP agent: an Ed25519 signing key and (once built) its Manifest.
#[napi]
pub struct AitpAgent {
    key: Arc<AitpSigningKey>,
    manifest: Option<Manifest>,
}

#[napi]
impl AitpAgent {
    /// Generate an agent with a fresh random Ed25519 key.
    #[napi(factory)]
    pub fn generate() -> Self {
        Self {
            key: Arc::new(AitpSigningKey::generate()),
            manifest: None,
        }
    }

    /// Construct an agent from a 32-byte Ed25519 seed (deterministic).
    #[napi(factory)]
    pub fn from_seed(seed: Buffer) -> Result<Self> {
        let arr: [u8; 32] = seed
            .as_ref()
            .try_into()
            .map_err(|_| Error::from_reason("seed must be exactly 32 bytes"))?;
        Ok(Self {
            key: Arc::new(AitpSigningKey::from_seed(&arr)),
            manifest: None,
        })
    }

    /// The agent's AID string (`aid:pubkey:...`).
    #[napi(getter)]
    pub fn aid(&self) -> String {
        self.key.aid().to_string()
    }

    /// Build and sign the agent's Manifest. Returns `ManifestEnvelope`
    /// JSON and caches the Manifest for `newSession` / `newResponder`.
    #[napi]
    pub fn build_manifest(&mut self, opts: ManifestOpts) -> Result<String> {
        let endpoint: url::Url = opts
            .handshake_endpoint
            .parse()
            .map_err(|e| Error::from_reason(format!("invalid handshakeEndpoint URL: {e}")))?;

        let mut builder = ManifestBuilder::new(&self.key)
            .display_name(&opts.display_name)
            .handshake_endpoint(endpoint)
            .identity_hint(IdentityHint {
                kind: IdentityHintKind::PinnedKey,
                subject: opts.display_name.clone(),
                issuer: None,
                public_key: Some(aitp_core::base64url::encode(
                    &self.key.verifying_key().to_bytes(),
                )),
            })
            .accept_identity_type("pinned_key")
            .ttl_secs(opts.ttl_secs.unwrap_or(3600) as i64);

        for cap in opts.offered_caps {
            builder = builder.offer(cap);
        }
        for cap in opts.required_caps.unwrap_or_default() {
            builder = builder.require(cap);
        }

        let manifest = builder
            .build()
            .map_err(|e| Error::from_reason(format!("manifest build failed: {e}")))?;
        self.manifest = Some(manifest.clone());

        serde_json::to_string(&ManifestEnvelope { manifest })
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Create a new outbound (initiator) handshake session.
    #[napi]
    pub fn new_session(&self) -> Result<JsInitiatorSession> {
        let manifest = self.cached_manifest()?;
        Ok(JsInitiatorSession::new(self.key.clone(), manifest))
    }

    /// Create a new inbound (responder) handshake session.
    #[napi]
    pub fn new_responder(&self) -> Result<JsResponderSession> {
        let manifest = self.cached_manifest()?;
        Ok(JsResponderSession::new(self.key.clone(), manifest))
    }

    /// Verify a TCT JSON string and require `requiredGrant`. Rejects on
    /// an invalid, mis-audienced, expired, or under-scoped TCT.
    #[napi]
    pub fn verify_tct(&self, tct_json: String, required_grant: String) -> Result<JsTctIdentity> {
        js_verify_tct(&self.key, &tct_json, &required_grant)
    }
}

impl AitpAgent {
    fn cached_manifest(&self) -> Result<Arc<Manifest>> {
        self.manifest
            .clone()
            .map(Arc::new)
            .ok_or_else(|| Error::from_reason("call buildManifest() before creating a session"))
    }
}
