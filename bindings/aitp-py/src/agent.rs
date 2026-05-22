//! `AitpAgent` — an Ed25519 identity plus its published Manifest.

use std::sync::Arc;

use aitp_crypto::AitpSigningKey;
use aitp_manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder, ManifestEnvelope};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use crate::session::{PyInitiatorSession, PyResponderSession};
use crate::tct::{py_verify_tct, PyTctIdentity};

/// An AITP agent: an Ed25519 signing key and (once built) its Manifest.
#[pyclass(name = "AitpAgent")]
pub struct PyAitpAgent {
    key: Arc<AitpSigningKey>,
    manifest: Option<Manifest>,
}

#[pymethods]
impl PyAitpAgent {
    /// Generate an agent with a fresh random Ed25519 key.
    #[staticmethod]
    fn generate() -> Self {
        Self {
            key: Arc::new(AitpSigningKey::generate()),
            manifest: None,
        }
    }

    /// Construct an agent from a 32-byte Ed25519 seed (deterministic).
    #[staticmethod]
    fn from_seed(seed: &[u8]) -> PyResult<Self> {
        let arr: [u8; 32] = seed
            .try_into()
            .map_err(|_| PyValueError::new_err("seed must be exactly 32 bytes"))?;
        Ok(Self {
            key: Arc::new(AitpSigningKey::from_seed(&arr)),
            manifest: None,
        })
    }

    /// The agent's AID string (`aid:pubkey:...`).
    #[getter]
    fn aid(&self) -> String {
        self.key.aid().to_string()
    }

    /// Build and sign the agent's Manifest. Returns `ManifestEnvelope`
    /// JSON and caches the Manifest for use by `new_session` /
    /// `new_responder`.
    #[pyo3(signature = (display_name, handshake_endpoint, offered_caps, required_caps=None, ttl_secs=None))]
    fn build_manifest(
        &mut self,
        display_name: &str,
        handshake_endpoint: &str,
        offered_caps: Vec<String>,
        required_caps: Option<Vec<String>>,
        ttl_secs: Option<i64>,
    ) -> PyResult<String> {
        let endpoint: url::Url = handshake_endpoint
            .parse()
            .map_err(|e| PyValueError::new_err(format!("invalid handshake_endpoint URL: {e}")))?;

        let mut builder = ManifestBuilder::new(&self.key)
            .display_name(display_name)
            .handshake_endpoint(endpoint)
            .identity_hint(IdentityHint {
                kind: IdentityHintKind::PinnedKey,
                subject: display_name.to_string(),
                issuer: None,
                public_key: Some(aitp_core::base64url::encode(
                    &self.key.verifying_key().to_bytes(),
                )),
            })
            .accept_identity_type("pinned_key")
            .ttl_secs(ttl_secs.unwrap_or(3600));

        for cap in offered_caps {
            builder = builder.offer(cap);
        }
        for cap in required_caps.unwrap_or_default() {
            builder = builder.require(cap);
        }

        let manifest = builder
            .build()
            .map_err(|e| PyRuntimeError::new_err(format!("manifest build failed: {e}")))?;
        self.manifest = Some(manifest.clone());

        serde_json::to_string(&ManifestEnvelope { manifest })
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Create a new outbound (initiator) handshake session.
    fn new_session(&self) -> PyResult<PyInitiatorSession> {
        let manifest = self.cached_manifest()?;
        Ok(PyInitiatorSession::new(self.key.clone(), manifest))
    }

    /// Create a new inbound (responder) handshake session.
    fn new_responder(&self) -> PyResult<PyResponderSession> {
        let manifest = self.cached_manifest()?;
        Ok(PyResponderSession::new(self.key.clone(), manifest))
    }

    /// Verify a TCT JSON string and require `required_grant`. Raises on
    /// an invalid, mis-audienced, expired, or under-scoped TCT.
    fn verify_tct(&self, tct_json: &str, required_grant: &str) -> PyResult<PyTctIdentity> {
        py_verify_tct(&self.key, tct_json, required_grant)
    }
}

impl PyAitpAgent {
    fn cached_manifest(&self) -> PyResult<Arc<Manifest>> {
        self.manifest.clone().map(Arc::new).ok_or_else(|| {
            PyRuntimeError::new_err("call build_manifest() before creating a session")
        })
    }
}
