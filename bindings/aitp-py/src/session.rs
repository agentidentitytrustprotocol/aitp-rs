//! Initiator- and responder-side handshake sessions.
//!
//! Each method consumes/produces JSON strings that are HTTP request /
//! response bodies; agent code passes them straight to/from its HTTP
//! layer.

use std::sync::Arc;

use aitp_core::{AitpEnvelope, MessageType, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_envelope::{sign_envelope, sign_envelope_with};
use aitp_handshake::{
    Initiator, MutualCommitAckPayload, MutualCommitPayload, MutualHelloAckPayload,
    MutualHelloPayload, PresentedIdentity, Responder,
};
use aitp_manifest::{Manifest, ManifestEnvelope};
use aitp_tct::TctEnvelope;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use uuid::Uuid;

use crate::helpers::{make_peer_config, NoOpJwksResolver};

// ── Initiator ───────────────────────────────────────────────────────────

/// Outbound handshake session — drives the initiator side.
#[pyclass(name = "InitiatorSession")]
pub struct PyInitiatorSession {
    key: Arc<AitpSigningKey>,
    manifest: Arc<Manifest>,
    inner: Option<Initiator>,
}

impl PyInitiatorSession {
    pub(crate) fn new(key: Arc<AitpSigningKey>, manifest: Arc<Manifest>) -> Self {
        Self {
            key,
            manifest,
            inner: None,
        }
    }
}

#[pymethods]
impl PyInitiatorSession {
    /// Step 1 — build the `MUTUAL_HELLO` envelope.
    ///
    /// `peer_manifest_json` is the `ManifestEnvelope` JSON from the peer's
    /// `GET /.well-known/aitp-manifest`. Returns the envelope JSON to
    /// `POST` to `/aitp/handshake/hello`.
    fn build_hello(
        &mut self,
        peer_manifest_json: &str,
        requested_grants: Vec<String>,
    ) -> PyResult<String> {
        let ManifestEnvelope {
            manifest: peer_manifest,
        } = serde_json::from_str(peer_manifest_json)
            .map_err(|e| PyValueError::new_err(format!("invalid peer manifest JSON: {e}")))?;

        // The pinned-key identity proof binds (message_id, timestamp), so
        // the envelope MUST be signed with the same pair the state
        // machine used to mint the proof.
        let msg_id = Uuid::new_v4();
        let ts = Timestamp::now();
        let jwks = NoOpJwksResolver;
        let cfg = make_peer_config(&self.key, &self.manifest, &jwks);
        let subject = self.manifest.identity_hint.subject.clone();

        let (initiator, hello) = Initiator::start(
            &cfg,
            PresentedIdentity::PinnedKey { subject },
            &peer_manifest.aid,
            &msg_id,
            ts,
            requested_grants,
        )
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        self.inner = Some(initiator);

        let payload =
            serde_json::to_value(&hello).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let env = sign_envelope_with(&self.key, MessageType::MutualHello, payload, msg_id, ts)
            .map_err(PyRuntimeError::new_err)?;
        serde_json::to_string(&env).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Step 2 — process `MUTUAL_HELLO_ACK`, produce `MUTUAL_COMMIT`.
    ///
    /// `hello_ack_json` is the response body from `/aitp/handshake/hello`.
    /// `session_id` is the `X-Aitp-Session-Id` response header (echoed
    /// back on the commit `POST`). Returns the `MUTUAL_COMMIT` envelope
    /// JSON.
    fn process_hello_ack(&mut self, hello_ack_json: &str, _session_id: &str) -> PyResult<String> {
        let envelope: AitpEnvelope = serde_json::from_str(hello_ack_json)
            .map_err(|e| PyValueError::new_err(format!("invalid envelope JSON: {e}")))?;
        let ack: MutualHelloAckPayload = serde_json::from_value(envelope.payload.clone())
            .map_err(|e| PyValueError::new_err(format!("invalid hello_ack payload: {e}")))?;

        let jwks = NoOpJwksResolver;
        let cfg = make_peer_config(&self.key, &self.manifest, &jwks);
        let commit = self
            .inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("call build_hello() first"))?
            .on_hello_ack(&envelope, &ack, &cfg)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        // MUTUAL_COMMIT carries no pinned-key proof, so a fresh
        // (message_id, timestamp) is fine.
        let payload =
            serde_json::to_value(&commit).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let env = sign_envelope(&self.key, MessageType::MutualCommit, payload)
            .map_err(PyRuntimeError::new_err)?;
        serde_json::to_string(&env).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Step 3 — process `MUTUAL_COMMIT_ACK`. Returns the `TctEnvelope`
    /// JSON: the TCT the peer issued to us. Store it and present it as
    /// `X-AITP-TCT` on subsequent capability calls.
    fn complete(&mut self, commit_ack_json: &str) -> PyResult<String> {
        let envelope: AitpEnvelope = serde_json::from_str(commit_ack_json)
            .map_err(|e| PyValueError::new_err(format!("invalid envelope JSON: {e}")))?;
        let ack: MutualCommitAckPayload = serde_json::from_value(envelope.payload.clone())
            .map_err(|e| PyValueError::new_err(format!("invalid commit_ack payload: {e}")))?;

        let jwks = NoOpJwksResolver;
        let cfg = make_peer_config(&self.key, &self.manifest, &jwks);
        let tct = self
            .inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("call process_hello_ack() first"))?
            .on_commit_ack(&envelope, &ack, &cfg)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        serde_json::to_string(&TctEnvelope { tct })
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}

// ── Responder ───────────────────────────────────────────────────────────

/// Inbound handshake session — drives the responder side.
#[pyclass(name = "ResponderSession")]
pub struct PyResponderSession {
    key: Arc<AitpSigningKey>,
    manifest: Arc<Manifest>,
    inner: Option<Responder>,
}

impl PyResponderSession {
    pub(crate) fn new(key: Arc<AitpSigningKey>, manifest: Arc<Manifest>) -> Self {
        Self {
            key,
            manifest,
            inner: None,
        }
    }
}

#[pymethods]
impl PyResponderSession {
    /// Process an incoming `MUTUAL_HELLO` envelope.
    ///
    /// `hello_json` is the `POST /aitp/handshake/hello` request body.
    /// Returns `(hello_ack_json, session_id)` — set `hello_ack_json` as
    /// the response body and `session_id` as the `X-Aitp-Session-Id`
    /// response header.
    fn process_hello(&mut self, hello_json: &str) -> PyResult<(String, String)> {
        let envelope: AitpEnvelope = serde_json::from_str(hello_json)
            .map_err(|e| PyValueError::new_err(format!("invalid envelope JSON: {e}")))?;
        let hello: MutualHelloPayload = serde_json::from_value(envelope.payload.clone())
            .map_err(|e| PyValueError::new_err(format!("invalid hello payload: {e}")))?;

        // The HELLO_ACK identity proof binds (message_id, timestamp);
        // sign the ack envelope with the same pair.
        let ack_msg_id = Uuid::new_v4();
        let ack_ts = Timestamp::now();
        let jwks = NoOpJwksResolver;
        let cfg = make_peer_config(&self.key, &self.manifest, &jwks);
        let subject = self.manifest.identity_hint.subject.clone();
        // Mutual handshake: the responder must also receive a TCT, so it
        // requests every capability the initiator's manifest offers.
        let requested = hello.manifest.offered_capabilities.clone();

        let (responder, ack) = Responder::on_hello(
            &envelope,
            &hello,
            PresentedIdentity::PinnedKey { subject },
            &ack_msg_id,
            ack_ts,
            &cfg,
            requested,
        )
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        let session_id = Uuid::new_v4().to_string();
        self.inner = Some(responder);

        let payload =
            serde_json::to_value(&ack).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let env = sign_envelope_with(
            &self.key,
            MessageType::MutualHelloAck,
            payload,
            ack_msg_id,
            ack_ts,
        )
        .map_err(PyRuntimeError::new_err)?;
        let ack_json =
            serde_json::to_string(&env).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok((ack_json, session_id))
    }

    /// Process an incoming `MUTUAL_COMMIT` envelope.
    ///
    /// `commit_json` is the `POST /aitp/handshake/commit` request body.
    /// Returns `(commit_ack_json, tct_json)` — set `commit_ack_json` as
    /// the response body; `tct_json` is the `TctEnvelope` JSON the
    /// initiator issued to us.
    fn process_commit(&mut self, commit_json: &str) -> PyResult<(String, String)> {
        let envelope: AitpEnvelope = serde_json::from_str(commit_json)
            .map_err(|e| PyValueError::new_err(format!("invalid envelope JSON: {e}")))?;
        let commit: MutualCommitPayload = serde_json::from_value(envelope.payload.clone())
            .map_err(|e| PyValueError::new_err(format!("invalid commit payload: {e}")))?;

        let jwks = NoOpJwksResolver;
        let cfg = make_peer_config(&self.key, &self.manifest, &jwks);
        let (ack, held_tct) = self
            .inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("call process_hello() first"))?
            .on_commit(&envelope, &commit, &cfg)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        let payload =
            serde_json::to_value(&ack).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let env = sign_envelope(&self.key, MessageType::MutualCommitAck, payload)
            .map_err(PyRuntimeError::new_err)?;
        let ack_json =
            serde_json::to_string(&env).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let tct_json = serde_json::to_string(&TctEnvelope { tct: held_tct })
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok((ack_json, tct_json))
    }
}
