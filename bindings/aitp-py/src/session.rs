//! Initiator- and responder-side handshake sessions.
//!
//! Each method consumes/produces JSON strings that are HTTP request /
//! response bodies; agent code passes them straight to/from its HTTP
//! layer.
//!
//! Sessions are constructed with a [`SessionContext`] carrying the JWKS
//! provider (for OIDC verification), accepted trust anchors, and the
//! agent's own identity-hint kind (which determines whether HELLO /
//! HELLO_ACK should present a pinned-key or OIDC proof). When the agent
//! is in OIDC mode, `build_hello` / `process_hello` require an
//! `oidc_mint_jwt` callable that mints the JWT with the handshake-
//! generated nonce.

use std::sync::Arc;

use aitp_core::{AitpEnvelope, MessageType, RawUrl, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_envelope::{sign_envelope, sign_envelope_with};
use aitp_handshake::{
    CompletedHandshake, Initiator, JwksResolver, MutualCommitAckPayload, MutualCommitPayload,
    MutualHelloAckPayload, MutualHelloPayload, PresentedIdentity, Responder,
};
use aitp_manifest::{IdentityHintKind, Manifest, ManifestEnvelope};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use uuid::Uuid;

use crate::helpers::{make_peer_config, NoOpJwksResolver};
use crate::oidc::make_oidc_minter;

/// Per-session configuration cached at agent.new_session() time.
pub struct SessionContext {
    /// JWKS resolver — `None` ⇒ no resolver was wired in (pinned-key-only).
    pub jwks: Option<Arc<dyn JwksResolver + Send + Sync + 'static>>,
    /// Accepted OIDC issuer trust anchors for verifying peer identity.
    pub trust_anchors: Vec<RawUrl>,
    /// Our own manifest's identity_hint.kind — drives whether we present
    /// pinned-key or OIDC in outbound payloads.
    pub identity_kind: IdentityHintKind,
    /// Our own manifest identity_hint.subject — used as the OIDC `sub`
    /// claim placeholder and pinned-key `subject` field.
    pub identity_subject: String,
    /// Our own manifest identity_hint.issuer — for OIDC, the URL the
    /// IdP will sign tokens for. None for pinned-key.
    pub identity_issuer: Option<RawUrl>,
}

impl SessionContext {
    /// Build a `PresentedIdentity` for an outbound HELLO / HELLO_ACK.
    ///
    /// In pinned-key mode, returns `PinnedKey { subject }`. In OIDC mode,
    /// requires an `oidc_mint_jwt` callable and returns `OidcMinter`.
    fn presented_identity(&self, oidc_mint_jwt: Option<Py<PyAny>>) -> PyResult<PresentedIdentity> {
        match self.identity_kind {
            IdentityHintKind::PinnedKey => Ok(PresentedIdentity::PinnedKey {
                subject: self.identity_subject.clone(),
            }),
            IdentityHintKind::Oidc => {
                let cb = oidc_mint_jwt.ok_or_else(|| {
                    PyValueError::new_err(
                        "agent manifest is OIDC; `oidc_mint_jwt` callable is required",
                    )
                })?;
                let issuer_raw = self.identity_issuer.as_ref().ok_or_else(|| {
                    PyRuntimeError::new_err(
                        "OIDC identity_hint missing issuer (build_manifest invariant violated)",
                    )
                })?;
                let issuer_url = issuer_raw.parse_url().map_err(|e| {
                    PyRuntimeError::new_err(format!("identity_hint.issuer not a URL: {e}"))
                })?;
                Ok(PresentedIdentity::OidcMinter {
                    issuer: issuer_url,
                    subject: self.identity_subject.clone(),
                    mint_jwt: make_oidc_minter(cb),
                })
            }
            // `IdentityHintKind` is `#[non_exhaustive]`; reject any
            // future variant the Python SDK hasn't yet wired up.
            other => Err(PyRuntimeError::new_err(format!(
                "unsupported identity_hint kind {other:?}; \
                 update the Python SDK to handle this variant"
            ))),
        }
    }

    fn jwks_for_call(&self) -> Box<dyn JwksResolver + '_> {
        match &self.jwks {
            Some(arc) => {
                // Re-borrow the trait object behind the Arc for the
                // lifetime of this call. PeerConfig only needs &dyn for
                // one synchronous step.
                Box::new(SessionJwksRef { inner: arc.clone() })
            }
            None => Box::new(NoOpJwksResolver),
        }
    }
}

/// Adapter that lets an `Arc<dyn JwksResolver>` be borrowed as a
/// `&dyn JwksResolver` for one PeerConfig construction.
struct SessionJwksRef {
    inner: Arc<dyn JwksResolver + Send + Sync + 'static>,
}

impl JwksResolver for SessionJwksRef {
    fn resolve(
        &self,
        issuer: &url::Url,
    ) -> Result<Vec<aitp_handshake::JwkPublicKey>, aitp_handshake::ResolveError> {
        self.inner.resolve(issuer)
    }
}

// ── Initiator ───────────────────────────────────────────────────────────

/// Outbound handshake session — drives the initiator side.
#[pyclass(name = "InitiatorSession")]
pub struct PyInitiatorSession {
    key: Arc<AitpSigningKey>,
    manifest: Arc<Manifest>,
    ctx: SessionContext,
    inner: Option<Initiator>,
}

impl PyInitiatorSession {
    pub(crate) fn new(
        key: Arc<AitpSigningKey>,
        manifest: Arc<Manifest>,
        ctx: SessionContext,
    ) -> Self {
        Self {
            key,
            manifest,
            ctx,
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
    ///
    /// `oidc_mint_jwt` is required when this agent's manifest is OIDC;
    /// the callable receives the handshake-generated `pop_nonce` and
    /// must return a freshly-minted JWT whose `nonce` claim equals
    /// that nonce. Ignored for pinned-key agents.
    #[pyo3(signature = (peer_manifest_json, requested_grants, oidc_mint_jwt=None))]
    fn build_hello(
        &mut self,
        peer_manifest_json: &str,
        requested_grants: Vec<String>,
        oidc_mint_jwt: Option<Py<PyAny>>,
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
        let jwks = self.ctx.jwks_for_call();
        let cfg = make_peer_config(
            &self.key,
            &self.manifest,
            jwks.as_ref(),
            &self.ctx.trust_anchors,
        );
        let presented = self.ctx.presented_identity(oidc_mint_jwt)?;

        let (initiator, hello) = Initiator::start(
            &cfg,
            presented,
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
    fn process_hello_ack(&mut self, hello_ack_json: &str, _session_id: &str) -> PyResult<String> {
        let envelope: AitpEnvelope = serde_json::from_str(hello_ack_json)
            .map_err(|e| PyValueError::new_err(format!("invalid envelope JSON: {e}")))?;
        let ack: MutualHelloAckPayload = serde_json::from_value(envelope.payload.clone())
            .map_err(|e| PyValueError::new_err(format!("invalid hello_ack payload: {e}")))?;

        let jwks = self.ctx.jwks_for_call();
        let cfg = make_peer_config(
            &self.key,
            &self.manifest,
            jwks.as_ref(),
            &self.ctx.trust_anchors,
        );
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

    /// Step 3 — process `MUTUAL_COMMIT_ACK`. Returns a JSON object
    /// `{"tct": "<compact JWS>", "grant_voucher": "<compact JWS>" | null}`:
    /// the TCT the peer issued to us, plus the companion grant voucher
    /// (when issued — the voucher is what lets us later mint delegations).
    fn complete(&mut self, commit_ack_json: &str) -> PyResult<String> {
        let envelope: AitpEnvelope = serde_json::from_str(commit_ack_json)
            .map_err(|e| PyValueError::new_err(format!("invalid envelope JSON: {e}")))?;
        let ack: MutualCommitAckPayload = serde_json::from_value(envelope.payload.clone())
            .map_err(|e| PyValueError::new_err(format!("invalid commit_ack payload: {e}")))?;

        let jwks = self.ctx.jwks_for_call();
        let cfg = make_peer_config(
            &self.key,
            &self.manifest,
            jwks.as_ref(),
            &self.ctx.trust_anchors,
        );
        let completed = self
            .inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("call process_hello_ack() first"))?
            .on_commit_ack(&envelope, &ack, &cfg)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        completed_handshake_json(&completed)
    }
}

/// Serialize a [`CompletedHandshake`] to the binding's wire shape:
/// `{"tct": "<compact JWS>", "grant_voucher": "<compact JWS>" | null}`.
fn completed_handshake_json(completed: &CompletedHandshake) -> PyResult<String> {
    let out = serde_json::json!({
        "tct": completed.tct.token,
        "grant_voucher": completed.grant_voucher,
    });
    serde_json::to_string(&out).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

// ── Responder ───────────────────────────────────────────────────────────

/// Inbound handshake session — drives the responder side.
#[pyclass(name = "ResponderSession")]
pub struct PyResponderSession {
    key: Arc<AitpSigningKey>,
    manifest: Arc<Manifest>,
    ctx: SessionContext,
    inner: Option<Responder>,
}

impl PyResponderSession {
    pub(crate) fn new(
        key: Arc<AitpSigningKey>,
        manifest: Arc<Manifest>,
        ctx: SessionContext,
    ) -> Self {
        Self {
            key,
            manifest,
            ctx,
            inner: None,
        }
    }
}

#[pymethods]
impl PyResponderSession {
    /// Process an incoming `MUTUAL_HELLO` envelope.
    ///
    /// `oidc_mint_jwt` is required when this agent's manifest is OIDC;
    /// see `InitiatorSession.build_hello` for semantics.
    #[pyo3(signature = (hello_json, oidc_mint_jwt=None))]
    fn process_hello(
        &mut self,
        hello_json: &str,
        oidc_mint_jwt: Option<Py<PyAny>>,
    ) -> PyResult<(String, String)> {
        let envelope: AitpEnvelope = serde_json::from_str(hello_json)
            .map_err(|e| PyValueError::new_err(format!("invalid envelope JSON: {e}")))?;
        let hello: MutualHelloPayload = serde_json::from_value(envelope.payload.clone())
            .map_err(|e| PyValueError::new_err(format!("invalid hello payload: {e}")))?;

        // The HELLO_ACK identity proof binds (message_id, timestamp);
        // sign the ack envelope with the same pair.
        let ack_msg_id = Uuid::new_v4();
        let ack_ts = Timestamp::now();
        let jwks = self.ctx.jwks_for_call();
        let cfg = make_peer_config(
            &self.key,
            &self.manifest,
            jwks.as_ref(),
            &self.ctx.trust_anchors,
        );
        let presented = self.ctx.presented_identity(oidc_mint_jwt)?;
        // Mutual handshake: the responder must also receive a TCT, so it
        // requests every capability the initiator's manifest offers.
        let requested = hello.manifest.offered_capabilities.clone();

        let (responder, ack) = Responder::on_hello(
            &envelope,
            &hello,
            presented,
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
    fn process_commit(&mut self, commit_json: &str) -> PyResult<(String, String)> {
        let envelope: AitpEnvelope = serde_json::from_str(commit_json)
            .map_err(|e| PyValueError::new_err(format!("invalid envelope JSON: {e}")))?;
        let commit: MutualCommitPayload = serde_json::from_value(envelope.payload.clone())
            .map_err(|e| PyValueError::new_err(format!("invalid commit payload: {e}")))?;

        let jwks = self.ctx.jwks_for_call();
        let cfg = make_peer_config(
            &self.key,
            &self.manifest,
            jwks.as_ref(),
            &self.ctx.trust_anchors,
        );
        let (ack, completed) = self
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
        let completed_json = completed_handshake_json(&completed)?;
        Ok((ack_json, completed_json))
    }
}
