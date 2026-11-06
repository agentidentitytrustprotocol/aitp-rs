//! Initiator- and responder-side handshake sessions.
//!
//! Each method consumes/produces JSON strings that are HTTP request /
//! response bodies; agent code passes them straight to/from its HTTP
//! layer.
//!
//! Sessions are constructed with a [`SessionContext`] carrying the JWKS
//! provider (for OIDC verification), accepted trust anchors, the
//! pinned-key trust store (the peer AIDs this session trusts), and the
//! agent's own identity-hint kind (which determines whether HELLO /
//! HELLO_ACK should present a pinned-key or OIDC proof). When the agent
//! is in OIDC mode, `build_hello` / `process_hello` require an
//! `oidc_mint_jwt` callable that mints the JWT with the handshake-
//! generated nonce.

use std::collections::HashSet;
use std::sync::Arc;

use aitp::core::{AitpEnvelope, MessageType, RawUrl, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::envelope::{sign_envelope, sign_envelope_with};
use aitp::handshake::{
    CompletedHandshake, HandshakeError, IdentityKind, Initiator, JwksResolver,
    MutualCommitAckPayload, MutualCommitPayload, MutualHelloAckPayload, MutualHelloPayload,
    PresentedIdentity, Responder, StaticPinnedKeyStore, MUTUAL_COMMIT_ACK_PAYLOAD_MEMBERS,
    MUTUAL_COMMIT_PAYLOAD_MEMBERS, MUTUAL_HELLO_ACK_PAYLOAD_MEMBERS, MUTUAL_HELLO_PAYLOAD_MEMBERS,
};
use aitp::manifest::{
    check_identity_type_compatibility, verify_manifest, Manifest, ManifestVerifyContext,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use uuid::Uuid;

use crate::helpers::{
    binding_revocation, handshake_code, make_peer_config, runtime_error, NoOpJwksResolver,
    NO_TCT_STEP,
};
use crate::oidc::make_oidc_minter;
use crate::wire;

/// Per-session configuration cached at agent.new_session() time.
pub struct SessionContext {
    /// JWKS resolver — `None` ⇒ no resolver was wired in (pinned-key-only).
    pub jwks: Option<Arc<dyn JwksResolver + Send + Sync + 'static>>,
    /// Accepted OIDC issuer trust anchors for verifying peer identity.
    pub trust_anchors: Vec<RawUrl>,
    /// Our own manifest's identity_hint.kind — drives whether we present
    /// pinned-key or OIDC in outbound payloads.
    pub identity_kind: IdentityKind,
    /// Our own manifest identity_hint.subject — used as the OIDC `sub`
    /// claim placeholder and pinned-key `subject` field.
    pub identity_subject: String,
    /// Our own manifest identity_hint.issuer — for OIDC, the URL the
    /// IdP will sign tokens for. None for pinned-key.
    pub identity_issuer: Option<RawUrl>,
    /// Local pinned-key trust store (RFC-AITP-0002 §3.2), built from the
    /// `pinned_keys` AIDs passed to `new_session` / `new_responder`. A
    /// `pinned_key` peer whose key is not in it is rejected with
    /// `IDENTITY_FAILED`; empty ⇒ every pinned-key peer is rejected.
    pub pinned_keys: StaticPinnedKeyStore,
    /// Accept a peer Manifest whose `handshake_endpoint` is plain
    /// `http://localhost` or `http://127.0.0.1`. Off unless the caller
    /// opts in.
    pub insecure_localhost: bool,
}

impl SessionContext {
    /// Build a `PresentedIdentity` for an outbound HELLO / HELLO_ACK.
    ///
    /// In pinned-key mode, returns `PinnedKey { subject }`. In OIDC mode,
    /// requires an `oidc_mint_jwt` callable and returns `OidcMinter`.
    fn presented_identity(&self, oidc_mint_jwt: Option<Py<PyAny>>) -> PyResult<PresentedIdentity> {
        match self.identity_kind {
            IdentityKind::PinnedKey => Ok(PresentedIdentity::PinnedKey {
                subject: self.identity_subject.clone(),
            }),
            IdentityKind::Oidc => {
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
            // `IdentityKind` is `#[non_exhaustive]`; reject any
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
    ) -> Result<Vec<aitp::handshake::JwkPublicKey>, aitp::handshake::ResolveError> {
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
    /// `POST` to `/aitp/handshake/hello`. The peer's Manifest is verified
    /// first (RFC-AITP-0003 §5, including step 6's identity type check),
    /// under the session's loopback opt-in.
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
        let peer_manifest = wire::manifest(peer_manifest_json).map_err(|e| {
            let code = match e {
                wire::WireError::ManifestVersionUnknown => "MANIFEST_VERSION_UNKNOWN",
                wire::WireError::UnknownField(_) => "UNKNOWN_FIELD",
                _ => "MANIFEST_INVALID",
            };
            runtime_error(format!("invalid peer manifest JSON: {e}"), Some(code))
        })?;
        // RFC-AITP-0003 §5: no handshake starts from an unverified Manifest.
        let mut manifest_ctx = ManifestVerifyContext::now();
        if self.ctx.insecure_localhost {
            manifest_ctx = manifest_ctx.with_insecure_localhost_dangerous();
        }
        verify_manifest(&peer_manifest, &manifest_ctx)
            .and_then(|_| check_identity_type_compatibility(&peer_manifest, self.ctx.identity_kind))
            .map_err(|e| {
                let e = HandshakeError::from(e);
                runtime_error(e.to_string(), handshake_code(&e).as_deref())
            })?;

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
            &self.ctx.pinned_keys,
            NO_TCT_STEP,
            self.ctx.insecure_localhost,
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
        .map_err(|e| runtime_error(e.to_string(), handshake_code(&e).as_deref()))?;
        self.inner = Some(initiator);

        let payload =
            serde_json::to_value(&hello).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let env = sign_envelope_with(&self.key, MessageType::MutualHello, payload, msg_id, ts)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        serde_json::to_string(&env).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Step 2 — process `MUTUAL_HELLO_ACK`, produce `MUTUAL_COMMIT`.
    ///
    /// `session_id` is the responder's `X-Aitp-Session-Id` header. It is
    /// accepted for transport bookkeeping and parity with the Node SDK's
    /// `processHelloAck(helloAckJson, sessionId)` but not used here.
    fn process_hello_ack(&mut self, hello_ack_json: &str, session_id: &str) -> PyResult<String> {
        let _ = session_id;
        let envelope: AitpEnvelope = wire::envelope(hello_ack_json)
            .map_err(|e| PyValueError::new_err(format!("invalid envelope JSON: {e}")))?;
        let ack: MutualHelloAckPayload = wire::check_payload(
            &envelope,
            "MutualHelloAckPayload",
            MUTUAL_HELLO_ACK_PAYLOAD_MEMBERS,
        )
        .and_then(|()| serde_json::from_value(envelope.payload.clone()).map_err(wire::from_serde))
        .map_err(|e| PyValueError::new_err(format!("invalid hello_ack payload: {e}")))?;

        let jwks = self.ctx.jwks_for_call();
        let cfg = make_peer_config(
            &self.key,
            &self.manifest,
            jwks.as_ref(),
            &self.ctx.trust_anchors,
            &self.ctx.pinned_keys,
            NO_TCT_STEP,
            self.ctx.insecure_localhost,
        );
        let commit = self
            .inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("call build_hello() first"))?
            .on_hello_ack(&envelope, &ack, &cfg)
            .map_err(|e| runtime_error(e.to_string(), handshake_code(&e).as_deref()))?;

        // MUTUAL_COMMIT carries no pinned-key proof, so a fresh
        // (message_id, timestamp) is fine.
        let payload =
            serde_json::to_value(&commit).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let env = sign_envelope(&self.key, MessageType::MutualCommit, payload)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        serde_json::to_string(&env).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Step 3 — process `MUTUAL_COMMIT_ACK`. Returns a JSON object
    /// `{"tct": "<compact JWS>", "grant_voucher": "<compact JWS>" | null}`:
    /// the TCT the peer issued to us, plus the companion grant voucher
    /// (when issued — the voucher is what lets us later mint delegations).
    ///
    /// `revoked_jtis` is the peer's (the TCT issuer's) revocation deny list
    /// (RFC-AITP-0008). Without it the step fails closed: the peer's TCT is
    /// rejected with `RuntimeError.code == "TCT_REVOKED"` and a "revocation
    /// source unavailable" message. Pass `revocation="fail_open"` to skip the
    /// check instead.
    #[pyo3(signature = (commit_ack_json, revoked_jtis = None, revocation = None))]
    fn complete(
        &mut self,
        commit_ack_json: &str,
        revoked_jtis: Option<HashSet<String>>,
        revocation: Option<&str>,
    ) -> PyResult<String> {
        let envelope: AitpEnvelope = wire::envelope(commit_ack_json)
            .map_err(|e| PyValueError::new_err(format!("invalid envelope JSON: {e}")))?;
        let ack: MutualCommitAckPayload = wire::check_payload(
            &envelope,
            "MutualCommitAckPayload",
            MUTUAL_COMMIT_ACK_PAYLOAD_MEMBERS,
        )
        .and_then(|()| serde_json::from_value(envelope.payload.clone()).map_err(wire::from_serde))
        .map_err(|e| PyValueError::new_err(format!("invalid commit_ack payload: {e}")))?;

        let deny = handshake_revocation(revoked_jtis.as_ref(), revocation)?;
        let check = |q: &aitp::tct::RevocationQuery<'_>| deny.status(q);
        let source = deny.source(&check);
        let jwks = self.ctx.jwks_for_call();
        let cfg = make_peer_config(
            &self.key,
            &self.manifest,
            jwks.as_ref(),
            &self.ctx.trust_anchors,
            &self.ctx.pinned_keys,
            source,
            self.ctx.insecure_localhost,
        );
        let completed = self
            .inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("call process_hello_ack() first"))?
            .on_commit_ack(&envelope, &ack, &cfg)
            .map_err(|e| runtime_error(e.to_string(), handshake_code(&e).as_deref()))?;

        completed_handshake_json(&completed)
    }
}

/// Serialize a [`CompletedHandshake`] to the binding's wire shape:
/// `{"tct": "<compact JWS>", "grant_voucher": "<compact JWS>" | null}`.
fn completed_handshake_json(completed: &CompletedHandshake) -> PyResult<String> {
    let out = serde_json::json!({
        "tct": completed.tct().token(),
        "grant_voucher": completed.grant_voucher(),
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
        let envelope: AitpEnvelope = wire::envelope(hello_json)
            .map_err(|e| PyValueError::new_err(format!("invalid envelope JSON: {e}")))?;
        let hello: MutualHelloPayload = wire::check_payload(
            &envelope,
            "MutualHelloPayload",
            MUTUAL_HELLO_PAYLOAD_MEMBERS,
        )
        .and_then(|()| serde_json::from_value(envelope.payload.clone()).map_err(wire::from_serde))
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
            &self.ctx.pinned_keys,
            NO_TCT_STEP,
            self.ctx.insecure_localhost,
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
        .map_err(|e| runtime_error(e.to_string(), handshake_code(&e).as_deref()))?;

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
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let ack_json =
            serde_json::to_string(&env).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok((ack_json, session_id))
    }

    /// Process an incoming `MUTUAL_COMMIT` envelope.
    ///
    /// `revoked_jtis` / `revocation` as in `InitiatorSession.complete`: the
    /// initiator's TCT fails closed without the initiator's deny list.
    #[pyo3(signature = (commit_json, revoked_jtis = None, revocation = None))]
    fn process_commit(
        &mut self,
        commit_json: &str,
        revoked_jtis: Option<HashSet<String>>,
        revocation: Option<&str>,
    ) -> PyResult<(String, String)> {
        let envelope: AitpEnvelope = wire::envelope(commit_json)
            .map_err(|e| PyValueError::new_err(format!("invalid envelope JSON: {e}")))?;
        let commit: MutualCommitPayload = wire::check_payload(
            &envelope,
            "MutualCommitPayload",
            MUTUAL_COMMIT_PAYLOAD_MEMBERS,
        )
        .and_then(|()| serde_json::from_value(envelope.payload.clone()).map_err(wire::from_serde))
        .map_err(|e| PyValueError::new_err(format!("invalid commit payload: {e}")))?;

        let deny = handshake_revocation(revoked_jtis.as_ref(), revocation)?;
        let check = |q: &aitp::tct::RevocationQuery<'_>| deny.status(q);
        let source = deny.source(&check);
        let jwks = self.ctx.jwks_for_call();
        let cfg = make_peer_config(
            &self.key,
            &self.manifest,
            jwks.as_ref(),
            &self.ctx.trust_anchors,
            &self.ctx.pinned_keys,
            source,
            self.ctx.insecure_localhost,
        );
        let (ack, completed) = self
            .inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("call process_hello() first"))?
            .on_commit(&envelope, &commit, &cfg)
            .map_err(|e| runtime_error(e.to_string(), handshake_code(&e).as_deref()))?;

        let payload =
            serde_json::to_value(&ack).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let env = sign_envelope(&self.key, MessageType::MutualCommitAck, payload)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let ack_json =
            serde_json::to_string(&env).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let completed_json = completed_handshake_json(&completed)?;
        Ok((ack_json, completed_json))
    }
}

/// Parse a commit step's deny list and `revocation` mode.
fn handshake_revocation(
    revoked_jtis: Option<&HashSet<String>>,
    revocation: Option<&str>,
) -> PyResult<crate::helpers::BindingRevocation> {
    binding_revocation(
        revoked_jtis.map(|s| s.iter().map(String::as_str)),
        revocation,
    )
    .map_err(PyValueError::new_err)
}
