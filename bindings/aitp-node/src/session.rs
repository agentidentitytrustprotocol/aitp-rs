//! Initiator- and responder-side handshake sessions.
//!
//! Each method consumes/produces JSON strings that are HTTP request /
//! response bodies. Sessions cache the JWKS provider + trust anchors
//! supplied at construction; OIDC-mode agents pass an `oidcMintJwt`
//! callback at each `buildHello` / `processHello` call.

use std::sync::Arc;

use aitp_core::{AitpEnvelope, MessageType, RawUrl, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_envelope::{sign_envelope, sign_envelope_with};
use aitp_handshake::{
    Initiator, JwksResolver, MutualCommitAckPayload, MutualCommitPayload, MutualHelloAckPayload,
    MutualHelloPayload, PresentedIdentity, Responder,
};
use aitp_manifest::{IdentityHintKind, Manifest, ManifestEnvelope};
use aitp_tct::VerifiedTct;
use napi::bindgen_prelude::*;
use napi::{Env, JsFunction};
use napi_derive::napi;
use uuid::Uuid;

use crate::helpers::{make_peer_config, NoOpJwksResolver};
use crate::oidc::make_oidc_minter;

/// Per-session OIDC + trust-anchor context.
pub struct SessionContext {
    pub jwks: Option<Arc<dyn JwksResolver + Send + Sync + 'static>>,
    pub trust_anchors: Vec<RawUrl>,
    pub identity_kind: IdentityHintKind,
    pub identity_subject: String,
    pub identity_issuer: Option<RawUrl>,
}

impl SessionContext {
    fn presented_identity(
        &self,
        env: Env,
        oidc_mint_jwt: Option<JsFunction>,
    ) -> Result<PresentedIdentity> {
        match self.identity_kind {
            IdentityHintKind::PinnedKey => Ok(PresentedIdentity::PinnedKey {
                subject: self.identity_subject.clone(),
            }),
            IdentityHintKind::Oidc => {
                let cb = oidc_mint_jwt.ok_or_else(|| {
                    Error::from_reason("agent manifest is OIDC; `oidcMintJwt` callable is required")
                })?;
                let issuer_raw = self.identity_issuer.as_ref().ok_or_else(|| {
                    Error::from_reason(
                        "OIDC identity_hint missing issuer (buildManifest invariant violated)",
                    )
                })?;
                let issuer_url = issuer_raw.parse_url().map_err(|e| {
                    Error::from_reason(format!("identity_hint.issuer not a URL: {e}"))
                })?;
                let mint_jwt = make_oidc_minter(env, cb)?;
                Ok(PresentedIdentity::OidcMinter {
                    issuer: issuer_url,
                    subject: self.identity_subject.clone(),
                    mint_jwt,
                })
            }
            // `IdentityHintKind` is `#[non_exhaustive]`; reject any
            // future variant the Node SDK hasn't yet wired up.
            other => Err(Error::from_reason(format!(
                "unsupported identity_hint kind {other:?}; \
                 update the Node SDK to handle this variant"
            ))),
        }
    }

    fn jwks_for_call(&self) -> Box<dyn JwksResolver + '_> {
        match &self.jwks {
            Some(arc) => Box::new(SessionJwksRef { inner: arc.clone() }),
            None => Box::new(NoOpJwksResolver),
        }
    }
}

struct SessionJwksRef {
    inner: Arc<dyn JwksResolver + Send + Sync + 'static>,
}

impl JwksResolver for SessionJwksRef {
    fn resolve(
        &self,
        issuer: &url::Url,
    ) -> std::result::Result<Vec<aitp_handshake::JwkPublicKey>, aitp_handshake::ResolveError> {
        self.inner.resolve(issuer)
    }
}

/// Result of `processHello`: response body plus session id.
#[napi(object)]
pub struct JsHelloAckResult {
    /// `MUTUAL_HELLO_ACK` envelope JSON — set as the HTTP response body.
    pub ack_json: String,
    /// Correlation id — set as the `X-Aitp-Session-Id` response header.
    pub session_id: String,
}

/// The salient claims of a TCT obtained at handshake completion. Mirrors
/// `aitp_tct::TctClaims`; timestamps are Unix seconds as JS `number`s.
#[napi(object)]
pub struct JsHandshakeTctClaims {
    /// Issuer AID (`iss`) — the peer that minted and is bound by the TCT.
    pub iss: String,
    /// Subject AID (`sub`) — the holder the TCT authorizes.
    pub sub: String,
    /// Audience AID (`aud`). In v0.2 this equals `sub`.
    pub aud: String,
    /// Capability grants the TCT authorizes.
    pub grants: Vec<String>,
    /// Issued-at, Unix seconds (`iat`).
    pub iat: f64,
    /// Expiry, Unix seconds (`exp`).
    pub exp: f64,
    /// TCT unique identifier (`jti`, UUID string).
    pub jti: String,
}

impl JsHandshakeTctClaims {
    fn from_verified(v: &VerifiedTct) -> Self {
        let c = &v.claims;
        Self {
            iss: c.iss.to_string(),
            sub: c.sub.to_string(),
            aud: c.aud.to_string(),
            grants: c.grants.clone(),
            iat: c.iat.0 as f64,
            exp: c.exp.0 as f64,
            jti: c.jti.to_string(),
        }
    }
}

/// A completed handshake: the TCT the peer issued to us (as an opaque
/// compact-JWS token plus its decoded claims) and the optional companion
/// grant voucher (`typ: aitp-grant+jwt`) used to mint delegations
/// (RFC-AITP-0005 §8). `grantVoucher` is `null` when the issuing peer's
/// policy forbids us from delegating.
#[napi(object)]
pub struct JsCompletedHandshake {
    /// The TCT as an opaque compact-JWS string. Pass verbatim to
    /// `verifyTct` / `verifyTctCached`.
    pub tct: String,
    /// The decoded (already-verified) TCT claims.
    pub claims: JsHandshakeTctClaims,
    /// The companion grant voucher (compact JWS), or `null`. Pass to
    /// `buildDelegation` to delegate the held grants.
    pub grant_voucher: Option<String>,
}

/// Result of `processCommit`: response body plus the completed handshake
/// (held TCT token, its claims, and the optional grant voucher).
#[napi(object)]
pub struct JsCommitAckResult {
    /// `MUTUAL_COMMIT_ACK` envelope JSON — set as the HTTP response body.
    pub ack_json: String,
    /// The TCT (and voucher) the initiator issued to us.
    pub completed: JsCompletedHandshake,
}

// ── Initiator ───────────────────────────────────────────────────────────

/// Outbound handshake session — drives the initiator side.
#[napi]
pub struct JsInitiatorSession {
    key: Arc<AitpSigningKey>,
    manifest: Arc<Manifest>,
    ctx: SessionContext,
    inner: Option<Initiator>,
}

impl JsInitiatorSession {
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

#[napi]
impl JsInitiatorSession {
    /// Step 1 — build the `MUTUAL_HELLO` envelope.
    ///
    /// `oidcMintJwt`: required for OIDC agents. Receives the handshake-
    /// generated `pop_nonce` (string) and must return the JWT (string).
    #[napi]
    pub fn build_hello(
        &mut self,
        env: Env,
        peer_manifest_json: String,
        requested_grants: Vec<String>,
        oidc_mint_jwt: Option<JsFunction>,
    ) -> Result<String> {
        let ManifestEnvelope {
            manifest: peer_manifest,
        } = serde_json::from_str(&peer_manifest_json)
            .map_err(|e| Error::from_reason(format!("invalid peer manifest JSON: {e}")))?;

        let msg_id = Uuid::new_v4();
        let ts = Timestamp::now();
        let jwks = self.ctx.jwks_for_call();
        let cfg = make_peer_config(
            &self.key,
            &self.manifest,
            jwks.as_ref(),
            &self.ctx.trust_anchors,
        );
        let presented = self.ctx.presented_identity(env, oidc_mint_jwt)?;

        let (initiator, hello) = Initiator::start(
            &cfg,
            presented,
            &peer_manifest.aid,
            &msg_id,
            ts,
            requested_grants,
        )
        .map_err(|e| Error::from_reason(e.to_string()))?;
        self.inner = Some(initiator);

        let payload =
            serde_json::to_value(&hello).map_err(|e| Error::from_reason(e.to_string()))?;
        let env_out = sign_envelope_with(&self.key, MessageType::MutualHello, payload, msg_id, ts)
            .map_err(Error::from_reason)?;
        serde_json::to_string(&env_out).map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Step 2 — process `MUTUAL_HELLO_ACK`, produce `MUTUAL_COMMIT`.
    #[napi]
    pub fn process_hello_ack(
        &mut self,
        hello_ack_json: String,
        _session_id: String,
    ) -> Result<String> {
        let envelope: AitpEnvelope = serde_json::from_str(&hello_ack_json)
            .map_err(|e| Error::from_reason(format!("invalid envelope JSON: {e}")))?;
        let ack: MutualHelloAckPayload = serde_json::from_value(envelope.payload.clone())
            .map_err(|e| Error::from_reason(format!("invalid hello_ack payload: {e}")))?;

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
            .ok_or_else(|| Error::from_reason("call buildHello() first"))?
            .on_hello_ack(&envelope, &ack, &cfg)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let payload =
            serde_json::to_value(&commit).map_err(|e| Error::from_reason(e.to_string()))?;
        let env_out = sign_envelope(&self.key, MessageType::MutualCommit, payload)
            .map_err(Error::from_reason)?;
        serde_json::to_string(&env_out).map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Step 3 — process `MUTUAL_COMMIT_ACK`. Returns the completed
    /// handshake: the TCT the peer issued to us (opaque compact-JWS
    /// token plus its decoded claims) and the optional grant voucher.
    #[napi]
    pub fn complete(&mut self, commit_ack_json: String) -> Result<JsCompletedHandshake> {
        let envelope: AitpEnvelope = serde_json::from_str(&commit_ack_json)
            .map_err(|e| Error::from_reason(format!("invalid envelope JSON: {e}")))?;
        let ack: MutualCommitAckPayload = serde_json::from_value(envelope.payload.clone())
            .map_err(|e| Error::from_reason(format!("invalid commit_ack payload: {e}")))?;

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
            .ok_or_else(|| Error::from_reason("call processHelloAck() first"))?
            .on_commit_ack(&envelope, &ack, &cfg)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(JsCompletedHandshake {
            tct: completed.tct.token.clone(),
            claims: JsHandshakeTctClaims::from_verified(&completed.tct),
            grant_voucher: completed.grant_voucher,
        })
    }
}

// ── Responder ───────────────────────────────────────────────────────────

/// Inbound handshake session — drives the responder side.
#[napi]
pub struct JsResponderSession {
    key: Arc<AitpSigningKey>,
    manifest: Arc<Manifest>,
    ctx: SessionContext,
    inner: Option<Responder>,
}

impl JsResponderSession {
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

#[napi]
impl JsResponderSession {
    /// Process an incoming `MUTUAL_HELLO` envelope.
    ///
    /// `oidcMintJwt`: required for OIDC agents (see `JsInitiatorSession.buildHello`).
    #[napi]
    pub fn process_hello(
        &mut self,
        env: Env,
        hello_json: String,
        oidc_mint_jwt: Option<JsFunction>,
    ) -> Result<JsHelloAckResult> {
        let envelope: AitpEnvelope = serde_json::from_str(&hello_json)
            .map_err(|e| Error::from_reason(format!("invalid envelope JSON: {e}")))?;
        let hello: MutualHelloPayload = serde_json::from_value(envelope.payload.clone())
            .map_err(|e| Error::from_reason(format!("invalid hello payload: {e}")))?;

        let ack_msg_id = Uuid::new_v4();
        let ack_ts = Timestamp::now();
        let jwks = self.ctx.jwks_for_call();
        let cfg = make_peer_config(
            &self.key,
            &self.manifest,
            jwks.as_ref(),
            &self.ctx.trust_anchors,
        );
        let presented = self.ctx.presented_identity(env, oidc_mint_jwt)?;
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
        .map_err(|e| Error::from_reason(e.to_string()))?;

        let session_id = Uuid::new_v4().to_string();
        self.inner = Some(responder);

        let payload = serde_json::to_value(&ack).map_err(|e| Error::from_reason(e.to_string()))?;
        let env_out = sign_envelope_with(
            &self.key,
            MessageType::MutualHelloAck,
            payload,
            ack_msg_id,
            ack_ts,
        )
        .map_err(Error::from_reason)?;
        let ack_json =
            serde_json::to_string(&env_out).map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(JsHelloAckResult {
            ack_json,
            session_id,
        })
    }

    /// Process an incoming `MUTUAL_COMMIT` envelope.
    #[napi]
    pub fn process_commit(&mut self, commit_json: String) -> Result<JsCommitAckResult> {
        let envelope: AitpEnvelope = serde_json::from_str(&commit_json)
            .map_err(|e| Error::from_reason(format!("invalid envelope JSON: {e}")))?;
        let commit: MutualCommitPayload = serde_json::from_value(envelope.payload.clone())
            .map_err(|e| Error::from_reason(format!("invalid commit payload: {e}")))?;

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
            .ok_or_else(|| Error::from_reason("call processHello() first"))?
            .on_commit(&envelope, &commit, &cfg)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let payload = serde_json::to_value(&ack).map_err(|e| Error::from_reason(e.to_string()))?;
        let env_out = sign_envelope(&self.key, MessageType::MutualCommitAck, payload)
            .map_err(Error::from_reason)?;
        let ack_json =
            serde_json::to_string(&env_out).map_err(|e| Error::from_reason(e.to_string()))?;
        let completed_js = JsCompletedHandshake {
            tct: completed.tct.token.clone(),
            claims: JsHandshakeTctClaims::from_verified(&completed.tct),
            grant_voucher: completed.grant_voucher,
        };
        Ok(JsCommitAckResult {
            ack_json,
            completed: completed_js,
        })
    }
}
