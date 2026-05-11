//! HTTP server primitives: Manifest server, handshake server.

use crate::common::{sign_envelope, sign_envelope_with, verify_envelope_signature};
use aitp_core::{AitpEnvelope, ErrorCode, MessageType, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp_handshake::{
    JwksResolver, MutualCommitPayload, MutualHelloPayload, PeerConfig, PresentedIdentity, Responder,
};
use aitp_manifest::{Manifest, ManifestEnvelope};
use aitp_tct::RevocationListEnvelope;
#[cfg(feature = "experimental-renewal")]
use aitp_tct::{process_renewal_request, TctEnvelope, TctRenewalPayload};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use parking_lot::Mutex;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(feature = "experimental-renewal")]
use tracing::instrument;
use tracing::{debug, warn};
use uuid::Uuid;

/// Default period after which an in-progress handshake session is
/// garbage-collected if it has not progressed. A healthy four-message
/// handshake on a local network completes in tens of milliseconds; one
/// minute leaves room for slow clients without indefinitely retaining
/// half-finished state.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(60);

/// Producer of the local issuer's [`RevocationListEnvelope`] for the
/// outbound `/.well-known/aitp-revocation-list` endpoint
/// (RFC-AITP-0008 §1.5).
///
/// Implementations choose how to source the list — common options:
/// - hold an in-memory `RwLock<RevocationListEnvelope>` and update it
///   from your control plane,
/// - re-sign on every poll from a database table, or
/// - lazily mint an empty signed snapshot for issuers that have nothing
///   to revoke (this is itself a meaningful signed assertion).
///
/// The producer is sync; if the source is I/O-bound, fan out to a
/// background task and just return the latest cached value here.
pub trait RevocationListProducer: Send + Sync + 'static {
    /// Return the current snapshot.
    fn current(&self) -> RevocationListEnvelope;
}

/// Server that exposes `/.well-known/aitp-manifest` returning
/// `{"manifest": <inner>}`.
pub struct ManifestServer {
    manifest: Arc<Manifest>,
}

impl ManifestServer {
    /// Wrap a [`Manifest`] for serving.
    pub fn new(manifest: Manifest) -> Self {
        Self {
            manifest: Arc::new(manifest),
        }
    }

    /// The axum router (mount under whatever prefix you want; usually `/`).
    pub fn router(self) -> Router {
        let manifest = self.manifest;
        Router::new().route(
            "/.well-known/aitp-manifest",
            get(move || {
                let manifest = manifest.clone();
                async move {
                    let env = ManifestEnvelope {
                        manifest: (*manifest).clone(),
                    };
                    Json(env)
                }
            }),
        )
    }
}

/// Server that drives the responder side of the handshake.
///
/// Mounts:
/// - `POST /aitp/handshake/hello` accepts MUTUAL_HELLO, replies with
///   MUTUAL_HELLO_ACK
/// - `POST /aitp/handshake/commit` accepts MUTUAL_COMMIT, replies with
///   MUTUAL_COMMIT_ACK
///
/// Sessions are correlated by the `X-Aitp-Session-Id` HTTP header; clients
/// receive a session id in the same header on the HELLO_ACK response.
pub struct HandshakeServer<R: JwksResolver + Send + Sync + 'static> {
    state: Arc<HandshakeState<R>>,
    revocation_producer: Option<Arc<dyn RevocationListProducer>>,
}

/// Sliding-window rate-limit policy (RFC-AITP-0009 §3.1). Off by
/// default. When configured, [`HandshakeServer::enforce_rate_limit`]
/// counts events keyed by IP and (optionally) AID over the most
/// recent 60-second window and rejects with HTTP 429 once a key
/// crosses its limit.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Max requests per source IP in any rolling 60s window. `None`
    /// disables the per-IP gate.
    pub requests_per_ip_per_60s: Option<u32>,
    /// Max requests per peer AID (extracted from envelope sender)
    /// in any rolling 60s window. `None` disables the per-AID gate.
    pub requests_per_aid_per_60s: Option<u32>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_ip_per_60s: Some(120),
            requests_per_aid_per_60s: Some(60),
        }
    }
}

/// Outcome of a [`HandshakeServer::enforce_rate_limit`] check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitOutcome {
    /// Both keys (IP and AID, where supplied) are within their windows.
    Allow,
    /// At least one key exceeded its 60s window — HTTP 429.
    DenyTooManyRequests {
        /// Free-form reason for telemetry — names the key that
        /// triggered the deny.
        reason: String,
    },
}

/// Configures DPoP enforcement for protected endpoints surfaced via
/// [`HandshakeServer`] (RFC 9449). Off by default — the handshake
/// endpoints themselves are not DPoP-protected. Operators wiring up a
/// session-bundle or other DPoP-bound endpoint (RFC-AITP-0010 §X)
/// install a policy via [`HandshakeServer::with_dpop_policy`] and gate
/// requests with [`HandshakeServer::verify_dpop_request`].
#[derive(Clone, Debug)]
pub struct DpopPolicy {
    /// When `true`, requests routed through
    /// [`HandshakeServer::verify_dpop_request`] MUST carry an
    /// `Authorization: DPoP <token>` and a `DPoP` proof header.
    pub required: bool,
    /// Permitted absolute drift (seconds) between the proof's `iat`
    /// and the server clock (RFC 9449 §4.3). Common production
    /// default: 60.
    pub iat_tolerance_secs: i64,
}

impl Default for DpopPolicy {
    fn default() -> Self {
        Self {
            required: false,
            iat_tolerance_secs: 60,
        }
    }
}

struct HandshakeState<R: JwksResolver + Send + Sync> {
    signing_key: AitpSigningKey,
    manifest: Manifest,
    trust_anchors: Vec<aitp_core::RawUrl>,
    jwks_resolver: R,
    /// Capabilities this responder requests from the peer. Per
    /// RFC-AITP-0004 §4.1 the issuing peer's TCT grants are
    /// `peer_requested ∩ self_offered`; if the responder requests
    /// nothing, the initiator's grant intersection is empty and the
    /// handshake aborts with `POLICY_VIOLATION`.
    requested_grants: Vec<String>,
    sessions: Mutex<HashMap<Uuid, SessionEntry>>,
    session_ttl: Duration,
    /// Replay deny list (RFC-AITP-0001 §5.5). Every accepted envelope's
    /// `message_id` is recorded for `replay_window`; a duplicate within
    /// that window is rejected with `REPLAY_DETECTED`. Entries older
    /// than the window are evicted on the next request that triggers a
    /// check, so the map size is bounded by traffic in the window.
    seen_message_ids: Mutex<HashMap<Uuid, Instant>>,
    replay_window: Duration,
    /// Optional DPoP enforcement policy. Off by default; when set,
    /// protected endpoints (operator-mounted) MUST present a valid
    /// DPoP proof via [`HandshakeServer::verify_dpop_request`].
    /// Stored under interior mutability so [`HandshakeServer::
    /// with_dpop_policy`] can be called on a built server without
    /// reconstructing the Arc.
    dpop_policy: Mutex<Option<DpopPolicy>>,
    /// Shared DPoP `jti` replay cache. Always allocated even when
    /// `dpop_policy` is `None` so that callers can opportunistically
    /// validate DPoP-bound requests in middleware without re-creating
    /// the cache.
    dpop_replay_cache: Arc<crate::dpop::DpopReplayCache>,
    /// Optional rate-limit configuration. Off by default; operators
    /// install via [`HandshakeServer::with_rate_limit`]. Enforcement
    /// is per-key sliding 60s windows backed by `rate_limit_events`.
    rate_limit_config: Mutex<Option<RateLimitConfig>>,
    /// Per-key event timestamps for the rolling rate-limit window.
    /// Keyed by either `ip:<ip>` or `aid:<aid>`. Bounded by the
    /// configured limit; entries older than 60s are swept on every
    /// check.
    rate_limit_events: Mutex<HashMap<String, Vec<Instant>>>,
}

/// Default replay-deny-list window. RFC-AITP-0001 §5.5 says the window
/// MUST be at least the timestamp tolerance; 5 minutes is a generous
/// floor that aligns with our default `iat_tolerance_secs`.
pub const DEFAULT_REPLAY_WINDOW: Duration = Duration::from_secs(300);

/// Maximum acceptable absolute drift (seconds) between a sender's
/// envelope timestamp and the server's clock. RFC-AITP-0001 §5.5 says
/// "MUST be ≤ 300 s" — older messages MUST be rejected as
/// `TIMESTAMP_EXPIRED`.
pub const DEFAULT_TIMESTAMP_TOLERANCE_SECS: i64 = 300;

/// Maximum acceptable POST body size for handshake endpoints. AITP
/// payloads are bounded — even a Manifest fits well under 32 KB. 256 KB
/// is a generous ceiling that still rejects accidental gigabyte uploads.
pub const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024;

/// Wall-clock cap on body read. Defends against slow-loris attackers
/// who trickle a small body across many seconds: the body-size cap
/// alone admits a 256 KB body delivered at 1 byte/s for ~3 days,
/// holding a connection slot the whole time. With this timeout, the
/// client must finish sending the body within `DEFAULT_BODY_READ_TIMEOUT`
/// seconds or the request is rejected as `INVALID_ENVELOPE`. The
/// default of 5 s is generous for ~256 KB on any non-pathological
/// network.
pub const DEFAULT_BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);

struct SessionEntry {
    responder: Responder,
    created_at: Instant,
}

impl<R: JwksResolver + Send + Sync + 'static> HandshakeServer<R> {
    /// Construct a server. The `signing_key` is used both for the
    /// envelope signature on outbound replies and for the responder
    /// state machine. `requested_grants` are the capabilities this
    /// responder asks of the initiator (RFC-AITP-0004 §4.1).
    ///
    /// In-progress handshake sessions expire after [`DEFAULT_SESSION_TTL`].
    /// Use [`Self::with_session_ttl`] to override.
    pub fn new(
        signing_key: AitpSigningKey,
        manifest: Manifest,
        trust_anchors: Vec<aitp_core::RawUrl>,
        jwks_resolver: R,
        requested_grants: Vec<String>,
    ) -> Self {
        Self::with_session_ttl(
            signing_key,
            manifest,
            trust_anchors,
            jwks_resolver,
            requested_grants,
            DEFAULT_SESSION_TTL,
        )
    }

    /// Same as [`Self::new`] with an explicit session TTL. Tests use
    /// short TTLs to exercise the expiry path; production callers
    /// should prefer [`Self::new`].
    pub fn with_session_ttl(
        signing_key: AitpSigningKey,
        manifest: Manifest,
        trust_anchors: Vec<aitp_core::RawUrl>,
        jwks_resolver: R,
        requested_grants: Vec<String>,
        session_ttl: Duration,
    ) -> Self {
        Self::with_session_ttl_and_replay_window(
            signing_key,
            manifest,
            trust_anchors,
            jwks_resolver,
            requested_grants,
            session_ttl,
            DEFAULT_REPLAY_WINDOW,
        )
    }

    /// Same as [`Self::with_session_ttl`] with an explicit replay-deny-list
    /// window. Tests use short windows to exercise eviction.
    pub fn with_session_ttl_and_replay_window(
        signing_key: AitpSigningKey,
        manifest: Manifest,
        trust_anchors: Vec<aitp_core::RawUrl>,
        jwks_resolver: R,
        requested_grants: Vec<String>,
        session_ttl: Duration,
        replay_window: Duration,
    ) -> Self {
        Self {
            state: Arc::new(HandshakeState {
                signing_key,
                manifest,
                trust_anchors,
                jwks_resolver,
                requested_grants,
                sessions: Mutex::new(HashMap::new()),
                session_ttl,
                seen_message_ids: Mutex::new(HashMap::new()),
                replay_window,
                dpop_policy: Mutex::new(None),
                dpop_replay_cache: Arc::new(crate::dpop::DpopReplayCache::default()),
                rate_limit_config: Mutex::new(None),
                rate_limit_events: Mutex::new(HashMap::new()),
            }),
            revocation_producer: None,
        }
    }

    /// Attach a [`RevocationListProducer`] so the server's router will
    /// also serve `GET /.well-known/aitp-revocation-list`.
    pub fn with_revocation_producer(mut self, producer: Arc<dyn RevocationListProducer>) -> Self {
        self.revocation_producer = Some(producer);
        self
    }

    /// Attach a DPoP enforcement policy. The handshake endpoints
    /// themselves are not DPoP-protected, but operators mounting
    /// additional DPoP-bound routes (e.g. session bundles) can use
    /// [`Self::verify_dpop_request`] from middleware or per-route
    /// handlers to enforce the policy. Pre-rc.2 the server allocated
    /// a `DpopReplayCache` but never consulted it; this method gives
    /// callers a way to opt into RFC 9449 §4.3 enforcement.
    pub fn with_dpop_policy(self, policy: DpopPolicy) -> Self {
        *self.state.dpop_policy.lock() = Some(policy);
        self
    }

    /// Attach a rate-limit configuration (RFC-AITP-0009 §3.1). The
    /// per-key sliding window is 60 seconds; entries older than that
    /// are evicted on every check, so the in-memory bound is roughly
    /// (active sources × limit).
    pub fn with_rate_limit(self, config: RateLimitConfig) -> Self {
        *self.state.rate_limit_config.lock() = Some(config);
        self
    }

    /// Test whether a single event from `client_ip` (optionally tied
    /// to `peer_aid`) would exceed the configured per-key 60s window.
    /// On `Allow`, the event is recorded; on `DenyTooManyRequests`,
    /// no event is recorded (so a denied caller doesn't accelerate
    /// its own deny — the limit hold window is exactly 60s of
    /// admitted traffic).
    ///
    /// Returns `Allow` when no policy is configured.
    pub fn enforce_rate_limit(
        &self,
        client_ip: Option<&str>,
        peer_aid: Option<&aitp_core::Aid>,
    ) -> RateLimitOutcome {
        let config = match self.state.rate_limit_config.lock().clone() {
            Some(c) => c,
            None => return RateLimitOutcome::Allow,
        };
        let mut events = self.state.rate_limit_events.lock();
        let now = Instant::now();
        let window = Duration::from_secs(60);
        // Tentative event additions, to be committed only if both
        // gates pass. Avoids partial-state under contention.
        let mut additions: Vec<String> = Vec::new();
        if let (Some(limit), Some(ip)) = (config.requests_per_ip_per_60s, client_ip) {
            let key = format!("ip:{ip}");
            let entry = events.entry(key.clone()).or_default();
            entry.retain(|t| now.duration_since(*t) < window);
            if entry.len() as u32 >= limit {
                return RateLimitOutcome::DenyTooManyRequests {
                    reason: format!("rate limit exceeded for IP {ip}"),
                };
            }
            additions.push(key);
        }
        if let (Some(limit), Some(aid)) = (config.requests_per_aid_per_60s, peer_aid) {
            let key = format!("aid:{}", aid.as_str());
            let entry = events.entry(key.clone()).or_default();
            entry.retain(|t| now.duration_since(*t) < window);
            if entry.len() as u32 >= limit {
                return RateLimitOutcome::DenyTooManyRequests {
                    reason: format!("rate limit exceeded for AID {}", aid.as_str()),
                };
            }
            additions.push(key);
        }
        for k in additions {
            events.entry(k).or_default().push(now);
        }
        RateLimitOutcome::Allow
    }

    /// Verify a DPoP-bound request against the configured policy.
    /// Returns `Err` with the appropriate [`crate::dpop::DpopError`]
    /// mapped to HTTP 401 if the policy is `required` and the request
    /// is missing or invalid headers. When policy is not configured or
    /// `required == false` and headers are absent, returns `Ok(None)`.
    pub fn verify_dpop_request(
        &self,
        request: &Request,
        expected_jkt: &str,
        expected_method: &str,
        expected_url: &str,
    ) -> Result<Option<crate::dpop::DpopProof>, crate::dpop::DpopError> {
        let policy = self.state.dpop_policy.lock().clone().unwrap_or_default();
        let authz = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let dpop_hdr = request
            .headers()
            .get("dpop")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if authz.is_empty() || dpop_hdr.is_empty() {
            if policy.required {
                return Err(crate::dpop::DpopError::MalformedHeader);
            }
            return Ok(None);
        }
        let parsed = crate::dpop::DpopHeader::parse(authz, dpop_hdr)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let proof = crate::dpop::verify_dpop_proof_full(
            &parsed,
            &crate::dpop::DpopVerifyContext {
                expected_method,
                expected_url,
                expected_jkt,
                expected_access_token: Some(parsed.access_token.as_bytes()),
                replay_cache: &self.state.dpop_replay_cache,
                iat_tolerance_secs: policy.iat_tolerance_secs,
                now_unix_secs: now,
                expected_nonce: None,
            },
        )?;
        Ok(Some(proof))
    }

    /// The axum router for this handshake server.
    pub fn router(self) -> Router {
        let router = Router::new()
            .route("/aitp/handshake/hello", post(handle_hello::<R>))
            .route("/aitp/handshake/commit", post(handle_commit::<R>));
        #[cfg(feature = "experimental-renewal")]
        let router = router.route("/aitp/handshake/renew", post(handle_renew::<R>));
        let mut router = router.with_state(self.state);
        if let Some(producer) = self.revocation_producer {
            router = router.merge(revocation_router(producer));
        }
        router
    }
}

/// `POST /aitp/handshake/renew` accepts a [`TctRenewalPayload`] and
/// returns a fresh [`TctEnvelope`]. Gated behind the
/// `experimental-renewal` Cargo feature (RFC-AITP-0004 §8.1).
#[cfg(feature = "experimental-renewal")]
#[instrument(level = "debug", skip(state, request))]
async fn handle_renew<R: JwksResolver + Send + Sync + 'static>(
    State(state): State<Arc<HandshakeState<R>>>,
    request: Request,
) -> Result<Response, ResponseError> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.starts_with("application/json") {
        return Err(ResponseError::aitp(
            ErrorCode::InvalidEnvelope,
            "expected Content-Type: application/json".into(),
        ));
    }
    let body = read_body_with_timeout(request, DEFAULT_BODY_READ_TIMEOUT).await?;
    let payload: TctRenewalPayload = serde_json::from_slice(&body).map_err(|e| {
        ResponseError::aitp(ErrorCode::InvalidEnvelope, format!("malformed JSON: {e}"))
    })?;
    let now = Timestamp::now();
    let renewed = process_renewal_request(
        &payload,
        &state.signing_key,
        state.manifest.expires_at,
        now,
        aitp_tct::DEFAULT_TCT_TTL_SECS,
    )
    .map_err(|e| ResponseError::aitp(ErrorCode::TctSignatureInvalid, e.to_string()))?;
    Ok(Json(TctEnvelope { tct: renewed }).into_response())
}

fn revocation_router(producer: Arc<dyn RevocationListProducer>) -> Router {
    Router::new().route(
        "/.well-known/aitp-revocation-list",
        get(move || {
            let producer = producer.clone();
            async move { Json(producer.current()) }
        }),
    )
}

const SESSION_HEADER: &str = "x-aitp-session-id";

async fn handle_hello<R: JwksResolver + Send + Sync + 'static>(
    State(state): State<Arc<HandshakeState<R>>>,
    request: Request,
) -> Result<Response, ResponseError> {
    let envelope = parse_envelope_request(request, MessageType::MutualHello).await?;
    enforce_envelope_boundary_checks(&state, &envelope)?;
    let payload: MutualHelloPayload =
        serde_json::from_value(envelope.payload.clone()).map_err(|e| {
            ResponseError::aitp(
                ErrorCode::InvalidEnvelope,
                format!("malformed payload: {e}"),
            )
        })?;
    // Verify envelope signature using the *peer's* claimed key. Bootstrap
    // verification will check that the AID's public key actually matches
    // what the manifest claims.
    let peer_pk = AitpVerifyingKey::from_aid(&envelope.sender.agent_id).map_err(|_| {
        ResponseError::aitp(ErrorCode::InvalidEnvelope, "sender AID malformed".into())
    })?;
    verify_envelope_signature(&envelope, &peer_pk).map_err(|_| {
        ResponseError::aitp(
            ErrorCode::InvalidSignature,
            "envelope signature invalid".into(),
        )
    })?;

    let cfg = PeerConfig {
        signing_key: &state.signing_key,
        manifest: &state.manifest,
        trust_anchors: &state.trust_anchors,
        jwks_resolver: &state.jwks_resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: aitp_core::Timestamp::now(),
    };
    // Server uses pinned-key identity by default (the demo). Production
    // deployments wanting OIDC should construct PresentedIdentity::Oidc
    // outside and use a custom server.
    let pubkey_b64 = aitp_core::base64url::encode(&state.signing_key.verifying_key().to_bytes());
    let _ = pubkey_b64; // captured by PresentedIdentity below
    let ack_mid = Uuid::new_v4();
    let ack_ts = aitp_core::Timestamp::now();
    let (responder, ack_payload) = Responder::on_hello(
        &envelope,
        &payload,
        PresentedIdentity::PinnedKey {
            subject: state
                .manifest
                .display_name
                .clone()
                .unwrap_or_else(|| "responder".into()),
        },
        &ack_mid,
        ack_ts,
        &cfg,
        state.requested_grants.clone(),
    )
    .map_err(|e| ResponseError::aitp(handshake_error_code(&e), e.to_string()))?;

    let session_id = Uuid::new_v4();
    {
        let mut sessions = state.sessions.lock();
        sweep_expired(&mut sessions, state.session_ttl);
        sessions.insert(
            session_id,
            SessionEntry {
                responder,
                created_at: Instant::now(),
            },
        );
    }

    // Use the *same* (ack_mid, ack_ts) that built the identity proof inside
    // `ack_payload`. The pinned-key proof is bound to those values; if we
    // re-generated them here the receiving peer would fail identity
    // verification.
    let ack_payload_value =
        serde_json::to_value(&ack_payload).map_err(|_| ResponseError::server_error())?;
    let ack_envelope = sign_envelope_with(
        &state.signing_key,
        MessageType::MutualHelloAck,
        ack_payload_value,
        ack_mid,
        ack_ts,
    )
    .map_err(|_| ResponseError::server_error())?;
    let mut response = Json(ack_envelope).into_response();
    let session_header_value = session_id
        .to_string()
        .parse()
        .map_err(|_| ResponseError::server_error())?;
    response
        .headers_mut()
        .insert(SESSION_HEADER, session_header_value);
    Ok(response)
}

async fn handle_commit<R: JwksResolver + Send + Sync + 'static>(
    State(state): State<Arc<HandshakeState<R>>>,
    request: Request,
) -> Result<Response, ResponseError> {
    let headers = request.headers().clone();
    let envelope = parse_envelope_request(request, MessageType::MutualCommit).await?;
    enforce_envelope_boundary_checks(&state, &envelope)?;
    let session_id = headers
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            ResponseError::aitp(
                ErrorCode::InvalidEnvelope,
                "missing or malformed session header".into(),
            )
        })?;
    let mut entry = {
        let mut sessions = state.sessions.lock();
        let expired_present = sessions
            .get(&session_id)
            .is_some_and(|e| Instant::now().duration_since(e.created_at) > state.session_ttl);
        sweep_expired(&mut sessions, state.session_ttl);
        if expired_present {
            return Err(ResponseError::aitp(
                ErrorCode::TimestampExpired,
                "session expired".into(),
            ));
        }
        sessions.remove(&session_id).ok_or_else(|| {
            ResponseError::aitp(ErrorCode::InvalidEnvelope, "unknown session".into())
        })?
    };
    let payload: MutualCommitPayload =
        serde_json::from_value(envelope.payload.clone()).map_err(|e| {
            ResponseError::aitp(
                ErrorCode::InvalidEnvelope,
                format!("malformed payload: {e}"),
            )
        })?;

    let peer_pk = AitpVerifyingKey::from_aid(&envelope.sender.agent_id).map_err(|_| {
        ResponseError::aitp(ErrorCode::InvalidEnvelope, "sender AID malformed".into())
    })?;
    verify_envelope_signature(&envelope, &peer_pk).map_err(|_| {
        ResponseError::aitp(
            ErrorCode::InvalidSignature,
            "envelope signature invalid".into(),
        )
    })?;

    let cfg = PeerConfig {
        signing_key: &state.signing_key,
        manifest: &state.manifest,
        trust_anchors: &state.trust_anchors,
        jwks_resolver: &state.jwks_resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: aitp_core::Timestamp::now(),
    };
    let (ack_payload, _our_held_tct) = entry
        .responder
        .on_commit(&envelope, &payload, &cfg)
        .map_err(|e| ResponseError::aitp(handshake_error_code(&e), e.to_string()))?;
    let ack_payload_value =
        serde_json::to_value(&ack_payload).map_err(|_| ResponseError::server_error())?;
    let ack_envelope = sign_envelope(
        &state.signing_key,
        MessageType::MutualCommitAck,
        ack_payload_value,
    )
    .map_err(|_| ResponseError::server_error())?;
    Ok(Json(ack_envelope).into_response())
}

/// Wire-format error response: status + AITP error JSON.
///
/// The body is a registered AITP error envelope:
///
/// ```json
/// { "error": { "code": "REPLAY_DETECTED", "message": "duplicate message_id" } }
/// ```
///
/// Codes come from the AITP error-code registry
/// ([`aitp_core::ErrorCode`]). Production deployments parse `error.code`
/// and ignore `error.message`.
#[derive(Debug)]
struct ResponseError {
    status: StatusCode,
    code: ErrorCode,
    message: String,
}

impl ResponseError {
    /// Map an [`ErrorCode`] + message to a `ResponseError`. Status code
    /// is fixed at 400 — every AITP-defined failure on the handshake
    /// path is a client-side problem.
    fn aitp(code: ErrorCode, message: String) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message,
        }
    }

    /// Internal-error fallback — used only when `sign_envelope` fails,
    /// which would indicate a bug.
    fn server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: ErrorCode::InvalidEnvelope,
            message: "internal error signing reply envelope".into(),
        }
    }
}

impl IntoResponse for ResponseError {
    fn into_response(self) -> Response {
        // Emit a structured event for every error envelope we ship.
        // Operators dashboarding on AITP error rates key off
        // `aitp.error.envelope` event names.
        warn!(
            target: "aitp.error.envelope",
            code = ?self.code,
            status = self.status.as_u16(),
            message = %self.message,
            "AITP error envelope returned"
        );
        // The body is constructed from a json! macro over `Serialize`
        // types we control, so to_vec() and Response::builder() are
        // infallible in practice. We `expect` rather than `unwrap` to
        // surface a clear panic message if a future change breaks
        // either invariant.
        let body = json!({
            "error": {
                "code": self.code,
                "message": self.message,
            },
        });
        let body_bytes =
            serde_json::to_vec(&body).expect("serializing a static json! body cannot fail");
        let mut resp = Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body_bytes))
            .expect("response with valid status + headers + body builds");
        resp.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        resp
    }
}

/// Read the request body with two bounds:
/// - **Size**: refused with `INVALID_ENVELOPE` if it exceeds
///   [`DEFAULT_MAX_BODY_BYTES`].
/// - **Wall-clock**: refused with `INVALID_ENVELOPE` if the entire
///   body cannot be drained within `timeout`. Defeats slow-loris
///   clients trickling bytes within the body cap.
async fn read_body_with_timeout(
    request: Request,
    timeout: Duration,
) -> Result<axum::body::Bytes, ResponseError> {
    let body_fut = to_bytes(request.into_body(), DEFAULT_MAX_BODY_BYTES);
    match tokio::time::timeout(timeout, body_fut).await {
        Ok(Ok(b)) => Ok(b),
        Ok(Err(e)) => Err(ResponseError::aitp(
            ErrorCode::InvalidEnvelope,
            format!("oversized or unreadable body: {e}"),
        )),
        Err(_elapsed) => Err(ResponseError::aitp(
            ErrorCode::InvalidEnvelope,
            format!("body read exceeded {}s", timeout.as_secs()),
        )),
    }
}

/// Read the request body, validate Content-Type, oversize, JSON parse,
/// and message-type alignment. The boundary check returns AITP error
/// envelopes for every failure path (RFC-AITP-0001 §6).
async fn parse_envelope_request(
    request: Request,
    expected: MessageType,
) -> Result<AitpEnvelope, ResponseError> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.starts_with("application/json") {
        return Err(ResponseError::aitp(
            ErrorCode::InvalidEnvelope,
            format!("expected Content-Type: application/json, got `{content_type}`"),
        ));
    }
    let body = read_body_with_timeout(request, DEFAULT_BODY_READ_TIMEOUT).await?;
    let envelope: AitpEnvelope = serde_json::from_slice(&body).map_err(|e| {
        ResponseError::aitp(ErrorCode::InvalidEnvelope, format!("malformed JSON: {e}"))
    })?;
    if envelope.message_type != expected {
        return Err(ResponseError::aitp(
            ErrorCode::InvalidEnvelope,
            format!(
                "expected message_type={expected:?}, got {:?}",
                envelope.message_type
            ),
        ));
    }
    Ok(envelope)
}

/// Boundary checks applied to every accepted envelope: timestamp
/// tolerance + replay-deny-list. Done before payload parsing so a
/// flood of stale or replayed envelopes does not exercise the
/// downstream parser path.
fn enforce_envelope_boundary_checks<R: JwksResolver + Send + Sync + 'static>(
    state: &Arc<HandshakeState<R>>,
    envelope: &AitpEnvelope,
) -> Result<(), ResponseError> {
    // RFC-AITP-0001 §5.6: "Verifiers receiving an unknown `version` MUST
    // respond with `UNKNOWN_VERSION`." Done before any other check so a
    // peer using a forward version learns about the mismatch first.
    if envelope.version != "aitp/0.1" {
        return Err(ResponseError::aitp(
            ErrorCode::UnknownVersion,
            format!(
                "unsupported envelope version `{}` (this implementation accepts `aitp/0.1`)",
                envelope.version
            ),
        ));
    }
    let now = Timestamp::now();
    let drift = (envelope.timestamp.0 - now.0).abs();
    if drift > DEFAULT_TIMESTAMP_TOLERANCE_SECS {
        return Err(ResponseError::aitp(
            ErrorCode::TimestampExpired,
            format!(
                "envelope timestamp drift {drift}s exceeds {DEFAULT_TIMESTAMP_TOLERANCE_SECS}s",
            ),
        ));
    }
    check_and_record_message_id(state, &envelope.message_id)?;
    Ok(())
}

/// Map a `HandshakeError` into the closest registered AITP error code.
fn handshake_error_code(err: &aitp_handshake::HandshakeError) -> ErrorCode {
    use aitp_handshake::HandshakeError as HE;
    match err {
        HE::Identity(_) => ErrorCode::IdentityFailed,
        HE::Tct(_) => ErrorCode::TctSignatureInvalid,
        HE::Manifest(_) => ErrorCode::ManifestSignatureInvalid,
        HE::PolicyViolation => ErrorCode::PolicyViolation,
        HE::PopVerificationFailed => ErrorCode::PopVerificationFailed,
        HE::NonceMismatch => ErrorCode::NonceMismatch,
        HE::InsufficientGrants => ErrorCode::InsufficientGrants,
        HE::IncompatibleTrustAnchors => ErrorCode::IncompatibleTrustAnchors,
        HE::InvalidSignature => ErrorCode::InvalidSignature,
        HE::InvalidEnvelope(_) | HE::State(_) | HE::Rng(_) | HE::Canonicalization(_) => {
            ErrorCode::InvalidEnvelope
        }
        HE::Crypto(_) => ErrorCode::InvalidSignature,
    }
}

/// Check the per-server message_id deny list (RFC-AITP-0001 §5.5).
/// Evicts entries older than the configured `replay_window` first, then
/// records this message_id. Duplicate within the window → REPLAY_DETECTED.
fn check_and_record_message_id<R: JwksResolver + Send + Sync + 'static>(
    state: &Arc<HandshakeState<R>>,
    mid: &Uuid,
) -> Result<(), ResponseError> {
    let now = Instant::now();
    let mut seen = state.seen_message_ids.lock();
    seen.retain(|_, ts| now.duration_since(*ts) < state.replay_window);
    if seen.insert(*mid, now).is_some() {
        return Err(ResponseError::aitp(
            ErrorCode::ReplayDetected,
            "duplicate message_id within replay window".into(),
        ));
    }
    Ok(())
}

fn sweep_expired(sessions: &mut HashMap<Uuid, SessionEntry>, ttl: Duration) {
    let now = Instant::now();
    let before = sessions.len();
    sessions.retain(|_, e| now.duration_since(e.created_at) <= ttl);
    let evicted = before - sessions.len();
    if evicted > 0 {
        debug!(evicted, "swept expired handshake sessions");
    }
}
