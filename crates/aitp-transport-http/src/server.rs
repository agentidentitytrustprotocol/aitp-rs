//! HTTP server primitives: Manifest server, handshake server.

use crate::common::{sign_envelope, sign_envelope_with, verify_envelope_signature};
use aitp_core::{AitpEnvelope, ErrorCode, MessageType, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp_handshake::{
    JwksResolver, MutualCommitPayload, MutualHelloPayload, PeerConfig, PinnedKeyStore,
    PresentedIdentity, Responder,
};
use aitp_manifest::{Manifest, ManifestEnvelope};
use aitp_tct::RevocationListEnvelope;
#[cfg(feature = "experimental-renewal")]
use aitp_tct::{process_renewal_request, TctRenewalPayload};
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

/// Default upper bound on the number of in-progress handshake sessions
/// retained server-side. Once exceeded, the oldest sessions are evicted
/// preemptively even if their TTL has not elapsed. This defends against
/// a HELLO flood that would otherwise grow the session table without
/// bound until the next sweep. 10 000 in-flight sessions covers a
/// realistic peak for a single-host responder; operators with higher
/// throughput should raise this via [`HandshakeServer::with_max_sessions`].
pub const DEFAULT_MAX_SESSIONS: usize = 10_000;

/// Default period for the background session sweeper. Sweep-on-request
/// alone is insufficient: a HELLO flood that goes quiet leaves stale
/// sessions occupying memory until the next request arrives. A periodic
/// sweep evicts those entries on a bounded schedule independent of
/// traffic. The default is half the [`DEFAULT_SESSION_TTL`] so any
/// expired session is reclaimed within at most `TTL + period` from
/// its creation. Disabled by [`Duration::ZERO`].
pub const DEFAULT_SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

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
    /// Hard cap on the number of in-progress sessions retained
    /// server-side. When an insert would exceed this, the oldest
    /// entry is evicted regardless of its TTL. Atomic so
    /// [`HandshakeServer::with_max_sessions`] can configure it after
    /// the `Arc<HandshakeState>` is already built.
    max_sessions: std::sync::atomic::AtomicUsize,
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
    /// Optional local pinned-key trust store (RFC-AITP-0002 §3.2
    /// step 1). When `Some`, an initiator presenting a pinned-key
    /// identity whose Ed25519 public key is not in the store is
    /// rejected with `IDENTITY_FAILED`; when `None`, the pinned-key
    /// check proves key possession only. Installed via
    /// [`HandshakeServer::with_pinned_key_store`]. Stored under
    /// interior mutability so the builder can configure a server whose
    /// `Arc<HandshakeState>` is already shared.
    pinned_key_store: Mutex<Option<Arc<dyn PinnedKeyStore>>>,
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
                max_sessions: std::sync::atomic::AtomicUsize::new(DEFAULT_MAX_SESSIONS),
                seen_message_ids: Mutex::new(HashMap::new()),
                replay_window,
                dpop_policy: Mutex::new(None),
                dpop_replay_cache: Arc::new(crate::dpop::DpopReplayCache::default()),
                rate_limit_config: Mutex::new(None),
                rate_limit_events: Mutex::new(HashMap::new()),
                pinned_key_store: Mutex::new(None),
            }),
            revocation_producer: None,
        }
    }

    /// Override the in-flight session cap (default
    /// [`DEFAULT_MAX_SESSIONS`]). When the cap is reached, every new
    /// HELLO evicts the oldest in-flight session before inserting, so
    /// the server's session-table memory footprint stays bounded
    /// under adversarial HELLO floods. `max_sessions` MUST be > 0.
    pub fn with_max_sessions(self, max_sessions: usize) -> Self {
        assert!(max_sessions > 0, "max_sessions must be > 0");
        self.state
            .max_sessions
            .store(max_sessions, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Spawn a background task on the current Tokio runtime that
    /// periodically evicts sessions older than the configured TTL.
    /// Without this, sweep happens only on the next request, so a
    /// HELLO burst that goes quiet retains memory until the next
    /// request arrives.
    ///
    /// Returns a [`tokio::task::JoinHandle`] the caller can keep to
    /// abort the sweeper on shutdown, or `Err` if no Tokio runtime
    /// is currently active. The returned handle is detached if
    /// dropped — the task aborts implicitly when the
    /// `Arc<HandshakeState>` it weakly references is dropped, so a
    /// caller that does not need fine-grained shutdown control may
    /// safely discard it.
    pub fn spawn_session_sweeper(
        &self,
        interval: Duration,
    ) -> Result<tokio::task::JoinHandle<()>, tokio::runtime::TryCurrentError> {
        let handle = tokio::runtime::Handle::try_current()?;
        let weak = Arc::downgrade(&self.state);
        let ttl = self.state.session_ttl;
        let join = handle.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Don't fire a spurious immediate tick: the first call to
            // `tick()` always returns instantly, which would log a
            // zero-eviction sweep at startup. Consume that first tick.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(state) = weak.upgrade() else {
                    debug!("HandshakeState dropped; session sweeper exiting");
                    return;
                };
                let mut sessions = state.sessions.lock();
                sweep_expired(&mut sessions, ttl);
            }
        });
        Ok(join)
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

    /// Attach a local pinned-key trust store (RFC-AITP-0002 §3.2
    /// step 1). Without this, the responder's pinned-key verification
    /// proves only that the initiator possesses the key matching its
    /// AID — not that the responder has any reason to *trust* that key.
    /// Production servers accepting pinned-key initiators MUST configure
    /// a store; an initiator whose key is absent is rejected with
    /// `IDENTITY_FAILED`. OIDC trust is configured separately via the
    /// `trust_anchors` + `jwks_resolver` arguments to [`Self::new`].
    pub fn with_pinned_key_store(self, store: Arc<dyn PinnedKeyStore>) -> Self {
        *self.state.pinned_key_store.lock() = Some(store);
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
    ///
    /// The handshake handlers ([`Self::router`]'s `hello` / `commit`
    /// routes) call this internally per RFC-AITP-0009 §3.1 — after the
    /// replay deny-list check and before timestamp validation. Calling
    /// it again from operator middleware double-counts the request;
    /// most operators only need [`Self::with_rate_limit`].
    pub fn enforce_rate_limit(
        &self,
        client_ip: Option<&str>,
        peer_aid: Option<&aitp_core::Aid>,
    ) -> RateLimitOutcome {
        rate_limit_check(&self.state, client_ip, peer_aid)
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
/// returns a fresh `{"tct": "<compact JWS>", "grant_voucher": …}` body.
/// Gated behind the `experimental-renewal` Cargo feature
/// (RFC-AITP-0004 §8.1).
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
    #[derive(serde::Serialize)]
    struct RenewalResponse {
        tct: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        grant_voucher: Option<String>,
    }
    Ok(Json(RenewalResponse {
        tct: renewed.token,
        grant_voucher: renewed.voucher,
    })
    .into_response())
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
    let source_ip = extract_source_ip(&request);
    let envelope = parse_envelope_request(request, MessageType::MutualHello).await?;
    enforce_envelope_boundary_checks(&state, &envelope, source_ip.as_deref())?;
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

    // Snapshot the pinned-key trust store (RFC-AITP-0002 §3.2 step 1);
    // the clone outlives `cfg` and the synchronous `Responder::on_hello`
    // call below.
    let pinned_store = state.pinned_key_store.lock().clone();
    let cfg = PeerConfig {
        signing_key: &state.signing_key,
        manifest: &state.manifest,
        trust_anchors: &state.trust_anchors,
        jwks_resolver: &state.jwks_resolver,
        pinned_key_store: pinned_store.as_deref(),
        grant_policy: None,
        revocation_check: None,
        now: aitp_core::Timestamp::now(),
    };
    // Server uses pinned-key identity by default (the demo). Production
    // deployments wanting OIDC should construct PresentedIdentity::Oidc
    // outside and use a custom server. The public key is materialized
    // inside `Responder::on_hello` from `state.signing_key`; no need to
    // compute it here.
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
        let cap = state
            .max_sessions
            .load(std::sync::atomic::Ordering::Relaxed);
        // Enforce the cap by evicting the oldest entries until the
        // insert will leave us at or below the cap. This bounds memory
        // under HELLO floods even when every retained session is still
        // within its TTL.
        evict_to_capacity(&mut sessions, cap.saturating_sub(1));
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
    let source_ip = extract_source_ip(&request);
    let envelope = parse_envelope_request(request, MessageType::MutualCommit).await?;
    enforce_envelope_boundary_checks(&state, &envelope, source_ip.as_deref())?;
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

    // Snapshot the pinned-key trust store (RFC-AITP-0002 §3.2 step 1);
    // the clone outlives `cfg` and the synchronous `on_commit` call.
    let pinned_store = state.pinned_key_store.lock().clone();
    let cfg = PeerConfig {
        signing_key: &state.signing_key,
        manifest: &state.manifest,
        trust_anchors: &state.trust_anchors,
        jwks_resolver: &state.jwks_resolver,
        pinned_key_store: pinned_store.as_deref(),
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
    /// When `false` the response body is empty and no AITP `error`
    /// envelope is emitted. Used for rejections that never reached the
    /// protocol layer — RFC-AITP-0009 §3.1 says a rate-limited request
    /// "never reached the protocol layer", so its HTTP 429 carries no
    /// AITP `error` payload.
    emit_envelope: bool,
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
            emit_envelope: true,
        }
    }

    /// Internal-error fallback — used only when `sign_envelope` fails,
    /// which would indicate a bug.
    fn server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: ErrorCode::InvalidEnvelope,
            message: "internal error signing reply envelope".into(),
            emit_envelope: true,
        }
    }

    /// HTTP 429 for a rate-limited request. Per RFC-AITP-0009 §3.1 the
    /// body is empty — the request never reached the protocol layer, so
    /// there is no AITP `error` envelope to return. `reason` is recorded
    /// in server telemetry only.
    fn too_many_requests(reason: String) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            // Unused: `emit_envelope` is false so `code` is never
            // serialized. There is no registered AITP error code for
            // rate limiting precisely because no envelope is emitted.
            code: ErrorCode::InvalidEnvelope,
            message: reason,
            emit_envelope: false,
        }
    }
}

impl IntoResponse for ResponseError {
    fn into_response(self) -> Response {
        if !self.emit_envelope {
            // Pre-protocol rejection (rate limiting): empty body, no
            // AITP `error` envelope (RFC-AITP-0009 §3.1). Logged under
            // a distinct target so it does not skew AITP-error-envelope
            // dashboards.
            warn!(
                target: "aitp.error.rate_limited",
                status = self.status.as_u16(),
                message = %self.message,
                "request rejected before the protocol layer"
            );
            let mut resp = Response::builder()
                .status(self.status)
                .body(Body::empty())
                .expect("response with valid status + empty body builds");
            resp.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            );
            return resp;
        }
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

/// Best-effort source-IP extraction for per-IP rate limiting
/// (RFC-AITP-0009 §3.1). Prefers `X-Forwarded-For` (first / client
/// hop), then `X-Real-IP`, then the peer socket address — the last is
/// only present when the router is served with
/// `into_make_service_with_connect_info::<SocketAddr>()`.
///
/// `X-Forwarded-For` and `X-Real-IP` are client-spoofable unless the
/// server sits behind a trusted proxy that overwrites them; operators
/// relying on the per-IP gate SHOULD deploy behind such a proxy. The
/// per-AID gate, keyed off the authenticated envelope `sender`, is not
/// spoofable this way and is the stronger of the two limits.
fn extract_source_ip(request: &Request) -> Option<String> {
    let headers = request.headers();
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let trimmed = first.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let trimmed = xri.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
}

/// Sliding-window rate-limit evaluation shared by
/// [`HandshakeServer::enforce_rate_limit`] and the handshake handlers.
/// On `Allow` the event is recorded; on `DenyTooManyRequests` nothing
/// is recorded, so a denied caller does not accelerate its own deny.
/// Returns `Allow` when no policy is configured.
fn rate_limit_check<R: JwksResolver + Send + Sync>(
    state: &HandshakeState<R>,
    client_ip: Option<&str>,
    peer_aid: Option<&aitp_core::Aid>,
) -> RateLimitOutcome {
    let config = match state.rate_limit_config.lock().clone() {
        Some(c) => c,
        None => return RateLimitOutcome::Allow,
    };
    let mut events = state.rate_limit_events.lock();
    let now = Instant::now();
    let window = Duration::from_secs(60);
    // Tentative event additions, committed only if both gates pass.
    // Avoids partial-state under contention.
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

/// Boundary checks applied to every accepted envelope. Done before
/// payload parsing so a flood of stale, replayed, or over-quota
/// envelopes does not exercise the downstream parser path.
///
/// RFC-AITP-0009 §3.1 makes the order **normative**:
/// version → replay deny-list → rate limiting → timestamp tolerance.
/// Replay runs before rate limiting so a captured-and-replayed envelope
/// is rejected without consuming the sender's rate-limit slot; rate
/// limiting runs before timestamp validation so a flood of distinct
/// fresh envelopes is shed before any per-envelope clock comparison.
fn enforce_envelope_boundary_checks<R: JwksResolver + Send + Sync + 'static>(
    state: &Arc<HandshakeState<R>>,
    envelope: &AitpEnvelope,
    source_ip: Option<&str>,
) -> Result<(), ResponseError> {
    // RFC-AITP-0001 §5.6: "Verifiers receiving an unknown `version` MUST
    // respond with `UNKNOWN_VERSION`." A structural protocol-identity
    // check; done first so a peer on a forward version learns about the
    // mismatch before anything else.
    if envelope.version != "aitp/0.2" {
        return Err(ResponseError::aitp(
            ErrorCode::UnknownVersion,
            format!(
                "unsupported envelope version `{}` (this implementation accepts `aitp/0.1`)",
                envelope.version
            ),
        ));
    }

    // 1. Replay deny-list (RFC-AITP-0001 §5.5). First, so a replayed
    //    envelope is rejected with REPLAY_DETECTED without burning the
    //    sender AID's rate-limit budget.
    check_and_record_message_id(state, &envelope.message_id)?;

    // 2. Rate limiting (RFC-AITP-0009 §3.1). Keyed off the source IP
    //    and the envelope `sender` AID. Rejection is HTTP 429 with no
    //    AITP error envelope — the request never reached the protocol
    //    layer.
    //
    //    Note: RFC-AITP-0009 §3.1 places rate limiting (step 2) ahead
    //    of envelope signature verification (step 5), so the `sender`
    //    AID is NOT yet authenticated here — an attacker can forge it.
    //    The per-AID limit is therefore a best-effort gate; the per-IP
    //    limit (keyed off the transport, not the payload) is the firmer
    //    of the two. Deployments needing an authenticated per-AID limit
    //    must additionally throttle after signature verification.
    if let RateLimitOutcome::DenyTooManyRequests { reason } =
        rate_limit_check(state, source_ip, Some(&envelope.sender.agent_id))
    {
        return Err(ResponseError::too_many_requests(reason));
    }

    // 3. Timestamp tolerance (RFC-AITP-0001 §5.5).
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
    Ok(())
}

/// Map a `HandshakeError` into the closest registered AITP error code.
fn handshake_error_code(err: &aitp_handshake::HandshakeError) -> ErrorCode {
    use aitp_handshake::HandshakeError as HE;
    use aitp_tct::TctError;
    match err {
        HE::Identity(_) => ErrorCode::IdentityFailed,
        // RFC-AITP-0005 §9: a peer-issued TCT can fail for distinct,
        // separately-registered reasons. Collapsing every TctError to
        // TCT_SIGNATURE_INVALID misreports a revoked or expired TCT to
        // the peer as a signature failure.
        HE::Tct(tct_err) => match tct_err {
            TctError::Revoked => ErrorCode::TctRevoked,
            TctError::Expired => ErrorCode::TctExpired,
            TctError::ExpiresAfterManifest => ErrorCode::TctExpiresAfterManifest,
            _ => ErrorCode::TctSignatureInvalid,
        },
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
        // `HandshakeError` is `#[non_exhaustive]`; any future variant
        // we haven't yet mapped to a specific wire code defaults to
        // INVALID_ENVELOPE rather than panicking.
        _ => ErrorCode::InvalidEnvelope,
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

/// Evict the oldest sessions until `sessions.len() <= cap`. Logs at
/// WARN when entries within their TTL are evicted, because that
/// signals load above the configured cap — operators should investigate
/// either a HELLO flood or a too-low cap.
fn evict_to_capacity(sessions: &mut HashMap<Uuid, SessionEntry>, cap: usize) {
    evict_oldest_to_capacity(sessions, cap, |entry| entry.created_at);
}

/// Generic eviction helper. Drops the entries with the smallest
/// `instant_of(entry)` until `map.len() <= cap`. Pulled out so unit
/// tests can exercise the eviction logic on a simpler value type.
fn evict_oldest_to_capacity<V>(
    map: &mut HashMap<Uuid, V>,
    cap: usize,
    instant_of: impl Fn(&V) -> Instant,
) {
    if map.len() <= cap {
        return;
    }
    let mut by_age: Vec<(Uuid, Instant)> = map.iter().map(|(k, v)| (*k, instant_of(v))).collect();
    by_age.sort_by_key(|(_, t)| *t);
    let to_evict = map.len() - cap;
    let evicted = to_evict;
    for (key, _) in by_age.into_iter().take(to_evict) {
        map.remove(&key);
    }
    warn!(
        evicted,
        cap, "evicted oldest in-flight sessions to enforce max_sessions cap"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitp_handshake::HandshakeError;
    use aitp_tct::TctError;

    /// GAP-2: `handshake_error_code` previously collapsed every
    /// `HandshakeError::Tct(_)` to `TCT_SIGNATURE_INVALID`, so a peer
    /// presenting a revoked or expired TCT during the handshake was
    /// told its signature was bad. Each `TctError` reason now maps to
    /// its own registered code.
    #[test]
    fn tct_error_variants_map_to_distinct_codes() {
        assert_eq!(
            handshake_error_code(&HandshakeError::Tct(TctError::Revoked)),
            ErrorCode::TctRevoked,
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::Tct(TctError::Expired)),
            ErrorCode::TctExpired,
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::Tct(TctError::ExpiresAfterManifest)),
            ErrorCode::TctExpiresAfterManifest,
        );
        // Reasons without a dedicated code still fall back to
        // TCT_SIGNATURE_INVALID — the catch-all is intentional.
        assert_eq!(
            handshake_error_code(&HandshakeError::Tct(TctError::SignatureInvalid)),
            ErrorCode::TctSignatureInvalid,
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::Tct(TctError::AudienceMismatch)),
            ErrorCode::TctSignatureInvalid,
        );
    }

    #[test]
    fn evict_oldest_to_capacity_drops_oldest_first() {
        use std::thread::sleep;
        use std::time::Duration as StdDuration;

        let mut map: HashMap<Uuid, Instant> = HashMap::new();
        let oldest = Uuid::new_v4();
        map.insert(oldest, Instant::now());
        sleep(StdDuration::from_millis(2));
        let middle = Uuid::new_v4();
        map.insert(middle, Instant::now());
        sleep(StdDuration::from_millis(2));
        let newest = Uuid::new_v4();
        map.insert(newest, Instant::now());

        evict_oldest_to_capacity(&mut map, 2, |t| *t);
        assert_eq!(map.len(), 2, "should retain exactly cap entries");
        assert!(!map.contains_key(&oldest), "oldest must be evicted");
        assert!(map.contains_key(&middle));
        assert!(map.contains_key(&newest));
    }

    #[test]
    fn evict_oldest_to_capacity_is_noop_when_under_cap() {
        let mut map: HashMap<Uuid, Instant> = HashMap::new();
        for _ in 0..5 {
            map.insert(Uuid::new_v4(), Instant::now());
        }
        evict_oldest_to_capacity(&mut map, 10, |t| *t);
        assert_eq!(map.len(), 5);
    }
}
