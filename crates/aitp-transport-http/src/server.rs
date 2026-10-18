//! HTTP server primitives: Manifest server, handshake server.

use crate::common::{sign_envelope, sign_envelope_with, verify_envelope_signature};
pub use crate::source_ip::{resolve_source_ip, TrustedProxy, TrustedProxyParseError};
use aitp_core::{
    check_members, from_serde_error, parse_envelope_wire, AitpEnvelope, CheckedJson,
    EnvelopeParseError, ErrorCode, MessageType, Timestamp,
};
use aitp_crypto::{AitpSigner, AitpVerifyingKey};
use aitp_handshake::{
    HandshakeError, JwksResolver, MutualCommitPayload, MutualHelloPayload, NoPinnedKeys,
    PeerConfig, PinnedKeyStore, PresentedIdentity, Responder, MUTUAL_COMMIT_PAYLOAD_MEMBERS,
    MUTUAL_HELLO_PAYLOAD_MEMBERS,
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
/// bound until the next sweep. 1 000 is the RFC-AITP-0009 §3.1
/// recommended maximum of concurrent in-flight handshake sessions;
/// operators with higher throughput should raise this via
/// [`HandshakeServer::with_max_sessions`].
pub const DEFAULT_MAX_SESSIONS: usize = 1_000;

/// Default period for the background session sweeper. Sweep-on-request
/// alone is insufficient: a HELLO flood that goes quiet leaves stale
/// sessions occupying memory until the next request arrives. A periodic
/// sweep evicts those entries on a bounded schedule independent of
/// traffic. The default is half the [`DEFAULT_SESSION_TTL`] so any
/// expired session is reclaimed within at most `TTL + period` from
/// its creation. The sweeper starts automatically with the router
/// (see [`HandshakeServer::router`]); turn it off with
/// [`HandshakeServer::without_session_sweeper`] or by passing
/// [`Duration::ZERO`] to [`HandshakeServer::with_session_sweep_interval`].
pub const DEFAULT_SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Path at which [`HandshakeServer::router`] serves `ListRevoked`, the
/// issuer's signed revocation snapshot (RFC-AITP-0005 §11,
/// RFC-AITP-0008 §1.5). The issuer's Manifest advertises the absolute
/// URL of this route via
/// [`ManifestBuilder::revocation_list_uri`](aitp_manifest::ManifestBuilder::revocation_list_uri),
/// e.g. `origin.join(REVOCATION_LIST_PATH)`.
pub const REVOCATION_LIST_PATH: &str = "/.well-known/aitp-revocation-list";

/// Validity window of the default signed empty snapshot a
/// [`HandshakeServer`] serves when no [`RevocationListProducer`] is
/// attached.
const DEFAULT_EMPTY_SNAPSHOT_TTL_SECS: i64 = 3600;

/// How long a default signed empty snapshot is reused before it is
/// re-signed. Bounds signing-backend load (a KMS call per poll on an
/// unauthenticated GET) while keeping `published_at` fresh well inside
/// any sane `max_staleness_secs`.
const DEFAULT_EMPTY_SNAPSHOT_REFRESH_SECS: i64 = 60;

/// Producer of the local issuer's [`RevocationListEnvelope`] for the
/// outbound [`REVOCATION_LIST_PATH`] endpoint (RFC-AITP-0008 §1.5).
///
/// A [`HandshakeServer`] always serves `ListRevoked` (RFC-AITP-0005 §11).
/// Without a producer it serves a signed empty snapshot, which is only
/// true for a deployment that never revokes; attach a producer as soon
/// as the deployment can revoke.
///
/// Implementations choose how to source the list — common options:
/// - hold an in-memory `RwLock<RevocationListEnvelope>` and update it
///   from your control plane, or
/// - re-sign on every poll from a database table.
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
/// - `GET` [`REVOCATION_LIST_PATH`] serves `ListRevoked`, always
///   (RFC-AITP-0005 §11); see [`Self::with_revocation_producer`]
///
/// Sessions are correlated by the `X-Aitp-Session-Id` HTTP header; clients
/// receive a session id in the same header on the HELLO_ACK response.
pub struct HandshakeServer<R: JwksResolver + Send + Sync + 'static> {
    state: Arc<HandshakeState<R>>,
    revocation_producer: Option<Arc<dyn RevocationListProducer>>,
}

/// Sliding-window rate-limit policy for the handshake endpoint
/// (RFC-AITP-0009 §3.1, which makes rate limiting a MUST).
///
/// On by default with [`RateLimitConfig::default`], the §3.1
/// recommended values. [`HandshakeServer::enforce_rate_limit`] counts
/// events over the most recent 60-second window and rejects with HTTP
/// 429 once a key crosses its limit.
///
/// The transport limit always applies. Its key is the peer IP (IPv6
/// folded to its /64, IPv4-mapped folded to IPv4), taken from
/// `X-Forwarded-For` / `X-Real-IP` only when the immediate hop is in
/// [`Self::trusted_proxies`]. The per-AID limit is extra: the envelope
/// `sender` is unauthenticated at that point, so §3.1 forbids it from
/// being the only key.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Max requests per transport source in any rolling 60 s window.
    pub requests_per_source_per_60s: u32,
    /// Max requests per peer AID (the envelope `sender`, unverified)
    /// in any rolling 60 s window, on top of the transport limit.
    /// `None` disables this extra gate.
    pub requests_per_aid_per_60s: Option<u32>,
    /// Immediate hops whose forwarding headers are believed. Empty
    /// (the default) means forwarding headers are ignored and the
    /// socket peer is the source.
    pub trusted_proxies: Vec<TrustedProxy>,
}

impl RateLimitConfig {
    /// RFC-AITP-0009 §3.1 recommended handshake requests per source IP
    /// per 60 s.
    pub const RECOMMENDED_PER_SOURCE: u32 = 30;
    /// RFC-AITP-0009 §3.1 recommended handshake requests per initiator
    /// AID per 60 s.
    pub const RECOMMENDED_PER_AID: u32 = 10;
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_source_per_60s: Self::RECOMMENDED_PER_SOURCE,
            requests_per_aid_per_60s: Some(Self::RECOMMENDED_PER_AID),
            trusted_proxies: Vec::new(),
        }
    }
}

/// The bucket key for a transport source: IPv4 (IPv4-mapped IPv6
/// folded), or the /64 of an IPv6 address, since a single host is
/// routinely handed a whole /64. `None` (no connect info) shares one
/// bucket rather than letting the self-asserted AID become the only key.
fn transport_key(source: Option<std::net::IpAddr>) -> String {
    use std::net::IpAddr;
    match source.map(|ip| ip.to_canonical()) {
        Some(IpAddr::V4(v4)) => format!("ip:{v4}"),
        Some(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("ip6:{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        None => "ip:unknown".to_string(),
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
    signing_key: Arc<dyn AitpSigner>,
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
    /// Period of the background session sweeper started by
    /// [`HandshakeServer::router`]; `None` disables it. Under a `Mutex`
    /// so the builder can change it on an already-`Arc`'d server.
    session_sweep_interval: Mutex<Option<Duration>>,
    /// Set once a sweeper task has been spawned for this state, so the
    /// automatic start in `router()` / the first HELLO happens once.
    sweeper_started: std::sync::atomic::AtomicBool,
    /// Replay deny list (RFC-AITP-0001 §5.5). Every accepted envelope's
    /// `message_id` is recorded for `replay_window`; a duplicate within
    /// that window is rejected with `REPLAY_DETECTED`. Backed by a
    /// pluggable [`ReplayGuard`](crate::replay_store::ReplayGuard):
    /// the default is per-process in-memory, but a clustered deployment
    /// supplies a shared store via
    /// [`HandshakeServer::with_replay_guard`] (see [`crate::replay_store`]).
    /// Held under a `Mutex` only so the builder can swap it on an
    /// already-`Arc`'d server; the guard itself is cheap to clone.
    replay_guard: Mutex<Arc<dyn crate::replay_store::ReplayGuard>>,
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
    /// replace via [`HandshakeServer::with_rate_limit`]. Enforcement
    /// is per-key sliding 60s windows backed by `rate_limit_events`.
    rate_limit_config: Mutex<Option<RateLimitConfig>>,
    /// Per-key event timestamps for the rolling rate-limit window.
    /// Keyed by either `ip:<ip>` or `aid:<aid>`. Bounded by the
    /// configured limit; entries older than 60s are swept on every
    /// check.
    rate_limit_events: Mutex<HashMap<String, Vec<Instant>>>,
    /// Local pinned-key trust store (RFC-AITP-0002 §3.2 step 3), keyed
    /// by `(algorithm, key)`. An initiator presenting a pinned-key
    /// identity whose key is not in the store is rejected with
    /// `IDENTITY_FAILED`. Defaults to [`NoPinnedKeys`] (fail closed: no
    /// pinned-key initiator is admitted until a store is installed via
    /// [`HandshakeServer::with_pinned_key_store`]). There is no
    /// possession-only mode. Stored under interior mutability so the
    /// builder can configure a server whose `Arc<HandshakeState>` is
    /// already shared.
    pinned_key_store: Mutex<Arc<dyn PinnedKeyStore>>,
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
    ///
    /// `signing_key` may be any [`AitpSigner`] (in-process key, KMS, HSM).
    /// A backend failure while answering a request is a local fault: it
    /// is answered with HTTP 500 / `INVALID_ENVELOPE`, never a
    /// peer-blamed signature code.
    pub fn new<S: AitpSigner + 'static>(
        signing_key: S,
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
    ///
    /// `signing_key` may be any [`AitpSigner`] (in-process key, KMS, HSM);
    /// see [`Self::new`].
    pub fn with_session_ttl<S: AitpSigner + 'static>(
        signing_key: S,
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
    ///
    /// `signing_key` may be any [`AitpSigner`] (in-process key, KMS, HSM);
    /// see [`Self::new`].
    pub fn with_session_ttl_and_replay_window<S: AitpSigner + 'static>(
        signing_key: S,
        manifest: Manifest,
        trust_anchors: Vec<aitp_core::RawUrl>,
        jwks_resolver: R,
        requested_grants: Vec<String>,
        session_ttl: Duration,
        replay_window: Duration,
    ) -> Self {
        Self {
            state: Arc::new(HandshakeState {
                signing_key: Arc::new(signing_key),
                manifest,
                trust_anchors,
                jwks_resolver,
                requested_grants,
                sessions: Mutex::new(HashMap::new()),
                session_ttl,
                max_sessions: std::sync::atomic::AtomicUsize::new(DEFAULT_MAX_SESSIONS),
                session_sweep_interval: Mutex::new(Some(DEFAULT_SESSION_SWEEP_INTERVAL)),
                sweeper_started: std::sync::atomic::AtomicBool::new(false),
                replay_guard: Mutex::new(Arc::new(crate::replay_store::InMemoryReplayGuard::new())),
                replay_window,
                dpop_policy: Mutex::new(None),
                dpop_replay_cache: Arc::new(crate::dpop::DpopReplayCache::default()),
                rate_limit_config: Mutex::new(Some(RateLimitConfig::default())),
                rate_limit_events: Mutex::new(HashMap::new()),
                pinned_key_store: Mutex::new(Arc::new(NoPinnedKeys)),
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

    /// Change the period of the background session sweeper (default
    /// [`DEFAULT_SESSION_SWEEP_INTERVAL`]). [`Duration::ZERO`] disables
    /// it, like [`Self::without_session_sweeper`].
    pub fn with_session_sweep_interval(self, interval: Duration) -> Self {
        *self.state.session_sweep_interval.lock() = (!interval.is_zero()).then_some(interval);
        self
    }

    /// Don't start the background session sweeper. Expired sessions
    /// are then evicted only when the next HELLO or COMMIT arrives, so
    /// a HELLO burst that goes quiet holds memory until more traffic
    /// comes. Use this only when something else sweeps, e.g. a manual
    /// [`Self::spawn_session_sweeper`] with your own shutdown handling.
    pub fn without_session_sweeper(self) -> Self {
        *self.state.session_sweep_interval.lock() = None;
        self
    }

    /// Spawn a background task on the current Tokio runtime that
    /// periodically evicts sessions older than the configured TTL.
    ///
    /// [`Self::router`] already starts one at the configured interval
    /// unless [`Self::without_session_sweeper`] was called; calling this
    /// first replaces that automatic sweeper with one at `interval`.
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
        self.state
            .sweeper_started
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(spawn_sweeper_task(&handle, &self.state, interval))
    }

    /// Start the configured background sweeper if it is enabled, not
    /// already running, and a Tokio runtime is current. Called from
    /// [`Self::router`] and again from the HELLO handler, so a router
    /// built outside a runtime still gets its sweeper once it serves.
    fn ensure_session_sweeper(state: &Arc<HandshakeState<R>>) {
        use std::sync::atomic::Ordering;
        if state.sweeper_started.load(Ordering::Relaxed) {
            return;
        }
        let Some(interval) = *state.session_sweep_interval.lock() else {
            return;
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if state.sweeper_started.swap(true, Ordering::Relaxed) {
            return;
        }
        // Detached: the task holds only a `Weak` and exits once the
        // state is dropped, or with the runtime.
        drop(spawn_sweeper_task(&handle, state, interval));
    }

    /// Attach a [`RevocationListProducer`] as the source of the
    /// `GET` [`REVOCATION_LIST_PATH`] (`ListRevoked`) snapshot.
    ///
    /// The route is served either way (RFC-AITP-0005 §11): without a
    /// producer it returns an empty snapshot freshly signed by this
    /// server's `signing_key` (the TCT issuer key), re-signed every
    /// minute and valid for an hour. That asserts "this issuer has
    /// revoked nothing", so a deployment that can revoke MUST attach a
    /// producer backed by its deny list.
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

    /// Replace the rate-limit configuration (RFC-AITP-0009 §3.1). The
    /// default is [`RateLimitConfig::default`]. The per-key sliding
    /// window is 60 seconds; entries older than that are evicted on
    /// every check, so the in-memory bound is roughly
    /// (active sources × limit). Counters are per process.
    pub fn with_rate_limit(self, config: RateLimitConfig) -> Self {
        *self.state.rate_limit_config.lock() = Some(config);
        self
    }

    /// Turn the built-in rate limiter off. RFC-AITP-0009 §3.1 still
    /// requires per-source limiting at the handshake endpoint, so use
    /// this only when a layer in front of the server (an API gateway, a
    /// shared limiter in middleware) enforces it, keyed on the
    /// transport source.
    pub fn without_rate_limit(self) -> Self {
        *self.state.rate_limit_config.lock() = None;
        self
    }

    /// Install the local pinned-key trust store (RFC-AITP-0002 §3.2
    /// step 3), keyed by `(algorithm, key)`, Ed25519 or P-256. Until one
    /// is installed the server admits no pinned-key initiator (the
    /// default is [`NoPinnedKeys`]). An initiator whose key is absent is
    /// rejected with `IDENTITY_FAILED` before its proof is checked. OIDC
    /// trust is configured separately via the `trust_anchors` +
    /// `jwks_resolver` arguments to [`Self::new`].
    pub fn with_pinned_key_store(self, store: Arc<dyn PinnedKeyStore>) -> Self {
        *self.state.pinned_key_store.lock() = store;
        self
    }

    /// Replace the envelope replay-detection store (RFC-AITP-0001 §5.5).
    /// The default is per-process in-memory; a **clustered** deployment
    /// MUST supply a shared [`ReplayGuard`](crate::replay_store::ReplayGuard)
    /// (e.g. Redis) or use sticky routing, otherwise a message replayed
    /// to a second instance is accepted. To share one backend across
    /// both the envelope and DPoP replay checks, construct the DPoP
    /// cache with the same guard via
    /// [`DpopReplayCache::with_guard`](crate::dpop::DpopReplayCache::with_guard).
    /// See [`crate::replay_store`] for the clustering contract.
    pub fn with_replay_guard(self, guard: Arc<dyn crate::replay_store::ReplayGuard>) -> Self {
        *self.state.replay_guard.lock() = guard;
        self
    }

    /// Test whether a single event from transport source `client_ip`
    /// (optionally tied to `peer_aid`) would exceed the configured
    /// per-key 60s window. `None` is a source with no transport
    /// identifier; all such events share one bucket.
    /// On `Allow`, the event is recorded; on `DenyTooManyRequests`,
    /// no event is recorded (so a denied caller doesn't accelerate
    /// its own deny — the limit hold window is exactly 60s of
    /// admitted traffic).
    ///
    /// Returns `Allow` after [`Self::without_rate_limit`].
    ///
    /// The handshake handlers ([`Self::router`]'s `hello` / `commit`
    /// routes) call this internally per RFC-AITP-0009 §3.1 — after the
    /// replay deny-list check and before timestamp validation. Calling
    /// it again from operator middleware double-counts the request;
    /// most operators only need [`Self::with_rate_limit`].
    pub fn enforce_rate_limit(
        &self,
        client_ip: Option<std::net::IpAddr>,
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
    ///
    /// Also starts the background session sweeper
    /// ([`DEFAULT_SESSION_SWEEP_INTERVAL`] unless changed with
    /// [`Self::with_session_sweep_interval`] or turned off with
    /// [`Self::without_session_sweeper`]). Called outside a Tokio
    /// runtime, the sweeper starts with the first HELLO instead.
    pub fn router(self) -> Router {
        Self::ensure_session_sweeper(&self.state);
        let router = Router::new()
            .route("/aitp/handshake/hello", post(handle_hello::<R>))
            .route("/aitp/handshake/commit", post(handle_commit::<R>));
        #[cfg(feature = "experimental-renewal")]
        let router = router.route("/aitp/handshake/renew", post(handle_renew::<R>));
        let advertised = self
            .state
            .manifest
            .extensions
            .as_ref()
            .is_some_and(|e| e.get(crate::revocation::REVOCATION_LIST_URI_EXT).is_some());
        if !advertised {
            // RFC-AITP-0005 §11 / RFC-AITP-0008 §1.4: a TCT issuer MUST
            // advertise its ListRevoked URL. Peers still accept the
            // Manifest, but treat this issuer's revocation as unavailable.
            warn!(
                key = crate::revocation::REVOCATION_LIST_URI_EXT,
                "handshake server Manifest does not advertise its ListRevoked URL; \
                 set it with ManifestBuilder::revocation_list_uri"
            );
        }
        let source = match self.revocation_producer {
            Some(producer) => RevocationSource::Producer(producer),
            None => RevocationSource::SignedEmpty(SignedEmptySnapshot::new(Arc::clone(
                &self.state.signing_key,
            ))),
        };
        router
            .with_state(self.state)
            .merge(revocation_router(source))
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
    // `TctRenewalPayload` is `#[serde(deny_unknown_fields)]` with no
    // `extensions` slot of its own (RFC-AITP-0013 defines no such
    // member), so there is no separate member-set check to run first —
    // `from_serde_error` recovers the offending name directly from the
    // residual serde error, the same degradation path
    // `aitp_tct::renewal::process_renewal_request` uses for the nested
    // `TctClaims` object.
    let payload: TctRenewalPayload = serde_json::from_slice(&body).map_err(|e| {
        if let Some(field) = from_serde_error(&e) {
            ResponseError::aitp(ErrorCode::UnknownField, format!("unknown field `{field}`"))
        } else {
            ResponseError::aitp(ErrorCode::InvalidEnvelope, format!("malformed JSON: {e}"))
        }
    })?;
    let now = Timestamp::now();
    let renewed = process_renewal_request(
        &payload,
        &*state.signing_key,
        state.manifest.expires_at,
        now,
        aitp_tct::DEFAULT_TCT_TTL_SECS,
    )
    .map_err(|e| {
        if tct_signer_failure(&e) {
            ResponseError::local_signer_failure(&e)
        } else {
            ResponseError::aitp(ErrorCode::TctSignatureInvalid, e.to_string())
        }
    })?;
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

/// Where the `ListRevoked` route gets its snapshot.
enum RevocationSource {
    /// Operator-supplied deny list.
    Producer(Arc<dyn RevocationListProducer>),
    /// Default: an empty snapshot signed by the issuer key.
    SignedEmpty(SignedEmptySnapshot),
}

/// Default `ListRevoked` snapshot: empty `entries`, `issuer` = the
/// server's own AID, signed by the same key that signs its TCTs, so a
/// consumer verifies it against the issuer Manifest's key
/// (RFC-AITP-0008 §1.5 "Empty lists are signed"). Reused for
/// [`DEFAULT_EMPTY_SNAPSHOT_REFRESH_SECS`], then re-signed.
struct SignedEmptySnapshot {
    issuer: aitp_core::Aid,
    provider: crate::revocation::EmptyRevocationProvider,
    cached: Mutex<Option<RevocationListEnvelope>>,
}

impl SignedEmptySnapshot {
    fn new(signing_key: Arc<dyn AitpSigner>) -> Self {
        Self {
            issuer: signing_key.aid().clone(),
            provider: crate::revocation::EmptyRevocationProvider::new(signing_key)
                .with_ttl_secs(DEFAULT_EMPTY_SNAPSHOT_TTL_SECS),
            cached: Mutex::new(None),
        }
    }

    fn current(&self) -> Result<RevocationListEnvelope, crate::revocation::RevocationError> {
        use crate::revocation::RevocationProvider as _;
        let now = Timestamp::now();
        let mut cached = self.cached.lock();
        if let Some(env) = cached.as_ref() {
            let age = now.0.saturating_sub(env.revocation_list.published_at.0);
            if (0..DEFAULT_EMPTY_SNAPSHOT_REFRESH_SECS).contains(&age) {
                return Ok(env.clone());
            }
        }
        let env = self.provider.fetch(&self.issuer)?;
        *cached = Some(env.clone());
        Ok(env)
    }
}

fn revocation_router(source: RevocationSource) -> Router {
    let source = Arc::new(source);
    Router::new().route(
        REVOCATION_LIST_PATH,
        get(move || {
            let source = source.clone();
            async move {
                match &*source {
                    RevocationSource::Producer(p) => Json(p.current()).into_response(),
                    RevocationSource::SignedEmpty(d) => match d.current() {
                        Ok(env) => Json(env).into_response(),
                        // Local signing-backend fault: there is no
                        // snapshot to serve. Consumers see the issuer as
                        // unreachable and apply their fail mode
                        // (RFC-AITP-0008 §3).
                        Err(e) => {
                            warn!(error = %e, "could not sign default revocation snapshot");
                            StatusCode::SERVICE_UNAVAILABLE.into_response()
                        }
                    },
                }
            }
        }),
    )
}

const SESSION_HEADER: &str = "x-aitp-session-id";

async fn handle_hello<R: JwksResolver + Send + Sync + 'static>(
    state: State<Arc<HandshakeState<R>>>,
    request: Request,
) -> Result<Response, ResponseError> {
    // Thin wrapper: record the terminal outcome once, regardless of which
    // `?` inside the inner handler returned.
    let out = handle_hello_inner(state, request).await;
    crate::obs::handshake("hello", if out.is_ok() { "ok" } else { "rejected" });
    out
}

async fn handle_hello_inner<R: JwksResolver + Send + Sync + 'static>(
    State(state): State<Arc<HandshakeState<R>>>,
    request: Request,
) -> Result<Response, ResponseError> {
    // No-op once running; covers a router built outside a runtime.
    HandshakeServer::<R>::ensure_session_sweeper(&state);
    let source_ip = request_source(&state, &request);
    let envelope = parse_envelope_request(request, MessageType::MutualHello).await?;
    enforce_envelope_boundary_checks(&state, &envelope, source_ip)?;
    // RFC-AITP-0001 §7: an unknown sibling member of the payload is a
    // reject, same as an unknown envelope member — checked before typed
    // deserialization so it is never masked by `deny_unknown_fields`'
    // opaque serde error.
    check_members(
        "MutualHelloPayload",
        &envelope.payload,
        MUTUAL_HELLO_PAYLOAD_MEMBERS,
    )
    .map_err(|e| {
        ResponseError::aitp(
            handshake_error_code(&HandshakeError::UnknownField(e.field.clone())),
            format!("unknown field `{}` in MUTUAL_HELLO payload", e.field),
        )
    })?;
    let payload: MutualHelloPayload =
        serde_json::from_value(envelope.payload.clone()).map_err(|e| {
            if let Some(field) = from_serde_error(&e) {
                ResponseError::aitp(
                    handshake_error_code(&HandshakeError::UnknownField(field.clone())),
                    format!("unknown field `{field}` in MUTUAL_HELLO payload"),
                )
            } else {
                ResponseError::aitp(
                    ErrorCode::InvalidEnvelope,
                    format!("malformed payload: {e}"),
                )
            }
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

    // Snapshot the pinned-key trust store (RFC-AITP-0002 §3.2 step 3);
    // the clone outlives `cfg` and the synchronous `Responder::on_hello`
    // call below.
    let pinned_store = state.pinned_key_store.lock().clone();
    let cfg = PeerConfig {
        signing_key: &*state.signing_key,
        manifest: &state.manifest,
        trust_anchors: &state.trust_anchors,
        jwks_resolver: &state.jwks_resolver,
        pinned_key_store: &*pinned_store,
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
    .map_err(|e| handshake_response_error(&e))?;

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
        &*state.signing_key,
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
    state: State<Arc<HandshakeState<R>>>,
    request: Request,
) -> Result<Response, ResponseError> {
    let out = handle_commit_inner(state, request).await;
    crate::obs::handshake("commit", if out.is_ok() { "ok" } else { "rejected" });
    out
}

async fn handle_commit_inner<R: JwksResolver + Send + Sync + 'static>(
    State(state): State<Arc<HandshakeState<R>>>,
    request: Request,
) -> Result<Response, ResponseError> {
    let headers = request.headers().clone();
    let source_ip = request_source(&state, &request);
    let envelope = parse_envelope_request(request, MessageType::MutualCommit).await?;
    enforce_envelope_boundary_checks(&state, &envelope, source_ip)?;
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
    // RFC-AITP-0001 §7: same member-set discipline as MUTUAL_HELLO.
    check_members(
        "MutualCommitPayload",
        &envelope.payload,
        MUTUAL_COMMIT_PAYLOAD_MEMBERS,
    )
    .map_err(|e| {
        ResponseError::aitp(
            handshake_error_code(&HandshakeError::UnknownField(e.field.clone())),
            format!("unknown field `{}` in MUTUAL_COMMIT payload", e.field),
        )
    })?;
    let payload: MutualCommitPayload =
        serde_json::from_value(envelope.payload.clone()).map_err(|e| {
            if let Some(field) = from_serde_error(&e) {
                ResponseError::aitp(
                    handshake_error_code(&HandshakeError::UnknownField(field.clone())),
                    format!("unknown field `{field}` in MUTUAL_COMMIT payload"),
                )
            } else {
                ResponseError::aitp(
                    ErrorCode::InvalidEnvelope,
                    format!("malformed payload: {e}"),
                )
            }
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

    // Snapshot the pinned-key trust store (RFC-AITP-0002 §3.2 step 3);
    // the clone outlives `cfg` and the synchronous `on_commit` call.
    let pinned_store = state.pinned_key_store.lock().clone();
    let cfg = PeerConfig {
        signing_key: &*state.signing_key,
        manifest: &state.manifest,
        trust_anchors: &state.trust_anchors,
        jwks_resolver: &state.jwks_resolver,
        pinned_key_store: &*pinned_store,
        grant_policy: None,
        revocation_check: None,
        now: aitp_core::Timestamp::now(),
    };
    let (ack_payload, _our_held_tct) = entry
        .responder
        .on_commit(&envelope, &payload, &cfg)
        .map_err(|e| handshake_response_error(&e))?;
    let ack_payload_value =
        serde_json::to_value(&ack_payload).map_err(|_| ResponseError::server_error())?;
    let ack_envelope = sign_envelope(
        &*state.signing_key,
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

    /// HTTP 500 for a failure of our own signing backend (KMS throttled,
    /// HSM unreachable, key mismatch). Local, not the peer's fault, so
    /// it never carries a peer-blamed signature code: the closest
    /// registered code is `INVALID_ENVELOPE`, as for [`Self::server_error`].
    fn local_signer_failure(err: &dyn std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: ErrorCode::InvalidEnvelope,
            message: format!("internal error: local signing backend failed: {err}"),
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
    // RFC-AITP-0001 §5.4.5 / issue #140: a duplicate JSON key anywhere in
    // the body — at the envelope's own top level or nested inside
    // `payload`, `sender`, etc. — MUST be rejected. This has to run
    // against the ORIGINAL bytes, before `Value` ever exists: `Value`'s
    // object representation is last-write-wins on a duplicate key, so the
    // information is unrecoverable one line down.
    // `CheckedJson::from_slice` runs that check before building the
    // `Value`, and is the only input `parse_envelope_wire` accepts.
    let value = CheckedJson::from_slice(&body).map_err(|e| {
        ResponseError::aitp(ErrorCode::InvalidEnvelope, format!("malformed JSON: {e}"))
    })?;
    // RFC-AITP-0001 §7: reject an envelope carrying a top-level member
    // outside the schema-declared set with `UNKNOWN_FIELD` rather than
    // the generic `INVALID_ENVELOPE` a bare `from_value` would produce.
    // Version checking (RFC-AITP-0001 §5.6) happens afterward in
    // `enforce_envelope_boundary_checks`, so a structurally-clean but
    // forward-versioned envelope still parses here and is only rejected
    // there — `parse_envelope_wire` never inspects `version`.
    let envelope: AitpEnvelope = parse_envelope_wire(&value).map_err(|e| match e {
        EnvelopeParseError::UnknownField(field) => {
            ResponseError::aitp(ErrorCode::UnknownField, format!("unknown field `{field}`"))
        }
        EnvelopeParseError::Malformed(msg) => {
            ResponseError::aitp(ErrorCode::InvalidEnvelope, format!("malformed JSON: {msg}"))
        }
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

/// The rate-limit source for a request: [`resolve_source_ip`] on the
/// socket peer, present when the router is served with
/// `into_make_service_with_connect_info::<SocketAddr>()`. `None`
/// without connect info.
fn extract_source_ip(
    request: &Request,
    trusted_proxies: &[TrustedProxy],
) -> Option<std::net::IpAddr> {
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())?;
    Some(resolve_source_ip(peer, request.headers(), trusted_proxies))
}

/// [`extract_source_ip`] against the configured trusted proxies.
fn request_source<R: JwksResolver + Send + Sync>(
    state: &HandshakeState<R>,
    request: &Request,
) -> Option<std::net::IpAddr> {
    let config = state.rate_limit_config.lock();
    let proxies = config
        .as_ref()
        .map(|c| c.trusted_proxies.as_slice())
        .unwrap_or(&[]);
    extract_source_ip(request, proxies)
}

/// Sliding-window rate-limit evaluation shared by
/// [`HandshakeServer::enforce_rate_limit`] and the handshake handlers.
/// On `Allow` the event is recorded; on `DenyTooManyRequests` nothing
/// is recorded, so a denied caller does not accelerate its own deny.
/// Returns `Allow` when no policy is configured.
fn rate_limit_check<R: JwksResolver + Send + Sync>(
    state: &HandshakeState<R>,
    client_ip: Option<std::net::IpAddr>,
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
    let key = transport_key(client_ip);
    let entry = events.entry(key.clone()).or_default();
    entry.retain(|t| now.duration_since(*t) < window);
    if entry.len() as u32 >= config.requests_per_source_per_60s {
        return RateLimitOutcome::DenyTooManyRequests {
            reason: format!("rate limit exceeded for source {key}"),
        };
    }
    additions.push(key);
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
    source_ip: Option<std::net::IpAddr>,
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

/// Whether `err` is our own signing backend failing (a local fault).
fn tct_signer_failure(err: &aitp_tct::TctError) -> bool {
    matches!(
        err,
        aitp_tct::TctError::Crypto(aitp_crypto::CryptoError::Signer(_))
    )
}

/// Whether `err` is our own signing backend failing while building a
/// proof, PoP, TCT or Manifest (a local fault, not the peer's).
fn handshake_signer_failure(err: &aitp_handshake::HandshakeError) -> bool {
    use aitp_crypto::CryptoError;
    use aitp_handshake::HandshakeError as HE;
    match err {
        HE::Crypto(CryptoError::Signer(_)) => true,
        HE::Tct(t) => tct_signer_failure(t),
        HE::Manifest(aitp_manifest::ManifestError::Crypto(CryptoError::Signer(_))) => true,
        _ => false,
    }
}

/// Map a `HandshakeError` to the response: a local signer failure is
/// HTTP 500 ([`ResponseError::local_signer_failure`]); everything else is
/// a 400 with [`handshake_error_code`].
fn handshake_response_error(err: &aitp_handshake::HandshakeError) -> ResponseError {
    if handshake_signer_failure(err) {
        ResponseError::local_signer_failure(err)
    } else {
        ResponseError::aitp(handshake_error_code(err), err.to_string())
    }
}

/// Map a `HandshakeError` into the closest registered AITP error code.
fn handshake_error_code(err: &aitp_handshake::HandshakeError) -> ErrorCode {
    use aitp_handshake::HandshakeError as HE;
    use aitp_tct::TctError;
    match err {
        HE::Identity(_) => ErrorCode::IdentityFailed,
        // RFC-AITP-0001 §5.4.3 / RFC-AITP-0007 §3: an unresolvable
        // issuer key is retryable and gets its own code, distinct from
        // a bad proof.
        HE::KeyResolutionFailed { .. } => ErrorCode::KeyResolutionFailed,
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
        // RFC-AITP-0003 §5 / issue #144: a wrapped ManifestError can fail
        // for distinct, separately-registered reasons. Collapsing every
        // variant to MANIFEST_SIGNATURE_INVALID misreports an expired,
        // PoP-failed, version-mismatched, or structurally-invalid
        // manifest as a signature failure. Mirrors the HE::Tct arm above.
        HE::Manifest(m) => {
            use aitp_manifest::ManifestError;
            match m {
                ManifestError::Expired => ErrorCode::ManifestExpired,
                ManifestError::PopFailed => ErrorCode::ManifestPopFailed,
                ManifestError::VersionUnknown => ErrorCode::ManifestVersionUnknown,
                ManifestError::UnknownField(_) => ErrorCode::UnknownField,
                ManifestError::Malformed(_) => ErrorCode::ManifestInvalid,
                // `IncompatibleIdentityType` deliberately does not match the
                // conformance adapter's bare `"INCOMPATIBLE_IDENTITY_TYPE"`
                // string (`crates/aitp-rs-adapter/src/lib.rs`) — `ErrorCode`
                // has no dedicated variant for it, so this maps to the
                // closest registered code instead. A pre-existing registry
                // gap, out of issue #144's scope; see the plan's Open
                // Question 5 (`plans/manifest-revocation-error-codes.md`).
                ManifestError::IncompatibleIdentityType(_) => ErrorCode::IdentityFailed,
                // A malformed Manifest `identity_hint` is a Manifest
                // structural rejection (RFC-AITP-0003 §3.1, `man-006` /
                // `man-007`), matching the conformance adapter (issue #179).
                ManifestError::IdentityHintMalformed(_) => ErrorCode::ManifestInvalid,
                // SignatureInvalid, AidMismatch, Crypto, Canonicalization,
                // Rng, MissingField (builder-side only, unreachable from
                // wire parsing) — and any future #[non_exhaustive] variant.
                _ => ErrorCode::ManifestSignatureInvalid,
            }
        }
        HE::GrantOverflow => ErrorCode::GrantOverflow,
        HE::PolicyViolation => ErrorCode::PolicyViolation,
        HE::PopVerificationFailed => ErrorCode::PopVerificationFailed,
        HE::NonceMismatch => ErrorCode::NonceMismatch,
        HE::InsufficientGrants => ErrorCode::InsufficientGrants,
        HE::IncompatibleTrustAnchors => ErrorCode::IncompatibleTrustAnchors,
        HE::InvalidSignature => ErrorCode::InvalidSignature,
        HE::InvalidEnvelope(_) | HE::State(_) | HE::Rng(_) | HE::Canonicalization(_) => {
            ErrorCode::InvalidEnvelope
        }
        // Our own signing backend failed: a local fault, never blamed on
        // the peer as a bad signature. `handshake_response_error` also
        // turns it into HTTP 500.
        HE::Crypto(aitp_crypto::CryptoError::Signer(_)) => ErrorCode::InvalidEnvelope,
        HE::Crypto(_) => ErrorCode::InvalidSignature,
        // RFC-AITP-0001 §7 / issue #140 Phase 7b: a dedicated core code,
        // never left to the `_ => INVALID_ENVELOPE` catch-all below —
        // mirrors the conformance adapter's `handshake_error_code`.
        HE::UnknownField(_) => ErrorCode::UnknownField,
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
    // Clone the guard Arc out from under the short lock, then run the
    // (self-synchronizing) check without holding the server-state lock.
    let guard = state.replay_guard.lock().clone();
    if guard.check_and_record(&mid.to_string(), state.replay_window) {
        Ok(())
    } else {
        crate::obs::replay_rejected();
        Err(ResponseError::aitp(
            ErrorCode::ReplayDetected,
            "duplicate message_id within replay window".into(),
        ))
    }
}

/// The session sweeper loop shared by [`HandshakeServer::spawn_session_sweeper`]
/// and the automatic start. Holds only a `Weak` to the state, so it
/// exits on the first tick after the server is dropped.
fn spawn_sweeper_task<R: JwksResolver + Send + Sync + 'static>(
    handle: &tokio::runtime::Handle,
    state: &Arc<HandshakeState<R>>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(state);
    let ttl = state.session_ttl;
    handle.spawn(async move {
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
    })
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
    crate::obs::sessions_evicted(evicted as u64);
    warn!(
        evicted,
        cap, "evicted oldest in-flight sessions to enforce max_sessions cap"
    );
}

#[cfg(test)]
#[path = "server_sweeper_tests.rs"]
mod sweeper_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use aitp_handshake::HandshakeError;
    use aitp_tct::TctError;

    /// A failure of our own signing backend is a local fault: HTTP 500
    /// with `INVALID_ENVELOPE`, never a peer-blamed signature code —
    /// whether it surfaces directly or wrapped in a TCT/Manifest error.
    #[test]
    fn local_signer_failure_is_never_blamed_on_the_peer() {
        use aitp_crypto::{CryptoError, SignerError};
        let signer = || CryptoError::Signer(SignerError::VerificationFailed);
        for err in [
            HandshakeError::Crypto(signer()),
            HandshakeError::Tct(TctError::Crypto(signer())),
            HandshakeError::Manifest(aitp_manifest::ManifestError::Crypto(signer())),
        ] {
            let resp = handshake_response_error(&err);
            assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR, "{err:?}");
            assert_eq!(resp.code, ErrorCode::InvalidEnvelope, "{err:?}");
        }
        assert_eq!(
            handshake_error_code(&HandshakeError::Crypto(signer())),
            ErrorCode::InvalidEnvelope
        );
        // A real bad signature from the peer is still a 400.
        let peer = handshake_response_error(&HandshakeError::Crypto(CryptoError::SignatureInvalid));
        assert_eq!(peer.status, StatusCode::BAD_REQUEST);
        assert_eq!(peer.code, ErrorCode::InvalidSignature);
    }

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

    /// Issue #144: `handshake_error_code` previously collapsed every
    /// `HandshakeError::Manifest(_)` to `MANIFEST_SIGNATURE_INVALID`, so
    /// a peer presenting an expired, PoP-failed, version-mismatched, or
    /// structurally-invalid manifest during the handshake was told its
    /// signature was bad. Each `ManifestError` reason now maps to its
    /// own registered code.
    #[test]
    fn manifest_error_variants_map_to_distinct_codes() {
        use aitp_manifest::ManifestError;

        assert_eq!(
            handshake_error_code(&HandshakeError::Manifest(ManifestError::Malformed(
                "missing handshake_endpoint".into()
            ))),
            ErrorCode::ManifestInvalid,
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::Manifest(ManifestError::Expired)),
            ErrorCode::ManifestExpired,
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::Manifest(ManifestError::PopFailed)),
            ErrorCode::ManifestPopFailed,
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::Manifest(ManifestError::VersionUnknown)),
            ErrorCode::ManifestVersionUnknown,
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::Manifest(ManifestError::UnknownField(
                "extra".into()
            ))),
            ErrorCode::UnknownField,
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::Manifest(
                ManifestError::IdentityHintMalformed("missing issuer")
            )),
            ErrorCode::ManifestInvalid,
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::Manifest(
                ManifestError::IncompatibleIdentityType("oidc")
            )),
            ErrorCode::IdentityFailed,
        );
        // Reasons without a dedicated code still fall back to
        // MANIFEST_SIGNATURE_INVALID — the catch-all is intentional.
        assert_eq!(
            handshake_error_code(&HandshakeError::Manifest(ManifestError::SignatureInvalid)),
            ErrorCode::ManifestSignatureInvalid,
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::Manifest(ManifestError::AidMismatch)),
            ErrorCode::ManifestSignatureInvalid,
        );
    }

    /// Issue #144: `HE::GrantOverflow` had no arm and fell through the
    /// `_` catch-all to `INVALID_ENVELOPE`, despite `GrantOverflow`
    /// already being a registered code the conformance adapter maps
    /// correctly.
    #[test]
    fn grant_overflow_maps_to_its_own_code() {
        assert_eq!(
            handshake_error_code(&HandshakeError::GrantOverflow),
            ErrorCode::GrantOverflow,
        );
    }

    /// RFC-AITP-0001 §5.4.3 / RFC-AITP-0007 §3: an unresolvable issuer
    /// key is retryable and must not fall through the `_` catch-all to
    /// `INVALID_ENVELOPE`, nor be conflated with a bad proof
    /// (`IDENTITY_FAILED`).
    #[test]
    fn key_resolution_failed_maps_to_its_own_code() {
        assert_eq!(
            handshake_error_code(&HandshakeError::KeyResolutionFailed {
                issuer: "https://idp.example.com".into(),
                reason: "jwks fetch failed".into(),
            }),
            ErrorCode::KeyResolutionFailed,
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
