//! The issuer's TCT renewal HTTP endpoint (RFC-AITP-0013 §2, §3, §6).
//!
//! [`RenewalServer::router`] mounts one `POST` route at the path of the
//! Manifest's [`RENEW_URI_EXT`]. Host it next to the handshake server:
//!
//! ```ignore
//! let app = handshake.into_router()
//!     .merge(ManifestServer::new(manifest.clone()).into_router())
//!     .merge(renewal.router()?);
//! axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
//! ```
//!
//! The route has its own per-source rate limit (RFC-AITP-0009 §3.1),
//! separate from the handshake server's.

use crate::renewal::{
    parse_renewal_request, process_renewal_request, renew_uri_from_manifest,
    renewal_error_envelope, renewal_response_envelope, RenewalContext, RenewalError,
    RenewalGrantPolicyFn, RENEW_URI_EXT,
};
use aitp::__private::DEFAULT_MAX_BODY_BYTES;
use aitp::core::nonce_store::{NonceStore, NonceStoreError};
use aitp::core::{ErrorCode, Timestamp};
use aitp::crypto::AitpSigner;
use aitp::manifest::Manifest;
use aitp::tct::{RevocationQuery, RevocationSource, RevocationStatus, RevocationUnavailable};
use aitp::transport::server::DEFAULT_BODY_READ_TIMEOUT;
use aitp::transport::{
    resolve_source_ip, RateLimitConfig, RevocationListProducer, REVOCATION_LIST_PATH,
};
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{instrument, warn};
use uuid::Uuid;

/// Paths [`RenewalServer::router`] refuses to mount on: the handshake
/// routes, the revocation list and the Manifest.
const RESERVED_PATHS: &[&str] = &[
    "/aitp/handshake/hello",
    "/aitp/handshake/commit",
    REVOCATION_LIST_PATH,
    "/.well-known/aitp-manifest",
];

/// Number of tracked sources above which idle ones are dropped.
const RATE_LIMIT_SWEEP_THRESHOLD: usize = 4096;

/// Why a [`RenewalServer`] could not be built or mounted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RenewalServerError {
    /// The signer's AID is not the Manifest's `aid`.
    #[error("signer AID is not the Manifest aid")]
    KeyMismatch,
    /// The Manifest advertises no usable [`RENEW_URI_EXT`].
    #[error("Manifest advertises no usable {RENEW_URI_EXT}")]
    NotAdvertised,
    /// The advertised path is one another AITP route uses.
    #[error("{RENEW_URI_EXT} path {0} collides with another AITP route")]
    PathCollision(String),
}

/// The issuer's renewal endpoint (RFC-AITP-0013).
///
/// Each request is rate limited per transport source, then runs
/// [`process_renewal_request`] against the Manifest's current
/// `offered_capabilities` and `expires_at`, the revocation producer's
/// current list and the nonce store. The answer is a signed `tct`
/// envelope, or a signed `error` envelope.
pub struct RenewalServer {
    signer: Arc<dyn AitpSigner>,
    manifest: Manifest,
    revocation: Arc<dyn RevocationListProducer>,
    nonce_store: Arc<dyn NonceStore>,
    grant_policy: Option<Arc<RenewalGrantPolicyFn>>,
    rate_limit: Option<RateLimitConfig>,
    body_limit: usize,
}

impl RenewalServer {
    /// A renewal server signing with `signer`, which must be the key of
    /// `manifest`. `revocation` is the issuer's own revocation list (the
    /// same producer as the handshake server's); `nonce_store` records
    /// every accepted `pop_nonce` (share one store across replicas).
    ///
    /// The rate limit is on with [`RateLimitConfig::default`]; the body
    /// limit is [`DEFAULT_MAX_BODY_BYTES`].
    pub fn new(
        signer: Arc<dyn AitpSigner>,
        manifest: Manifest,
        revocation: Arc<dyn RevocationListProducer>,
        nonce_store: Arc<dyn NonceStore>,
    ) -> Result<Self, RenewalServerError> {
        if signer.aid() != &manifest.aid {
            return Err(RenewalServerError::KeyMismatch);
        }
        Ok(Self {
            signer,
            manifest,
            revocation,
            nonce_store,
            grant_policy: None,
            rate_limit: Some(RateLimitConfig::default()),
            body_limit: DEFAULT_MAX_BODY_BYTES,
        })
    }

    /// Re-run `policy` on every renewal, after the Manifest
    /// intersection. An empty result refuses the renewal with
    /// `POLICY_VIOLATION`.
    pub fn with_grant_policy(mut self, policy: Arc<RenewalGrantPolicyFn>) -> Self {
        self.grant_policy = Some(policy);
        self
    }

    /// Replace the rate limit. Only `requests_per_source_per_60s` and
    /// `trusted_proxies` apply: the request names no AID before it is
    /// verified.
    pub fn with_rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit = Some(config);
        self
    }

    /// Turn the rate limit off.
    pub fn without_rate_limit(mut self) -> Self {
        self.rate_limit = None;
        self
    }

    /// Set the maximum request body size in bytes.
    pub fn with_request_body_limit(mut self, bytes: usize) -> Self {
        self.body_limit = bytes;
        self
    }

    /// The axum router with the renewal route, at the path of the
    /// Manifest's [`RENEW_URI_EXT`]. Serve it with
    /// `into_make_service_with_connect_info::<SocketAddr>()`: with the
    /// rate limit on, a request without a client address is answered
    /// with HTTP 500.
    pub fn router(self) -> Result<Router, RenewalServerError> {
        // Only the path is used, to mount this route, so loopback `http`
        // is accepted; the scheme policy is the client's.
        let uri = renew_uri_from_manifest(&self.manifest, true)
            .ok_or(RenewalServerError::NotAdvertised)?;
        let path = uri.path().to_string();
        if RESERVED_PATHS.contains(&path.as_str()) {
            return Err(RenewalServerError::PathCollision(path));
        }
        let state = Arc::new(RouteState {
            server: self,
            events: Mutex::new(HashMap::new()),
        });
        Ok(Router::new()
            .route(&path, post(handle_renew))
            .with_state(state))
    }
}

struct RouteState {
    server: RenewalServer,
    /// Accepted request times per transport key, newest last.
    events: Mutex<HashMap<String, Vec<Instant>>>,
}

/// `POST <renew_uri path>`: a renewal request (RFC-AITP-0013 §3),
/// answered with a signed `tct` envelope (§6) or a signed `error`
/// envelope.
#[instrument(level = "debug", skip(state, request))]
async fn handle_renew(State(state): State<Arc<RouteState>>, request: Request) -> Response {
    let server = &state.server;
    let signer = &*server.signer;
    if let Some(config) = &server.rate_limit {
        let Some(peer) = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())
        else {
            return refusal(
                signer,
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InvalidEnvelope,
                "internal error: no client address for the rate limit",
                true,
            );
        };
        let source = resolve_source_ip(peer, request.headers(), &config.trusted_proxies);
        if !rate_limit_allows(&state.events, config, source) {
            warn!(
                target: "aitp.error.rate_limited",
                status = 429u16,
                "renewal request rejected before the protocol layer"
            );
            return too_many_requests();
        }
    }
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.starts_with("application/json") {
        return refusal(
            signer,
            StatusCode::BAD_REQUEST,
            ErrorCode::PopResponseInvalid,
            "expected Content-Type: application/json",
            false,
        );
    }
    let body = match tokio::time::timeout(
        DEFAULT_BODY_READ_TIMEOUT,
        to_bytes(request.into_body(), server.body_limit),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(e)) => {
            return refusal(
                signer,
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidEnvelope,
                &format!("oversized or unreadable body: {e}"),
                false,
            )
        }
        Err(_) => {
            return refusal(
                signer,
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidEnvelope,
                &format!(
                    "body read exceeded {}s",
                    DEFAULT_BODY_READ_TIMEOUT.as_secs()
                ),
                false,
            )
        }
    };
    let payload = match parse_renewal_request(&body) {
        Ok(p) => p,
        Err(e) => return failure(signer, &e),
    };
    // The issuer's own revocation list, read fresh for each request.
    // An unreadable list leaves the status unknown: the renewal fails
    // closed with `RevocationUnavailable` after the PoP check.
    let revoked: Result<HashSet<Uuid>, String> = server
        .revocation
        .current()
        .await
        .map(|env| env.revocation_list.entries.iter().map(|e| e.jti).collect())
        .map_err(|e| e.to_string());
    let revocation_check = move |q: &RevocationQuery<'_>| match &revoked {
        Ok(revoked) if revoked.contains(q.jti) => Ok(RevocationStatus::Revoked),
        Ok(_) => Ok(RevocationStatus::Clear),
        Err(e) => Err(RevocationUnavailable::new(format!(
            "issuer revocation list: {e}"
        ))),
    };
    let now = Timestamp::now();
    let mut ctx = RenewalContext::new(
        server.manifest.expires_at,
        &server.manifest.offered_capabilities,
        RevocationSource::Check(&revocation_check),
        &*server.nonce_store,
        now,
    );
    if let Some(policy) = server.grant_policy.as_deref() {
        ctx = ctx.grant_policy(policy);
    }
    let renewed = match process_renewal_request(&payload, signer, &ctx).await {
        Ok(r) => r,
        Err(e) => return failure(signer, &e),
    };
    match renewal_response_envelope(signer, &renewed, &payload.pop_nonce, Uuid::new_v4(), now) {
        Ok(envelope) => Json(envelope).into_response(),
        Err(e) => local_signer_failure(&e),
    }
}

/// Sliding 60 s window per transport key. A denied request is not
/// recorded.
fn rate_limit_allows(
    events: &Mutex<HashMap<String, Vec<Instant>>>,
    config: &RateLimitConfig,
    source: IpAddr,
) -> bool {
    let window = Duration::from_secs(60);
    let now = Instant::now();
    let mut events = events.lock();
    if events.len() > RATE_LIMIT_SWEEP_THRESHOLD {
        events.retain(|_, times| {
            times
                .last()
                .is_some_and(|t| now.duration_since(*t) < window)
        });
    }
    let entry = events.entry(transport_key(source)).or_default();
    entry.retain(|t| now.duration_since(*t) < window);
    if entry.len() as u32 >= config.requests_per_source_per_60s {
        return false;
    }
    entry.push(now);
    true
}

/// IPv4 (IPv4-mapped IPv6 folded), or the /64 of an IPv6 address.
fn transport_key(source: IpAddr) -> String {
    match source.to_canonical() {
        IpAddr::V4(v4) => format!("ip:{v4}"),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("ip6:{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

/// The refusal for a renewal failure: a local fault is a retryable 5xx
/// (503 for a full nonce store), everything else a 400 with
/// [`RenewalError::error_code`].
fn failure(signer: &dyn AitpSigner, err: &RenewalError) -> Response {
    match err {
        RenewalError::NonceStore(store_err) => {
            let status = match store_err {
                NonceStoreError::AtCapacity { .. } => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            refusal(
                signer,
                status,
                ErrorCode::InvalidEnvelope,
                &format!("internal error: renewal replay guard: {store_err}"),
                true,
            )
        }
        e if e.is_local_fault() => local_signer_failure(e),
        e => refusal(
            signer,
            StatusCode::BAD_REQUEST,
            e.error_code(),
            &e.to_string(),
            false,
        ),
    }
}

/// A signed `error` envelope refusing a renewal (RFC-AITP-0013 §6).
fn refusal(
    signer: &dyn AitpSigner,
    status: StatusCode,
    code: ErrorCode,
    reason: &str,
    retryable: bool,
) -> Response {
    warn!(
        target: "aitp.error.envelope",
        code = ?code,
        status = status.as_u16(),
        message = %reason,
        "AITP renewal error envelope returned"
    );
    match renewal_error_envelope(
        signer,
        code,
        reason,
        retryable,
        Uuid::new_v4(),
        Timestamp::now(),
    ) {
        Ok(envelope) => (status, Json(envelope)).into_response(),
        Err(e) => local_signer_failure(&e),
    }
}

/// HTTP 500 for the issuer's own signer failing: an unsigned
/// `{"error": {code, message}}` body with `INVALID_ENVELOPE`.
fn local_signer_failure(err: &dyn std::fmt::Display) -> Response {
    let message = format!("internal error: local signing backend failed: {err}");
    warn!(
        target: "aitp.error.envelope",
        code = ?ErrorCode::InvalidEnvelope,
        status = 500u16,
        message = %message,
        "AITP error envelope returned"
    );
    let body = serde_json::json!({
        "error": { "code": ErrorCode::InvalidEnvelope, "message": message },
    });
    let mut resp = (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    resp
}

/// HTTP 429 with an empty body (RFC-AITP-0009 §3.1).
fn too_many_requests() -> Response {
    let mut resp = Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .body(Body::empty())
        .expect("response with valid status + empty body builds");
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    resp
}
