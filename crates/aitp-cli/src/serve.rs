//! `aitp serve --interop` (`serve` feature): the public interop peer.
//!
//! A responder anyone can complete a real handshake with, after
//! registering a key (see [`crate::enrol`] and docs/interop-peer.md):
//!
//! - `GET /.well-known/aitp-manifest`, the handshake routes and the
//!   peer's own `ListRevoked` snapshot, from `aitp::transport`;
//! - `POST /enroll/challenge` and `POST /enroll`: key registration into
//!   the pinned-key store the handshake verifies against, with a TTL, a
//!   cap and a per-IP rate limit;
//! - `POST /echo/challenge` and `POST /echo`: present the TCT this peer
//!   issued you with proof of possession (see [`crate::echo`]), get its
//!   verified claims back;
//! - `GET /status`.
//!
//! It requests and grants only [`ECHO_CAP`]. Plain HTTP: TLS is
//! terminated at the platform edge, whose hop is named with
//! `--trusted-proxy` so per-IP limits see the client address.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use aitp::core::{base64url, parse_envelope_wire, Aid, CheckedJson, MessageType, Timestamp};
use aitp::crypto::{jws, AitpSigningKey, AitpVerifyingKey, Digest32};
use aitp::handshake::admission::{
    ChallengeSource, ConsumeOutcome, InMemoryNonceStore, IssuedNonce, NonceStore, NonceStoreError,
    TokenBucketLimiter,
};
use aitp::handshake::{JwkPublicKey, JwksResolver, PinnedKeyStore, ResolveError};
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use aitp::tct::{
    verify_pop_response, verify_tct, PopChallenge, PopResponse, TctClaims, TctError,
    TctVerifyContext,
};
use aitp::transport::{
    resolve_source_ip, sign_envelope, verify_envelope_signature, HandshakeServer, ManifestServer,
    RateLimitConfig, RevocationFailMode, RevocationPolicy, TrustedProxy, REVOCATION_LIST_PATH,
};
use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use tower::ServiceExt;
use tracing::info;

use uuid::Uuid;

use crate::echo::{self, ECHO_CAP};
use crate::enrol::{self, Challenge, Enrolled, ErrorBody, NONCE_LEN};
use crate::CliResult;

/// Display name, and so the pinned-key subject `HandshakeServer`
/// presents, which must match the Manifest's identity hint.
const PEER_NAME: &str = "AITP interop peer";
/// Request body cap for every route.
const BODY_LIMIT: usize = 64 * 1024;
/// Whole-request deadline.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// How long an enrolment or echo challenge is accepted.
const CHALLENGE_TTL_SECS: i64 = 60;
/// Outstanding challenges held at once, per kind; beyond that,
/// `enrol_busy` / `echo_busy`.
const MAX_OUTSTANDING_CHALLENGES: usize = 10_000;
/// Manifest lifetime. The peer re-signs it every half lifetime.
const MANIFEST_TTL_SECS: i64 = 24 * 3600;

/// `aitp serve` options. Each can also come from the environment, the
/// way a container platform passes configuration.
#[derive(clap::Args)]
pub(crate) struct ServeArgs {
    /// Run the public interop peer (docs/interop-peer.md). Required:
    /// it is the only mode.
    #[arg(long, required = true)]
    interop: bool,
    /// Listen address. Default: `0.0.0.0:$PORT`, or `0.0.0.0:8080`.
    #[arg(long, env = "AITP_LISTEN", value_name = "ADDR")]
    listen: Option<SocketAddr>,
    /// Public origin, as clients reach it (e.g.
    /// `https://interop.example`). It goes into the Manifest's handshake
    /// endpoint and revocation list URL. Default: `http://localhost:<port>`.
    #[arg(long, env = "AITP_PUBLIC_URL", value_name = "URL")]
    public_url: Option<url::Url>,
    /// The peer's signing key: `aitp keygen` output or a bare hex seed.
    /// Read from this file, else from the `AITP_PEER_KEY` variable.
    #[arg(long, env = "AITP_PEER_KEY_FILE", value_name = "FILE")]
    key: Option<String>,
    /// Immediate hop (IP or CIDR) whose `X-Forwarded-For` is believed,
    /// e.g. the platform's edge proxy. Repeatable, or comma-separated in
    /// the variable.
    #[arg(
        long = "trusted-proxy",
        env = "AITP_TRUSTED_PROXIES",
        value_delimiter = ',',
        value_name = "CIDR"
    )]
    trusted_proxies: Vec<TrustedProxy>,
    /// How long an enrolment lasts, in seconds.
    #[arg(long, env = "AITP_ENROL_TTL", default_value_t = 24 * 3600)]
    enrol_ttl: i64,
    /// Most enrolled keys held at once; at the cap the oldest goes first.
    #[arg(long, env = "AITP_ENROL_CAP", default_value_t = 10_000)]
    enrol_cap: usize,
    /// Enrolment attempts allowed per client IP (IPv6: per /64) per
    /// hour: a burst of this many, refilling evenly over the hour.
    #[arg(long, env = "AITP_ENROL_PER_IP_PER_HOUR", default_value_t = 5)]
    enrol_per_ip_per_hour: u32,
}

pub(crate) fn run(args: ServeArgs) -> CliResult {
    debug_assert!(args.interop);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let key = Arc::new(load_key(args.key.as_deref())?);
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve(args, key))
}

fn load_key(path: Option<&str>) -> Result<AitpSigningKey, Box<dyn std::error::Error>> {
    if let Some(path) = path {
        return crate::key_from_file(path, crate::Suite::Ed25519);
    }
    let text = std::env::var("AITP_PEER_KEY")
        .map_err(|_| "no peer key: pass --key <FILE> or set AITP_PEER_KEY")?;
    crate::key_from_text(&text, "AITP_PEER_KEY", crate::Suite::Ed25519)
}

async fn serve(args: ServeArgs, key: Arc<AitpSigningKey>) -> CliResult {
    let listen = match args.listen {
        Some(addr) => addr,
        None => {
            let port = std::env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8080);
            SocketAddr::from(([0, 0, 0, 0], port))
        }
    };
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let bound = listener.local_addr()?;
    let public_url = match args.public_url {
        Some(url) => url,
        None => format!("http://localhost:{}", bound.port()).parse()?,
    };

    let peer = Arc::new(Interop {
        key: Arc::clone(&key),
        aid: key.aid().clone(),
        enrolled: Arc::new(EnrolledKeys::new(args.enrol_cap)),
        enrol_ttl: args.enrol_ttl,
        nonces: InMemoryNonceStore::new(MAX_OUTSTANDING_CHALLENGES),
        // Challenges are cheap to issue but hold store slots.
        challenge_limiter: TokenBucketLimiter::new(10, 1.0 / 6.0),
        enrol_limiter: TokenBucketLimiter::new(
            args.enrol_per_ip_per_hour,
            f64::from(args.enrol_per_ip_per_hour.max(1)) / 3600.0,
        ),
        echo_nonces: InMemoryNonceStore::new(MAX_OUTSTANDING_CHALLENGES),
        // One `aitp echo` spends two: a challenge, then the answer.
        echo_limiter: TokenBucketLimiter::new(10, 1.0 / 6.0),
        revoked: HashSet::new(),
        trusted_proxies: args.trusted_proxies,
        aitp: RwLock::new(Router::new()),
    });
    peer.rebuild(&key, &public_url)?;
    tokio::spawn(refresh_manifest(
        Arc::clone(&peer),
        Arc::clone(&key),
        public_url.clone(),
    ));

    let app = router(Arc::clone(&peer));
    // Tests and the container read this line to learn the bound port.
    eprintln!("aitp: interop peer {} listening on {bound}", peer.aid);
    info!(aid = %peer.aid, %bound, %public_url, "interop peer listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    info!("interop peer stopped");
    Ok(())
}

/// Shared state of the interop routes.
struct Interop {
    key: Arc<AitpSigningKey>,
    aid: Aid,
    enrolled: Arc<EnrolledKeys>,
    enrol_ttl: i64,
    nonces: InMemoryNonceStore,
    challenge_limiter: TokenBucketLimiter,
    enrol_limiter: TokenBucketLimiter,
    /// Outstanding `/echo` PoP challenges, keyed by [`echo_slot`].
    echo_nonces: InMemoryNonceStore,
    /// Both `/echo` routes, per client address.
    echo_limiter: TokenBucketLimiter,
    /// The deny list behind the served `ListRevoked` snapshot: empty,
    /// because this peer revokes nothing.
    revoked: HashSet<Uuid>,
    trusted_proxies: Vec<TrustedProxy>,
    /// Manifest + handshake routes, rebuilt with a freshly signed
    /// Manifest by [`refresh_manifest`].
    aitp: RwLock<Router>,
}

impl Interop {
    /// Sign a new Manifest and swap in AITP routes serving it. Handshakes
    /// in flight on the old routes (a 60s window) fail and are retried.
    fn rebuild(&self, key: &Arc<AitpSigningKey>, public_url: &url::Url) -> CliResult {
        let manifest = interop_manifest(key, public_url)?;
        let handshake = HandshakeServer::new(
            Arc::clone(key),
            manifest.clone(),
            vec![],
            NoJwks,
            vec![ECHO_CAP.into()],
        )
        .with_pinned_key_store(Arc::clone(&self.enrolled) as Arc<dyn PinnedKeyStore>)
        .with_rate_limit(RateLimitConfig {
            trusted_proxies: self.trusted_proxies.clone(),
            ..RateLimitConfig::default()
        })
        // The peer never uses the TCT it receives; it authorises nothing.
        // So an initiator with no revocation list to publish (a CLI, a CI
        // job) is accepted, logged at info; an advertised list that
        // cannot be checked is still refused.
        .with_revocation_policy(RevocationPolicy {
            fail_mode: RevocationFailMode::FailOpenIfUnadvertised,
            ..RevocationPolicy::default()
        });
        let routes = ManifestServer::new(manifest)
            .router()
            .merge(handshake.router());
        *self.aitp.write().expect("not poisoned") = routes;
        Ok(())
    }

    fn source(&self, peer: SocketAddr, headers: &HeaderMap) -> ChallengeSource {
        ChallengeSource::ip(resolve_source_ip(peer.ip(), headers, &self.trusted_proxies))
    }
}

fn interop_manifest(
    key: &AitpSigningKey,
    public_url: &url::Url,
) -> Result<Manifest, Box<dyn std::error::Error>> {
    Ok(ManifestBuilder::new(key)
        .display_name(PEER_NAME)
        .handshake_endpoint(public_url.join("/aitp/handshake/")?.as_str().parse()?)
        .revocation_list_uri(public_url.join(REVOCATION_LIST_PATH)?.as_str().parse()?)
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: PEER_NAME.into(),
            issuer: None,
            public_key: Some(base64url::encode(&key.verifying_key().to_compressed())),
        })
        .accept_identity_type("pinned_key")
        .offer(ECHO_CAP)
        .ttl_secs(MANIFEST_TTL_SECS)
        .build()?)
}

async fn refresh_manifest(peer: Arc<Interop>, key: Arc<AitpSigningKey>, public_url: url::Url) {
    let every = Duration::from_secs((MANIFEST_TTL_SECS / 2) as u64);
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    loop {
        ticker.tick().await;
        match peer.rebuild(&key, &public_url) {
            Ok(()) => info!("re-signed the Manifest"),
            Err(e) => tracing::error!(error = %e, "re-signing the Manifest failed"),
        }
    }
}

fn router(peer: Arc<Interop>) -> Router {
    Router::new()
        .route(enrol::CHALLENGE_PATH, post(enroll_challenge))
        .route(enrol::ENROLL_PATH, post(enroll))
        .route(echo::CHALLENGE_PATH, post(echo_challenge))
        .route(echo::ECHO_PATH, post(echo))
        .route("/status", get(status))
        .fallback(aitp_routes)
        .with_state(peer)
        .layer(middleware::from_fn(limits))
}

/// Body cap and deadline for every request, the AITP routes included
/// (they read bodies with their own, larger, limit).
async fn limits(request: Request, next: Next) -> Response {
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > BODY_LIMIT) {
        return too_large();
    }
    let (parts, body) = request.into_parts();
    let work = async move {
        let Ok(bytes) = to_bytes(body, BODY_LIMIT).await else {
            return too_large();
        };
        next.run(Request::from_parts(parts, Body::from(bytes)))
            .await
    };
    match tokio::time::timeout(REQUEST_TIMEOUT, work).await {
        Ok(response) => response,
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
}

fn too_large() -> Response {
    refuse(
        StatusCode::PAYLOAD_TOO_LARGE,
        "bad_request",
        &format!("request body over {BODY_LIMIT} bytes"),
    )
}

async fn aitp_routes(State(peer): State<Arc<Interop>>, request: Request) -> Response {
    let routes = peer.aitp.read().expect("not poisoned").clone();
    match routes.oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

fn refuse(status: StatusCode, error: &str, message: &str) -> Response {
    (
        status,
        Json(ErrorBody {
            error: error.into(),
            message: message.into(),
        }),
    )
        .into_response()
}

fn rate_limited(retry_after: Duration) -> Response {
    let mut response = refuse(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "too many requests from this address",
    );
    let secs = retry_after.as_secs().max(1).to_string();
    if let Ok(v) = secs.parse() {
        response.headers_mut().insert(header::RETRY_AFTER, v);
    }
    response
}

async fn enroll_challenge(
    State(peer): State<Arc<Interop>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let source = peer.source(addr, &headers);
    if let Err(retry) = peer.challenge_limiter.check_key(source.transport_key()) {
        return rate_limited(retry);
    }
    let mut nonce = [0u8; NONCE_LEN];
    if rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut nonce).is_err() {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "enrol_busy",
            "no randomness",
        );
    }
    let now = Timestamp::now();
    let expires_at = now.plus_secs(CHALLENGE_TTL_SECS);
    let record = IssuedNonce::new(
        nonce,
        peer.aid.clone(),
        source.transport_key(),
        now,
        expires_at,
    );
    match peer.nonces.issue(&record).await {
        Ok(()) => Json(Challenge {
            nonce: base64url::encode(&nonce),
            peer_aid: peer.aid.clone(),
            expires_at: expires_at.0,
        })
        .into_response(),
        Err(NonceStoreError::AtCapacity { retry_after, .. }) => {
            let mut response = refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "enrol_busy",
                "too many outstanding challenges; retry shortly",
            );
            if let Some(v) = retry_after.and_then(|d| d.as_secs().max(1).to_string().parse().ok()) {
                response.headers_mut().insert(header::RETRY_AFTER, v);
            }
            response
        }
        Err(e) => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "enrol_busy",
            &e.to_string(),
        ),
    }
}

async fn enroll(
    State(peer): State<Arc<Interop>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Every attempt counts against the address, valid or not.
    let source = peer.source(addr, &headers);
    if let Err(retry) = peer.enrol_limiter.check_key(source.transport_key()) {
        return rate_limited(retry);
    }
    let request = match enrol::parse_enroll(&body) {
        Ok(r) => r,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, "bad_request", &e),
    };
    // Signature before the nonce, so a forged request cannot burn an
    // honest client's challenge.
    let digest = enrol::signing_digest(&request.aid, &peer.aid, &request.nonce);
    if request.key.verify_jcs(&digest, &request.signature).is_err() {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "bad_signature",
            "signature does not verify under the AID's key for this challenge",
        );
    }
    let now = Timestamp::now();
    match peer.nonces.consume(&request.nonce, &peer.aid, now).await {
        Ok(ConsumeOutcome::Consumed) => {}
        Ok(ConsumeOutcome::Expired) => {
            return refuse(StatusCode::UNAUTHORIZED, "bad_nonce", "challenge expired")
        }
        Ok(_) => {
            return refuse(
                StatusCode::UNAUTHORIZED,
                "bad_nonce",
                "unknown or already used challenge",
            )
        }
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "enrol_busy",
                &e.to_string(),
            )
        }
    }
    let expires_at = now.plus_secs(peer.enrol_ttl);
    let canonical = request.key.to_aid();
    peer.enrolled.insert(request.key, expires_at);
    info!(aid = %canonical, source = source.transport_key(), "enrolled");
    Json(Enrolled {
        aid: canonical,
        expires_at: expires_at.0,
        capabilities: vec![ECHO_CAP.into()],
    })
    .into_response()
}

/// A refusal with a registered AITP code (`401`) or the grant check's
/// `POLICY_VIOLATION` (`403`).
#[derive(Debug)]
struct Refusal(StatusCode, &'static str, String);

impl Refusal {
    fn pop(message: impl Into<String>) -> Self {
        Self(
            StatusCode::UNAUTHORIZED,
            "POP_RESPONSE_INVALID",
            message.into(),
        )
    }

    fn into_response(self) -> Response {
        refuse(self.0, self.1, &self.2)
    }
}

/// `POST /echo/challenge`: verify the TCT's own claims, then issue a
/// signed `pop_challenge` for its `jti`. A token that would fail at
/// `/echo` anyway never gets a challenge slot.
async fn echo_challenge(
    State(peer): State<Arc<Interop>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let source = peer.source(addr, &headers);
    if let Err(retry) = peer.echo_limiter.check_key(source.transport_key()) {
        return rate_limited(retry);
    }
    let request: echo::ChallengeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, "bad_request", &e.to_string()),
    };
    let now = Timestamp::now();
    let claims = match verify_own_tct(&request.tct, &peer.aid, now) {
        Ok(claims) => claims,
        Err(refusal) => return refusal.into_response(),
    };
    let mut nonce = [0u8; NONCE_LEN];
    if rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut nonce).is_err() {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "echo_busy",
            "no randomness",
        );
    }
    let nonce_b64 = base64url::encode(&nonce);
    let record = IssuedNonce::new(
        echo_slot(claims.jti, &nonce_b64),
        peer.aid.clone(),
        source.transport_key(),
        now,
        now.plus_secs(CHALLENGE_TTL_SECS),
    );
    match peer.echo_nonces.issue(&record).await {
        Ok(()) => {}
        Err(NonceStoreError::AtCapacity { retry_after, .. }) => {
            let mut response = refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "echo_busy",
                "too many outstanding challenges; retry shortly",
            );
            if let Some(v) = retry_after.and_then(|d| d.as_secs().max(1).to_string().parse().ok()) {
                response.headers_mut().insert(header::RETRY_AFTER, v);
            }
            return response;
        }
        Err(e) => return refuse(StatusCode::SERVICE_UNAVAILABLE, "echo_busy", &e.to_string()),
    }
    let payload = echo::ChallengePayload {
        tct_jti: claims.jti,
        nonce: nonce_b64,
    };
    match serde_json::to_value(payload)
        .map_err(|e| e.to_string())
        .and_then(|p| sign_envelope(peer.key.as_ref(), MessageType::PopChallenge, p))
    {
        Ok(envelope) => Json(envelope).into_response(),
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, "echo_busy", &e),
    }
}

/// `POST /echo`: the issuer-as-resource-server check of RFC-AITP-0005
/// §10.5, then the claims back.
async fn echo(
    State(peer): State<Arc<Interop>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let source = peer.source(addr, &headers);
    if let Err(retry) = peer.echo_limiter.check_key(source.transport_key()) {
        return rate_limited(retry);
    }
    let request: echo::EchoRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, "bad_request", &e.to_string()),
    };
    match check_echo(&peer, &request, Timestamp::now()).await {
        Ok(claims) => Json(serde_json::json!({ "echo": claims })).into_response(),
        Err(refusal) => refusal.into_response(),
    }
}

/// RFC-AITP-0005 §10.5, in order: the TCT as its issuer sees it (own
/// signature, `iss`, `aud` == `sub`, in date) and the grant; downstream
/// PoP (§6.2) over the challenge issued for this `jti`, from `sub`; the
/// peer's own revocation list last.
async fn check_echo(
    peer: &Interop,
    request: &echo::EchoRequest,
    now: Timestamp,
) -> Result<TctClaims, Refusal> {
    let claims = verify_own_tct(&request.tct, &peer.aid, now)?;

    let checked = CheckedJson::from_slice(
        &serde_json::to_vec(&request.pop_response).map_err(|e| Refusal::pop(e.to_string()))?,
    )
    .map_err(|e| Refusal::pop(format!("pop_response: {e}")))?;
    let envelope =
        parse_envelope_wire(&checked).map_err(|e| Refusal::pop(format!("pop_response: {e}")))?;
    let response: PopResponse = serde_json::from_value(envelope.payload.clone())
        .map_err(|e| Refusal::pop(format!("pop_response payload: {e}")))?;

    // Consume the challenge before checking the answer: any answer,
    // right or wrong, uses it up.
    match peer
        .echo_nonces
        .consume(&echo_slot(claims.jti, &response.nonce_echo), &peer.aid, now)
        .await
    {
        Ok(ConsumeOutcome::Consumed) => {}
        Ok(ConsumeOutcome::Expired) => {
            return Err(Refusal(
                StatusCode::UNAUTHORIZED,
                "POP_CHALLENGE_INVALID",
                "the challenge expired".into(),
            ))
        }
        Ok(_) => {
            return Err(Refusal::pop(format!(
                "no outstanding challenge for jti {} with that nonce",
                claims.jti
            )))
        }
        Err(e) => {
            return Err(Refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "echo_busy",
                e.to_string(),
            ))
        }
    }

    // §6.2 step 1, and the presenter must be `sub` (§10.5).
    if envelope.message_type != MessageType::PopResponse {
        return Err(Refusal::pop("envelope is not a pop_response"));
    }
    if envelope.sender.agent_id != claims.sub {
        return Err(Refusal::pop("pop_response sender is not the TCT subject"));
    }
    let sub_key =
        AitpVerifyingKey::from_aid(&claims.sub).map_err(|e| Refusal::pop(e.to_string()))?;
    verify_envelope_signature(&envelope, &sub_key)
        .map_err(|_| Refusal::pop("pop_response envelope signature"))?;
    // Steps 2 to 4: nonce echo, PoP signature under the `sub` key, and
    // `cnf.jkt`. The store already enforced expiry.
    let challenge = PopChallenge {
        tct_jti: claims.jti,
        nonce: response.nonce_echo.clone(),
        expires_at: now,
    };
    verify_pop_response(&challenge, &response, &claims, now)
        .map_err(|e| Refusal::pop(e.to_string()))?;

    // Revocation last, against the list this peer serves. It revokes
    // nothing (the snapshot at REVOCATION_LIST_PATH is always empty), so
    // the list is empty here too.
    if peer.revoked.contains(&claims.jti) {
        return Err(Refusal(
            StatusCode::UNAUTHORIZED,
            "TCT_REVOKED",
            format!("jti {} is revoked", claims.jti),
        ));
    }
    Ok(claims)
}

/// The nonce-store slot for a challenge: it binds the nonce to the TCT
/// it was issued for, so an answer naming another `jti` finds nothing.
fn echo_slot(jti: Uuid, nonce: &str) -> [u8; NONCE_LEN] {
    let mut input = b"aitp-interop-echo-v1\0".to_vec();
    input.extend_from_slice(jti.as_bytes());
    input.extend_from_slice(nonce.as_bytes());
    let mut slot = [0u8; NONCE_LEN];
    slot.copy_from_slice(&Digest32::sha256(&input).as_bytes()[..NONCE_LEN]);
    slot
}

/// The checks on a TCT this peer issued that need no PoP (RFC-AITP-0005
/// §10.5 items 1 and 2): its own signature and `iss`, `aud` == `sub`,
/// in date, then the [`ECHO_CAP`] grant. Revocation is deferred to the
/// end of [`check_echo`].
fn verify_own_tct(token: &str, self_aid: &Aid, now: Timestamp) -> Result<TctClaims, Refusal> {
    let invalid = |m: String| Refusal(StatusCode::UNAUTHORIZED, "TCT_SIGNATURE_INVALID", m);
    let payload =
        jws::decode_payload_unverified(token).map_err(|e| invalid(format!("not a JWS: {e}")))?;
    let sub = serde_json::from_slice::<serde_json::Value>(&payload)
        .ok()
        .and_then(|v| v.get("sub").and_then(|s| s.as_str()).map(Aid::parse))
        .and_then(Result::ok)
        .ok_or_else(|| invalid("TCT has no valid sub".into()))?;
    // The expected audience is `sub`, which PoP later proves is the
    // presenter; it is never taken from `aud` itself.
    let ctx = TctVerifyContext::builder(&sub, self_aid, now)
        .skip_manifest_expiry_cap_dangerous()
        .accept_unchecked_revocation_dangerous()
        .build()
        .expect("both decisions are made");
    let claims = verify_tct(token, &ctx)
        .map(|v| v.claims)
        .map_err(|e| match e {
            TctError::Expired => Refusal(StatusCode::UNAUTHORIZED, "TCT_EXPIRED", e.to_string()),
            TctError::AudienceMismatch => invalid("aud differs from sub".into()),
            e => invalid(e.to_string()),
        })?;
    if !claims.grants.iter().any(|g| g == ECHO_CAP) {
        return Err(Refusal(
            StatusCode::FORBIDDEN,
            "POLICY_VIOLATION",
            format!("the TCT does not grant {ECHO_CAP}"),
        ));
    }
    Ok(claims)
}

async fn status(State(peer): State<Arc<Interop>>) -> Response {
    Json(serde_json::json!({
        "status": "ok",
        "aid": peer.aid,
        "version": env!("CARGO_PKG_VERSION"),
        "capabilities": [ECHO_CAP],
        "enrolled": peer.enrolled.len(Timestamp::now()),
    }))
    .into_response()
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    info!("shutting down");
}

/// The interop peer's pinned-key store: enrolled keys, each until its
/// expiry, at most `cap` at once (oldest enrolment evicted first).
struct EnrolledKeys {
    cap: usize,
    inner: Mutex<Enrolment>,
}

#[derive(Default)]
struct Enrolment {
    /// Canonical AID -> (key, expiry).
    keys: HashMap<String, (AitpVerifyingKey, Timestamp)>,
    /// Canonical AIDs, oldest enrolment first. May hold stale entries
    /// for re-enrolled AIDs; `keys` is the source of truth.
    order: VecDeque<(String, Timestamp)>,
}

impl EnrolledKeys {
    fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            inner: Mutex::default(),
        }
    }

    fn insert(&self, key: AitpVerifyingKey, expires_at: Timestamp) {
        let aid = key.to_aid().to_string();
        let mut st = self.inner.lock().expect("not poisoned");
        st.keys.insert(aid.clone(), (key, expires_at));
        st.order.push_back((aid, expires_at));
        while st.keys.len() > self.cap {
            let Some((oldest, at)) = st.order.pop_front() else {
                break;
            };
            // Skip an entry superseded by a later re-enrolment.
            if st.keys.get(&oldest).is_some_and(|(_, exp)| *exp == at) {
                st.keys.remove(&oldest);
            }
        }
        // Keep `order` from growing without bound under re-enrolment.
        if st.order.len() > 2 * self.cap {
            let Enrolment { keys, order } = &mut *st;
            order.retain(|(aid, at)| keys.get(aid).is_some_and(|(_, exp)| exp == at));
        }
    }

    fn len(&self, now: Timestamp) -> usize {
        let mut st = self.inner.lock().expect("not poisoned");
        st.keys.retain(|_, (_, exp)| !exp.is_in_the_past(now));
        st.keys.len()
    }
}

impl PinnedKeyStore for EnrolledKeys {
    fn is_trusted(&self, key: &AitpVerifyingKey) -> bool {
        let st = self.inner.lock().expect("not poisoned");
        st.keys
            .get(key.to_aid().as_str())
            .is_some_and(|(k, exp)| k == key && !exp.is_in_the_past(Timestamp::now()))
    }
}

/// OIDC is not offered, so no JWKS is ever resolved.
struct NoJwks;

impl JwksResolver for NoJwks {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vk(seed: u8) -> AitpVerifyingKey {
        AitpSigningKey::from_seed(&[seed; 32]).verifying_key()
    }

    #[test]
    fn enrolled_keys_expire() {
        let store = EnrolledKeys::new(10);
        store.insert(vk(1), Timestamp::now().plus_secs(60));
        store.insert(vk(2), Timestamp::now().plus_secs(-1));
        assert!(store.is_trusted(&vk(1)));
        assert!(!store.is_trusted(&vk(2)));
        assert!(!store.is_trusted(&vk(3)));
        assert_eq!(store.len(Timestamp::now()), 1);
    }

    #[test]
    fn cap_evicts_the_oldest_enrolment() {
        let store = EnrolledKeys::new(2);
        let later = Timestamp::now().plus_secs(60);
        store.insert(vk(1), later);
        store.insert(vk(2), later);
        // Re-enrolling 1 makes 2 the oldest.
        store.insert(vk(1), later.plus_secs(1));
        store.insert(vk(3), later);
        assert!(store.is_trusted(&vk(1)));
        assert!(!store.is_trusted(&vk(2)));
        assert!(store.is_trusted(&vk(3)));
    }

    #[test]
    fn order_stays_bounded_under_re_enrolment() {
        let store = EnrolledKeys::new(2);
        let t = Timestamp::now().plus_secs(60);
        for i in 0..100 {
            store.insert(vk(1), t.plus_secs(i));
        }
        assert!(store.inner.lock().unwrap().order.len() <= 4);
        assert!(store.is_trusted(&vk(1)));
    }

    fn issue(
        peer: &AitpSigningKey,
        holder: &AitpSigningKey,
        grants: &[&str],
    ) -> (String, TctClaims) {
        use aitp::tct::TctBuilder;
        let issued = TctBuilder::new(peer)
            .subject(holder.aid().clone())
            .audience(holder.aid().clone())
            .subject_pubkey(holder.verifying_key())
            .grants(grants.iter().copied())
            .issued_at(Timestamp::now())
            .build()
            .unwrap();
        (issued.token, issued.claims)
    }

    fn interop(key: AitpSigningKey) -> Interop {
        let key = Arc::new(key);
        Interop {
            aid: key.aid().clone(),
            key,
            enrolled: Arc::new(EnrolledKeys::new(10)),
            enrol_ttl: 60,
            nonces: InMemoryNonceStore::new(10),
            challenge_limiter: TokenBucketLimiter::new(10, 1.0),
            enrol_limiter: TokenBucketLimiter::new(10, 1.0),
            echo_nonces: InMemoryNonceStore::new(10),
            echo_limiter: TokenBucketLimiter::new(10, 1.0),
            revoked: HashSet::new(),
            trusted_proxies: vec![],
            aitp: RwLock::new(Router::new()),
        }
    }

    /// Issue a challenge for `jti` the way `/echo/challenge` does and
    /// return its signed envelope.
    async fn challenge(peer: &Interop, jti: Uuid) -> aitp::core::AitpEnvelope {
        let nonce = base64url::encode(&[jti.as_bytes()[0]; NONCE_LEN]);
        let now = Timestamp::now();
        let record = IssuedNonce::new(
            echo_slot(jti, &nonce),
            peer.aid.clone(),
            "test",
            now,
            now.plus_secs(60),
        );
        peer.echo_nonces.issue(&record).await.unwrap();
        let payload = serde_json::to_value(echo::ChallengePayload {
            tct_jti: jti,
            nonce,
        })
        .unwrap();
        sign_envelope(peer.key.as_ref(), MessageType::PopChallenge, payload).unwrap()
    }

    fn request(tct: &str, response: aitp::core::AitpEnvelope) -> echo::EchoRequest {
        echo::EchoRequest {
            tct: tct.into(),
            pop_response: serde_json::to_value(response).unwrap(),
        }
    }

    fn code(r: Result<TctClaims, Refusal>) -> &'static str {
        match r {
            Ok(_) => "ok",
            Err(Refusal(_, code, _)) => code,
        }
    }

    #[tokio::test]
    async fn echo_accepts_pop_once() {
        let peer = interop(AitpSigningKey::from_seed(&[1; 32]));
        let holder = AitpSigningKey::from_seed(&[2; 32]);
        let (tct, claims) = issue(&peer.key, &holder, &[ECHO_CAP]);
        let ch = challenge(&peer, claims.jti).await;
        let resp = echo::respond(&holder, &peer.aid, claims.jti, ch).unwrap();
        let req = request(&tct, resp);
        let now = Timestamp::now();
        let ok = check_echo(&peer, &req, now).await.unwrap();
        assert_eq!(ok.sub, *holder.aid());
        // Replayed: the challenge is gone.
        assert_eq!(
            code(check_echo(&peer, &req, now).await),
            "POP_RESPONSE_INVALID"
        );
    }

    #[tokio::test]
    async fn a_wrong_answer_burns_the_challenge() {
        let peer = interop(AitpSigningKey::from_seed(&[1; 32]));
        let holder = AitpSigningKey::from_seed(&[2; 32]);
        let thief = AitpSigningKey::from_seed(&[3; 32]);
        let (tct, claims) = issue(&peer.key, &holder, &[ECHO_CAP]);
        let ch = challenge(&peer, claims.jti).await;
        let now = Timestamp::now();
        // Signed by a key other than `sub`'s.
        let forged = echo::respond(&thief, &peer.aid, claims.jti, ch.clone()).unwrap();
        assert_eq!(
            code(check_echo(&peer, &request(&tct, forged), now).await),
            "POP_RESPONSE_INVALID"
        );
        // The honest answer to the same challenge now finds nothing.
        let honest = echo::respond(&holder, &peer.aid, claims.jti, ch).unwrap();
        assert_eq!(
            code(check_echo(&peer, &request(&tct, honest), now).await),
            "POP_RESPONSE_INVALID"
        );
    }

    #[tokio::test]
    async fn a_challenge_is_bound_to_its_jti() {
        let peer = interop(AitpSigningKey::from_seed(&[1; 32]));
        let holder = AitpSigningKey::from_seed(&[2; 32]);
        let (_, first) = issue(&peer.key, &holder, &[ECHO_CAP]);
        let (tct2, second) = issue(&peer.key, &holder, &[ECHO_CAP]);
        let ch = challenge(&peer, first.jti).await;
        let resp = echo::respond(&holder, &peer.aid, first.jti, ch).unwrap();
        assert_eq!(
            code(check_echo(&peer, &request(&tct2, resp), Timestamp::now()).await),
            "POP_RESPONSE_INVALID"
        );
        assert_ne!(first.jti, second.jti);
    }

    #[test]
    fn own_tct_checks_issuer_audience_and_grant() {
        let peer = AitpSigningKey::from_seed(&[1; 32]);
        let holder = AitpSigningKey::from_seed(&[2; 32]);
        let now = Timestamp::now();
        let (tct, _) = issue(&peer, &holder, &[ECHO_CAP]);
        assert!(verify_own_tct(&tct, peer.aid(), now).is_ok());
        let other = AitpSigningKey::from_seed(&[3; 32]);
        assert_eq!(
            code(verify_own_tct(&tct, other.aid(), now)),
            "TCT_SIGNATURE_INVALID"
        );
        let (no_grant, _) = issue(&peer, &holder, &["something.else"]);
        assert_eq!(
            code(verify_own_tct(&no_grant, peer.aid(), now)),
            "POLICY_VIOLATION"
        );
    }
}
