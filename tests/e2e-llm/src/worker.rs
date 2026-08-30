//! In-process LLM-backed AITP responder, built on the **maintained**
//! high-level server API rather than a hand-rolled copy of it.
//!
//! [`aitp::transport::HandshakeServer`] owns the Mutual Handshake routes
//! (`/aitp/handshake/{hello,commit}`) and the revocation endpoint; we
//! merge two app-specific routes onto its router:
//!
//!   - `GET  /.well-known/aitp-manifest` — pinned-key manifest
//!   - `POST /work`                      — TCT-protected LLM endpoint
//!
//! This mirrors `examples/two-agents/src/bin/agent-b.rs` on purpose.
//! An earlier revision of this file re-implemented the responder state
//! machine by hand (`Responder::on_hello` / `on_commit`, hand-signed
//! envelopes); because this package is excluded from the workspace,
//! nothing compiled it, and it rotted silently across two breaking
//! releases. Building on the same API the demo uses means a breaking
//! change to that API now breaks the demo too — which CI *does* build.
//!
//! # Revocation
//!
//! The worker publishes a signed revocation snapshot via
//! [`HandshakeServer::with_revocation_producer`] and enforces it in
//! `/work` through a strict [`TctVerifyContext`]. That is deliberate:
//! the revocation snapshot is one of the two artifacts whose JCS
//! signing input changed in 0.5.0, so tier-3 should exercise it over a
//! real socket rather than assume tier-1 covers it.

use std::collections::HashSet;
use std::sync::Arc;

use aitp::core::{Aid, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp::manifest::{Manifest, ManifestEnvelope};
use aitp::tct::{
    sign_revocation_list, verify_tct, RevocationEntry, RevocationList, RevocationListEnvelope,
    TctClaims, TctVerifyContext,
};
use aitp::transport::{HandshakeServer, RevocationListProducer};
use aitp_example_two_agents::build_demo_manifest;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::Url;
use uuid::Uuid;

use crate::llm::{self, Provider};

/// Grant string used by tier-3 tests. The worker only honours requests
/// whose TCT carries this in `grants`.
pub const WORK_CAPABILITY: &str = "task.delegate";

/// JSON body posted to `/work`.
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkRequest {
    /// Natural-language task for the worker's LLM to answer.
    pub task: String,
}

/// JSON body returned by `/work`.
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkResponse {
    /// LLM-generated answer.
    pub answer: String,
    /// Provider label (e.g. `anthropic/claude-haiku-4-5`) for traceability.
    pub provider: String,
    /// AID of the worker that produced the answer.
    pub worker_aid: String,
}

/// Mutable revocation snapshot source.
///
/// Re-signs on every `current()` call rather than caching an envelope,
/// so a `jti` revoked mid-test is reflected on the very next fetch —
/// and so every fetch exercises the production signing path
/// ([`sign_revocation_list`]) rather than replaying one pre-built blob.
struct LiveRevocations {
    issuer: AitpSigningKey,
    revoked: Mutex<Vec<RevocationEntry>>,
}

impl RevocationListProducer for LiveRevocations {
    fn current(&self) -> RevocationListEnvelope {
        let now = Timestamp::now();
        let entries = self.revoked.lock().clone();
        sign_revocation_list(
            RevocationList {
                version: "aitp/0.2".into(),
                issuer: self.issuer.aid().clone(),
                published_at: now,
                expires_at: Timestamp(now.0 + 3600),
                entries,
                extensions: None,
            },
            &self.issuer,
        )
        .expect("revocation snapshot signs")
    }
}

/// Handle returned by [`spawn`]. Call [`Worker::shutdown`] to stop the
/// server.
pub struct Worker {
    pub aid: Aid,
    pub origin: Url,
    revocations: Arc<LiveRevocations>,
    join: JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl Worker {
    /// Revoke `jti`, so the next `/work` call presenting a TCT with that
    /// id is refused and the next revocation-snapshot fetch lists it.
    pub fn revoke(&self, jti: Uuid) {
        self.revocations.revoked.lock().push(RevocationEntry {
            jti,
            revoked_at: Timestamp::now(),
            reason: Some("revoked by tier-3 test".into()),
        });
    }

    /// Stop the server. Blocks (asynchronously) until the axum task
    /// exits.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.join.await;
    }
}

/// JWKS resolver for the pinned-key-only harness: OIDC resolution is
/// never invoked, so it returns an empty key set.
struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

/// State for the two app routes merged on top of the handshake server.
struct AppState {
    aid: Aid,
    manifest: Manifest,
    revocations: Arc<LiveRevocations>,
    provider: Provider,
    display_name: String,
}

/// Spawn an LLM-backed AITP responder. Binds to `127.0.0.1:0` so each
/// test gets a free port and never collides with anything else on the
/// host.
pub async fn spawn(
    display_name: &str,
    seed: &[u8; 32],
    provider: Provider,
) -> anyhow::Result<Worker> {
    let key = AitpSigningKey::from_seed(seed);
    // Bind first so we know the port the manifest needs to advertise.
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let port = addr.port();

    let manifest = build_demo_manifest(&key, display_name, port, &[WORK_CAPABILITY]);
    let aid = key.aid().clone();
    let origin: Url = format!("http://localhost:{port}").parse()?;

    let revocations = Arc::new(LiveRevocations {
        issuer: AitpSigningKey::from_seed(seed),
        revoked: Mutex::new(Vec::new()),
    });

    let state = Arc::new(AppState {
        aid: aid.clone(),
        manifest: manifest.clone(),
        revocations: Arc::clone(&revocations),
        provider,
        display_name: display_name.to_string(),
    });

    // The handshake server owns its own copy of the key + manifest and
    // serves /aitp/handshake/{hello,commit} plus the revocation
    // endpoint. We request `task.delegate` of the initiator so the
    // symmetric handshake's grant intersection is non-empty on our side.
    let server = HandshakeServer::new(
        key,
        manifest,
        vec![],
        NoOpResolver,
        vec![WORK_CAPABILITY.into()],
    )
    .with_revocation_producer(Arc::clone(&revocations) as Arc<dyn RevocationListProducer>);

    let app = server.router().merge(
        Router::new()
            .route("/.well-known/aitp-manifest", get(serve_manifest))
            .route("/work", post(handle_work))
            .with_state(state),
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let join = tokio::spawn(async move {
        let serve =
            axum::serve(listener, app.into_make_service()).with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            });
        if let Err(e) = serve.await {
            tracing::error!("worker server exited with error: {e}");
        }
    });

    Ok(Worker {
        aid,
        origin,
        revocations,
        join,
        shutdown: shutdown_tx,
    })
}

async fn serve_manifest(State(state): State<Arc<AppState>>) -> Json<ManifestEnvelope> {
    Json(ManifestEnvelope {
        manifest: state.manifest.clone(),
    })
}

async fn handle_work(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<WorkRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // The header value is the TCT itself: an opaque compact JWS string.
    let token = headers
        .get("x-aitp-tct")
        .ok_or((StatusCode::UNAUTHORIZED, "missing X-AITP-TCT header".into()))?
        .to_str()
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
        .to_string();

    // TCT verification is scoped to a block: `TctVerifyContext` borrows
    // a `&dyn Fn` and is therefore `!Send`, so it must be dropped before
    // the `.await` on the LLM call below — otherwise the future axum
    // schedules cannot be `Send`.
    let grants = {
        let claims = verify_work_tct(&token, &state.aid, &state.revocations)?;
        claims.grants
    };

    if !grants.iter().any(|g| g == WORK_CAPABILITY) {
        return Err((
            StatusCode::FORBIDDEN,
            format!("{WORK_CAPABILITY} not granted"),
        ));
    }

    // Now call the LLM. The worker has full latitude on the prompt —
    // tier-3 doesn't constrain it.
    let system = format!(
        "You are an AITP-mutually-authenticated worker agent named {}. \
         A peer agent has delegated a task to you over a verified \
         Trust Context Token. Produce a concise, professional answer \
         in 1-3 sentences. Do not introduce yourself.",
        state.display_name
    );
    let answer = llm::complete(&state.provider, &system, &req.task)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("llm: {e}")))?;

    Ok(Json(WorkResponse {
        answer,
        provider: state.provider.label(),
        worker_aid: state.aid.to_string(),
    }))
}

/// Verify a TCT presented to `/work`.
///
/// Unlike the demo's `verify_echo_tct`, this uses the **strict**
/// [`TctVerifyContext::builder`] and supplies a real revocation source,
/// so a revoked-but-unexpired TCT is refused. The issuer-Manifest
/// expiry cap is explicitly waived: the worker issued this TCT itself
/// and holds its own Manifest, so the cap adds nothing here — but the
/// waiver is written out rather than defaulted, which is the point of
/// the strict builder.
fn verify_work_tct(
    token: &str,
    worker_aid: &Aid,
    revocations: &LiveRevocations,
) -> Result<TctClaims, (StatusCode, String)> {
    use aitp::crypto::jws;

    // Peek (unverified) at the claims to learn the presented subject;
    // `verify_tct` re-establishes everything cryptographically below.
    let payload = jws::decode_payload_unverified(token)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let peeked: TctClaims = serde_json::from_slice(&payload).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("malformed TCT claims: {e}"),
        )
    })?;
    if &peeked.iss != worker_aid {
        return Err((
            StatusCode::FORBIDDEN,
            "TCT not issued by this worker".into(),
        ));
    }

    // Snapshot the revoked set once so the closure below borrows an
    // owned value rather than holding the mutex across verification.
    let revoked: HashSet<Uuid> = revocations.revoked.lock().iter().map(|e| e.jti).collect();
    let is_revoked = |jti: &Uuid| revoked.contains(jti);

    // Holder receipt: subject == audience == caller.
    let ctx = TctVerifyContext::builder(&peeked.sub, worker_aid, Timestamp::now())
        .revocation_check(&is_revoked)
        .skip_manifest_expiry_cap_dangerous()
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let verified = verify_tct(token, &ctx).map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))?;
    Ok(verified.claims)
}
