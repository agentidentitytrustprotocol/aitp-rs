//! In-process LLM-backed AITP responder. Spawns an axum server on a
//! random local port with the four standard endpoints:
//!
//!   - `GET  /.well-known/aitp-manifest` — pinned-key manifest
//!   - `POST /aitp/handshake/hello`      — `MutualHello`  → `MutualHelloAck`
//!   - `POST /aitp/handshake/commit`     — `MutualCommit` → `MutualCommitAck`
//!   - `POST /work`                       — TCT-protected LLM endpoint
//!
//! The handshake handlers are lifted from `examples/two-agents`; the
//! `/work` handler is the tier-3 addition: it verifies a presented TCT,
//! prompts the configured LLM with the task, and returns the answer.

use std::collections::HashMap;
use std::sync::Arc;

use aitp::core::{Aid, AitpEnvelope, MessageType, Timestamp};
use aitp::crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp::handshake::{
    JwkPublicKey, JwksResolver, MutualCommitPayload, MutualHelloPayload, PeerConfig,
    PresentedIdentity, ResolveError, Responder,
};
use aitp::manifest::{Manifest, ManifestEnvelope};
use aitp::tct::{verify_tct, Tct, TctEnvelope, TctVerifyContext};
use aitp_example_two_agents::{build_demo_manifest, sign_envelope, sign_envelope_with};
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

/// Handle returned by [`spawn`]. Drop or call [`Worker::shutdown`] to
/// stop the server.
pub struct Worker {
    pub aid: Aid,
    pub origin: Url,
    join: JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl Worker {
    /// Stop the server. Blocks (asynchronously) until the axum task
    /// exits.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.join.await;
    }
}

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

struct AppState {
    signing_key: Arc<AitpSigningKey>,
    manifest: Arc<Manifest>,
    sessions: Mutex<HashMap<Uuid, Responder>>,
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

    // The worker offers `task.delegate` and requires nothing of the
    // peer — symmetric to the two-agent demo's `demo.echo`.
    let manifest =
        build_demo_manifest(&key, display_name, port, &[WORK_CAPABILITY], &[WORK_CAPABILITY]);

    let aid = key.aid().clone();
    let origin: Url = format!("http://localhost:{port}").parse()?;

    let state = Arc::new(AppState {
        signing_key: Arc::new(key),
        manifest: Arc::new(manifest),
        sessions: Mutex::new(HashMap::new()),
        provider,
        display_name: display_name.to_string(),
    });

    let app = Router::new()
        .route("/.well-known/aitp-manifest", get(serve_manifest))
        .route("/aitp/handshake/hello", post(handle_hello))
        .route("/aitp/handshake/commit", post(handle_commit))
        .route("/work", post(handle_work))
        .with_state(state);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let join = tokio::spawn(async move {
        let serve = axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            });
        if let Err(e) = serve.await {
            tracing::error!("worker server exited with error: {e}");
        }
    });

    Ok(Worker {
        aid,
        origin,
        join,
        shutdown: shutdown_tx,
    })
}

async fn serve_manifest(State(state): State<Arc<AppState>>) -> Json<ManifestEnvelope> {
    Json(ManifestEnvelope {
        manifest: (*state.manifest).clone(),
    })
}

async fn handle_hello(
    State(state): State<Arc<AppState>>,
    Json(envelope): Json<AitpEnvelope>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if envelope.message_type != MessageType::MutualHello {
        return Err((StatusCode::BAD_REQUEST, "expected mutual_hello".into()));
    }
    let payload: MutualHelloPayload = serde_json::from_value(envelope.payload.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    verify_envelope_sig(&envelope).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let cfg = PeerConfig {
        signing_key: &state.signing_key,
        manifest: &state.manifest,
        trust_anchors: &[],
        jwks_resolver: &NoOpResolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: Timestamp::now(),
    };
    let ack_mid = Uuid::new_v4();
    let ack_ts = Timestamp::now();
    let (responder, ack_payload) = Responder::on_hello(
        &envelope,
        &payload,
        PresentedIdentity::PinnedKey {
            subject: state.display_name.clone(),
        },
        &ack_mid,
        ack_ts,
        &cfg,
        vec![WORK_CAPABILITY.into()],
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let session_id = Uuid::new_v4();
    state.sessions.lock().insert(session_id, responder);

    let ack_env = sign_envelope_with(
        &state.signing_key,
        MessageType::MutualHelloAck,
        serde_json::to_value(&ack_payload).unwrap(),
        ack_mid,
        ack_ts,
    );
    let mut headers = HeaderMap::new();
    headers.insert("x-aitp-session-id", session_id.to_string().parse().unwrap());
    Ok((headers, Json(ack_env)))
}

async fn handle_commit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(envelope): Json<AitpEnvelope>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if envelope.message_type != MessageType::MutualCommit {
        return Err((StatusCode::BAD_REQUEST, "expected mutual_commit".into()));
    }
    let session_id = headers
        .get("x-aitp-session-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing session id".to_string()))?;
    let mut responder = state
        .sessions
        .lock()
        .remove(&session_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "unknown session".to_string()))?;
    let payload: MutualCommitPayload = serde_json::from_value(envelope.payload.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    verify_envelope_sig(&envelope).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let cfg = PeerConfig {
        signing_key: &state.signing_key,
        manifest: &state.manifest,
        trust_anchors: &[],
        jwks_resolver: &NoOpResolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: Timestamp::now(),
    };
    let (ack_payload, _worker_holds_tct_for_planner) = responder
        .on_commit(&envelope, &payload, &cfg)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let ack_env = sign_envelope(
        &state.signing_key,
        MessageType::MutualCommitAck,
        serde_json::to_value(&ack_payload).unwrap(),
    );
    Ok(Json(ack_env))
}

async fn handle_work(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<WorkRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Verify the presented TCT (same shape as `examples/two-agents`'s
    // `/echo` handler — TCT lives in the `X-AITP-TCT` header). The
    // verification is scoped to a block so `TctVerifyContext`, which
    // holds a `&dyn Fn` and is therefore `!Send`, is dropped before
    // the LLM call below — otherwise the future axum schedules can't
    // be `Send`.
    let tct_header = headers
        .get("x-aitp-tct")
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing X-AITP-TCT header".into()))?;
    let tct_json = tct_header
        .to_str()
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let env: TctEnvelope =
        serde_json::from_str(tct_json).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let tct: Tct = env.tct;

    {
        let issuer_pk = AitpVerifyingKey::from_aid(&tct.issuer)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        let ctx = TctVerifyContext {
            expected_audience: &tct.subject,
            issuer_pubkey: &issuer_pk,
            now: Timestamp::now(),
            issuer_manifest_expires_at: None,
            revocation_check: None,
        };
        verify_tct(&tct, &ctx).map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))?;
    }

    if !tct.grants.iter().any(|g| g == WORK_CAPABILITY) {
        return Err((
            StatusCode::FORBIDDEN,
            format!("{WORK_CAPABILITY} not granted"),
        ));
    }
    if &tct.issuer != state.signing_key.aid() {
        return Err((
            StatusCode::FORBIDDEN,
            "TCT not issued by this worker".into(),
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
        worker_aid: state.signing_key.aid().to_string(),
    }))
}

fn verify_envelope_sig(envelope: &AitpEnvelope) -> Result<(), String> {
    let pk = AitpVerifyingKey::from_aid(&envelope.sender.agent_id)
        .map_err(|e| format!("bad sender AID: {e}"))?;
    let digest = aitp::core::envelope_signing_digest(
        &envelope.message_id,
        envelope.timestamp,
        &envelope.sender.agent_id,
        &envelope.payload,
    )
    .map_err(|e| format!("jcs failure: {e}"))?;
    let sig = aitp::crypto::Signature::parse(&envelope.signature)
        .map_err(|e| format!("malformed signature: {e}"))?;
    pk.verify(&digest, &sig)
        .map_err(|_| "envelope signature verification failed".to_string())
}
