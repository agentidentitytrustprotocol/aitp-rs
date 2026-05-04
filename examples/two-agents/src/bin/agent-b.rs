//! Agent B — accepts incoming AITP handshakes, exposes a `/echo`
//! capability protected by TCT verification.

use aitp::core::{Aid, AitpEnvelope, MessageType};
use aitp::crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp::handshake::{
    JwkPublicKey, JwksResolver, MutualCommitPayload, MutualHelloPayload, PeerConfig,
    PresentedIdentity, ResolveError, Responder,
};
use aitp::manifest::ManifestEnvelope;
use aitp::tct::{verify_tct, Tct, TctEnvelope, TctVerifyContext};
use aitp_example_two_agents::{build_demo_manifest, sign_envelope, sign_envelope_with};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "agent-b", about = "AITP demo: target peer")]
struct Cli {
    #[arg(long, default_value_t = 8002)]
    port: u16,
    #[arg(long, default_value = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]
    seed: String,
}

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let seed = expand_seed(&cli.seed);
    let key = AitpSigningKey::from_seed(&seed);
    let manifest = build_demo_manifest(&key, "agent-b", cli.port, &["demo.echo"], &[]);
    println!("agent-b: AID = {}", key.aid());
    println!("agent-b: listening on http://localhost:{}", cli.port);

    let state = Arc::new(AppState {
        signing_key: Arc::new(key),
        manifest: Arc::new(manifest),
        sessions: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/.well-known/aitp-manifest", get(serve_manifest))
        .route("/aitp/handshake/hello", post(handle_hello))
        .route("/aitp/handshake/commit", post(handle_commit))
        .route("/echo", post(handle_echo))
        .with_state(state);

    let listener = TcpListener::bind(("127.0.0.1", cli.port)).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

fn expand_seed(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = bytes[i % bytes.len()];
    }
    out
}

struct AppState {
    signing_key: Arc<AitpSigningKey>,
    manifest: Arc<aitp::manifest::Manifest>,
    sessions: Mutex<HashMap<Uuid, Responder>>,
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
    verify_envelope(&envelope).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let cfg = PeerConfig {
        signing_key: &state.signing_key,
        manifest: &state.manifest,
        trust_anchors: &[],
        jwks_resolver: &NoOpResolver,
        pinned_key_store: None,
        grant_policy: None,
        now: aitp::core::Timestamp::now(),
    };
    let ack_mid = Uuid::new_v4();
    let ack_ts = aitp::core::Timestamp::now();
    // Bob also requests demo.echo from Alice so the symmetric handshake's
    // grant intersection on her side is non-empty.
    let (responder, ack_payload) = Responder::on_hello(
        &envelope,
        &payload,
        PresentedIdentity::PinnedKey {
            subject: "agent-b".into(),
        },
        &ack_mid,
        ack_ts,
        &cfg,
        vec!["demo.echo".into()],
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let session_id = Uuid::new_v4();
    state.sessions.lock().unwrap().insert(session_id, responder);
    // The ack envelope MUST use the same `(ack_mid, ack_ts)` that was
    // used to build the identity proof inside `ack_payload`, because the
    // pinned-key proof binding is `sha256(envelope.message_id|timestamp)`.
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
        .unwrap()
        .remove(&session_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "unknown session".to_string()))?;
    let payload: MutualCommitPayload = serde_json::from_value(envelope.payload.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    verify_envelope(&envelope).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let cfg = PeerConfig {
        signing_key: &state.signing_key,
        manifest: &state.manifest,
        trust_anchors: &[],
        jwks_resolver: &NoOpResolver,
        pinned_key_store: None,
        grant_policy: None,
        now: aitp::core::Timestamp::now(),
    };
    let (ack_payload, _bob_holds_tct_for_alice) = responder
        .on_commit(&envelope, &payload, &cfg)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let ack_env = sign_envelope(
        &state.signing_key,
        MessageType::MutualCommitAck,
        serde_json::to_value(&ack_payload).unwrap(),
    );
    Ok(Json(ack_env))
}

async fn handle_echo(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<String, (StatusCode, String)> {
    let tct_header = headers
        .get("x-aitp-tct")
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing X-AITP-TCT header".into()))?;
    let tct_json = tct_header
        .to_str()
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let env: TctEnvelope =
        serde_json::from_str(tct_json).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let tct: Tct = env.tct;
    // Issuer == agent-b (we issued this for the caller). Audience == caller AID.
    let issuer_pk = AitpVerifyingKey::from_aid(&tct.issuer)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let ctx = TctVerifyContext {
        expected_audience: &tct.subject, // holder receipt: subject == audience == caller
        issuer_pubkey: &issuer_pk,
        now: aitp::core::Timestamp::now(),
        revocation_check: None,
    };
    verify_tct(&tct, &ctx).map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))?;
    if !tct.grants.contains(&"demo.echo".to_string()) {
        return Err((StatusCode::FORBIDDEN, "demo.echo not granted".into()));
    }
    if &tct.issuer != state.signing_key.aid() {
        return Err((
            StatusCode::FORBIDDEN,
            "TCT not issued by this server".into(),
        ));
    }
    Ok(format!(
        "echo from agent-b to {}: {}",
        tct.subject,
        String::from_utf8_lossy(&body)
    ))
}

fn verify_envelope(envelope: &AitpEnvelope) -> Result<(), String> {
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

#[allow(dead_code)]
fn _aid_unused(_: &Aid) {}
