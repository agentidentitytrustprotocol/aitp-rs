//! Agent B — target peer, built on the high-level server API.
//!
//! [`aitp::transport::HandshakeServer`] serves the Mutual Handshake
//! routes (`/aitp/handshake/hello` + `/commit`) and issues the caller a
//! TCT. We merge two app-specific routes onto its router:
//!
//! - `GET /.well-known/aitp-manifest` — so a peer can discover us, and
//! - `POST /echo` — the `demo.echo` capability, gated on TCT verification.
//!
//! Contrast with the initiator in `agent-a.rs`, which drives the other
//! side of this handshake with `aitp::facade::run_initiator_handshake`.

use aitp::core::Aid;
use aitp::crypto::AitpSigningKey;
use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp::manifest::{Manifest, ManifestEnvelope};
use aitp::transport::{with_request_body_limit_default, HandshakeServer};
use aitp_example_two_agents::{build_demo_manifest, expand_seed, verify_echo_tct};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(name = "agent-b", about = "AITP demo: target peer (facade server)")]
struct Cli {
    #[arg(long, default_value_t = 8002)]
    port: u16,
    #[arg(long, default_value = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]
    seed: String,
}

/// JWKS resolver for the pinned-key-only demo: OIDC resolution is never
/// invoked, so it returns an empty key set.
struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

/// State for the two app routes we add on top of the handshake server.
struct EchoState {
    aid: Aid,
    manifest: Manifest,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let key = AitpSigningKey::from_seed(&expand_seed(&cli.seed));
    let manifest = build_demo_manifest(&key, "agent-b", cli.port, &["demo.echo"]);
    println!("agent-b: AID = {}", key.aid());
    println!("agent-b: listening on http://localhost:{}", cli.port);

    let echo_state = Arc::new(EchoState {
        aid: key.aid().clone(),
        manifest: manifest.clone(),
    });

    // The handshake server owns its own copy of the key + manifest and
    // serves /aitp/handshake/{hello,commit}. We request `demo.echo` of
    // the initiator so the symmetric handshake's grant intersection is
    // non-empty on our side too.
    let server = HandshakeServer::new(
        key,
        manifest,
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    );

    let app = server.router().merge(
        Router::new()
            .route("/.well-known/aitp-manifest", get(serve_manifest))
            .route("/echo", post(handle_echo))
            .with_state(echo_state),
    );
    // Bound request bodies to the recommended default (handshake
    // payloads are small); see examples/observability/README.md.
    let app = with_request_body_limit_default(app);

    let listener = TcpListener::bind(("127.0.0.1", cli.port)).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn serve_manifest(State(state): State<Arc<EchoState>>) -> Json<ManifestEnvelope> {
    Json(ManifestEnvelope {
        manifest: state.manifest.clone(),
    })
}

async fn handle_echo(
    State(state): State<Arc<EchoState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<String, (StatusCode, String)> {
    // The header value is the TCT itself: an opaque compact JWS string.
    let token = headers
        .get("x-aitp-tct")
        .ok_or((StatusCode::UNAUTHORIZED, "missing X-AITP-TCT header".into()))?
        .to_str()
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let caller = verify_echo_tct(token, &state.aid).map_err(|e| (StatusCode::FORBIDDEN, e))?;
    Ok(format!(
        "echo from agent-b to {}: {}",
        caller,
        String::from_utf8_lossy(&body)
    ))
}
