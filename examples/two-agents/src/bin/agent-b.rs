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
use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError, StaticPinnedKeyStore};
use aitp::manifest::{Manifest, ManifestEnvelope};
use aitp::transport::{
    with_request_body_limit_default, HandshakeServer, RevocationFailMode, RevocationPolicy,
};
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
    /// Bind address. Defaults to loopback (`127.0.0.1`) for the local
    /// demo; set `0.0.0.0` to accept connections from other hosts /
    /// containers (see the docker-compose example).
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]
    seed: String,
    /// Pinned-key peer AID to trust (RFC-AITP-0002 §3.2). Repeatable.
    /// Defaults to the AID agent-a derives from its default seed, so the
    /// out-of-the-box demo works; a peer not listed here is rejected.
    #[arg(long = "trust")]
    trust: Vec<String>,
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
    let trusted: Vec<Aid> = if cli.trust.is_empty() {
        vec![
            AitpSigningKey::from_seed(&expand_seed("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
                .aid()
                .clone(),
        ]
    } else {
        cli.trust
            .iter()
            .map(|s| Aid::parse(s).expect("--trust takes an AID"))
            .collect()
    };
    for aid in &trusted {
        println!("agent-b: trusting pinned key {aid}");
    }
    let pinned = StaticPinnedKeyStore::from_aids(&trusted).expect("--trust AIDs are pinnable keys");
    let server = HandshakeServer::new(
        key,
        manifest,
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    .with_pinned_key_store(Arc::new(pinned))
    // Revocation is fail_closed by default (RFC-AITP-0008 §3.1): the
    // initiator's Manifest must advertise a reachable `ListRevoked`
    // snapshot. agent-a is a pure client that serves nothing at the URL
    // it advertises, so the demo opts out explicitly. agent-a itself
    // keeps the default and checks our list. A deployment should not
    // opt out.
    .with_revocation_policy(
        RevocationPolicy::default().with_fail_mode(RevocationFailMode::FailOpen),
    );

    // `into_router` (feature `experimental-axum`) mounts the handshake
    // next to our own routes; `server.serve(listener)` hosts it alone.
    let app = server.into_router().merge(
        Router::new()
            .route("/.well-known/aitp-manifest", get(serve_manifest))
            .route("/echo", post(handle_echo))
            .with_state(echo_state),
    );
    // Bound request bodies to the recommended default (handshake
    // payloads are small); see examples/observability/README.md.
    let app = with_request_body_limit_default(app);

    let listener = TcpListener::bind((cli.host.as_str(), cli.port))
        .await
        .unwrap();
    // The peer address reaches the rate limiter only through ConnectInfo.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap();
}

async fn serve_manifest(State(state): State<Arc<EchoState>>) -> Json<ManifestEnvelope> {
    Json(ManifestEnvelope::new(state.manifest.clone()))
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
