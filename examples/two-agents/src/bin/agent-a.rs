//! Agent A — initiator, built on the high-level client API.
//!
//! The entire four-message Mutual Handshake is driven by one call to
//! [`aitp::facade::run_initiator_handshake`]: it fetches B's Manifest,
//! sends HELLO, drives HELLO_ACK → COMMIT → COMMIT_ACK, and hands back a
//! [`SessionContext`](aitp::facade::SessionContext) holding the TCT B
//! issued us. We then use that TCT to invoke B's `/echo` capability.
//!
//! Trust posture: we pin B's key (TOFU — pin-on-first-fetch) and pass it
//! via [`TrustMode::PinnedKeys`]. A production initiator pins the peer
//! key out of band (config, KMS) rather than trusting the first Manifest
//! it sees.

use aitp::core::base64url;
use aitp::crypto::AitpSigningKey;
use aitp::facade::{run_initiator_handshake, IdentityMode, InitiatorConfig, TrustMode};
use aitp::handshake::StaticPinnedKeyStore;
use aitp::tct::TctEnvelope;
use aitp::transport::ManifestFetcher;
use aitp_example_two_agents::{build_demo_manifest, expand_seed};
use clap::Parser;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "agent-a", about = "AITP demo: initiating peer (facade client)")]
struct Cli {
    #[arg(long, default_value_t = 8001)]
    port: u16,
    #[arg(long, default_value = "http://localhost:8002")]
    peer: String,
    #[arg(long, default_value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    seed: String,
    #[arg(long, default_value = "hello world")]
    message: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let key = AitpSigningKey::from_seed(&expand_seed(&cli.seed));
    // We offer demo.echo so B's symmetric grant request is satisfiable;
    // pinned-key identity "agent-a" matches our Manifest identity hint.
    let manifest = build_demo_manifest(&key, "agent-a", cli.port, &["demo.echo"]);
    println!("agent-a: AID = {}", key.aid());

    let peer_origin: url::Url = cli.peer.parse()?;

    // Discover B's Manifest (also serves as a readiness poll). The
    // verified Manifest's pinned public key becomes our trust anchor.
    let fetcher = ManifestFetcher::new();
    let bob_manifest = wait_for_peer(&fetcher, &peer_origin).await?;
    println!("agent-a: fetched B's manifest, AID = {}", bob_manifest.aid);

    let bob_pinned_key: [u8; 32] = bob_manifest
        .identity_hint
        .public_key
        .as_deref()
        .ok_or("peer manifest has no pinned public_key")
        .and_then(|s| base64url::decode_strict_exact::<32>(s).map_err(|_| "bad pinned key"))?;
    let store = StaticPinnedKeyStore::new(vec![bob_pinned_key]);

    // One call drives the whole handshake and returns the TCT B issued us.
    let session = run_initiator_handshake(InitiatorConfig {
        signing_key: &key,
        own_manifest: &manifest,
        peer_origin: peer_origin.clone(),
        trust_mode: TrustMode::PinnedKeys(&store),
        identity_mode: IdentityMode::PinnedKey {
            subject: "agent-a".into(),
        },
        requested_grants: vec!["demo.echo".into()],
    })
    .await?;
    println!(
        "agent-a: handshake complete — holding TCT issued by {} with grants {:?}",
        session.held_tct.issuer, session.held_tct.grants
    );

    // Invoke B's /echo using the received TCT.
    let tct_header = serde_json::to_string(&TctEnvelope {
        tct: session.held_tct,
    })?;
    let client = reqwest::Client::new();
    let echo_resp = client
        .post(peer_origin.join("/echo")?)
        .header("x-aitp-tct", tct_header)
        .body(cli.message)
        .send()
        .await?;
    let status = echo_resp.status();
    let body = echo_resp.text().await?;
    println!("agent-a: /echo => {status} {body}");
    if !status.is_success() {
        return Err(format!("echo failed: {body}").into());
    }
    Ok(())
}

/// Poll the peer's Manifest endpoint until it comes up (or time out).
async fn wait_for_peer(
    fetcher: &ManifestFetcher,
    peer_origin: &url::Url,
) -> Result<aitp::manifest::Manifest, Box<dyn std::error::Error>> {
    for attempt in 0..40 {
        match fetcher.fetch(peer_origin).await {
            Ok(manifest) => return Ok(manifest),
            Err(_) if attempt < 39 => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => return Err(format!("agent-b never came up: {e}").into()),
        }
    }
    unreachable!("loop returns on the final attempt")
}
