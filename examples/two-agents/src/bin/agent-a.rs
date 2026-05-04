//! Agent A — initiator. Fetches B's manifest, runs the handshake, then
//! invokes B's `/echo` capability with the received TCT.

use aitp::core::{AitpEnvelope, MessageType};
use aitp::crypto::AitpSigningKey;
use aitp::handshake::{
    Initiator, JwkPublicKey, JwksResolver, MutualCommitAckPayload, MutualHelloAckPayload,
    PeerConfig, PresentedIdentity, ResolveError,
};
use aitp::manifest::ManifestEnvelope;
use aitp::tct::TctEnvelope;
use aitp_example_two_agents::{build_demo_manifest, sign_envelope};
use clap::Parser;
use std::time::Duration;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "agent-a", about = "AITP demo: initiating peer")]
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

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let seed = expand_seed(&cli.seed);
    let key = AitpSigningKey::from_seed(&seed);
    // Both demo agents are symmetric: each offers demo.echo to the other
    // (so the mutual handshake's grant intersection is non-empty on both
    // sides) and neither requires anything of the peer.
    let manifest = build_demo_manifest(&key, "agent-a", cli.port, &["demo.echo"], &[]);
    println!("agent-a: AID = {}", key.aid());

    let peer_origin: url::Url = cli.peer.parse()?;

    // Wait for B to be ready.
    let client = reqwest::Client::new();
    for attempt in 0..40 {
        let resp = client
            .get(peer_origin.join("/.well-known/aitp-manifest")?)
            .timeout(Duration::from_secs(1))
            .send()
            .await;
        if resp.is_ok() {
            break;
        }
        if attempt == 39 {
            return Err("agent-b never came up".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Fetch B's manifest and verify it.
    let body: ManifestEnvelope = client
        .get(peer_origin.join("/.well-known/aitp-manifest")?)
        .send()
        .await?
        .json()
        .await?;
    let bob_manifest = body.manifest;
    aitp::manifest::verify_manifest(&bob_manifest, &aitp::manifest::VerifyManifestContext::now())?;
    println!("agent-a: fetched B's manifest, AID = {}", bob_manifest.aid);

    // Run the handshake.
    let cfg = PeerConfig {
        signing_key: &key,
        manifest: &manifest,
        trust_anchors: &[],
        jwks_resolver: &NoOpResolver,
        now: aitp::core::Timestamp::now(),
    };
    let hello_mid = Uuid::new_v4();
    let hello_ts = aitp::core::Timestamp::now();
    let (mut initiator, hello_payload) = Initiator::start(
        &cfg,
        PresentedIdentity::PinnedKey {
            subject: "agent-a".into(),
        },
        &hello_mid,
        hello_ts,
        vec!["demo.echo".into()],
    )?;
    let hello_envelope = sign_envelope(
        &key,
        MessageType::MutualHello,
        serde_json::to_value(&hello_payload)?,
    );

    // Note: the envelope I just built used a fresh message_id/timestamp
    // from sign_envelope; rebuild it sharing the hello_mid/hello_ts so the
    // pinned-key identity proof's bound timestamps match.
    let hello_envelope = AitpEnvelope {
        message_id: hello_mid,
        timestamp: hello_ts,
        ..hello_envelope
    };
    // Re-sign with the new message_id/timestamp.
    let digest = aitp::core::envelope_signing_digest(
        &hello_mid,
        hello_ts,
        key.aid(),
        &hello_envelope.payload,
    )?;
    let hello_envelope = AitpEnvelope {
        signature: key.sign(&digest).into_string(),
        ..hello_envelope
    };

    println!("agent-a: sending MUTUAL_HELLO");
    let resp = client
        .post(peer_origin.join("/aitp/handshake/hello")?)
        .json(&hello_envelope)
        .send()
        .await?;
    let session_id = resp
        .headers()
        .get("x-aitp-session-id")
        .ok_or("server did not return a session id")?
        .to_str()?
        .to_string();
    let ack_envelope: AitpEnvelope = resp.json().await?;
    let ack_payload: MutualHelloAckPayload = serde_json::from_value(ack_envelope.payload.clone())?;

    // Drive the initiator forward.
    println!("agent-a: building MUTUAL_COMMIT");
    let commit_payload = initiator.on_hello_ack(&ack_envelope, &ack_payload, &cfg)?;
    let commit_mid = Uuid::new_v4();
    let commit_ts = aitp::core::Timestamp::now();
    let payload_value = serde_json::to_value(&commit_payload)?;
    let digest =
        aitp::core::envelope_signing_digest(&commit_mid, commit_ts, key.aid(), &payload_value)?;
    let commit_envelope = AitpEnvelope {
        version: "aitp/0.1".into(),
        message_type: MessageType::MutualCommit,
        message_id: commit_mid,
        timestamp: commit_ts,
        sender: aitp::core::Sender {
            agent_id: key.aid().clone(),
        },
        payload: payload_value,
        signature: key.sign(&digest).into_string(),
    };
    let resp = client
        .post(peer_origin.join("/aitp/handshake/commit")?)
        .header("x-aitp-session-id", &session_id)
        .json(&commit_envelope)
        .send()
        .await?;
    let commit_ack_envelope: AitpEnvelope = resp.json().await?;
    let commit_ack_payload: MutualCommitAckPayload =
        serde_json::from_value(commit_ack_envelope.payload.clone())?;
    let alice_holds_tct =
        initiator.on_commit_ack(&commit_ack_envelope, &commit_ack_payload, &cfg)?;
    println!(
        "agent-a: handshake complete — holding TCT issued by {} with grants {:?}",
        alice_holds_tct.issuer, alice_holds_tct.grants
    );

    // Invoke B's /echo using the received TCT.
    let tct_envelope = TctEnvelope {
        tct: alice_holds_tct,
    };
    let tct_header = serde_json::to_string(&tct_envelope)?;
    let echo_resp = client
        .post(peer_origin.join("/echo")?)
        .header("x-aitp-tct", tct_header)
        .body(cli.message)
        .send()
        .await?;
    let status = echo_resp.status();
    let body = echo_resp.text().await?;
    println!("agent-a: /echo => {} {}", status, body);
    if !status.is_success() {
        return Err(format!("echo failed: {body}").into());
    }

    Ok(())
}

fn expand_seed(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = bytes[i % bytes.len()];
    }
    out
}
