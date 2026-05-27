//! Planner side: drives the four-message handshake from the
//! initiator's point of view, then invokes the worker's `/work`
//! endpoint with the resulting TCT.
//!
//! Lifted from `examples/two-agents/src/bin/agent-a.rs` and trimmed of
//! the CLI / printlns. The TCT-presented invocation is the
//! `delegate_task` helper.

use std::time::Duration;

use aitp::core::{AitpEnvelope, MessageType, Sender, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::handshake::{
    Initiator, JwkPublicKey, JwksResolver, MutualCommitAckPayload, MutualHelloAckPayload,
    PeerConfig, PresentedIdentity, ResolveError,
};
use aitp::manifest::ManifestEnvelope;
use aitp::tct::{Tct, TctEnvelope};
use aitp_example_two_agents::build_demo_manifest;
use anyhow::{anyhow, Context};
use url::Url;
use uuid::Uuid;

use crate::worker::{WorkRequest, WorkResponse, WORK_CAPABILITY};

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

/// Outcome of a successful handshake. The TCT was issued by the worker
/// **for** this planner — the planner holds it and presents it on
/// every subsequent capability invocation.
pub struct HandshakeOutcome {
    pub planner_key: AitpSigningKey,
    pub tct: Tct,
}

/// Drive the initiator side of the AITP four-message handshake against
/// `worker_origin`. Returns the planner's signing key and the TCT it
/// received from the worker.
pub async fn handshake(
    display_name: &str,
    seed: &[u8; 32],
    planner_port_for_manifest: u16,
    worker_origin: &Url,
) -> anyhow::Result<HandshakeOutcome> {
    let key = AitpSigningKey::from_seed(seed);
    // The planner offers + requires the same capability so the mutual
    // intersection is non-empty on both sides.
    let manifest = build_demo_manifest(
        &key,
        display_name,
        planner_port_for_manifest,
        &[WORK_CAPABILITY],
        &[WORK_CAPABILITY],
    );

    let client = reqwest::Client::new();

    // Wait for the worker to come up (axum::serve binds early but
    // tasks may not yet be polling; this is paranoia, usually 0–1
    // iterations).
    for attempt in 0..40 {
        let r = client
            .get(worker_origin.join("/.well-known/aitp-manifest")?)
            .timeout(Duration::from_secs(1))
            .send()
            .await;
        if r.is_ok() {
            break;
        }
        if attempt == 39 {
            return Err(anyhow!("worker never came up at {worker_origin}"));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Fetch + verify the worker's manifest.
    let body: ManifestEnvelope = client
        .get(worker_origin.join("/.well-known/aitp-manifest")?)
        .send()
        .await?
        .json()
        .await
        .context("decoding worker manifest")?;
    let worker_manifest = body.manifest;
    aitp::manifest::verify_manifest(
        &worker_manifest,
        &aitp::manifest::VerifyManifestContext::now(),
    )
    .context("verifying worker manifest")?;

    let make_cfg = || PeerConfig {
        signing_key: &key,
        manifest: &manifest,
        trust_anchors: &[],
        jwks_resolver: &NoOpResolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: Timestamp::now(),
    };

    // ── MutualHello ───────────────────────────────────────────────
    let cfg = make_cfg();
    let hello_mid = Uuid::new_v4();
    let hello_ts = Timestamp::now();
    let (mut initiator, hello_payload) = Initiator::start(
        &cfg,
        PresentedIdentity::PinnedKey {
            subject: display_name.into(),
        },
        &worker_manifest.aid,
        &hello_mid,
        hello_ts,
        vec![WORK_CAPABILITY.into()],
    )?;
    // Re-sign the envelope so its `(message_id, timestamp)` match the
    // ones bound into the pinned-key identity proof.
    let hello_payload_value = serde_json::to_value(&hello_payload)?;
    let digest = aitp::core::envelope_signing_digest(
        &hello_mid,
        hello_ts,
        key.aid(),
        &hello_payload_value,
    )?;
    let hello_envelope = AitpEnvelope {
        version: "aitp/0.1".into(),
        message_type: MessageType::MutualHello,
        message_id: hello_mid,
        timestamp: hello_ts,
        sender: Sender {
            agent_id: key.aid().clone(),
        },
        payload: hello_payload_value,
        signature: key.sign(&digest).into_string(),
    };

    let resp = client
        .post(worker_origin.join("/aitp/handshake/hello")?)
        .json(&hello_envelope)
        .send()
        .await?;
    let resp = resp.error_for_status().context("MutualHello rejected")?;
    let session_id = resp
        .headers()
        .get("x-aitp-session-id")
        .ok_or_else(|| anyhow!("worker did not return x-aitp-session-id"))?
        .to_str()?
        .to_string();
    let ack_envelope: AitpEnvelope = resp.json().await?;
    let ack_payload: MutualHelloAckPayload = serde_json::from_value(ack_envelope.payload.clone())?;

    // ── MutualCommit ──────────────────────────────────────────────
    let cfg = make_cfg();
    let commit_payload = initiator.on_hello_ack(&ack_envelope, &ack_payload, &cfg)?;
    let commit_mid = Uuid::new_v4();
    let commit_ts = Timestamp::now();
    let payload_value = serde_json::to_value(&commit_payload)?;
    let digest =
        aitp::core::envelope_signing_digest(&commit_mid, commit_ts, key.aid(), &payload_value)?;
    let commit_envelope = AitpEnvelope {
        version: "aitp/0.1".into(),
        message_type: MessageType::MutualCommit,
        message_id: commit_mid,
        timestamp: commit_ts,
        sender: Sender {
            agent_id: key.aid().clone(),
        },
        payload: payload_value,
        signature: key.sign(&digest).into_string(),
    };
    let resp = client
        .post(worker_origin.join("/aitp/handshake/commit")?)
        .header("x-aitp-session-id", &session_id)
        .json(&commit_envelope)
        .send()
        .await?;
    let resp = resp.error_for_status().context("MutualCommit rejected")?;
    let commit_ack_envelope: AitpEnvelope = resp.json().await?;
    let commit_ack_payload: MutualCommitAckPayload =
        serde_json::from_value(commit_ack_envelope.payload.clone())?;

    let cfg = make_cfg();
    let planner_holds_tct =
        initiator.on_commit_ack(&commit_ack_envelope, &commit_ack_payload, &cfg)?;

    Ok(HandshakeOutcome {
        planner_key: key,
        tct: planner_holds_tct,
    })
}

/// Post `task` to the worker's `/work` endpoint, presenting `tct` in
/// the `X-AITP-TCT` header. Returns the decoded JSON response.
pub async fn delegate_task(
    worker_origin: &Url,
    tct: &Tct,
    task: &str,
) -> anyhow::Result<WorkResponse> {
    let client = reqwest::Client::new();
    let tct_header = serde_json::to_string(&TctEnvelope { tct: tct.clone() })?;
    let body = WorkRequest {
        task: task.to_string(),
    };
    let resp = client
        .post(worker_origin.join("/work")?)
        .header("x-aitp-tct", tct_header)
        .json(&body)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("/work returned {status}: {text}"));
    }
    let parsed: WorkResponse =
        serde_json::from_str(&text).context("decoding /work response")?;
    Ok(parsed)
}
