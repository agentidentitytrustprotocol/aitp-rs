//! Planner side: drives the four-message handshake from the initiator's
//! point of view, then invokes the worker's `/work` endpoint with the
//! resulting TCT.
//!
//! Mirrors `examples/two-agents/src/bin/agent-a.rs`: the whole handshake
//! is one call to [`run_initiator_handshake`]. An earlier revision drove
//! `Initiator::start` / `on_hello_ack` / `on_commit_ack` by hand and
//! hand-signed each envelope; that duplicated the facade's job and went
//! stale the moment the facade changed. See `worker.rs`'s module docs.

use std::time::Duration;

use aitp::core::base64url;
use aitp::core::{Aid, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::facade::{run_initiator_handshake, IdentityMode, InitiatorConfig, TrustMode};
use aitp::handshake::StaticPinnedKeyStore;
use aitp::manifest::Manifest;
use aitp::tct::{
    verify_revocation_list, RevocationListEnvelope, VerifiedTct, VerifyRevocationListContext,
};
use aitp::transport::ManifestFetcher;
use aitp_example_two_agents::build_demo_manifest;
use anyhow::{anyhow, Context};
use url::Url;

use crate::worker::{WorkRequest, WorkResponse, WORK_CAPABILITY};

/// Outcome of a successful handshake. The TCT was issued by the worker
/// **for** this planner — the planner holds it and presents it on every
/// subsequent capability invocation.
pub struct HandshakeOutcome {
    pub planner_key: AitpSigningKey,
    pub tct: VerifiedTct,
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
    // The planner offers the same capability the worker requests, so the
    // mutual intersection is non-empty on both sides.
    let manifest = build_demo_manifest(
        &key,
        display_name,
        planner_port_for_manifest,
        &[WORK_CAPABILITY],
    );

    // Discover the worker's Manifest (this doubles as a readiness poll).
    // The verified Manifest's pinned public key becomes our trust anchor
    // — TOFU, adequate for a local test, not for production.
    let worker_manifest = wait_for_worker(worker_origin).await?;
    let worker_pinned_key: [u8; 32] = worker_manifest
        .identity_hint
        .public_key
        .as_deref()
        .ok_or_else(|| anyhow!("worker manifest has no pinned public_key"))
        .and_then(|s| {
            base64url::decode_strict_exact::<32>(s)
                .map_err(|_| anyhow!("worker manifest pinned key is not 32 base64url bytes"))
        })?;
    let store = StaticPinnedKeyStore::new(vec![worker_pinned_key]);

    let session = run_initiator_handshake(InitiatorConfig::new(
        &key,
        &manifest,
        worker_origin.clone(),
        TrustMode::PinnedKeys(&store),
        IdentityMode::PinnedKey {
            subject: display_name.into(),
        },
        vec![WORK_CAPABILITY.into()],
    ))
    .await
    .context("initiator handshake")?;

    Ok(HandshakeOutcome {
        planner_key: key,
        tct: session.held_tct,
    })
}

/// Poll the worker's Manifest endpoint until it comes up (or time out).
async fn wait_for_worker(worker_origin: &Url) -> anyhow::Result<Manifest> {
    let fetcher = ManifestFetcher::new();
    for attempt in 0..40 {
        match fetcher.fetch(worker_origin).await {
            Ok(manifest) => return Ok(manifest),
            Err(_) if attempt < 39 => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => return Err(anyhow!("worker never came up at {worker_origin}: {e}")),
        }
    }
    unreachable!("loop returns on the final attempt")
}

/// Fetch the worker's published revocation snapshot and verify it under
/// the worker's AID.
///
/// This is the tier-3 exercise of the artifact whose JCS signing input
/// changed in 0.5.0: the bytes are produced by the server's
/// `sign_revocation_list` and consumed here by `verify_revocation_list`
/// after a real HTTP round-trip and a JSON re-serialization — so a
/// signing input that survives only in-process would not survive this.
pub async fn fetch_revocation_snapshot(
    worker_origin: &Url,
    worker_aid: &Aid,
) -> anyhow::Result<RevocationListEnvelope> {
    let client = reqwest::Client::new();
    let url = worker_origin.join("/.well-known/aitp-revocation-list")?;
    let resp = client.get(url).send().await?.error_for_status()?;
    let envelope: RevocationListEnvelope =
        resp.json().await.context("decoding revocation snapshot")?;
    verify_revocation_list(
        &envelope,
        &VerifyRevocationListContext::new(worker_aid, Timestamp::now()),
    )
    .map_err(|e| anyhow!("served revocation snapshot failed verification: {e}"))?;
    Ok(envelope)
}

/// Post `task` to the worker's `/work` endpoint, presenting `token` in
/// the `X-AITP-TCT` header. On the wire the TCT is the opaque compact
/// JWS string, forwarded as-is.
pub async fn delegate_task(
    worker_origin: &Url,
    token: &str,
    task: &str,
) -> anyhow::Result<WorkResponse> {
    let (status, text) = post_work(worker_origin, token, task).await?;
    if !status.is_success() {
        return Err(anyhow!("/work returned {status}: {text}"));
    }
    serde_json::from_str(&text).context("decoding /work response")
}

/// Like [`delegate_task`] but returns the raw status/body instead of
/// erroring on a rejection — for the negative paths (revoked TCT,
/// missing header) where the *refusal* is what's under test.
pub async fn try_delegate_task(
    worker_origin: &Url,
    token: &str,
    task: &str,
) -> anyhow::Result<(reqwest::StatusCode, String)> {
    post_work(worker_origin, token, task).await
}

async fn post_work(
    worker_origin: &Url,
    token: &str,
    task: &str,
) -> anyhow::Result<(reqwest::StatusCode, String)> {
    let client = reqwest::Client::new();
    let body = WorkRequest {
        task: task.to_string(),
    };
    let resp = client
        .post(worker_origin.join("/work")?)
        .header("x-aitp-tct", token)
        .json(&body)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    Ok((status, text))
}
