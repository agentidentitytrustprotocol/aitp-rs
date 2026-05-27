//! Tier-3 scenario: planner (plain code) handshakes with worker, then
//! delegates a task to the worker's LLM-driven `/work` endpoint.
//!
//! Skip-by-default. Requires `AITP_RUN_LLM_TESTS=1` plus at least one
//! provider key. See `tests/e2e-llm/README.md` for the gating story.

use aitp_e2e_llm_tests::{expand_seed, init_tracing, llm::Provider, load_env, planner, should_skip, worker};

#[tokio::test]
async fn planner_delegates_a_task_to_llm_worker_over_aitp() {
    load_env();
    init_tracing();

    if let Some(reason) = should_skip() {
        eprintln!("SKIPPED: {reason}");
        return;
    }

    let provider = Provider::from_env().expect("provider configured (skip gate already checked)");
    eprintln!("provider: {}", provider.label());

    // 1. Spawn the LLM-backed worker.
    let worker_seed = expand_seed("worker-seed-tier3-llm-handshake-demo");
    let worker = worker::spawn("aitp-worker", &worker_seed, provider)
        .await
        .expect("worker spawns");
    eprintln!("worker: AID  = {}", worker.aid);
    eprintln!("worker: origin = {}", worker.origin);

    // 2. Drive the four-message handshake from the planner side.
    //    `planner_port_for_manifest` is informational only — the
    //    planner never serves; the port goes into its manifest's
    //    `handshake_endpoint` URL so the worker can pin the identity.
    let planner_seed = expand_seed("planner-seed-tier3-llm-handshake-demo");
    let outcome = planner::handshake("aitp-planner", &planner_seed, 0, &worker.origin)
        .await
        .expect("handshake completes");

    eprintln!(
        "handshake: planner holds TCT issued by {} (grants={:?})",
        outcome.tct.issuer, outcome.tct.grants
    );

    // 3. Protocol assertions — these are the bits AITP guarantees,
    //    independent of what the LLM ends up saying.
    assert_eq!(
        &outcome.tct.issuer, &worker.aid,
        "TCT must be issued by the worker"
    );
    assert_eq!(
        outcome.tct.subject,
        *outcome.planner_key.aid(),
        "TCT subject must be the planner"
    );
    assert!(
        outcome.tct.grants.iter().any(|g| g == worker::WORK_CAPABILITY),
        "TCT must carry the {} grant",
        worker::WORK_CAPABILITY
    );

    // 4. Delegate a real task. The worker's LLM produces the answer
    //    after the worker's TCT verification passes.
    let task = "In one sentence, what is the purpose of a Trust Context Token in AITP?";
    let response = planner::delegate_task(&worker.origin, &outcome.tct, task)
        .await
        .expect("/work succeeds");

    eprintln!("worker answered ({}): {}", response.provider, response.answer);

    // 5. Output sanity — we cannot assert content of an LLM response,
    //    but we can require it to be non-trivial and provider-tagged.
    assert!(!response.answer.trim().is_empty(), "answer must not be empty");
    assert!(response.answer.len() > 10, "answer should be substantive");
    assert_eq!(response.worker_aid, worker.aid.to_string());

    worker.shutdown().await;
}
