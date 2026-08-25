//! Tier-3 scenario: a published revocation snapshot actually stops a
//! working delegation.
//!
//! This is the scenario the 0.5.0 signing-input change needs at tier 3.
//! The revocation snapshot is one of the two artifacts whose JCS signing
//! input moved from the transport-wrapped form (`{"revocation_list": …}`)
//! to the inner artifact body. Tier-1 KATs pin the bytes; the
//! cross-implementation `xcheck` job proves Rust and Python agree on
//! them. What neither covers is the full loop *in situ*: a server
//! signing a snapshot on demand, serving it over a socket, and a peer
//! fetching, verifying, and acting on it.
//!
//! Sequence:
//!   1. handshake — planner ends up holding a TCT the worker issued
//!   2. fetch + verify the worker's (empty) revocation snapshot
//!   3. delegate a task — succeeds (this leg calls the LLM)
//!   4. worker revokes the planner's TCT `jti`
//!   5. fetch + verify the snapshot again — now lists that `jti`
//!   6. delegate again — refused with 403
//!
//! Steps 2 and 5 are the ones that would have failed before 0.5.0 had
//! the two sides disagreed on the signing input; step 6 proves the
//! snapshot is load-bearing rather than decorative.
//!
//! Skip-by-default, same gate as every other file in this package.

use aitp_e2e_llm_tests::{
    expand_seed, init_tracing, llm::Provider, load_env, planner, should_skip, worker,
};

#[tokio::test]
async fn published_revocation_snapshot_stops_a_working_delegation() {
    load_env();
    init_tracing();

    if let Some(reason) = should_skip() {
        eprintln!("SKIPPED: {reason}");
        return;
    }

    let provider = Provider::from_env().expect("provider configured (skip gate already checked)");

    // Distinct seeds from the other scenario so the two tests can run
    // concurrently without sharing an AID (and so a failure names which
    // scenario produced it).
    let worker_seed = expand_seed("worker-seed-tier3-revocation-scenario");
    let worker = worker::spawn("aitp-worker-rev", &worker_seed, provider)
        .await
        .expect("worker spawns");

    let planner_seed = expand_seed("planner-seed-tier3-revocation-scenario");
    let outcome = planner::handshake("aitp-planner-rev", &planner_seed, 0, &worker.origin)
        .await
        .expect("handshake completes");
    let jti = outcome.tct.claims.jti;
    eprintln!("planner holds TCT jti={jti}");

    // ── 2. The snapshot verifies before anything is revoked ──────────
    // A snapshot signed over the wrapped form would fail here, at the
    // first `verify_revocation_list` after a real HTTP round-trip.
    let before = planner::fetch_revocation_snapshot(&worker.origin, &worker.aid)
        .await
        .expect("empty revocation snapshot must verify under the worker's AID");
    assert!(
        before.revocation_list.entries.is_empty(),
        "nothing has been revoked yet, got {:?}",
        before.revocation_list.entries
    );
    assert_eq!(
        before.revocation_list.issuer, worker.aid,
        "snapshot issuer must be the worker"
    );

    // ── 3. Delegation works while the TCT is live ────────────────────
    let task = "Reply with exactly one short sentence about delegated authority.";
    let response = planner::delegate_task(&worker.origin, &outcome.tct.token, task)
        .await
        .expect("/work succeeds while the TCT is live");
    assert!(
        !response.answer.trim().is_empty(),
        "answer must not be empty"
    );
    eprintln!("pre-revocation answer: {}", response.answer);

    // ── 4. Revoke it ─────────────────────────────────────────────────
    worker.revoke(jti);

    // ── 5. The re-signed snapshot still verifies, and now lists it ───
    // `current()` re-signs on every fetch, so this is a *different* set
    // of bytes from step 2 going through the same signing input.
    let after = planner::fetch_revocation_snapshot(&worker.origin, &worker.aid)
        .await
        .expect("post-revocation snapshot must verify under the worker's AID");
    assert_eq!(
        after.revocation_list.entries.len(),
        1,
        "snapshot must list exactly the revoked jti"
    );
    assert_eq!(after.revocation_list.entries[0].jti, jti);

    // ── 6. And the worker now refuses the same TCT ───────────────────
    // Note this rejection happens during TCT verification, *before* the
    // LLM call — so the negative leg costs no API credits.
    let (status, body) = planner::try_delegate_task(&worker.origin, &outcome.tct.token, task)
        .await
        .expect("request reaches the worker");
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "revoked TCT must be refused, got {status}: {body}"
    );
    eprintln!("post-revocation refusal: {status} {body}");

    worker.shutdown().await;
}

/// A TCT the worker never issued must be refused outright — guards the
/// issuer-pinning branch in `verify_work_tct`, which is otherwise only
/// ever taken on the happy path.
#[tokio::test]
async fn work_endpoint_refuses_a_tct_from_an_unknown_issuer() {
    load_env();
    init_tracing();

    if let Some(reason) = should_skip() {
        eprintln!("SKIPPED: {reason}");
        return;
    }

    let provider = Provider::from_env().expect("provider configured (skip gate already checked)");
    let worker_seed = expand_seed("worker-seed-tier3-foreign-issuer");
    let worker = worker::spawn("aitp-worker-foreign", &worker_seed, provider)
        .await
        .expect("worker spawns");

    // Mint a structurally valid TCT under a key the worker has never
    // seen. It carries the right grant and a live expiry — the *only*
    // thing wrong with it is the issuer.
    use aitp::core::Timestamp;
    use aitp::crypto::AitpSigningKey;
    use aitp::tct::TctBuilder;
    let stranger = AitpSigningKey::from_seed(&expand_seed("a-key-the-worker-never-saw"));
    let holder = AitpSigningKey::from_seed(&expand_seed("some-holder-key-for-foreign-tct"));
    let forged = TctBuilder::new(&stranger)
        .subject(holder.aid().clone())
        .audience(holder.aid().clone())
        .grants([worker::WORK_CAPABILITY])
        .ttl_secs(3600)
        .subject_pubkey(holder.verifying_key())
        .issued_at(Timestamp::now())
        .build()
        .expect("foreign TCT builds");

    let (status, body) =
        planner::try_delegate_task(&worker.origin, &forged.token, "should never be answered")
            .await
            .expect("request reaches the worker");
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "a TCT from an unknown issuer must be refused, got {status}: {body}"
    );

    worker.shutdown().await;
}
