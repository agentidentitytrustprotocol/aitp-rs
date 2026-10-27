//! One-way pinned-key admission (RFC-AITP-0002 §3.4, `feature:
//! aitp-pinned-admission`) and self-attestation verification
//! (RFC-AITP-0005 §5.3, `feature: aitp-self-attestation`).
//!
//! A fixture's verifier lives from its first admission step to the
//! runner's next `begin_fixture`, so a nonce consumed in one sequence
//! step stays consumed in the next (PLACEHOLDERS.md, pinned-admission
//! rows). The verifier is configured from the first step's inputs:
//! `self_aid`, `trust_store`, `max_outstanding_nonces`,
//! `presentation_rate_limit`, and `outstanding_challenges` seeded into
//! its nonce store.

use super::{checked, err, peek_token_aid_claim, trust_store_param, AdapterState};
use aitp::core::{base64url, Aid, Timestamp};
use aitp::handshake::admission::{
    AdmissionError, ChallengeRateLimiter, ChallengeSource, InMemoryNonceStore, IssuedNonce,
    NonceStore, PinnedAdmission, TokenBucketLimiter,
};
use serde_json::{json, Value};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

/// Source for a step that names none (TEST-NET-1).
const DEFAULT_SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

/// The fixture-scoped verifier.
pub(crate) struct AdmissionHarness {
    admission: PinnedAdmission,
}

/// Drive a future that never waits: every store the harness builds is
/// in memory, so each future is ready on its first poll.
pub(super) fn ready<F: Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => v,
        std::task::Poll::Pending => unreachable!("in-memory admission stores never wait"),
    }
}

/// The step's `now`, else the adapter clock (the runner pins it to the
/// reference clock).
fn step_now(state: &AdapterState, params: &Value) -> Timestamp {
    params
        .get("now")
        .and_then(Value::as_i64)
        .map(Timestamp)
        .unwrap_or_else(|| state.now())
}

fn step_source(params: &Value) -> Result<ChallengeSource, String> {
    match params.get("source") {
        None => Ok(ChallengeSource::ip(DEFAULT_SOURCE)),
        Some(Value::String(s)) => s
            .parse::<IpAddr>()
            .map(ChallengeSource::ip)
            .map_err(|e| format!("source `{s}`: {e}")),
        Some(other) => Err(format!("source must be an IP address string, got {other}")),
    }
}

fn build_harness(params: &Value, now: Timestamp) -> Result<AdmissionHarness, String> {
    let self_aid = params
        .get("self_aid")
        .and_then(Value::as_str)
        .ok_or("missing 'self_aid'")?;
    let self_aid = Aid::parse(self_aid).map_err(|e| format!("self_aid: {e}"))?;
    // The fixture's store is the whole store: absent means empty
    // (PLACEHOLDERS.md, `id-*` row), never a harness default.
    let trust = trust_store_param(params).unwrap_or_default();
    let nonces = Arc::new(match params.get("max_outstanding_nonces") {
        None => InMemoryNonceStore::default(),
        Some(v) => {
            let bound = v
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .filter(|&n| n > 0)
                .ok_or("max_outstanding_nonces must be a positive integer")?;
            InMemoryNonceStore::new(bound)
        }
    });
    for (i, ch) in params
        .get("outstanding_challenges")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        seed_challenge(nonces.as_ref(), ch, now)
            .map_err(|e| format!("outstanding_challenges[{i}]: {e}"))?;
    }
    let mut builder = PinnedAdmission::builder(self_aid, nonces, Arc::new(trust));
    if let Some(limit) = params.get("presentation_rate_limit") {
        builder = builder.presentation_rate_limiter(presentation_limiter(limit)?);
    }
    Ok(AdmissionHarness {
        admission: builder.build(),
    })
}

/// `{per_source, window_seconds}`: a bucket of `per_source` tokens that
/// refills over `window_seconds`.
fn presentation_limiter(limit: &Value) -> Result<Arc<dyn ChallengeRateLimiter>, String> {
    let per_source = limit
        .get("per_source")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|&n| n > 0)
        .ok_or("presentation_rate_limit.per_source must be a positive integer")?;
    let window = limit
        .get("window_seconds")
        .and_then(Value::as_u64)
        .filter(|&n| n > 0)
        .ok_or("presentation_rate_limit.window_seconds must be a positive integer")?;
    Ok(Arc::new(TokenBucketLimiter::new(
        per_source,
        f64::from(per_source) / window as f64,
    )))
}

fn seed_challenge(store: &InMemoryNonceStore, ch: &Value, now: Timestamp) -> Result<(), String> {
    let pop_nonce = ch
        .get("pop_nonce")
        .and_then(Value::as_str)
        .ok_or("missing pop_nonce")?;
    // A seeded nonce of the wrong length cannot be issued; it is the
    // presentation's problem (`id-014`), so seed nothing.
    let Ok(nonce) = base64url::decode_strict_exact::<{ aitp::handshake::POP_NONCE_LEN }>(pop_nonce)
    else {
        return Ok(());
    };
    let verifier = ch
        .get("verifier_aid")
        .and_then(Value::as_str)
        .ok_or("missing verifier_aid")?;
    let verifier = Aid::parse(verifier).map_err(|e| format!("verifier_aid: {e}"))?;
    let expires_at = ch
        .get("expires_at")
        .and_then(Value::as_i64)
        .map(Timestamp)
        .ok_or("missing expires_at")?;
    // Issued no later than it expires, so an already-expired challenge
    // (`id-020`) is recorded and then found expired.
    let issued_at = Timestamp(now.0.min(expires_at.0));
    let rec = IssuedNonce::new(nonce, verifier, "fixture", issued_at, expires_at);
    ready(store.issue(&rec)).map_err(|e| e.to_string())
}

fn harness<'s>(
    state: &'s mut AdapterState,
    params: &Value,
    now: Timestamp,
) -> Result<&'s AdmissionHarness, String> {
    if state.admission.is_none() {
        state.admission = Some(build_harness(params, now)?);
    }
    Ok(state.admission.as_ref().expect("set above"))
}

fn admission_err(id: &str, e: &AdmissionError) -> Value {
    // A wire code wins: `CHALLENGE_REFUSED` (id-016) has one, carried in
    // a 503 over HTTP. A rate limit has none (RFC-AITP-0009 §3.1):
    // refused below the protocol layer, so report the HTTP 429.
    match (e.code(), e.http_status()) {
        (Some(code), _) => err(id, code, &e.to_string()),
        (None, Some(status)) => {
            json!({"id": id, "ok": false, "http_status": status, "message": e.to_string()})
        }
        (None, None) => err(id, "INTERNAL_ERROR", &e.to_string()),
    }
}

/// `verify_identity_presentation`: admit one `identity_presentation`
/// envelope in the §3.4 check order.
pub(crate) fn verify_identity_presentation_op(
    state: &mut AdapterState,
    id: &str,
    params: Value,
) -> Value {
    let now = step_now(state, &params);
    let source = match step_source(&params) {
        Ok(s) => s,
        Err(e) => return err(id, "INVALID_REQUEST", &e),
    };
    let Some(envelope) = params.get("envelope") else {
        return err(id, "INVALID_REQUEST", "missing 'envelope'");
    };
    let h = match harness(state, &params, now) {
        Ok(h) => h,
        Err(e) => return err(id, "INVALID_REQUEST", &e),
    };
    match ready(h.admission.admit_wire_at(&checked(envelope), &source, now)) {
        Ok(a) => json!({"id": id, "ok": true, "result": {
            "admitted": true,
            "subject": a.subject,
            "agent_id": a.key.aid.to_string(),
            "message_id": a.message_id.to_string(),
        }}),
        Err(e) => admission_err(id, &e),
    }
}

/// `issue_presentation_challenge`: issue a challenge to the step's
/// `source`. The runner captures `result.pop_nonce` as
/// `__ISSUED_NONCE_<n>__`.
pub(crate) fn issue_presentation_challenge_op(
    state: &mut AdapterState,
    id: &str,
    params: Value,
) -> Value {
    let now = step_now(state, &params);
    let source = match step_source(&params) {
        Ok(s) => s,
        Err(e) => return err(id, "INVALID_REQUEST", &e),
    };
    let h = match harness(state, &params, now) {
        Ok(h) => h,
        Err(e) => return err(id, "INVALID_REQUEST", &e),
    };
    match ready(h.admission.challenge_at(&source, now)) {
        Ok(c) => json!({"id": id, "ok": true, "result": {
            "pop_nonce": c.pop_nonce,
            "verifier_aid": c.verifier_aid.to_string(),
            "expires_at": c.expires_at.0,
        }}),
        Err(e) => admission_err(id, &e),
    }
}

/// `verify_attestation`: relying-party verification of a
/// self-attestation (RFC-AITP-0005 §5.3). Not a grant context. The
/// issuer is the token's `iss`, and must be in the relying party's
/// `trust_store` (the §7.3 exception: its own record of keys trusted at
/// `iat`).
pub(crate) fn verify_attestation_op(state: &AdapterState, id: &str, params: Value) -> Value {
    let Some(token) = params.get("tct_token").and_then(Value::as_str) else {
        return err(
            id,
            "INVALID_REQUEST",
            "missing 'tct_token' (compact JWS string)",
        );
    };
    let Some(statement_key) = params.get("expected_ext_key").and_then(Value::as_str) else {
        return err(id, "INVALID_REQUEST", "missing 'expected_ext_key'");
    };
    let Some(issuer) = peek_token_aid_claim(token, "iss") else {
        return err(id, "TCT_SIGNATURE_INVALID", "no decodable `iss` claim");
    };
    let trusted = match trust_store_param(&params) {
        Some(store) => aitp::crypto::AitpVerifyingKey::from_aid(&issuer)
            .map(|k| aitp::handshake::PinnedKeyStore::is_trusted(&store, &k))
            .unwrap_or(false),
        None => false,
    };
    if !trusted {
        return err(
            id,
            "TCT_SIGNATURE_INVALID",
            "attestation issuer is not in trust_store",
        );
    }
    let now = step_now(state, &params);
    let waive = params
        .get("waive_manifest_cap")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let manifest_expires_at = params
        .get("issuer_manifest")
        .and_then(|m| m.get("expires_at"))
        .and_then(Value::as_i64)
        .map(Timestamp);
    let builder = aitp::tct::AttestationVerifyContext::builder(&issuer, statement_key, now)
        .accept_unchecked_revocation_dangerous();
    let builder = match (manifest_expires_at, waive) {
        (Some(exp), _) => builder.issuer_manifest_expires_at(exp),
        (None, true) => builder.waive_manifest_cap_issuer_has_no_manifest(),
        (None, false) => {
            return err(
                id,
                "INVALID_REQUEST",
                "neither issuer_manifest nor waive_manifest_cap: the Manifest-cap decision is mandatory",
            )
        }
    };
    let ctx = match builder.build() {
        Ok(c) => c,
        Err(e) => return err(id, "INTERNAL_ERROR", &e.to_string()),
    };
    match aitp::tct::verify_attestation(token, &ctx) {
        Ok(v) => json!({"id": id, "ok": true, "result": {
            "verified": true,
            "statement": v.statement,
        }}),
        Err(e) => err(id, &super::tct_error_code(&e), &e.to_string()),
    }
}
