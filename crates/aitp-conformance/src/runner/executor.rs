//! Fixture runner.

use crate::adapter::{Adapter, OpResult};
use crate::fixture::{
    Fixture, FixtureExpected, FixtureInputVariant, FixtureStatus, RunnerContext, REFERENCE_NOW,
};
use std::collections::HashSet;
use std::time::Instant;

/// Result of running one fixture.
#[derive(Debug, Clone)]
pub enum FixtureResult {
    /// All assertions passed.
    Pass {
        /// Fixture ID.
        id: String,
        /// Wall-clock duration of the run.
        duration_ms: u64,
    },
    /// One or more assertions failed.
    Fail {
        /// Fixture ID.
        id: String,
        /// Why the fixture failed.
        reason: String,
        /// Wall-clock duration.
        duration_ms: u64,
    },
    /// Fixture skipped because the adapter doesn't support a required op
    /// or feature.
    Skip {
        /// Fixture ID.
        id: String,
        /// Reason for skipping.
        reason: String,
    },
}

/// Executes fixtures against an adapter.
pub struct Runner<A: Adapter> {
    adapter: A,
    /// Per-run substitution context — handles `__UPPER_SNAKE__`
    /// placeholders defined in the spec's
    /// `schemas/conformance/PLACEHOLDERS.md`.
    ctx: RunnerContext,
    /// When `true` (the default), the runner pins the adapter's
    /// notion of "now" to [`REFERENCE_NOW`] before every fixture by
    /// invoking `set_clock`. This matches the convention used to
    /// mint the conformance fixtures: every `expires_at` /
    /// `issued_at` in the fixtures was computed against the same
    /// reference clock, so an adapter using wall time would
    /// spuriously report `EXPIRED` errors. Adapters that don't
    /// support `set_clock` continue past the pre-init silently.
    pin_clock: bool,
    /// Feature flags this runner has been told the implementation
    /// supports. Used by [`Self::should_skip_for_v0_1`] to decide
    /// whether a non-core fixture runs (when its `feature` is in
    /// this set) or skips. An empty set means strict v0.1: only
    /// `status: core` fixtures run.
    enabled_features: HashSet<String>,
    /// Whether `set_features` has been broadcast to the adapter
    /// for the current `enabled_features` set. Flipped to `false`
    /// when [`Self::with_feature`] adds a new entry.
    features_announced: bool,
}

impl<A: Adapter> Runner<A> {
    /// Construct a runner around an adapter. Defaults to:
    ///
    /// - pinning the adapter clock to [`REFERENCE_NOW`] before
    ///   every fixture, and
    /// - strict v0.1 mode (no feature flags enabled, so non-core
    ///   fixtures SKIP automatically).
    pub fn new(adapter: A) -> Self {
        Self {
            adapter,
            ctx: RunnerContext::new(),
            pin_clock: true,
            enabled_features: HashSet::new(),
            features_announced: false,
        }
    }

    /// Disable the auto `set_clock` precondition. Use only when an
    /// adapter is being driven outside the conformance fixture
    /// suite (the in-process adapter's unit tests, for instance).
    pub fn without_clock_pinning(mut self) -> Self {
        self.pin_clock = false;
        self
    }

    /// Enable a feature flag so fixtures matching it run instead
    /// of skipping. Examples: `experimental-multihop-delegation`,
    /// `experimental-session-bundle`, `experimental-renewal`.
    /// The adapter is also notified via the `set_features` op so
    /// it can flip RFC-0011 (multi-hop) and similar post-v0.1
    /// behaviors on. Call before `run()` — later calls don't
    /// re-broadcast.
    pub fn with_feature(mut self, feature: impl Into<String>) -> Self {
        self.enabled_features.insert(feature.into());
        self.features_announced = false;
        self
    }

    /// Return `Some(reason)` if the fixture should be SKIP per
    /// metadata: non-core status whose `feature` isn't in
    /// [`Self::enabled_features`].
    fn should_skip_for_v0_1(&self, fixture: &Fixture) -> Option<String> {
        // Negative-feature rule: a core fixture asserting a
        // v0.1-strict rejection (e.g. del-004 expects
        // `DELEGATION_MULTIHOP_NOT_SUPPORTED`) is no longer
        // applicable once the opposing experimental feature is
        // opted in. Skip rather than fail.
        if let Some(expected) = fixture.expected.as_ref() {
            if let Some(code) = expected.error_code.as_deref() {
                if let Some(feature) = negated_by_feature(code) {
                    if self.enabled_features.contains(feature) {
                        return Some(format!(
                            "feature `{feature}` enabled — assertion `{code}` {FEATURE_NEGATION_MARKER}"
                        ));
                    }
                }
            }
        }
        if matches!(fixture.status, FixtureStatus::Core) {
            return None;
        }
        if let Some(feature) = &fixture.feature {
            if self.enabled_features.contains(feature) {
                return None;
            }
            return Some(format!(
                "non-core fixture (status={:?}); requires feature `{feature}`",
                fixture.status
            ));
        }
        Some(format!(
            "non-core fixture (status={:?}); no feature flag declared",
            fixture.status
        ))
    }

    /// Run a single fixture.
    pub fn run(&mut self, fixture: &Fixture) -> FixtureResult {
        // SKIP non-core fixtures whose feature flag isn't enabled.
        // This is the v0.1-strict default — bundle-* and del-mh-*
        // fixtures land as SKIP unless the operator opts into
        // `experimental-session-bundle` / `experimental-multihop-delegation`.
        if let Some(reason) = self.should_skip_for_v0_1(fixture) {
            return FixtureResult::Skip {
                id: fixture.id.clone(),
                reason,
            };
        }
        // Announce the enabled feature set to the adapter so it
        // can flip post-v0.1 RFC behaviors on (multi-hop, bundles,
        // …). Best-effort: an adapter that doesn't implement
        // `set_features` returns `OP_NOT_SUPPORTED` and we continue
        // — the runner-side skip logic above already handled the
        // metadata pass. Broadcasts once per `with_feature` change.
        if !self.features_announced {
            let features: Vec<&String> = self.enabled_features.iter().collect();
            let _ = self
                .adapter
                .execute("set_features", serde_json::json!({ "features": features }));
            self.features_announced = true;
        }
        let started = Instant::now();
        // Pin the adapter's clock to the fixture-set reference
        // before any other op runs. This is best-effort: an adapter
        // that doesn't expose `set_clock` returns `OP_NOT_SUPPORTED`
        // and we proceed against wall time (the fixture is
        // responsible for its own time references).
        if self.pin_clock {
            // Adapter expects `now_unix_secs`; spec PLACEHOLDERS uses
            // `now`. Send both keys so either calling convention
            // works. Surface non-OK results via tracing so an
            // adapter that buggily accepts the call without moving
            // its clock leaves a breadcrumb — every "expired"
            // fixture would otherwise fail mysteriously.
            match self.adapter.execute(
                "set_clock",
                serde_json::json!({
                    "now_unix_secs": REFERENCE_NOW,
                    "now": REFERENCE_NOW,
                }),
            ) {
                Ok(crate::adapter::OpResult::Ok { .. }) => {}
                Ok(crate::adapter::OpResult::Err {
                    error_code,
                    message,
                    ..
                }) => {
                    tracing::debug!(
                        fixture = %fixture.id,
                        error_code = %error_code,
                        message = %message,
                        "set_clock precondition rejected by adapter; running against wall time"
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        fixture = %fixture.id,
                        error = %e,
                        "set_clock precondition failed; running against wall time"
                    );
                }
            }
        }
        // Apply preconditions if any. Schema is permissive — the
        // preconditions block is JSON-shaped, so we forward each top-level
        // key as an op invocation. Adapters that don't support the op
        // simply emit `OP_NOT_SUPPORTED`, which we treat as a skip.
        if let Err(reason) = self.apply_preconditions(&fixture.preconditions) {
            return FixtureResult::Skip {
                id: fixture.id.clone(),
                reason,
            };
        }

        // Pin the adapter's reference clock to the substitution clock
        // (PLACEHOLDERS.md: `__NOW__` = 1711900000) so time-relative
        // checks are deterministic. Tier-D op — adapters without it
        // (or that reject it) just run on their own clock, matching
        // the pre-v0.2 behavior.
        let _ = self.adapter.execute(
            "set_clock",
            serde_json::json!({ "now_unix_secs": self.ctx.now }),
        );

        // Tell the adapter a new fixture starts, so state a sequence
        // carries across its steps (a pinned-admission verifier's
        // consumed nonces and recorded `message_id`s) does not leak
        // between fixtures. Tier-D and optional: an adapter without it
        // keeps its state, as before.
        let _ = self.adapter.execute("begin_fixture", serde_json::json!({}));

        // Reset per-fixture substitution state (nonce counter +
        // last_nonce) before walking the input.
        self.ctx.reset_per_fixture();

        let outcome = match &fixture.input.variant {
            FixtureInputVariant::Single(params) => {
                let mut params = params.clone();
                apply_receiver_policy_default(&fixture.id, &mut params);
                self.ctx.substitute(&mut params);
                self.run_single(&params, fixture.expected.as_ref())
            }
            FixtureInputVariant::Sequence { sequence, context } => {
                let mut context = context.clone();
                // Substitute placeholders in the sibling context
                // BEFORE merging into each step — otherwise step
                // ordering for nonce-counter generation would
                // depend on context-vs-step order.
                let mut context_value = serde_json::Value::Object(context.clone());
                self.ctx.substitute(&mut context_value);
                context = match context_value {
                    serde_json::Value::Object(m) => m,
                    _ => serde_json::Map::new(),
                };
                self.run_sequence(sequence, &context, fixture.input.operation.as_deref())
            }
        };

        let duration_ms = started.elapsed().as_millis() as u64;
        // spec #77: a placeholder the runner could not mint reached the
        // adapter as a sentinel, so an outcome that matched was not
        // evidence of the check the fixture names. FAIL, never PASS.
        let unminted = self.ctx.unminted();
        let outcome = match outcome {
            Err(StepError::Skip(_)) => outcome,
            _ if !unminted.is_empty() => {
                let mut reason = format!(
                    "unminted placeholders: {} (the runner cannot mint them, so the fixture's check was not exercised)",
                    unminted.join(", ")
                );
                if let Err(StepError::Fail(r)) = outcome {
                    reason.push_str("; also: ");
                    reason.push_str(&r);
                }
                Err(StepError::Fail(reason))
            }
            _ => outcome,
        };
        match outcome {
            Ok(()) => FixtureResult::Pass {
                id: fixture.id.clone(),
                duration_ms,
            },
            Err(StepError::Skip(reason)) => FixtureResult::Skip {
                id: fixture.id.clone(),
                reason,
            },
            Err(StepError::Fail(reason)) => FixtureResult::Fail {
                id: fixture.id.clone(),
                reason,
                duration_ms,
            },
        }
    }

    /// Send one op request to the adapter. Every request goes through
    /// here, so none carries a `*_claims` minting companion at any
    /// depth (PLACEHOLDERS.md: companions are minting inputs, never
    /// wire bytes, and runners ignore them at the `input` level). A
    /// strict verifier would rightly answer `UNKNOWN_FIELD` to one.
    fn execute(
        &mut self,
        op: &str,
        mut params: serde_json::Value,
    ) -> Result<OpResult, crate::adapter::AdapterError> {
        crate::fixture::strip_claims_companions(&mut params);
        self.adapter.execute(op, params)
    }

    fn apply_preconditions(&mut self, preconditions: &serde_json::Value) -> Result<(), String> {
        let Some(map) = preconditions.as_object() else {
            return Ok(());
        };
        for (op, params) in map {
            match self.execute(op, params.clone()) {
                Ok(OpResult::Ok { ok, .. }) if ok => continue,
                Ok(OpResult::Ok { .. }) => {
                    return Err(format!("precondition {op} returned ok=false"))
                }
                Ok(OpResult::Err {
                    error_code,
                    message,
                    ..
                }) => return Err(format!("precondition {op} failed: {error_code} {message}")),
                Err(e) => return Err(format!("precondition {op}: {e}")),
            }
        }
        Ok(())
    }

    fn run_single(
        &mut self,
        params: &serde_json::Value,
        expected: Option<&FixtureExpected>,
    ) -> Result<(), StepError> {
        let op = params
            .get("operation")
            .and_then(|v| v.as_str())
            .ok_or_else(|| StepError::Fail("input.operation missing".into()))?;
        let mut op_params = params.clone();
        if let Some(map) = op_params.as_object_mut() {
            map.remove("operation");
        }
        let result = self.execute(op, op_params.clone()).map_err(|e| match e {
            crate::adapter::AdapterError::OpNotSupported(_) => {
                StepError::Skip(format!("adapter does not support op {op}"))
            }
            other => StepError::Fail(other.to_string()),
        })?;
        if let Some(expected) = expected {
            assert_outcome(&result, expected)?;
            assert_renewal(&result, expected, &op_params)?;
        }
        Ok(())
    }

    /// Run each step, substituting it just before it executes: a step
    /// may carry a value an earlier step produced at run time
    /// (`__ISSUED_NONCE_<n>__`, the `pop_nonce` of the n-th successful
    /// `issue_presentation_challenge`), and anything minted over it
    /// (`__VALID_PINNED_PROOF__`, the envelope signature) must cover
    /// that value. Substitution is otherwise in step order, as before.
    fn run_sequence(
        &mut self,
        sequence: &[crate::fixture::SequenceStep],
        context: &serde_json::Map<String, serde_json::Value>,
        parent_op: Option<&str>,
    ) -> Result<(), StepError> {
        let mut issued_nonces: Vec<String> = Vec::new();
        for step in sequence {
            let mut step = step.clone();
            // Merge context fields under the step's params, with step
            // values taking precedence on any collision.
            if let Some(step_map) = step.params.as_object_mut() {
                for (k, v) in context.iter() {
                    step_map.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
            substitute_issued_nonces(&mut step.params, &issued_nonces);
            self.ctx.substitute(&mut step.params);
            // RFC-AITP fixture protocol: a step's `operation` field
            // takes precedence; if absent, it inherits from the
            // input-level `operation` field (e.g. `env-004`'s replay
            // sequence has the op at the parent level).
            let op_owned: Option<String> = step
                .params
                .get("operation")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .or_else(|| parent_op.map(str::to_string));
            let op = op_owned
                .as_deref()
                .ok_or_else(|| StepError::Fail(format!("step {}: operation missing", step.step)))?;
            let mut params = step.params.clone();
            if let Some(map) = params.as_object_mut() {
                map.remove("operation");
            }
            let result = self.execute(op, params.clone()).map_err(|e| match e {
                crate::adapter::AdapterError::OpNotSupported(_) => {
                    StepError::Skip(format!("adapter does not support op {op}"))
                }
                other => StepError::Fail(format!("step {}: {other}", step.step)),
            })?;
            if op == "issue_presentation_challenge" {
                if let OpResult::Ok { ok: true, result } = &result {
                    let nonce = result.get("pop_nonce").and_then(|v| v.as_str());
                    let Some(nonce) = nonce else {
                        return Err(StepError::Fail(format!(
                            "step {}: issue_presentation_challenge succeeded without result.pop_nonce",
                            step.step
                        )));
                    };
                    issued_nonces.push(nonce.to_string());
                }
            }
            assert_outcome(&result, &step.expected).map_err(|e| e.in_step(step.step))?;
            assert_renewal(&result, &step.expected, &params).map_err(|e| e.in_step(step.step))?;
        }
        Ok(())
    }
}

/// An `mh-*` `verify_handshake_payload` fixture runs RFC-AITP-0004 §5.1
/// through step 8, so the receiver's `accepted_identity_types` is the
/// stated `self_accepted_identity_types` or, when absent, the default
/// `["oidc"]`; the runner adds no types of its own. An `id-*` fixture
/// stops at step 6 and gets no policy (README, "Receiver policy inputs").
fn apply_receiver_policy_default(fixture_id: &str, params: &mut serde_json::Value) {
    if !fixture_id.starts_with("mh-") {
        return;
    }
    let Some(map) = params.as_object_mut() else {
        return;
    };
    if map.get("operation").and_then(|v| v.as_str()) == Some("verify_handshake_payload") {
        map.entry("self_accepted_identity_types")
            .or_insert_with(|| serde_json::json!(["oidc"]));
    }
}

/// Replace each `__ISSUED_NONCE_<n>__` string (1-based) whose nonce
/// has been captured. One not yet captured is left for the placeholder
/// pass, which records it as unminted.
fn substitute_issued_nonces(value: &mut serde_json::Value, issued: &[String]) {
    match value {
        serde_json::Value::String(s) => {
            let n = s
                .strip_prefix("__ISSUED_NONCE_")
                .and_then(|r| r.strip_suffix("__"))
                .and_then(|n| n.parse::<usize>().ok());
            if let Some(nonce) = n.and_then(|n| n.checked_sub(1)).and_then(|i| issued.get(i)) {
                *s = nonce.clone();
            }
        }
        serde_json::Value::Array(items) => {
            items
                .iter_mut()
                .for_each(|v| substitute_issued_nonces(v, issued));
        }
        serde_json::Value::Object(map) => {
            map.values_mut()
                .for_each(|v| substitute_issued_nonces(v, issued));
        }
        _ => {}
    }
}

/// How a failure was reported, for messages: the error code, else the
/// HTTP status.
fn describe_failure(error_code: &str, http_status: Option<u16>) -> String {
    match (error_code.is_empty(), http_status) {
        (false, _) => format!("error {error_code}"),
        (true, Some(status)) => format!("HTTP {status} with no error code"),
        (true, None) => "an error with no code".into(),
    }
}

fn assert_outcome(actual: &OpResult, expected: &FixtureExpected) -> Result<(), StepError> {
    match (expected.outcome.as_str(), actual) {
        ("success", OpResult::Ok { ok, .. }) if *ok => {}
        (
            "success",
            OpResult::Err {
                error_code,
                http_status,
                ..
            },
        ) => {
            return Err(StepError::Fail(format!(
                "expected success, got {}",
                describe_failure(error_code, *http_status)
            )))
        }
        (
            "failure",
            OpResult::Err {
                error_code,
                http_status,
                ..
            },
        ) => {
            let got = describe_failure(error_code, *http_status);
            if let Some(want) = &expected.error_code {
                if want != error_code {
                    return Err(StepError::Fail(format!("expected error {want}, got {got}")));
                }
            }
            if let Some(want) = expected.http_status {
                if *http_status != Some(want) {
                    return Err(StepError::Fail(format!("expected HTTP {want}, got {got}")));
                }
                // A request refused below the protocol layer gets no
                // AITP error envelope (RFC-AITP-0009 §3.1).
                if expected.error_code.is_none() && !error_code.is_empty() {
                    return Err(StepError::Fail(format!(
                        "expected HTTP {want} with no error code, got {got}"
                    )));
                }
            }
        }
        ("failure", OpResult::Ok { .. }) => {
            return Err(StepError::Fail("expected failure, got success".into()))
        }
        (other, _) => {
            return Err(StepError::Fail(format!(
                "fixture expected.outcome = {other} (must be 'success' or 'failure')"
            )))
        }
    }
    assert_side_effects(actual, expected)
}

/// Assert any side effect the adapter *reported* matches the fixture's
/// `expected.side_effects`. Side-effect keys the adapter did not report
/// are un-instrumented and skipped — but a *reported* value that
/// disagrees with the fixture is a hard failure (conformance README,
/// "Side-effect assertions": a runner MUST NOT silently pass).
fn assert_side_effects(actual: &OpResult, expected: &FixtureExpected) -> Result<(), StepError> {
    let Some(want) = &expected.side_effects else {
        return Ok(());
    };
    // Only an `Ok` result carries a `result` body that can carry a
    // `side_effects` object; an `Err` result reports none.
    let reported = match actual {
        OpResult::Ok { result, .. } => result.get("side_effects").and_then(|v| v.as_object()),
        OpResult::Err { .. } => None,
    };
    let Some(reported) = reported else {
        return Ok(()); // adapter instrumented no side effect — skip
    };
    for (key, want_val) in want {
        if let Some(got_val) = reported.get(key) {
            if got_val != want_val {
                return Err(StepError::Fail(format!(
                    "side effect `{key}`: expected {want_val}, adapter reported {got_val}"
                )));
            }
        }
        // key absent from the adapter's report → un-instrumented → skip
    }
    Ok(())
}

/// Assert a `renew_tct` success (RFC-AITP-0013 §6) against
/// `expected.renewed_tct_claims`, `renewed_jti_differs` and `response`.
/// The runner reads them from the response envelope the adapter returns
/// as `result.response_envelope`, not from anything the adapter decoded.
/// A fixture that expects them from an adapter that returns no envelope
/// fails.
fn assert_renewal(
    actual: &OpResult,
    expected: &FixtureExpected,
    params: &serde_json::Value,
) -> Result<(), StepError> {
    if expected.renewed_tct_claims.is_none()
        && expected.renewed_jti_differs.is_none()
        && expected.response.is_none()
    {
        return Ok(());
    }
    let OpResult::Ok { result, .. } = actual else {
        return Ok(()); // assert_outcome already failed a non-success
    };
    let envelope = result.get("response_envelope").ok_or_else(|| {
        StepError::Fail("renewal succeeded without result.response_envelope".into())
    })?;
    let payload = &envelope["payload"];
    let renewed = payload["tct"]
        .as_str()
        .and_then(jws_claims)
        .ok_or_else(|| StepError::Fail("response payload.tct is not a decodable JWS".into()))?;
    if let Some(want) = &expected.renewed_tct_claims {
        for (claim, want_val) in want {
            if renewed.get(claim) != Some(want_val) {
                return Err(StepError::Fail(format!(
                    "renewed TCT `{claim}`: expected {want_val}, got {}",
                    renewed.get(claim).unwrap_or(&serde_json::Value::Null)
                )));
            }
        }
    }
    if let Some(want) = expected.renewed_jti_differs {
        let current = params["renewal_request"]["current_tct"]
            .as_str()
            .and_then(jws_claims)
            .ok_or_else(|| StepError::Fail("renewal_request.current_tct is not a JWS".into()))?;
        if (current.get("jti") != renewed.get("jti")) != want {
            return Err(StepError::Fail(format!(
                "renewed jti differs: expected {want}, renewed jti {}",
                renewed.get("jti").unwrap_or(&serde_json::Value::Null)
            )));
        }
    }
    if let Some(want) = &expected.response {
        for (key, want_val) in want {
            let got = match key.as_str() {
                "message_type" => &envelope["message_type"],
                "sender" => &envelope["sender"]["agent_id"],
                other => &payload[other],
            };
            if got != want_val {
                return Err(StepError::Fail(format!(
                    "response `{key}`: expected {want_val}, got {got}"
                )));
            }
        }
    }
    Ok(())
}

/// The payload of a compact JWS, decoded without verification.
fn jws_claims(token: &str) -> Option<serde_json::Value> {
    let bytes = aitp::crypto::jws::decode_payload_unverified(token).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[derive(Debug)]
enum StepError {
    Fail(String),
    Skip(String),
}

impl StepError {
    fn in_step(self, step: impl std::fmt::Display) -> Self {
        match self {
            Self::Fail(m) => Self::Fail(format!("step {step}: {m}")),
            other => other,
        }
    }
}

/// Suffix of a SKIP reason produced by feature negation. The
/// conformance gate ([`crate::runner::check_gate`]) keys on it to
/// exempt such skips.
pub(crate) const FEATURE_NEGATION_MARKER: &str = "no longer applies";

/// Maps a v0.1-strict rejection error code to the experimental
/// feature whose opt-in invalidates the assertion. See
/// [`Runner::should_skip_for_v0_1`].
fn negated_by_feature(error_code: &str) -> Option<&'static str> {
    match error_code {
        "DELEGATION_MULTIHOP_NOT_SUPPORTED" => Some("experimental-multihop-delegation"),
        "BUNDLE_NOT_SUPPORTED" => Some("experimental-session-bundle"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn receiver_policy_default_applies_to_mh_payload_fixtures_only() {
        let mut absent = json!({"operation": "verify_handshake_payload"});
        apply_receiver_policy_default("mh-011", &mut absent);
        assert_eq!(absent["self_accepted_identity_types"], json!(["oidc"]));

        let mut stated = json!({
            "operation": "verify_handshake_payload",
            "self_accepted_identity_types": ["pinned_key"],
        });
        apply_receiver_policy_default("mh-012", &mut stated);
        assert_eq!(
            stated["self_accepted_identity_types"],
            json!(["pinned_key"])
        );

        let mut id_fixture = json!({"operation": "verify_handshake_payload"});
        apply_receiver_policy_default("id-017", &mut id_fixture);
        assert!(id_fixture.get("self_accepted_identity_types").is_none());
    }

    fn expected(v: serde_json::Value) -> FixtureExpected {
        serde_json::from_value(v).unwrap()
    }

    /// A compact JWS whose payload is `claims` (header and signature
    /// are not read by `assert_renewal`).
    fn jws(claims: serde_json::Value) -> String {
        format!(
            "e30.{}.AA",
            aitp::core::base64url::encode(claims.to_string().as_bytes())
        )
    }

    #[test]
    fn renewal_assertions_read_the_response_envelope() {
        let want = expected(json!({
            "outcome": "success",
            "renewed_tct_claims": {"exp": 100},
            "renewed_jti_differs": true,
            "response": {"message_type": "tct", "sender": "aid:x", "pop_nonce_echo": "n"},
        }));
        let params = json!({"renewal_request": {"current_tct": jws(json!({"jti": "a"}))}});
        let ok = |exp: i64, jti: &str, echo: &str| OpResult::Ok {
            ok: true,
            result: json!({"response_envelope": {
                "message_type": "tct",
                "sender": {"agent_id": "aid:x"},
                "payload": {"tct": jws(json!({"jti": jti, "exp": exp})), "pop_nonce_echo": echo},
            }}),
        };
        assert!(assert_renewal(&ok(100, "b", "n"), &want, &params).is_ok());
        assert!(assert_renewal(&ok(101, "b", "n"), &want, &params).is_err());
        assert!(assert_renewal(&ok(100, "a", "n"), &want, &params).is_err());
        assert!(assert_renewal(&ok(100, "b", "m"), &want, &params).is_err());
        let bare = OpResult::Ok {
            ok: true,
            result: json!({}),
        };
        assert!(assert_renewal(&bare, &want, &params).is_err());
    }

    fn err(code: &str, http_status: Option<u16>) -> OpResult {
        OpResult::Err {
            ok: false,
            error_code: code.into(),
            message: String::new(),
            http_status,
        }
    }

    #[test]
    fn issued_nonces_substitute_by_one_based_index() {
        let issued = vec!["n1".to_string(), "n2".to_string()];
        let mut v = json!({"a": "__ISSUED_NONCE_2__", "b": ["__ISSUED_NONCE_1__"],
                           "c": "__ISSUED_NONCE_3__", "d": "__ISSUED_NONCE_0__"});
        substitute_issued_nonces(&mut v, &issued);
        assert_eq!(
            v,
            json!({"a": "n2", "b": ["n1"], "c": "__ISSUED_NONCE_3__", "d": "__ISSUED_NONCE_0__"})
        );
    }

    #[test]
    fn http_status_expectation() {
        let want = expected(json!({"outcome": "failure", "http_status": 429}));
        assert!(assert_outcome(&err("", Some(429)), &want).is_ok());
        // A code means the request reached the protocol layer.
        assert!(assert_outcome(&err("IDENTITY_FAILED", Some(429)), &want).is_err());
        assert!(assert_outcome(&err("IDENTITY_FAILED", None), &want).is_err());
        assert!(assert_outcome(&err("", Some(503)), &want).is_err());
        // An error-code expectation is not met by a bare status.
        let code = expected(json!({"outcome": "failure", "error_code": "REPLAY_DETECTED"}));
        match assert_outcome(&err("", Some(429)), &code) {
            Err(StepError::Fail(m)) => assert!(m.contains("HTTP 429 with no error code"), "{m}"),
            other => panic!("{other:?}"),
        }
    }
}
