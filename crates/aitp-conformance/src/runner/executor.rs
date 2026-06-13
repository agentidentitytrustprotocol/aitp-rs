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
                            "feature `{feature}` enabled — assertion `{code}` no longer applies"
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

        // Reset per-fixture substitution state (nonce counter +
        // last_nonce) before walking the input.
        self.ctx.reset_per_fixture();

        let outcome = match &fixture.input.variant {
            FixtureInputVariant::Single(params) => {
                let mut params = params.clone();
                self.ctx.substitute(&mut params);
                self.run_single(&params, fixture.expected.as_ref())
            }
            FixtureInputVariant::Sequence { sequence, context } => {
                let mut substituted = sequence.clone();
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
                for step in &mut substituted {
                    // Merge context fields under the step's params,
                    // with step values taking precedence on any
                    // collision.
                    if let Some(step_map) = step.params.as_object_mut() {
                        for (k, v) in context.iter() {
                            step_map.entry(k.clone()).or_insert_with(|| v.clone());
                        }
                    }
                    self.ctx.substitute(&mut step.params);
                }
                self.run_sequence(&substituted, fixture.input.operation.as_deref())
            }
        };

        let duration_ms = started.elapsed().as_millis() as u64;
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

    fn apply_preconditions(&mut self, preconditions: &serde_json::Value) -> Result<(), String> {
        let Some(map) = preconditions.as_object() else {
            return Ok(());
        };
        for (op, params) in map {
            match self.adapter.execute(op, params.clone()) {
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
        let result = self.adapter.execute(op, op_params).map_err(|e| match e {
            crate::adapter::AdapterError::OpNotSupported(_) => {
                StepError::Skip(format!("adapter does not support op {op}"))
            }
            other => StepError::Fail(other.to_string()),
        })?;
        if let Some(expected) = expected {
            assert_outcome(&result, expected)?;
        }
        Ok(())
    }

    fn run_sequence(
        &mut self,
        sequence: &[crate::fixture::SequenceStep],
        parent_op: Option<&str>,
    ) -> Result<(), StepError> {
        for step in sequence {
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
            let result = self
                .adapter
                .execute(op, params)
                .map_err(|e| StepError::Fail(format!("step {}: {e}", step.step)))?;
            assert_outcome(&result, &step.expected)?;
        }
        Ok(())
    }
}

fn assert_outcome(actual: &OpResult, expected: &FixtureExpected) -> Result<(), StepError> {
    match (expected.outcome.as_str(), actual) {
        ("success", OpResult::Ok { ok, .. }) if *ok => {}
        ("success", OpResult::Err { error_code, .. }) => {
            return Err(StepError::Fail(format!(
                "expected success, got error {error_code}"
            )))
        }
        ("failure", OpResult::Err { error_code, .. }) => {
            if let Some(want) = &expected.error_code {
                if want != error_code {
                    return Err(StepError::Fail(format!(
                        "expected error {want}, got {error_code}"
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

#[derive(Debug)]
enum StepError {
    Fail(String),
    Skip(String),
}

/// Maps a v0.1-strict rejection error code to the experimental
/// feature whose opt-in invalidates the assertion. See
/// [`Runner::should_skip_for_v0_1`].
fn negated_by_feature(error_code: &str) -> Option<&'static str> {
    match error_code {
        "DELEGATION_MULTIHOP_NOT_SUPPORTED" => Some("experimental-multihop-delegation"),
        "BUNDLE_NOT_SUPPORTED" => Some("experimental-session-bundle"),
        "TCT_RENEWAL_NOT_SUPPORTED" => Some("experimental-renewal"),
        _ => None,
    }
}
