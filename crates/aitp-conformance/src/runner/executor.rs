//! Fixture runner.

use crate::adapter::{Adapter, OpResult};
use crate::fixture::{Fixture, FixtureExpected, FixtureInputVariant, RunnerContext, REFERENCE_NOW};
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
}

impl<A: Adapter> Runner<A> {
    /// Construct a runner around an adapter. Defaults to pinning
    /// the adapter clock to [`REFERENCE_NOW`] before every fixture.
    pub fn new(adapter: A) -> Self {
        Self {
            adapter,
            ctx: RunnerContext::new(),
            pin_clock: true,
        }
    }

    /// Disable the auto `set_clock` precondition. Use only when an
    /// adapter is being driven outside the conformance fixture
    /// suite (the in-process adapter's unit tests, for instance).
    pub fn without_clock_pinning(mut self) -> Self {
        self.pin_clock = false;
        self
    }

    /// Run a single fixture.
    pub fn run(&mut self, fixture: &Fixture) -> FixtureResult {
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

        // Reset per-fixture substitution state (nonce counter +
        // last_nonce) before walking the input.
        self.ctx.reset_per_fixture();

        let outcome = match &fixture.input.variant {
            FixtureInputVariant::Single(params) => {
                let mut params = params.clone();
                self.ctx.substitute(&mut params);
                self.run_single(&params, fixture.expected.as_ref())
            }
            FixtureInputVariant::Sequence { sequence } => {
                let mut substituted = sequence.clone();
                for step in &mut substituted {
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
        ("success", OpResult::Ok { ok, .. }) if *ok => Ok(()),
        ("success", OpResult::Err { error_code, .. }) => Err(StepError::Fail(format!(
            "expected success, got error {error_code}"
        ))),
        ("failure", OpResult::Err { error_code, .. }) => {
            if let Some(want) = &expected.error_code {
                if want == error_code {
                    Ok(())
                } else {
                    Err(StepError::Fail(format!(
                        "expected error {want}, got {error_code}"
                    )))
                }
            } else {
                Ok(())
            }
        }
        ("failure", OpResult::Ok { .. }) => {
            Err(StepError::Fail("expected failure, got success".into()))
        }
        (other, _) => Err(StepError::Fail(format!(
            "fixture expected.outcome = {other} (must be 'success' or 'failure')"
        ))),
    }
}

#[derive(Debug)]
enum StepError {
    Fail(String),
    Skip(String),
}
