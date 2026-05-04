//! Fixture runner.

use crate::adapter::{Adapter, OpResult};
use crate::fixture::{Fixture, FixtureExpected, FixtureInputVariant};
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
}

impl<A: Adapter> Runner<A> {
    /// Construct a runner around an adapter.
    pub fn new(adapter: A) -> Self {
        Self { adapter }
    }

    /// Run a single fixture.
    pub fn run(&mut self, fixture: &Fixture) -> FixtureResult {
        let started = Instant::now();
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

        let outcome = match &fixture.input.variant {
            FixtureInputVariant::Single(params) => {
                self.run_single(params, fixture.expected.as_ref())
            }
            FixtureInputVariant::Sequence { sequence } => self.run_sequence(sequence),
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

    fn run_sequence(&mut self, sequence: &[crate::fixture::SequenceStep]) -> Result<(), StepError> {
        for step in sequence {
            let op = step
                .params
                .get("operation")
                .and_then(|v| v.as_str())
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
