//! Fixture types matching the JSON schema in `schemas/conformance/`.

use serde::{Deserialize, Serialize};

/// A conformance test fixture.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Fixture {
    /// Unique fixture ID, e.g. `mh-006-audience-mismatch`.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Tags for filtering (e.g. "security", "tct", "mutual-handshake").
    #[serde(default)]
    pub tags: Vec<String>,
    /// Optional preconditions to set up before running the input.
    #[serde(default)]
    pub preconditions: serde_json::Value,
    /// Operation input.
    pub input: FixtureInput,
    /// Expected outcome.
    #[serde(default)]
    pub expected: Option<FixtureExpected>,
}

/// Operation input. Most fixtures use a flat object with `operation` and
/// operation-specific fields. `mh-001`-style fixtures use a `sequence`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FixtureInput {
    /// Either a single op or a multi-step sequence.
    #[serde(flatten)]
    pub variant: FixtureInputVariant,
}

/// Two kinds of fixture inputs.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FixtureInputVariant {
    /// Single-step: `{operation: "verify_tct", ...op_params}`.
    Single(serde_json::Value),
    /// Multi-step sequence (e.g. for replay tests).
    Sequence { sequence: Vec<SequenceStep> },
}

/// One step of a multi-step fixture.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SequenceStep {
    /// Step number (informational).
    pub step: u32,
    /// Per-step parameters.
    #[serde(flatten)]
    pub params: serde_json::Value,
    /// Per-step expected outcome.
    pub expected: FixtureExpected,
}

/// Expected outcome of an operation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FixtureExpected {
    /// `success` or `failure`.
    pub outcome: String,
    /// Expected error code on failure.
    #[serde(default)]
    pub error_code: Option<String>,
}
