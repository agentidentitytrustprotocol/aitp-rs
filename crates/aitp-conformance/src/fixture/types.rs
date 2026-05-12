//! Fixture types matching the JSON schema in `schemas/conformance/`.

use serde::{Deserialize, Serialize};

/// Conformance tier per the spec's
/// `aitp-conformance-fixture.schema.json` metadata block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureStatus {
    /// MUST pass for any v0.1-conformant implementation.
    Core,
    /// Draft-tier RFC (e.g. RFC-AITP-0010 session bundle,
    /// RFC-AITP-0011 multi-hop). v0.1 runners SKIP unless the
    /// implementation opts into the matching `feature`.
    Draft,
    /// Optional extension (e.g. RFC-AITP-0004 §8.1 renewal).
    Extension,
    /// Reserved for future spec work; no implementation is
    /// expected to handle the fixture yet.
    Reserved,
}

/// A conformance test fixture.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Fixture {
    /// Unique fixture ID, e.g. `mh-006-audience-mismatch`.
    pub id: String,
    /// Most-specific RFC the fixture exercises
    /// (e.g. `RFC-AITP-0011`). Captured for telemetry; the runner
    /// keys off `status` and `feature` for dispatch.
    #[serde(default)]
    pub rfc: Option<String>,
    /// Conformance tier. Absent in legacy fixtures (treated as
    /// `Core` for backward compat).
    #[serde(default = "default_status")]
    pub status: FixtureStatus,
    /// Whether a v0.1 implementation MUST pass this fixture.
    /// Always `false` when `status != Core`.
    #[serde(default = "default_required_for_v0_1")]
    pub required_for_v0_1: bool,
    /// Opt-in feature flag for non-core fixtures (null/None for
    /// core). Examples: `experimental-multihop-delegation`,
    /// `experimental-session-bundle`. The runner matches this
    /// against the runtime's enabled feature set; non-core
    /// fixtures whose feature isn't enabled SKIP.
    #[serde(default)]
    pub feature: Option<String>,
    /// Human-readable description.
    #[serde(default)]
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

fn default_status() -> FixtureStatus {
    FixtureStatus::Core
}

fn default_required_for_v0_1() -> bool {
    true
}

/// Operation input. Most fixtures use a flat object with `operation` and
/// operation-specific fields. `mh-001`-style fixtures use a `sequence`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(from = "serde_json::Value", into = "serde_json::Value")]
pub struct FixtureInput {
    /// Either a single op or a multi-step sequence.
    pub variant: FixtureInputVariant,
    /// Some fixtures (e.g. `env-004`) declare `operation` at the
    /// top level alongside a `sequence`, expecting each step to
    /// inherit it. Captured here so the runner can fall back.
    pub operation: Option<String>,
}

impl From<serde_json::Value> for FixtureInput {
    fn from(v: serde_json::Value) -> Self {
        // Pull off a top-level `operation` first (if present) and
        // strip it from the value before letting serde infer
        // Single vs Sequence — otherwise `operation` would leak
        // into Single's params and pollute the op call.
        let operation = v
            .get("operation")
            .and_then(|x| x.as_str())
            .map(str::to_string);
        let mut stripped = v.clone();
        if operation.is_some() {
            if let Some(map) = stripped.as_object_mut() {
                map.remove("operation");
            }
        }
        // Now classify: Sequence if the (stripped) value has
        // `sequence`, else Single (carrying the original value so
        // single-op fixtures still see `operation`).
        let variant = if stripped
            .as_object()
            .and_then(|m| m.get("sequence"))
            .is_some()
        {
            serde_json::from_value::<FixtureInputVariant>(stripped)
                .unwrap_or_else(|_| FixtureInputVariant::Single(v.clone()))
        } else {
            FixtureInputVariant::Single(v.clone())
        };
        Self { variant, operation }
    }
}

impl From<FixtureInput> for serde_json::Value {
    fn from(input: FixtureInput) -> Self {
        // Round-trip serialization: emit the variant and re-attach
        // `operation` at the top level if present.
        let mut v = serde_json::to_value(&input.variant).unwrap_or(serde_json::Value::Null);
        if let Some(op) = input.operation {
            if let Some(map) = v.as_object_mut() {
                map.insert("operation".into(), serde_json::Value::String(op));
            }
        }
        v
    }
}

/// Two kinds of fixture inputs.
//
// Order matters: `serde(untagged)` tries variants top-to-bottom and
// `Single(Value)` matches *any* JSON object. Sequence must come first
// so that fixtures carrying both top-level fields AND a `sequence`
// array (e.g. tct-006, where `tct_token` and `sequence` are siblings)
// route to the multi-step path instead of being treated as a
// flat single-op.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FixtureInputVariant {
    /// Multi-step sequence (e.g. for replay tests). Sibling fields
    /// alongside `sequence` (e.g. `tct_token` in tct-006) land in
    /// `context` and are merged into every step's params at
    /// dispatch time — the spec convention is that sequence-level
    /// context applies to each step.
    Sequence {
        sequence: Vec<SequenceStep>,
        #[serde(flatten)]
        context: serde_json::Map<String, serde_json::Value>,
    },
    /// Single-step: `{operation: "verify_tct", ...op_params}`.
    Single(serde_json::Value),
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
