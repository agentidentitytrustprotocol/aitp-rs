//! Output formatters: text, JSON, TAP.

use crate::runner::FixtureResult;

/// Output format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable colored output.
    Text,
    /// Machine-readable JSON array, emitted at the end.
    Json,
    /// Test Anything Protocol (TAP 13).
    Tap,
}

impl OutputFormat {
    /// Parse from CLI string.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "tap" => Ok(Self::Tap),
            other => Err(format!("unknown output format: {other}")),
        }
    }
}

/// Render the per-fixture result for [`OutputFormat::Text`].
pub fn render_text(result: &FixtureResult) -> String {
    match result {
        FixtureResult::Pass { id, duration_ms } => format!("  PASS {} [{}ms]", id, duration_ms),
        FixtureResult::Fail {
            id,
            reason,
            duration_ms,
        } => format!(
            "  FAIL {} [{}ms]\n        reason: {}",
            id, duration_ms, reason
        ),
        FixtureResult::Skip { id, reason } => format!("  SKIP {} ({})", id, reason),
    }
}

/// Render the final summary line.
pub fn render_summary(results: &[FixtureResult]) -> String {
    let mut p = 0;
    let mut f = 0;
    let mut s = 0;
    for r in results {
        match r {
            FixtureResult::Pass { .. } => p += 1,
            FixtureResult::Fail { .. } => f += 1,
            FixtureResult::Skip { .. } => s += 1,
        }
    }
    format!(
        "Summary: {} passed, {} failed, {} skipped of {} fixtures",
        p,
        f,
        s,
        results.len()
    )
}

/// Render TAP 13 output for the entire result set.
pub fn render_tap(results: &[FixtureResult]) -> String {
    let mut out = String::from("TAP version 13\n");
    out.push_str(&format!("1..{}\n", results.len()));
    for (i, r) in results.iter().enumerate() {
        let n = i + 1;
        match r {
            FixtureResult::Pass { id, .. } => out.push_str(&format!("ok {n} - {id}\n")),
            FixtureResult::Fail { id, reason, .. } => {
                out.push_str(&format!("not ok {n} - {id}\n"));
                out.push_str("  ---\n");
                out.push_str(&format!("  message: {}\n", reason.replace('\n', " ")));
                out.push_str("  ...\n");
            }
            FixtureResult::Skip { id, reason } => {
                out.push_str(&format!("ok {n} - {id} # SKIP {}\n", reason))
            }
        }
    }
    out
}

/// Render JSON output for the entire result set as an array of objects.
pub fn render_json(results: &[FixtureResult]) -> String {
    let arr: Vec<serde_json::Value> = results
        .iter()
        .map(|r| match r {
            FixtureResult::Pass { id, duration_ms } => serde_json::json!({
                "id": id,
                "outcome": "pass",
                "duration_ms": duration_ms,
            }),
            FixtureResult::Fail {
                id,
                reason,
                duration_ms,
            } => serde_json::json!({
                "id": id,
                "outcome": "fail",
                "reason": reason,
                "duration_ms": duration_ms,
            }),
            FixtureResult::Skip { id, reason } => serde_json::json!({
                "id": id,
                "outcome": "skip",
                "reason": reason,
            }),
        })
        .collect();
    serde_json::to_string_pretty(&arr).expect("serde_json::Value serialises")
}
