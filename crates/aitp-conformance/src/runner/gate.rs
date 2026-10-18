//! Exit-code conformance gate.
//!
//! The spec's conformance README ("Conformance runner enforcement
//! rules") says a runner selects fixtures by the protocol version it
//! tests — `required_for_v0_2` for a v0.2 runner, `required_for_v0_1`
//! for a v0.1 runner — and that a `status: core` fixture carrying the
//! matching flag MUST execute: an `OP_NOT_SUPPORTED` result or runner
//! SKIP MUST be reported as a failure (RFC-AITP-0001 §10 item 9).

use crate::fixture::Fixture;
use crate::runner::executor::FEATURE_NEGATION_MARKER;
use crate::runner::FixtureResult;
use std::fmt;
use std::str::FromStr;

/// The protocol version a run is gated against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    /// Gate on `required_for_v0_1` (the pre-0.15 runner behaviour).
    V0_1,
    /// Gate on `required_for_v0_2`. The default.
    #[default]
    V0_2,
}

impl Profile {
    /// Whether `fixture` MUST pass under this profile.
    pub fn requires(self, fixture: &Fixture) -> bool {
        match self {
            Self::V0_1 => fixture.required_for_v0_1,
            Self::V0_2 => fixture.required_for_v0_2,
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V0_1 => "v0.1",
            Self::V0_2 => "v0.2",
        })
    }
}

impl FromStr for Profile {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "v0.1" => Ok(Self::V0_1),
            "v0.2" => Ok(Self::V0_2),
            other => Err(format!("unknown profile `{other}` (expected v0.1 or v0.2)")),
        }
    }
}

/// Outcome of [`check_gate`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GateReport {
    /// Required fixtures that FAILed or were SKIPped, rendered as
    /// `"  <id>: FAIL|SKIP — <detail>"`.
    pub violations: Vec<String>,
    /// Required fixtures SKIPped because an opted-in feature negates
    /// their assertion (e.g. `del-007` under
    /// `experimental-multihop-delegation`). Not violations — the run
    /// deliberately tests behaviour beyond the profile — but reported
    /// so the exemption is never silent.
    pub exempted: Vec<String>,
}

impl GateReport {
    /// Whether the gate passed.
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Check every required fixture under `profile` passed. A required
/// fixture that FAILs, or is SKIPped for any reason other than feature
/// negation, is a violation.
pub fn check_gate(profile: Profile, fixtures: &[Fixture], results: &[FixtureResult]) -> GateReport {
    let mut report = GateReport::default();
    for r in results {
        let (id, kind, detail) = match r {
            FixtureResult::Pass { .. } => continue,
            FixtureResult::Fail { id, reason, .. } => (id, "FAIL", reason.as_str()),
            FixtureResult::Skip { id, reason } => (id, "SKIP", reason.as_str()),
        };
        if !fixtures.iter().any(|f| &f.id == id && profile.requires(f)) {
            continue;
        }
        if kind == "SKIP" && detail.contains(FEATURE_NEGATION_MARKER) {
            report.exempted.push(format!("  {id}: {detail}"));
        } else {
            report.violations.push(format!("  {id}: {kind} — {detail}"));
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(id: &str, v0_1: bool, v0_2: bool) -> Fixture {
        serde_json::from_value(json!({
            "id": id,
            "status": "core",
            "required_for_v0_1": v0_1,
            "required_for_v0_2": v0_2,
            "input": {"operation": "verify_jcs"},
        }))
        .unwrap()
    }

    fn skip(id: &str, reason: &str) -> FixtureResult {
        FixtureResult::Skip {
            id: id.into(),
            reason: reason.into(),
        }
    }

    fn fail(id: &str) -> FixtureResult {
        FixtureResult::Fail {
            id: id.into(),
            reason: "boom".into(),
            duration_ms: 0,
        }
    }

    #[test]
    fn profile_parses_and_defaults_to_v0_2() {
        assert_eq!(Profile::default(), Profile::V0_2);
        assert_eq!("v0.1".parse::<Profile>(), Ok(Profile::V0_1));
        assert_eq!("v0.2".parse::<Profile>(), Ok(Profile::V0_2));
        assert!("0.2".parse::<Profile>().is_err());
        assert_eq!(Profile::V0_2.to_string(), "v0.2");
    }

    #[test]
    fn v0_2_gate_fails_on_skipped_v0_2_fixture_only() {
        let fixtures = [
            fixture("v2-only", false, true),
            fixture("v1-only", true, false),
        ];
        let results = [
            skip("v2-only", "adapter does not support op future_op"),
            skip("v1-only", "adapter does not support op future_op"),
        ];
        let v2 = check_gate(Profile::V0_2, &fixtures, &results);
        assert_eq!(v2.violations.len(), 1, "{v2:?}");
        assert!(v2.violations[0].contains("v2-only: SKIP"), "{v2:?}");

        let v1 = check_gate(Profile::V0_1, &fixtures, &results);
        assert_eq!(v1.violations.len(), 1, "{v1:?}");
        assert!(v1.violations[0].contains("v1-only: SKIP"), "{v1:?}");
    }

    #[test]
    fn gate_reports_failing_required_fixture() {
        let fixtures = [fixture("a", false, true)];
        let r = check_gate(Profile::V0_2, &fixtures, &[fail("a")]);
        assert!(!r.passed());
        assert!(r.violations[0].contains("a: FAIL — boom"), "{r:?}");
        // Not required under v0.1: the gate itself is clean there (the
        // CLI still exits non-zero on any FAIL).
        assert!(check_gate(Profile::V0_1, &fixtures, &[fail("a")]).passed());
    }

    #[test]
    fn feature_negation_skip_is_exempted_not_silent() {
        let fixtures = [fixture("del-007", false, true)];
        let reason = format!(
            "feature `experimental-multihop-delegation` enabled — assertion \
             `DELEGATION_MULTIHOP_NOT_SUPPORTED` {FEATURE_NEGATION_MARKER}"
        );
        let r = check_gate(Profile::V0_2, &fixtures, &[skip("del-007", &reason)]);
        assert!(r.passed(), "{r:?}");
        assert_eq!(r.exempted.len(), 1);
        assert!(r.exempted[0].contains("del-007"));
    }

    #[test]
    fn passing_and_unrequired_fixtures_do_not_trip_the_gate() {
        let fixtures = [fixture("p", true, true), fixture("draft", false, false)];
        let results = [
            FixtureResult::Pass {
                id: "p".into(),
                duration_ms: 0,
            },
            skip(
                "draft",
                "non-core fixture (status=Draft); requires feature `x`",
            ),
        ];
        for profile in [Profile::V0_1, Profile::V0_2] {
            let r = check_gate(profile, &fixtures, &results);
            assert_eq!(r, GateReport::default(), "{profile}");
        }
    }
}
