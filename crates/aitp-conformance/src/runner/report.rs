//! Conformance report (`aitp-conformance run --report`).
//!
//! Emits the spec's `aitp-conformance-report.schema.json` document
//! (`report_version` "1", `$id`
//! `https://agentidentitytrustprotocol.io/schema/v0.3/conformance-report.json`).
//! The badge criteria behind `gates` are in the spec's
//! `docs/conformance-badge.md`; `scripts/check-conformance-report.py`
//! recomputes `totals`, every gate and the fixture digest from a report,
//! and this module computes them the same way.

use crate::fixture::{Fixture, FixtureStatus};
use crate::runner::FixtureResult;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

/// The core claim string (RFC-AITP-0001 §10).
pub const CORE_CLAIM: &str = "AITP v0.3";

/// Extension claim strings (RFC-AITP-0001 §10) and the fixture
/// `feature` each one gates on.
pub const FEATURE_CLAIMS: &[(&str, &str)] = &[
    ("AITP v0.3 pinned-admission", "aitp-pinned-admission"),
    ("AITP v0.3 self-attestation", "aitp-self-attestation"),
];

/// Protocol revision the fixtures test (`spec.protocol`).
pub const PROTOCOL: &str = "aitp/0.3";

/// The implementation under test.
#[derive(Debug, Clone, Serialize)]
pub struct Implementation {
    /// Implementation name, e.g. `aitp-rs`.
    pub name: String,
    /// Released version tested, or the commit of an unreleased build.
    pub version: String,
    /// Public `https://` source repository URL.
    pub repository: String,
    /// Full lowercase SHA of the source tested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

/// The runner that produced the report.
#[derive(Debug, Clone, Serialize)]
pub struct RunnerInfo {
    /// Runner name.
    pub name: String,
    /// Runner version.
    pub version: String,
}

impl RunnerInfo {
    /// This crate.
    pub fn this() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME").to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

/// The spec the fixtures came from.
#[derive(Debug, Clone, Serialize)]
pub struct SpecInfo {
    /// Full lowercase SHA of the spec commit whose fixtures ran.
    pub commit: String,
    /// Newest spec release tag at or before `commit`, e.g. `v0.3.2-draft`.
    pub version: String,
    /// Always [`PROTOCOL`].
    pub protocol: &'static str,
}

/// Everything in a report that does not come from the run itself.
#[derive(Debug, Clone)]
pub struct ReportMeta {
    /// The implementation under test.
    pub implementation: Implementation,
    /// The runner, when it is not the implementation itself.
    pub runner: Option<RunnerInfo>,
    /// The spec commit and release.
    pub spec: SpecInfo,
    /// [`fixtures_dir_digest`] of the fixtures directory.
    pub fixtures_dir_digest: String,
    /// The `--feature` set.
    pub features_enabled: Vec<String>,
    /// RFC 3339 UTC timestamp, e.g. `2026-10-24T12:00:00Z`.
    pub generated_at: String,
}

/// One fixture's result.
#[derive(Debug, Clone, Serialize)]
pub struct ReportResult {
    /// Fixture ID.
    pub id: String,
    /// `core`, `extension` or `draft`, copied from the fixture.
    pub status: &'static str,
    /// Copied from the fixture; `null` for core.
    pub feature: Option<String>,
    /// Copied from the fixture; `false` for non-core.
    pub required_for_v0_2: bool,
    /// `pass`, `fail` or `skip`.
    pub outcome: &'static str,
    /// Why the fixture did not pass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Wall-clock duration (absent for skips, which never ran).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Result counts for one fixture status.
#[derive(Debug, Clone, Default, Serialize)]
pub struct OutcomeCounts {
    /// Passed.
    pub pass: u64,
    /// Failed.
    pub fail: u64,
    /// Skipped.
    pub skip: u64,
    /// Excluded by role (this runner never reports it).
    pub excluded_by_role: u64,
}

/// Result counts by fixture status.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Totals {
    /// Core fixtures.
    pub core: OutcomeCounts,
    /// Extension fixtures.
    pub extension: OutcomeCounts,
    /// Draft fixtures.
    pub draft: OutcomeCounts,
}

/// One evaluated claim.
#[derive(Debug, Clone, Serialize)]
pub struct Gate {
    /// The claim string.
    pub name: &'static str,
    /// Whether the claim's criteria hold.
    pub passed: bool,
    /// `core-required-all-pass` or `feature-all-pass`.
    pub criteria: &'static str,
    /// Fixture IDs that keep the claim from passing, in results order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub blocking: Vec<String>,
}

/// A conformance report.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Always `"1"`.
    pub report_version: &'static str,
    /// The implementation under test.
    pub implementation: Implementation,
    /// The runner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner: Option<RunnerInfo>,
    /// The spec.
    pub spec: SpecInfo,
    /// Digest of the fixture set.
    pub fixtures_dir_digest: String,
    /// Sorted, deduplicated `--feature` set.
    pub features_enabled: Vec<String>,
    /// One entry per non-reserved fixture.
    pub results: Vec<ReportResult>,
    /// Counts over `results`.
    pub totals: Totals,
    /// The core claim, then each enabled extension claim.
    pub gates: Vec<Gate>,
    /// When the report was generated.
    pub generated_at: String,
}

impl Report {
    /// Whether every evaluated claim passed.
    pub fn all_gates_passed(&self) -> bool {
        self.gates.iter().all(|g| g.passed)
    }
}

/// Build a report from a whole-corpus run. `fixtures` and `results`
/// are paired by ID; reserved fixtures are left out. A result whose
/// fixture is missing from `fixtures` is dropped.
pub fn build_report(fixtures: &[Fixture], results: &[FixtureResult], meta: ReportMeta) -> Report {
    let by_id: HashMap<&str, &Fixture> = fixtures.iter().map(|f| (f.id.as_str(), f)).collect();
    let features_enabled: Vec<String> = meta
        .features_enabled
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let mut entries = Vec::new();
    let mut totals = Totals::default();
    for result in results {
        let (id, outcome, reason, duration_ms) = match result {
            FixtureResult::Pass { id, duration_ms } => (id, "pass", None, Some(*duration_ms)),
            FixtureResult::Fail {
                id,
                reason,
                duration_ms,
            } => (id, "fail", Some(reason.clone()), Some(*duration_ms)),
            FixtureResult::Skip { id, reason } => (id, "skip", Some(reason.clone()), None),
        };
        let Some(fixture) = by_id.get(id.as_str()) else {
            continue;
        };
        let (status, counts) = match fixture.status {
            FixtureStatus::Core => ("core", &mut totals.core),
            FixtureStatus::Extension => ("extension", &mut totals.extension),
            FixtureStatus::Draft => ("draft", &mut totals.draft),
            FixtureStatus::Reserved => continue,
        };
        match outcome {
            "pass" => counts.pass += 1,
            "fail" => counts.fail += 1,
            _ => counts.skip += 1,
        }
        entries.push(ReportResult {
            id: id.clone(),
            status,
            feature: fixture.feature.clone(),
            required_for_v0_2: fixture.required_for_v0_2,
            outcome,
            // The schema requires a non-empty reason on every non-pass.
            reason: reason.map(|r| if r.is_empty() { outcome.to_owned() } else { r }),
            duration_ms,
        });
    }

    // A skip blocks the core claim whatever its cause, including a core
    // fixture negated by an enabled draft feature: run the core claim
    // without draft features (docs/conformance-badge.md).
    let core_blocking: Vec<String> = entries
        .iter()
        .filter(|r| r.status == "core" && r.required_for_v0_2 && r.outcome != "pass")
        .map(|r| r.id.clone())
        .collect();
    let mut gates = vec![Gate {
        name: CORE_CLAIM,
        passed: core_blocking.is_empty(),
        criteria: "core-required-all-pass",
        blocking: core_blocking,
    }];
    for (claim, feature) in FEATURE_CLAIMS {
        if !features_enabled.iter().any(|f| f == feature) {
            continue;
        }
        let gated = entries
            .iter()
            .filter(|r| r.feature.as_deref() == Some(*feature));
        let covered = gated.clone().next().is_some();
        let blocking: Vec<String> = gated
            .filter(|r| r.outcome != "pass")
            .map(|r| r.id.clone())
            .collect();
        gates.push(Gate {
            name: claim,
            passed: covered && blocking.is_empty(),
            criteria: "feature-all-pass",
            blocking,
        });
    }

    Report {
        report_version: "1",
        implementation: meta.implementation,
        runner: meta.runner,
        spec: meta.spec,
        fixtures_dir_digest: meta.fixtures_dir_digest,
        features_enabled,
        results: entries,
        totals,
        gates,
        generated_at: meta.generated_at,
    }
}

/// `sha256:` + the SHA-256 of the `sha256sum`-format listing
/// (`<hex>  <name>\n`) of every top-level `*.json` file in `dir`,
/// sorted by file name in byte order. Equal to
/// `cd dir && LC_ALL=C sha256sum -- *.json | sha256sum`. File bytes are
/// hashed raw, with no newline normalisation, so the digest is the same
/// on every OS.
pub fn fixtures_dir_digest(dir: &Path) -> std::io::Result<String> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|n| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("non-UTF-8 file name {n:?}"),
            )
        })?;
        if name.ends_with(".json") && entry.path().is_file() {
            names.push(name);
        }
    }
    // `String`'s `Ord` is byte order.
    names.sort();
    let mut listing = Vec::new();
    for name in &names {
        let bytes = std::fs::read(dir.join(name))?;
        listing.extend_from_slice(hex::encode(Sha256::digest(&bytes)).as_bytes());
        listing.extend_from_slice(b"  ");
        listing.extend_from_slice(name.as_bytes());
        listing.push(b'\n');
    }
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(&listing))))
}

/// Whether `s` is a full lowercase 40-hex commit SHA.
pub fn is_commit_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(id: &str, status: FixtureStatus, feature: Option<&str>, req: bool) -> Fixture {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "status": match status {
                FixtureStatus::Core => "core",
                FixtureStatus::Extension => "extension",
                FixtureStatus::Draft => "draft",
                FixtureStatus::Reserved => "reserved",
            },
            "required_for_v0_2": req,
            "feature": feature,
            "description": "",
            "input": {"operation": "noop"},
            "expected": {"outcome": "success"},
        }))
        .unwrap()
    }

    fn meta(features: &[&str]) -> ReportMeta {
        ReportMeta {
            implementation: Implementation {
                name: "x".into(),
                version: "1".into(),
                repository: "https://example.com/x".into(),
                commit: None,
            },
            runner: None,
            spec: SpecInfo {
                commit: "0".repeat(40),
                version: "v0.3.2-draft".into(),
                protocol: PROTOCOL,
            },
            fixtures_dir_digest: format!("sha256:{}", "0".repeat(64)),
            features_enabled: features.iter().map(|s| s.to_string()).collect(),
            generated_at: "2026-10-24T00:00:00Z".into(),
        }
    }

    fn pass(id: &str) -> FixtureResult {
        FixtureResult::Pass {
            id: id.into(),
            duration_ms: 1,
        }
    }

    fn skip(id: &str) -> FixtureResult {
        FixtureResult::Skip {
            id: id.into(),
            reason: "why".into(),
        }
    }

    #[test]
    fn negated_core_skip_blocks_core_claim() {
        let fixtures = [
            fixture("a-001", FixtureStatus::Core, None, true),
            fixture("a-002", FixtureStatus::Core, None, false),
        ];
        let report = build_report(&fixtures, &[skip("a-001"), skip("a-002")], meta(&[]));
        assert!(!report.gates[0].passed);
        assert_eq!(report.gates[0].blocking, ["a-001"]);
        assert_eq!(report.totals.core.skip, 2);
    }

    #[test]
    fn extension_gate_only_when_enabled_and_covered() {
        let fixtures = [
            fixture("a-001", FixtureStatus::Core, None, true),
            fixture(
                "p-001",
                FixtureStatus::Extension,
                Some("aitp-pinned-admission"),
                false,
            ),
            fixture("r-001", FixtureStatus::Reserved, None, false),
        ];
        let results = [pass("a-001"), pass("p-001"), skip("r-001")];
        let off = build_report(&fixtures, &results, meta(&[]));
        assert_eq!(off.gates.len(), 1);
        assert_eq!(off.results.len(), 2, "reserved fixtures never appear");

        let on = build_report(
            &fixtures,
            &results,
            meta(&[
                "aitp-self-attestation",
                "aitp-pinned-admission",
                "aitp-pinned-admission",
            ]),
        );
        assert_eq!(
            on.features_enabled,
            ["aitp-pinned-admission", "aitp-self-attestation"]
        );
        let names: Vec<_> = on.gates.iter().map(|g| (g.name, g.passed)).collect();
        assert_eq!(
            names,
            [
                (CORE_CLAIM, true),
                ("AITP v0.3 pinned-admission", true),
                // Enabled but no fixture covers it: the claim cannot pass.
                ("AITP v0.3 self-attestation", false),
            ]
        );
    }

    #[test]
    fn commit_sha_shape() {
        assert!(is_commit_sha(&"a".repeat(40)));
        assert!(!is_commit_sha(&"A".repeat(40)));
        assert!(!is_commit_sha("8538bf1"));
    }
}
