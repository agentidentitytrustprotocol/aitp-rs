//! `aitp-conformance run --report` (#302): spawn the CLI against
//! `aitp-rs-adapter` on small corpora and check the report against the
//! vendored spec schema (`tests/schemas/aitp-conformance-report.schema.json`)
//! and a golden file. Regenerate the golden with `UPDATE_GOLDEN=1`.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Output;

const SPEC_COMMIT: &str = "8538bf1603d29db699d6f017184ee85922c60eba";

fn adapter_path() -> PathBuf {
    let exe = std::env::current_exe().expect("test exe path");
    let parent = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("target/<profile>/deps");
    let candidate = parent.join(format!("aitp-rs-adapter{}", std::env::consts::EXE_SUFFIX));
    if !candidate.exists() {
        panic!(
            "{} not found — run `cargo build -p aitp-conformance` first",
            candidate.display()
        );
    }
    candidate
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(id: &str, status: &str, feature: Option<&str>, req: bool, op: &str) -> Value {
    json!({
        "id": id,
        "status": status,
        "required_for_v0_1": false,
        "required_for_core": req,
        "feature": feature,
        "description": "report test fixture",
        "input": {"operation": op, "input": {}},
        "expected": {"outcome": "success"},
    })
}

/// A fresh corpus directory holding `fixtures`.
fn corpus(name: &str, fixtures: &[Value]) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("cli_report")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for f in fixtures {
        let id = f["id"].as_str().unwrap();
        std::fs::write(
            dir.join(format!("{id}.json")),
            serde_json::to_vec_pretty(f).unwrap(),
        )
        .unwrap();
    }
    dir
}

/// Core (passes), extension (enabled, passes), draft (not enabled, skips).
fn mini_corpus(name: &str) -> PathBuf {
    corpus(
        name,
        &[
            fixture("core-001", "core", None, true, "verify_jcs"),
            fixture(
                "ext-001",
                "extension",
                Some("aitp-pinned-admission"),
                false,
                "verify_jcs",
            ),
            fixture(
                "drf-001",
                "draft",
                Some("experimental-session-bundle"),
                false,
                "verify_jcs",
            ),
        ],
    )
}

fn run(dir: &Path, report: &Path, extra: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_aitp-conformance"))
        .arg("run")
        .arg("--target")
        .arg(adapter_path())
        .arg("--fixtures-dir")
        .arg(dir)
        .arg("--report")
        .arg(report)
        .args(extra)
        .output()
        .expect("spawn aitp-conformance")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn read_report(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("report written")).unwrap()
}

fn assert_schema_valid(report: &Value) {
    let schema: Value = serde_json::from_slice(
        &std::fs::read(workspace_root().join("tests/schemas/aitp-conformance-report.schema.json"))
            .unwrap(),
    )
    .unwrap();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let errors: Vec<String> = validator
        .iter_errors(report)
        .map(|e| format!("{} at {}", e, e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "report fails the schema: {errors:#?}");
}

#[test]
fn golden_report_on_mini_corpus() {
    let dir = mini_corpus("golden");
    let out_path = dir.with_extension("report.json");
    let out = run(
        &dir,
        &out_path,
        &[
            "--feature",
            "aitp-pinned-admission",
            "--spec-commit",
            SPEC_COMMIT,
            "--spec-version",
            "v0.3.2-draft",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let mut report = read_report(&out_path);
    assert_schema_valid(&report);

    // Normalise what varies run to run.
    let generated_at = report["generated_at"].as_str().unwrap().to_owned();
    assert!(
        generated_at.ends_with('Z') && generated_at.len() == 20,
        "{generated_at}"
    );
    report["generated_at"] = json!("<generated_at>");
    report["implementation"]["version"] = json!("<version>");
    report["runner"]["version"] = json!("<version>");
    for r in report["results"].as_array_mut().unwrap() {
        if r.get("duration_ms").is_some() {
            r["duration_ms"] = json!(0);
        }
    }

    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/report-mini.json");
    let actual = serde_json::to_string_pretty(&report).unwrap() + "\n";
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(golden.parent().unwrap()).unwrap();
        std::fs::write(&golden, &actual).unwrap();
    }
    // A Windows checkout may turn the golden's line endings into CRLF.
    let expected = std::fs::read_to_string(&golden)
        .expect("golden file; run with UPDATE_GOLDEN=1")
        .replace("\r\n", "\n");
    assert_eq!(actual, expected, "report differs from {}", golden.display());
}

#[test]
fn forced_core_skip_fails_the_core_gate() {
    let dir = corpus(
        "core-skip",
        &[
            fixture("core-001", "core", None, true, "verify_jcs"),
            fixture(
                "skip-001",
                "core",
                None,
                true,
                "future_op_reserved_for_v0_3",
            ),
        ],
    );
    let out_path = dir.with_extension("report.json");
    let out = run(
        &dir,
        &out_path,
        &[
            "--spec-commit",
            SPEC_COMMIT,
            "--spec-version",
            "v0.3.2-draft",
        ],
    );
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let report = read_report(&out_path);
    assert_schema_valid(&report);
    assert_eq!(
        report["gates"],
        json!([{
            "name": "AITP v0.3",
            "passed": false,
            "criteria": "core-required-all-pass",
            "blocking": ["skip-001"],
        }])
    );
    assert_eq!(report["totals"]["core"]["skip"], 1);
}

#[test]
fn missing_spec_commit_is_an_error() {
    // The corpus sits in the aitp-rs checkout, not a spec checkout, and
    // no SPEC_VERSION is in or above it, so there is no commit to use.
    let dir = mini_corpus("no-commit");
    let out_path = dir.with_extension("report.json");
    let _ = std::fs::remove_file(&out_path);
    let out = run(&dir, &out_path, &["--spec-version", "v0.3.2-draft"]);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("no spec commit"), "{}", stderr(&out));
    assert!(!out_path.exists(), "no report on a setup error");
}

#[test]
fn spec_version_file_supplies_the_commit() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("cli_report")
        .join("pinned");
    let _ = std::fs::remove_dir_all(&root);
    let dir = root.join("schemas");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("core-001.json"),
        serde_json::to_vec_pretty(&fixture("core-001", "core", None, true, "verify_jcs")).unwrap(),
    )
    .unwrap();
    std::fs::write(root.join("SPEC_VERSION"), format!("{SPEC_COMMIT}\n")).unwrap();
    let out_path = root.join("report.json");
    let out = run(&dir, &out_path, &["--spec-version", "v0.3.2-draft"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert_eq!(read_report(&out_path)["spec"]["commit"], SPEC_COMMIT);
}

#[test]
fn report_rejects_a_partial_run() {
    let dir = mini_corpus("partial");
    let out = run(
        &dir,
        &dir.with_extension("report.json"),
        &["--filter", "core", "--spec-commit", SPEC_COMMIT],
    );
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
}

#[test]
fn corrupting_one_fixture_changes_the_digest() {
    use aitp_conformance::runner::report::fixtures_dir_digest;
    let dir = mini_corpus("digest");
    let before = fixtures_dir_digest(&dir).unwrap();
    // Non-fixture files and subdirectories are outside the digest.
    std::fs::write(dir.join("README.md"), "x").unwrap();
    std::fs::create_dir_all(dir.join("reports")).unwrap();
    std::fs::write(dir.join("reports/r.json"), "{}").unwrap();
    assert_eq!(fixtures_dir_digest(&dir).unwrap(), before);

    let path = dir.join("core-001.json");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(b'\n');
    std::fs::write(&path, bytes).unwrap();
    assert_ne!(fixtures_dir_digest(&dir).unwrap(), before);
}

#[test]
fn digest_matches_the_sha256sum_listing() {
    use aitp_conformance::runner::report::fixtures_dir_digest;
    use sha2::{Digest, Sha256};
    let dir = corpus(
        "listing",
        &[json!({"id": "b"}), json!({"id": "a"}), json!({"id": "Z"})],
    );
    // `LC_ALL=C sha256sum -- *.json | sha256sum`, by hand: byte order
    // puts "Z.json" before "a.json", where a locale collation would not.
    let mut listing = String::new();
    for name in ["Z.json", "a.json", "b.json"] {
        let hash = hex::encode(Sha256::digest(std::fs::read(dir.join(name)).unwrap()));
        listing.push_str(&format!("{hash}  {name}\n"));
    }
    let want = format!("sha256:{}", hex::encode(Sha256::digest(listing.as_bytes())));
    assert_eq!(fixtures_dir_digest(&dir).unwrap(), want);
}
