//! `aitp-conformance run --profile` exit-code gate (#194): spawn the CLI
//! against `aitp-rs-adapter` with a one-fixture corpus whose op the
//! adapter does not support, so the fixture SKIPs (OP_NOT_SUPPORTED).

use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Output;

fn adapter_path() -> PathBuf {
    let exe = std::env::current_exe().expect("test exe path");
    let parent = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("target/<profile>/deps");
    let candidate = parent.join(format!("aitp-rs-adapter{}", std::env::consts::EXE_SUFFIX));
    if !candidate.exists() {
        panic!(
            "{} not found — run `cargo build -p aitp-rs-adapter` first",
            candidate.display()
        );
    }
    candidate
}

/// Write a corpus holding one core fixture that asks for an op the
/// adapter does not declare, carrying the given required flags.
fn corpus(name: &str, v0_1: bool, v0_2: bool) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let fixture = json!({
        "id": "skip-001",
        "status": "core",
        "required_for_v0_1": v0_1,
        "required_for_v0_2": v0_2,
        "feature": null,
        "description": "op the adapter does not support",
        "input": {"operation": "future_op_reserved_for_v0_3"},
        "expected": {"outcome": "success"},
    });
    std::fs::write(
        dir.join("skip-001.json"),
        serde_json::to_vec_pretty(&fixture).unwrap(),
    )
    .unwrap();
    dir
}

fn run(dir: &Path, extra: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_aitp-conformance"))
        .arg("run")
        .arg("--target")
        .arg(adapter_path())
        .arg("--fixtures-dir")
        .arg(dir)
        .args(extra)
        .output()
        .expect("spawn aitp-conformance")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn default_profile_fails_on_skipped_v0_2_required_fixture() {
    let dir = corpus("profile-v0_2-only", false, true);
    let o = run(&dir, &[]);
    assert_eq!(o.status.code(), Some(1), "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).contains("v0.2 conformance gate FAILED — 1 required fixture(s)"),
        "{}",
        stderr(&o)
    );
    assert!(stderr(&o).contains("skip-001: SKIP"), "{}", stderr(&o));

    // Explicit `--profile v0.2` behaves the same as the default.
    let o = run(&dir, &["--profile", "v0.2"]);
    assert_eq!(o.status.code(), Some(1), "stderr: {}", stderr(&o));
}

#[test]
fn v0_1_profile_ignores_v0_2_only_fixture() {
    let dir = corpus("profile-v0_2-only-under-v0_1", false, true);
    let o = run(&dir, &["--profile", "v0.1"]);
    assert_eq!(o.status.code(), Some(0), "stderr: {}", stderr(&o));
    assert!(!stderr(&o).contains("gate FAILED"), "{}", stderr(&o));
}

#[test]
fn v0_1_profile_fails_on_skipped_v0_1_required_fixture() {
    let dir = corpus("profile-v0_1-only", true, false);
    let o = run(&dir, &["--profile", "v0.1"]);
    assert_eq!(o.status.code(), Some(1), "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).contains("v0.1 conformance gate FAILED"),
        "{}",
        stderr(&o)
    );
    // The same fixture is not v0.2-required, so the default run passes.
    let o = run(&dir, &[]);
    assert_eq!(o.status.code(), Some(0), "stderr: {}", stderr(&o));
}

#[test]
fn unknown_profile_is_a_usage_error() {
    let dir = corpus("profile-unknown", true, true);
    let o = run(&dir, &["--profile", "v0.3"]);
    assert_eq!(o.status.code(), Some(2), "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("unknown profile"), "{}", stderr(&o));
}
