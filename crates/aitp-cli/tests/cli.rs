//! End-to-end tests for the `aitp` CLI: run the built binary and assert
//! on its output / exit status.

use std::path::PathBuf;
use std::process::Command;

/// Pinned KAT values (RFC-AITP-0001 known-answer vectors).
const ED25519_ZERO_AID: &str = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";
const P256_KAT005_AID: &str = "aid:pubkey:p256:AweBDql0zqV3PmO4l_N-O-mgnnpf6blxpE0QZawqOpMR";
const ZERO_SEED: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const P256_SEED: &str = "0505050505050505050505050505050505050505050505050505050505050505";

fn aitp() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aitp"))
}

/// Path to a file under the repo's `tests/schemas/known-answer` tree,
/// resolved from the crate dir so CWD doesn't matter.
fn kat(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/schemas/known-answer")
        .join(rel)
}

fn tct_token() -> String {
    let raw = std::fs::read_to_string(kat("signed-examples/tct/kat-keypair-001-issues-002.json"))
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    v["tct_token"].as_str().unwrap().to_string()
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn keygen_from_seed_reproduces_pinned_aids() {
    let out = aitp()
        .args(["keygen", "--seed", ZERO_SEED])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains(ED25519_ZERO_AID), "ed25519 keygen: {s}");
    assert!(s.contains(ZERO_SEED), "seed echoed back: {s}");

    let out = aitp()
        .args(["keygen", "--suite", "p256", "--seed", P256_SEED])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(stdout(&out).contains(P256_KAT005_AID), "p256 keygen");
}

#[test]
fn aid_derives_from_seed() {
    let out = aitp().args(["aid", "--seed", ZERO_SEED]).output().unwrap();
    assert!(out.status.success());
    assert_eq!(stdout(&out).trim(), ED25519_ZERO_AID);
}

#[test]
fn keygen_random_is_valid_and_distinct() {
    let a = stdout(&aitp().arg("keygen").output().unwrap());
    let b = stdout(&aitp().arg("keygen").output().unwrap());
    assert!(a.contains("aid:pubkey:") && b.contains("aid:pubkey:"));
    assert_ne!(a, b, "two random keygens must differ");
}

#[test]
fn bad_seed_exits_nonzero() {
    // Not hex.
    let out = aitp().args(["aid", "--seed", "nothex"]).output().unwrap();
    assert!(!out.status.success());
    // Wrong length.
    let out = aitp().args(["aid", "--seed", "00"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("32 bytes"));
}

#[test]
fn tct_inspect_decodes_claims() {
    let out = aitp()
        .args(["tct", "inspect", "--token", &tct_token()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("\"ver\": \"aitp/0.2\""), "claims JSON: {s}");
    assert!(s.contains("\"grants\""));
}

#[test]
fn tct_verify_ok_at_valid_time() {
    // The KAT token's window is around iat=1711900000; verify inside it.
    let out = aitp()
        .args([
            "tct",
            "verify",
            "--token",
            &tct_token(),
            "--at",
            "1711900500",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout(&out).contains("OK: TCT verifies"));
}

#[test]
fn tct_verify_reads_stdin_and_trims() {
    // Piping via stdin appends a newline; the CLI must trim it.
    use std::process::Stdio;
    let mut child = aitp()
        .args(["tct", "verify", "--token", "-", "--at", "1711900500"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    writeln!(child.stdin.take().unwrap(), "{}", tct_token()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout(&out).contains("OK: TCT verifies"));
}

#[test]
fn tct_verify_wrong_issuer_fails() {
    let out = aitp()
        .args([
            "tct",
            "verify",
            "--token",
            &tct_token(),
            "--at",
            "1711900500",
            "--issuer",
            P256_KAT005_AID,
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "a mismatched issuer must fail verification"
    );
}
