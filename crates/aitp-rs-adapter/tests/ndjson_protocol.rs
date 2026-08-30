//! Raw NDJSON transport tests for the `aitp-rs-adapter` binary.
//!
//! `src/main.rs` owns the stdin/stdout line framing that the
//! in-process `handle()` tests can't reach: blank-line skipping,
//! malformed-JSON handling, one-response-per-line, and clean shutdown.
//! These spawn the real binary and speak the wire protocol to it.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

/// Locate the freshly-built `aitp-rs-adapter` binary next to the test
/// harness (target/<profile>/deps/../aitp-rs-adapter[.exe]). Mirrors
/// the discovery helper in aitp-conformance's runner_integration.rs.
fn adapter_path() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("test exe path");
    let dir = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("target/<profile>/deps");
    let candidate = dir.join(format!("aitp-rs-adapter{}", std::env::consts::EXE_SUFFIX));
    assert!(
        candidate.exists(),
        "{} not found — run `cargo build -p aitp-rs-adapter` first",
        candidate.display()
    );
    candidate
}

/// Feed `input` to the adapter on stdin, close stdin, and collect the
/// non-empty response lines it wrote to stdout.
fn run_lines(input: &str) -> Vec<serde_json::Value> {
    let mut child = Command::new(adapter_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn adapter");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .expect("write stdin");
    // stdin dropped here → EOF, so the adapter's read loop terminates.

    let stdout = child.stdout.take().unwrap();
    let lines: Vec<serde_json::Value> = BufReader::new(stdout)
        .lines()
        .map(|l| l.expect("read line"))
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(&l).expect("adapter emits valid JSON per line"))
        .collect();

    let status = child.wait().expect("wait adapter");
    assert!(status.success(), "adapter exited non-zero: {status:?}");
    lines
}

#[test]
fn malformed_json_line_yields_error_and_stream_continues() {
    // A garbage line, then a valid init. The adapter must answer the
    // garbage with a MALFORMED_REQUEST error AND keep serving the
    // following valid request — one process, two responses.
    let input = "this is not json\n{\"id\":\"a\",\"op\":\"init\"}\n";
    let out = run_lines(input);
    assert_eq!(
        out.len(),
        2,
        "one response per non-empty input line: {out:?}"
    );

    assert_eq!(out[0]["ok"], serde_json::json!(false));
    assert_eq!(out[0]["error_code"], serde_json::json!("MALFORMED_REQUEST"));

    assert_eq!(out[1]["id"], serde_json::json!("a"));
    assert_eq!(out[1]["ok"], serde_json::json!(true));
    assert_eq!(
        out[1]["result"]["implementation"],
        serde_json::json!("aitp-rs")
    );
}

#[test]
fn duplicate_top_level_key_is_rejected_as_malformed_not_silently_accepted() {
    // Issue #140 / RFC-AITP-0001 §5.4.5: a duplicate JSON key anywhere in
    // the request must be rejected, not silently collapsed to its last
    // occurrence by `Value`'s last-write-wins map representation. This is
    // the wire-level regression test for `main.rs`'s raw-line
    // `reject_duplicate_keys` pre-check, ahead of the following valid
    // request continuing to be served.
    let input = concat!(
        "{\"id\":\"dup\",\"op\":\"init\",\"op\":\"shutdown\"}\n",
        "{\"id\":\"ok\",\"op\":\"init\"}\n",
    );
    let out = run_lines(input);
    assert_eq!(out.len(), 2, "one response per input line: {out:?}");
    assert_eq!(out[0]["ok"], serde_json::json!(false));
    assert_eq!(out[0]["error_code"], serde_json::json!("MALFORMED_REQUEST"));
    assert!(
        out[0]["message"]
            .as_str()
            .is_some_and(|m| m.contains("duplicate field `op`")),
        "expected a duplicate-field diagnostic, got: {:?}",
        out[0]["message"]
    );

    assert_eq!(out[1]["id"], serde_json::json!("ok"));
    assert_eq!(out[1]["ok"], serde_json::json!(true));
}

#[test]
fn duplicate_key_nested_inside_envelope_payload_is_rejected() {
    // The duplicate need not be at the request's own top level — it must
    // be caught anywhere in the document, including nested inside
    // `params.envelope.payload`, which downstream dispatch treats as an
    // opaque `serde_json::Value` navigated out of the SAME parsed
    // request document.
    let input = "{\"id\":\"dup\",\"op\":\"verify_envelope\",\"params\":{\"envelope\":{\"payload\":{\"x\":1,\"x\":2}}}}\n";
    let out = run_lines(input);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0]["ok"], serde_json::json!(false));
    assert_eq!(out[0]["error_code"], serde_json::json!("MALFORMED_REQUEST"));
    assert!(
        out[0]["message"]
            .as_str()
            .is_some_and(|m| m.contains("duplicate field `x`")),
        "expected a duplicate-field diagnostic, got: {:?}",
        out[0]["message"]
    );
}

#[test]
fn blank_lines_are_skipped() {
    let input = "\n   \n{\"id\":\"x\",\"op\":\"dump_session\",\"params\":{}}\n\n";
    let out = run_lines(input);
    assert_eq!(out.len(), 1, "blank lines produce no response: {out:?}");
    assert_eq!(out[0]["id"], serde_json::json!("x"));
    assert_eq!(out[0]["ok"], serde_json::json!(true));
}

#[test]
fn missing_id_defaults_to_unknown() {
    // No `id` field → the adapter falls back to the literal "unknown".
    let input = "{\"op\":\"dump_session\",\"params\":{}}\n";
    let out = run_lines(input);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0]["id"], serde_json::json!("unknown"));
    assert_eq!(out[0]["ok"], serde_json::json!(true));
}

#[test]
fn shutdown_stops_the_read_loop() {
    // Lines after `shutdown` must NOT be processed — the loop returns.
    let input = concat!(
        "{\"id\":\"1\",\"op\":\"init\"}\n",
        "{\"id\":\"2\",\"op\":\"shutdown\"}\n",
        "{\"id\":\"3\",\"op\":\"init\"}\n",
    );
    let out = run_lines(input);
    assert_eq!(out.len(), 2, "no response after shutdown: {out:?}");
    assert_eq!(out[0]["id"], serde_json::json!("1"));
    assert_eq!(out[1]["id"], serde_json::json!("2"));
    assert_eq!(out[1]["ok"], serde_json::json!(true));
}
