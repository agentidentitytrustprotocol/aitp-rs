//! Subprocess conformance adapter for `aitp-rs`.
//!
//! Reads NDJSON requests from stdin, dispatches via the library
//! [`aitp_rs_adapter::handle`], writes NDJSON responses to stdout.
//! See `docs/conformance.md` for the protocol.
//!
//! The dispatch logic lives in `lib.rs` so that the in-process
//! adapter in `aitp-conformance` can call into it without spawning
//! a subprocess.

use aitp_rs_adapter::{handle, AdapterState};
use serde_json::{json, Value};
use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut state = AdapterState::default();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("aitp-rs-adapter: stdin read error: {e}");
                return;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        // RFC-AITP-0001 §5.4.5 / issue #140: a duplicate JSON key anywhere
        // in the request MUST be rejected. Every downstream dispatch path
        // in `aitp_rs_adapter::handle` navigates a `serde_json::Value`
        // built from this line — and `Value`'s object representation is
        // last-write-wins on a duplicate key, which would silently
        // discard the very information needed to reject it. This is the
        // ONLY point in the whole request lifecycle where the original
        // bytes still exist, so the check runs here, before the `Value`
        // this request (and everything nested inside it — `envelope`,
        // `manifest`, `issuer_revocation_list.snapshot`, `session_bundle`,
        // handshake payloads, …) is ever built.
        if let Err(e) = aitp_core::reject_duplicate_keys(line.as_bytes()) {
            let resp = json!({
                "id": "unknown",
                "ok": false,
                "error_code": "MALFORMED_REQUEST",
                "message": e,
            });
            writeln!(out, "{resp}").ok();
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let resp = json!({
                    "id": "unknown",
                    "ok": false,
                    "error_code": "MALFORMED_REQUEST",
                    "message": e.to_string(),
                });
                writeln!(out, "{resp}").ok();
                continue;
            }
        };
        let id = request
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let op = request.get("op").and_then(|v| v.as_str()).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or_default();

        let response = handle(&mut state, id, op, params);
        writeln!(out, "{response}").ok();
        out.flush().ok();
        if op == "shutdown" {
            return;
        }
    }
}
