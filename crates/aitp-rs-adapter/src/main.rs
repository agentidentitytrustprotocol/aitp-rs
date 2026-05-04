//! Subprocess conformance adapter for `aitp-rs`.
//!
//! Reads NDJSON requests from stdin, dispatches via the library
//! [`aitp_rs_adapter::handle`], writes NDJSON responses to stdout.
//! See `docs/design/02-conformance-adapter.md` for the protocol.
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
