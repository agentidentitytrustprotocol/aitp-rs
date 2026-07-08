//! Dispatch-layer tests for the conformance adapter.
//!
//! These drive [`aitp_rs_adapter::handle`] in-process — the same entry
//! point `src/main.rs` calls for every NDJSON line — so they exercise
//! the op-routing, request-shape validation, and error envelope
//! conventions without spawning a subprocess. The happy-path op
//! coverage lives in `aitp-conformance`'s `runner_integration.rs`
//! (subprocess); here we pin the protocol *contract*: unknown ops,
//! missing params, `id` echoing, the `ok:false` error shape, and that
//! `AdapterState` persists across calls.

use aitp_rs_adapter::{handle, AdapterState};
use serde_json::{json, Value};

/// Every response echoes the request `id` and carries a boolean `ok`.
fn assert_envelope(resp: &Value, id: &str) {
    assert_eq!(resp["id"], json!(id), "response must echo request id");
    assert!(resp["ok"].is_boolean(), "response must carry a boolean ok");
}

fn assert_err(resp: &Value, id: &str, code: &str) {
    assert_envelope(resp, id);
    assert_eq!(resp["ok"], json!(false), "expected an error response");
    assert_eq!(resp["error_code"], json!(code));
    assert!(
        resp["message"].as_str().is_some(),
        "error responses carry a human-readable message"
    );
}

#[test]
fn init_reports_implementation_and_op_surface() {
    let mut state = AdapterState::default();
    let resp = handle(&mut state, "i1", "init", Value::Null);
    assert_envelope(&resp, "i1");
    assert_eq!(resp["ok"], json!(true));
    let result = &resp["result"];
    assert_eq!(result["implementation"], json!("aitp-rs"));
    assert_eq!(result["version"], json!(env!("CARGO_PKG_VERSION")));

    let ops: Vec<&str> = result["supported_ops"]
        .as_array()
        .expect("supported_ops is an array")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    // A representative op from each tier must be advertised.
    for expected in [
        "verify_jcs",       // Tier A
        "generate_keypair", // Tier B
        "start_handshake",  // Tier C
        "set_clock",        // Tier D
        "verify_session_bundle",
    ] {
        assert!(ops.contains(&expected), "init must advertise {expected}");
    }

    let features: Vec<&str> = result["supported_features"]
        .as_array()
        .expect("supported_features is an array")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(features.contains(&"pinned_key_identity"));
    assert!(features.contains(&"oidc_identity"));
}

/// Every op named in `init.supported_ops` must actually route in
/// `handle` — an advertised-but-unrouted op would land in the catch-all
/// `OP_NOT_SUPPORTED` arm and silently break conformance runs.
#[test]
fn every_advertised_op_is_routed() {
    let mut state = AdapterState::default();
    let init = handle(&mut state, "i", "init", Value::Null);
    let ops: Vec<String> = init["result"]["supported_ops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    for op in ops {
        // Call each op with an empty params object. A routed op either
        // succeeds or returns a *domain* error (missing field, bad
        // input) — never the OP_NOT_SUPPORTED catch-all.
        let resp = handle(&mut state, "probe", &op, json!({}));
        assert_ne!(
            resp["error_code"],
            json!("OP_NOT_SUPPORTED"),
            "advertised op {op} is not routed in handle()"
        );
    }
}

#[test]
fn unknown_op_yields_op_not_supported() {
    let mut state = AdapterState::default();
    let resp = handle(&mut state, "x1", "future_op_reserved_for_v0_3", json!({}));
    assert_err(&resp, "x1", "OP_NOT_SUPPORTED");
}

#[test]
fn missing_required_param_yields_invalid_request() {
    let mut state = AdapterState::default();
    // verify_jcs requires `input`; set_clock requires `now_unix_secs`;
    // set_features requires `features`. Each maps to INVALID_REQUEST.
    assert_err(
        &handle(&mut state, "a", "verify_jcs", json!({})),
        "a",
        "INVALID_REQUEST",
    );
    assert_err(
        &handle(&mut state, "b", "set_clock", json!({})),
        "b",
        "INVALID_REQUEST",
    );
    assert_err(
        &handle(&mut state, "c", "set_features", json!({})),
        "c",
        "INVALID_REQUEST",
    );
}

#[test]
fn response_id_echoes_arbitrary_request_id() {
    let mut state = AdapterState::default();
    for id in ["", "unicode-\u{1f512}", "with spaces", "42"] {
        let resp = handle(&mut state, id, "dump_session", json!({}));
        assert_eq!(resp["id"], json!(id));
    }
}

#[test]
fn verify_jcs_canonicalizes_object() {
    let mut state = AdapterState::default();
    let resp = handle(&mut state, "j", "verify_jcs", json!({"input": {}}));
    assert_eq!(resp["ok"], json!(true));
    // JCS of {} is the two bytes "{}".
    assert_eq!(resp["result"]["canonical_utf8"], json!("{}"));
    assert_eq!(resp["result"]["canonical_hex"], json!("7b7d"));
}

/// `AdapterState` threads across calls: a keypair generated in one call
/// is visible to `dump_session` in a later one, and `set_clock` sticks.
#[test]
fn state_persists_across_calls() {
    let mut state = AdapterState::default();

    let before = handle(&mut state, "d0", "dump_session", json!({}));
    assert_eq!(before["result"]["keypair_count"], json!(0));

    let kp = handle(
        &mut state,
        "g",
        "generate_keypair",
        json!({"seed": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
    );
    assert_eq!(kp["ok"], json!(true));

    handle(
        &mut state,
        "sc",
        "set_clock",
        json!({"now_unix_secs": 1_700_000_000i64}),
    );

    let after = handle(&mut state, "d1", "dump_session", json!({}));
    assert_eq!(after["result"]["keypair_count"], json!(1));
    assert_eq!(after["result"]["now_override"], json!(1_700_000_000i64));
}

/// A verify op fed a syntactically-broken artifact returns a structured
/// error (never a panic / process abort). We can't assert one exact
/// code across every malformed shape, but the response must be a
/// well-formed `ok:false` envelope.
#[test]
fn malformed_artifact_returns_structured_error_not_panic() {
    let mut state = AdapterState::default();

    let cases: &[(&str, Value)] = &[
        (
            "verify_tct",
            json!({"tct_token": "not-a-jws", "expected_audience": "aid:pubkey:x"}),
        ),
        ("verify_manifest", json!({"manifest": "not-an-object"})),
        ("verify_envelope", json!({"envelope": {"garbage": true}})),
        (
            "verify_delegation_token",
            json!({"delegation_token": "..", "verifier_aid": "aid:pubkey:x"}),
        ),
    ];
    for (op, params) in cases {
        let resp = handle(&mut state, "m", op, params.clone());
        assert_envelope(&resp, "m");
        assert_eq!(
            resp["ok"],
            json!(false),
            "op {op} on malformed input should fail cleanly, got {resp}"
        );
        assert!(
            resp["error_code"].as_str().is_some(),
            "op {op} error response must carry an error_code"
        );
    }
}

#[test]
fn shutdown_is_acknowledged() {
    let mut state = AdapterState::default();
    let resp = handle(&mut state, "s", "shutdown", Value::Null);
    assert_envelope(&resp, "s");
    assert_eq!(resp["ok"], json!(true));
}
