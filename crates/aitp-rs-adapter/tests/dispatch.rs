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

use aitp_core::Timestamp;
use aitp_crypto::{jws, AitpSigningKey};
use aitp_delegation::DelegationBuilder;
use aitp_rs_adapter::{handle, AdapterState};
use aitp_tct::TctBuilder;
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

/// `verify_delegation_token`'s single-hop `revocation_check` wiring
/// (RFC-AITP-0008 §3.3, `voucher.src_jti`) was previously only exercised
/// by `cargo check` — no fixture actually drove a revoked-then-verified
/// delegation through the adapter. A → B TCT+voucher, B → C delegation,
/// revoke the voucher's `src_jti` via `revoke_tct`, then confirm
/// `verify_delegation_token` reports `DELEGATION_SOURCE_TCT_REVOKED` —
/// and that the same token verifies clean before the revocation lands.
mod single_hop_revocation_check {
    use super::*;

    const NOW: i64 = 1_700_000_000;

    fn a() -> AitpSigningKey {
        AitpSigningKey::from_seed(&[0xA1; 32])
    }
    fn b() -> AitpSigningKey {
        AitpSigningKey::from_seed(&[0xB1; 32])
    }
    fn c() -> AitpSigningKey {
        AitpSigningKey::from_seed(&[0xC1; 32])
    }

    /// Returns (voucher's src_jti, the B->C delegation token).
    fn mint_delegation() -> (String, String) {
        let voucher = TctBuilder::new(&a())
            .subject(b().aid().clone())
            .audience(b().aid().clone())
            .grants(["read_data"])
            .ttl_secs(7200)
            .subject_pubkey(b().verifying_key())
            .issued_at(Timestamp(NOW))
            .build()
            .unwrap()
            .voucher
            .unwrap();
        let payload = jws::decode_payload_unverified(&voucher).unwrap();
        let voucher_claims: aitp_tct::GrantVoucherClaims =
            serde_json::from_slice(&payload).unwrap();
        let token = DelegationBuilder::new(&b(), &voucher)
            .unwrap()
            .delegatee(c().aid().clone())
            .scope(["read_data"])
            .ttl_secs(3600)
            .now(Timestamp(NOW))
            .build()
            .unwrap();
        (voucher_claims.src_jti.to_string(), token)
    }

    #[test]
    fn revoked_source_jti_is_rejected() {
        let mut state = AdapterState::default();
        let (src_jti, token) = mint_delegation();

        handle(
            &mut state,
            "clock",
            "set_clock",
            json!({"now_unix_secs": NOW + 60}),
        );
        let revoke = handle(&mut state, "rev", "revoke_tct", json!({"jti": src_jti}));
        assert_eq!(revoke["ok"], json!(true), "revoke_tct should succeed");

        let resp = handle(
            &mut state,
            "v",
            "verify_delegation_token",
            json!({
                "delegation_token": token,
                "verifier_aid": a().aid().to_string(),
            }),
        );
        assert_err(&resp, "v", "DELEGATION_SOURCE_TCT_REVOKED");
    }

    #[test]
    fn unrevoked_source_jti_verifies() {
        let mut state = AdapterState::default();
        let (_src_jti, token) = mint_delegation();

        handle(
            &mut state,
            "clock",
            "set_clock",
            json!({"now_unix_secs": NOW + 60}),
        );
        let resp = handle(
            &mut state,
            "v",
            "verify_delegation_token",
            json!({
                "delegation_token": token,
                "verifier_aid": a().aid().to_string(),
            }),
        );
        assert_eq!(
            resp["ok"],
            json!(true),
            "expected verification to succeed, got {resp}"
        );
        assert_eq!(resp["result"]["verified"], json!(true));
    }
}

/// `verify_session_bundle`'s wire-form handling
/// (`bundle-004-signature-sibling-rejected`).
///
/// Mints a real coordinator + single-participant bundle through the
/// adapter's own `issue_session_bundle` op, then drives
/// `verify_session_bundle` with both the well-formed wrapped shape and
/// the pre-erratum sibling shape the fixture uses, to confirm the
/// parsing-path change (routing through
/// `aitp_session_bundle::parse_session_bundle_wire`) rejects the latter
/// with `SESSION_BUNDLE_INVALID` while leaving the former unaffected.
mod session_bundle_wire_shape {
    use super::*;

    const NOW: i64 = 1_711_900_000;

    fn coordinator() -> AitpSigningKey {
        AitpSigningKey::from_seed(&[0xC0; 32])
    }
    fn participant() -> AitpSigningKey {
        AitpSigningKey::from_seed(&[0xA1; 32])
    }

    /// Issue a bundle via the adapter and return its `session_bundle`
    /// body (a JSON object with `signature` as a member).
    fn issue_bundle(state: &mut AdapterState) -> Value {
        let coord = coordinator();
        let part = participant();

        let tct = TctBuilder::new(&coord)
            .subject(part.aid().clone())
            .audience(part.aid().clone())
            .grants(["session.participate"])
            .ttl_secs(3600)
            .subject_pubkey(part.verifying_key())
            .issued_at(Timestamp(NOW))
            .build()
            .unwrap()
            .token;

        let gen = handle(
            state,
            "gen",
            "generate_keypair",
            json!({"seed": aitp_core::base64url::encode(&[0xC0; 32])}),
        );
        let handle_name = gen["result"]["handle"]
            .as_str()
            .expect("generate_keypair returns a handle")
            .to_string();

        let resp = handle(
            state,
            "issue",
            "issue_session_bundle",
            json!({
                "coordinator_keypair": handle_name,
                "issued_at": NOW,
                "participants": [
                    {"aid": part.aid().to_string(), "tct": tct},
                ],
            }),
        );
        assert_eq!(
            resp["ok"],
            json!(true),
            "issue_session_bundle should succeed, got {resp}"
        );
        resp["result"]["session_bundle"].clone()
    }

    #[test]
    fn wellformed_wrapped_bundle_verifies() {
        let mut state = AdapterState::default();
        let body = issue_bundle(&mut state);

        let resp = handle(
            &mut state,
            "v",
            "verify_session_bundle",
            json!({
                "session_bundle": { "session_bundle": body },
                "verifier_aid": participant().aid().to_string(),
                "now": NOW + 100,
            }),
        );
        assert_eq!(
            resp["ok"],
            json!(true),
            "well-formed wrapped bundle must still verify, got {resp}"
        );
        assert_eq!(resp["result"]["verified"], json!(true));
    }

    #[test]
    fn sibling_signature_shape_yields_session_bundle_invalid() {
        let mut state = AdapterState::default();
        let mut body = issue_bundle(&mut state);
        let signature = body
            .as_object_mut()
            .unwrap()
            .remove("signature")
            .expect("issued bundle carries a signature");

        // bundle-004-signature-sibling-rejected's exact input shape:
        // `{"session_bundle": {<body sans signature>}, "signature": <sig>}`.
        let resp = handle(
            &mut state,
            "v",
            "verify_session_bundle",
            json!({
                "session_bundle": { "session_bundle": body, "signature": signature },
                "verifier_aid": participant().aid().to_string(),
                "now": NOW + 100,
            }),
        );
        assert_err(&resp, "v", "SESSION_BUNDLE_INVALID");
    }
}
