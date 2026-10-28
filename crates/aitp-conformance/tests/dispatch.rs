//! Dispatch-layer tests for the conformance adapter.
//!
//! These drive [`aitp_conformance::rs_adapter::handle`] in-process — the same entry
//! point `src/main.rs` calls for every NDJSON line — so they exercise
//! the op-routing, request-shape validation, and error envelope
//! conventions without spawning a subprocess. The happy-path op
//! coverage lives in `aitp-conformance`'s `runner_integration.rs`
//! (subprocess); here we pin the protocol *contract*: unknown ops,
//! missing params, `id` echoing, the `ok:false` error shape, and that
//! `AdapterState` persists across calls.

use aitp::core::Timestamp;
use aitp::crypto::{jws, AitpSigningKey};
use aitp::delegation::DelegationBuilder;
use aitp::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder, ManifestEnvelope};
use aitp::tct::TctBuilder;
use aitp_conformance::rs_adapter::{handle, AdapterState};
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
        AitpSigningKey::from_ed25519_seed(&[0xA1; 32])
    }
    fn b() -> AitpSigningKey {
        AitpSigningKey::from_ed25519_seed(&[0xB1; 32])
    }
    fn c() -> AitpSigningKey {
        AitpSigningKey::from_ed25519_seed(&[0xC1; 32])
    }

    /// Returns (voucher's src_jti, the B->C delegation token).
    fn mint_delegation() -> (String, String) {
        let voucher = TctBuilder::new(&a())
            .subject(b().aid().clone())
            .audience(b().aid().clone())
            .grants(["read_data"])
            .ttl(std::time::Duration::from_secs(7200))
            .subject_pubkey(b().verifying_key())
            .issued_at(Timestamp(NOW))
            .build()
            .unwrap()
            .voucher
            .unwrap();
        let payload = jws::decode_payload_unverified(&voucher).unwrap();
        let voucher_claims: aitp::tct::GrantVoucherClaims =
            serde_json::from_slice(&payload).unwrap();
        let token = DelegationBuilder::new(&b(), &voucher)
            .unwrap()
            .delegatee(c().aid().clone())
            .scope(["read_data"])
            .ttl(std::time::Duration::from_secs(3600))
            .now(Timestamp(NOW))
            .build()
            .unwrap();
        (voucher_claims.src_jti.to_string(), token)
    }

    /// B's published Manifest envelope: the key source for B's
    /// delegation (RFC-AITP-0006 §4 step 1).
    fn b_manifest() -> Value {
        let manifest = ManifestBuilder::new(&b())
            .handshake_endpoint("https://b.example.com/aitp/handshake".parse().unwrap())
            .identity_hint(
                IdentityHint::new(IdentityHintKind::Oidc, "b")
                    .with_issuer("https://idp.example.com".parse().unwrap()),
            )
            .accept_trust_anchor("https://idp.example.com".parse().unwrap())
            .published_at(Timestamp(NOW))
            .ttl(std::time::Duration::from_secs(3600))
            .build()
            .unwrap();
        serde_json::to_value(ManifestEnvelope::new(manifest)).unwrap()
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
                "issuer_manifests": [b_manifest()],
            }),
        );
        assert_err(&resp, "v", "DELEGATION_SOURCE_TCT_REVOKED");
    }

    /// RFC-AITP-0006 §4 step 1: with no Manifest for B the issuer key
    /// cannot be resolved, so the token is rejected with
    /// `KEY_RESOLUTION_FAILED` (RFC-AITP-0007 §1) rather than verified
    /// under the key B's AID encodes.
    #[test]
    fn missing_issuer_manifest_is_key_resolution_failed() {
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
        assert_err(&resp, "v", "KEY_RESOLUTION_FAILED");
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
                "issuer_manifests": [b_manifest()],
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
/// `aitp_experimental::session_bundle::parse_session_bundle_wire`) rejects the latter
/// with `SESSION_BUNDLE_INVALID` while leaving the former unaffected.
mod session_bundle_wire_shape {
    use super::*;

    const NOW: i64 = 1_711_900_000;

    fn coordinator() -> AitpSigningKey {
        AitpSigningKey::from_ed25519_seed(&[0xC0; 32])
    }
    fn participant() -> AitpSigningKey {
        AitpSigningKey::from_ed25519_seed(&[0xA1; 32])
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
            .ttl(std::time::Duration::from_secs(3600))
            .subject_pubkey(part.verifying_key())
            .issued_at(Timestamp(NOW))
            .build()
            .unwrap()
            .token;

        let gen = handle(
            state,
            "gen",
            "generate_keypair",
            json!({"seed": aitp::core::base64url::encode(&[0xC0; 32])}),
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
                "coordinator_manifest": manifest_envelope(&coordinator(), 24 * 3600),
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

    /// `bundle-006-unknown-field-rejected`'s shape: an unknown member of
    /// the INNER body (not a wrapper sibling, not inside `extensions`)
    /// is the body-level `UNKNOWN_FIELD` class, distinct from the
    /// wrapper-level `SESSION_BUNDLE_INVALID` case above.
    #[test]
    fn unknown_body_member_yields_unknown_field() {
        let mut state = AdapterState::default();
        let mut body = issue_bundle(&mut state);
        body.as_object_mut()
            .unwrap()
            .insert("coordinator_note".into(), json!("primary-region"));

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
        assert_err(&resp, "v", "UNKNOWN_FIELD");
    }

    fn manifest_envelope(key: &AitpSigningKey, ttl_secs: u64) -> Value {
        use aitp::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder, ManifestEnvelope};
        let manifest = ManifestBuilder::new(key)
            .display_name("coordinator")
            .handshake_endpoint("https://coord.example/handshake".parse().unwrap())
            .identity_hint(
                IdentityHint::new(IdentityHintKind::PinnedKey, "coordinator")
                    .with_public_key(key.aid().identifier().to_string()),
            )
            .offer("session.coordinate")
            .published_at(Timestamp(NOW))
            .ttl(std::time::Duration::from_secs(ttl_secs))
            .build()
            .unwrap();
        serde_json::to_value(ManifestEnvelope::new(manifest)).unwrap()
    }

    /// RFC-AITP-0010 §5 step 5 (issues #197, #238): the
    /// `coordinator_manifest` is required, verified, and must be the
    /// coordinator's.
    #[test]
    fn coordinator_manifest_is_verified() {
        let mut state = AdapterState::default();
        let body = issue_bundle(&mut state);
        let verify = |state: &mut AdapterState, manifest: Value| {
            handle(
                state,
                "v",
                "verify_session_bundle",
                json!({
                    "session_bundle": { "session_bundle": body.clone() },
                    "verifier_aid": participant().aid().to_string(),
                    "now": NOW + 100,
                    "coordinator_manifest": manifest,
                }),
            )
        };

        let ok = verify(&mut state, manifest_envelope(&coordinator(), 24 * 3600));
        assert_eq!(ok["ok"], json!(true), "got {ok}");

        // The bare Manifest body (the `bundle-*` fixtures' shape) is
        // accepted as well as the `{"manifest": …}` envelope.
        let bare = manifest_envelope(&coordinator(), 24 * 3600)["manifest"].clone();
        let ok = verify(&mut state, bare);
        assert_eq!(ok["ok"], json!(true), "got {ok}");

        // bundle-007: a Manifest for another AID resolves no coordinator
        // key (RFC-AITP-0007 §1).
        let other = AitpSigningKey::from_ed25519_seed(&[0x77; 32]);
        let resp = verify(&mut state, manifest_envelope(&other, 24 * 3600));
        assert_err(&resp, "v", "KEY_RESOLUTION_FAILED");

        let resp = verify(&mut state, manifest_envelope(&coordinator(), 50));
        assert_err(&resp, "v", "MANIFEST_EXPIRED");
    }

    /// `bundle-008-version-unknown`'s shape: a validly signed bundle
    /// whose `version` is changed afterwards to `aitp/9.9`, so its
    /// signature no longer verifies either. `version` is checked before
    /// the signature (RFC-AITP-0010 §5 step 1), so the code is the
    /// bundle's unknown-version code (spec VERSIONING.md), not
    /// `BUNDLE_INVALID_SIGNATURE`.
    #[test]
    fn unknown_version_beats_invalid_signature() {
        let mut state = AdapterState::default();
        let mut body = issue_bundle(&mut state);
        body["version"] = json!("aitp/9.9");

        let resp = handle(
            &mut state,
            "v",
            "verify_session_bundle",
            json!({
                "session_bundle": { "session_bundle": body },
                "verifier_aid": participant().aid().to_string(),
                "now": NOW + 100,
                "coordinator_manifest": manifest_envelope(&coordinator(), 24 * 3600),
            }),
        );
        assert_err(&resp, "v", "BUNDLE_VERSION_MISMATCH");
    }

    /// #238: there is no AID-only fallback. A bundle that would verify
    /// under the coordinator's AID is still rejected without its
    /// Manifest, as KEY_RESOLUTION_FAILED (RFC-AITP-0010 §5 step 5).
    #[test]
    fn missing_coordinator_manifest_is_key_resolution_failed() {
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
        assert_err(&resp, "v", "KEY_RESOLUTION_FAILED");
    }
}

/// A rate-limited presentation is answered with `http_status` 429 and no
/// `error_code`; `begin_fixture` drops the fixture's verifier, so its
/// limiter state does not reach the next fixture.
#[test]
fn presentation_rate_limit_is_http_429_and_begin_fixture_resets() {
    let mut state = AdapterState::default();
    let params = json!({
        "self_aid": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
        "trust_store": [],
        "presentation_rate_limit": {"per_source": 1, "window_seconds": 60},
        "source": "198.51.100.7",
        "envelope": {},
    });
    let first = handle(
        &mut state,
        "p1",
        "verify_identity_presentation",
        params.clone(),
    );
    // `{}` has no `version`: RFC-AITP-0001 §5.4 check order step 1.
    assert_err(&first, "p1", "UNKNOWN_VERSION");
    let second = handle(
        &mut state,
        "p2",
        "verify_identity_presentation",
        params.clone(),
    );
    assert_envelope(&second, "p2");
    assert_eq!(second["ok"], json!(false));
    assert_eq!(second["http_status"], json!(429));
    assert!(second.get("error_code").is_none(), "{second}");

    let begin = handle(&mut state, "b", "begin_fixture", json!({}));
    assert_eq!(begin["ok"], json!(true));
    let third = handle(&mut state, "p3", "verify_identity_presentation", params);
    assert_err(&third, "p3", "UNKNOWN_VERSION");
}

/// RFC-AITP-0002 §3.4 (spec cfd2f16): a full nonce store is reported as
/// `CHALLENGE_REFUSED` (id-016), while a rate-limited challenge request
/// is `http_status` 429 with no `error_code`.
#[test]
fn challenge_refusal_is_a_code_and_challenge_rate_limit_is_http_429() {
    let aid = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";
    let mut state = AdapterState::default();
    let bound = json!({"self_aid": aid, "max_outstanding_nonces": 1, "source": "198.51.100.7"});
    let first = handle(
        &mut state,
        "c1",
        "issue_presentation_challenge",
        bound.clone(),
    );
    assert_eq!(first["ok"], json!(true), "{first}");
    let refused = handle(&mut state, "c2", "issue_presentation_challenge", bound);
    assert_err(&refused, "c2", "CHALLENGE_REFUSED");
    assert!(refused.get("http_status").is_none(), "{refused}");

    let mut state = AdapterState::default();
    let open = json!({"self_aid": aid, "source": "198.51.100.8"});
    for i in 0..aitp::handshake::admission::RecommendedLimiter::PER_TRANSPORT_PER_MINUTE {
        let r = handle(
            &mut state,
            &format!("o{i}"),
            "issue_presentation_challenge",
            open.clone(),
        );
        assert_eq!(r["ok"], json!(true), "{r}");
    }
    let limited = handle(&mut state, "l", "issue_presentation_challenge", open);
    assert_envelope(&limited, "l");
    assert_eq!(limited["ok"], json!(false));
    assert_eq!(limited["http_status"], json!(429));
    assert!(limited.get("error_code").is_none(), "{limited}");
}

/// RFC-AITP-0005 §10.5: `verify_tct_as_issuer` — the issuer receives
/// back a TCT it issued, answered by one `pop_response`. The presenter
/// AID comes from the PoP, and revocation is checked last.
mod verify_tct_as_issuer {
    use super::*;
    use aitp::core::{parse_envelope_wire, Timestamp};
    use aitp::tct::{sign_pop_response, PopChallenge};

    const NOW: i64 = 1_711_900_000;

    fn issuer() -> AitpSigningKey {
        AitpSigningKey::from_ed25519_seed(&[0xA1; 32])
    }
    fn holder() -> AitpSigningKey {
        AitpSigningKey::from_ed25519_seed(&[0xB1; 32])
    }
    fn stranger() -> AitpSigningKey {
        AitpSigningKey::from_ed25519_seed(&[0xC1; 32])
    }

    /// (token, jti): a TCT the issuer granted to the holder.
    fn issued() -> (String, String) {
        let tct = TctBuilder::new(&issuer())
            .subject(holder().aid().clone())
            .audience(holder().aid().clone())
            .grants(["macp.mode.task.v1"])
            .ttl(std::time::Duration::from_secs(3600))
            .subject_pubkey(holder().verifying_key())
            .issued_at(Timestamp(NOW - 60))
            .build()
            .unwrap();
        (tct.token, tct.claims.jti.to_string())
    }

    fn challenge(jti: &str, expires_at: i64) -> PopChallenge {
        PopChallenge::new(
            jti.parse().unwrap(),
            "ISIjJCUmJygpKissLS4vMA",
            Timestamp(expires_at),
        )
    }

    /// A `pop_response` envelope from `sender`, the PoP signed by `pop_key`.
    fn envelope(sender: &AitpSigningKey, pop_key: &AitpSigningKey, ch: &PopChallenge) -> Value {
        let response = sign_pop_response(ch, pop_key).unwrap();
        let mut wire = json!({
            "version": "aitp/0.3",
            "message_type": "pop_response",
            "message_id": "22222222-2222-4222-8222-222222220029",
            "timestamp": NOW,
            "sender": {"agent_id": sender.aid().to_string()},
            "payload": serde_json::to_value(&response).unwrap(),
            // Placeholder that parses; the digest excludes `signature`.
            "signature": "A".repeat(86),
        });
        let parsed = parse_envelope_wire(&wire.to_string().parse().unwrap()).unwrap();
        let digest = aitp::core::envelope_signing_digest(&parsed).unwrap();
        let sig = sender.sign_jcs(&aitp::crypto::Digest32::from(digest));
        wire["signature"] = json!(sig.as_str());
        wire
    }

    fn verify(state: &mut AdapterState, token: &str, ch: &PopChallenge, env: Value) -> Value {
        handle(state, "clock", "set_clock", json!({"now_unix_secs": NOW}));
        handle(
            state,
            "v",
            "verify_tct_as_issuer",
            json!({
                "self_aid": issuer().aid().to_string(),
                "tct_token": token,
                "outstanding_pop_challenges": [serde_json::to_value(ch).unwrap()],
                "envelope": env,
            }),
        )
    }

    #[test]
    fn holder_with_valid_pop_is_authorized() {
        let (token, jti) = issued();
        let ch = challenge(&jti, NOW + 30);
        let resp = verify(
            &mut AdapterState::default(),
            &token,
            &ch,
            envelope(&holder(), &holder(), &ch),
        );
        assert_eq!(resp["ok"], json!(true), "{resp}");
        assert_eq!(
            resp["result"]["presenter_aid"],
            json!(holder().aid().to_string())
        );
        assert_eq!(resp["result"]["grants"], json!(["macp.mode.task.v1"]));
        assert_eq!(
            resp["result"]["side_effects"]["capability_authorized"],
            json!(true)
        );
    }

    #[test]
    fn token_issued_by_another_agent_is_refused() {
        let (token, jti) = issued();
        let ch = challenge(&jti, NOW + 30);
        let mut state = AdapterState::default();
        handle(
            &mut state,
            "clock",
            "set_clock",
            json!({"now_unix_secs": NOW}),
        );
        let resp = handle(
            &mut state,
            "v",
            "verify_tct_as_issuer",
            json!({
                "self_aid": stranger().aid().to_string(),
                "tct_token": token,
                "outstanding_pop_challenges": [serde_json::to_value(&ch).unwrap()],
                "envelope": envelope(&holder(), &holder(), &ch),
            }),
        );
        assert_err(&resp, "v", "TCT_SIGNATURE_INVALID");
    }

    #[test]
    fn pop_from_a_non_subject_is_refused() {
        let (token, jti) = issued();
        let ch = challenge(&jti, NOW + 30);
        let resp = verify(
            &mut AdapterState::default(),
            &token,
            &ch,
            envelope(&stranger(), &stranger(), &ch),
        );
        assert_err(&resp, "v", "POP_RESPONSE_INVALID");
    }

    #[test]
    fn no_outstanding_challenge_for_the_jti_is_refused() {
        let (token, _) = issued();
        let other = challenge("00000000-0000-4000-8000-000000000000", NOW + 30);
        let resp = verify(
            &mut AdapterState::default(),
            &token,
            &other,
            envelope(&holder(), &holder(), &other),
        );
        assert_err(&resp, "v", "POP_RESPONSE_INVALID");
    }

    #[test]
    fn expired_challenge_is_refused() {
        let (token, jti) = issued();
        let ch = challenge(&jti, NOW - 50);
        let resp = verify(
            &mut AdapterState::default(),
            &token,
            &ch,
            envelope(&holder(), &holder(), &ch),
        );
        assert_err(&resp, "v", "POP_CHALLENGE_INVALID");
    }

    #[test]
    fn revocation_is_checked_after_a_valid_pop() {
        let (token, jti) = issued();
        let ch = challenge(&jti, NOW + 30);
        let mut state = AdapterState::default();
        handle(&mut state, "rev", "revoke_tct", json!({"jti": jti}));
        let resp = verify(&mut state, &token, &ch, envelope(&holder(), &holder(), &ch));
        assert_err(&resp, "v", "TCT_REVOKED");
        // A bad PoP on a revoked token still reports the PoP failure.
        let resp = verify(
            &mut state,
            &token,
            &ch,
            envelope(&holder(), &stranger(), &ch),
        );
        assert_err(&resp, "v", "POP_RESPONSE_INVALID");
    }
}
