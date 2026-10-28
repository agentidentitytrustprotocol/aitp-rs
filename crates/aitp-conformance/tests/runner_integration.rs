//! End-to-end runner tests: spawn `aitp-rs-adapter` as a subprocess and
//! exercise Tier A/B/C/D operations against it.

use aitp_conformance::adapter::{subprocess::SubprocessAdapter, Adapter};
use aitp_conformance::fixture::{Fixture, FixtureExpected, FixtureInput, FixtureInputVariant};
use aitp_conformance::runner::{FixtureResult, Runner};
use serde_json::{json, Value};

fn adapter_path() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("test exe path");
    let parent = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("target/<profile>/deps");
    // EXE_SUFFIX is "" on Unix, ".exe" on Windows — without it, this
    // helper silently looks for the wrong filename and every test in
    // this file panics on Windows CI.
    let candidate = parent.join(format!("aitp-rs-adapter{}", std::env::consts::EXE_SUFFIX));
    if !candidate.exists() {
        panic!(
            "{} not found — run `cargo build -p aitp-conformance` first",
            candidate.display()
        );
    }
    candidate
}

#[test]
fn jcs_canonicalize_roundtrip_via_adapter() {
    let adapter =
        SubprocessAdapter::spawn(adapter_path().to_str().unwrap(), &[]).expect("spawn adapter");
    let mut runner = Runner::new(adapter);
    let f = Fixture {
        id: "jcs-001-empty-object".into(),
        rfc: None,
        status: aitp_conformance::fixture::FixtureStatus::Core,
        required_for_v0_1: true,
        required_for_core: true,
        feature: None,
        description: "verify_jcs of {} returns expected canonical bytes".into(),
        tags: vec!["jcs".into()],
        preconditions: serde_json::Value::Null,
        input: FixtureInput {
            operation: None,
            variant: FixtureInputVariant::Single(json!({
                "operation": "verify_jcs",
                "input": {}
            })),
        },
        expected: Some(FixtureExpected {
            outcome: "success".into(),
            error_code: None,
            http_status: None,
            side_effects: None,
            renewed_tct_claims: None,
            renewed_jti_differs: None,
            response: None,
        }),
    };
    let r = runner.run(&f);
    assert!(matches!(r, FixtureResult::Pass { .. }), "got: {:?}", r);
}

/// spec #77: a fixture whose placeholder the runner cannot mint FAILs,
/// even when the adapter's rejection matches the expected outcome, since
/// the adapter rejected the sentinel, not the defect the fixture names.
#[test]
fn unminted_placeholder_fails_the_fixture() {
    let adapter =
        SubprocessAdapter::spawn(adapter_path().to_str().unwrap(), &[]).expect("spawn adapter");
    let mut runner = Runner::new(adapter);
    let f = Fixture {
        id: "unminted-001".into(),
        rfc: None,
        status: aitp_conformance::fixture::FixtureStatus::Core,
        required_for_v0_1: false,
        required_for_core: false,
        feature: None,
        description: "an expected rejection reached only through an unminted placeholder".into(),
        tags: vec![],
        preconditions: serde_json::Value::Null,
        input: FixtureInput {
            operation: None,
            variant: FixtureInputVariant::Single(json!({
                "operation": "verify_tct",
                "tct_token": "__NOT_A_REAL_PLACEHOLDER__",
                "issuer_aid": "aid:pubkey:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "expected_audience": "aid:pubkey:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            })),
        },
        expected: Some(FixtureExpected {
            outcome: "failure".into(),
            error_code: Some("INVALID_ENVELOPE".into()),
            http_status: None,
            side_effects: None,
            renewed_tct_claims: None,
            renewed_jti_differs: None,
            response: None,
        }),
    };
    match runner.run(&f) {
        FixtureResult::Fail { reason, .. } => {
            assert!(reason.contains("__NOT_A_REAL_PLACEHOLDER__"), "{reason}")
        }
        other => panic!("got: {other:?}"),
    }
}

#[test]
fn unsupported_op_yields_skip() {
    let adapter =
        SubprocessAdapter::spawn(adapter_path().to_str().unwrap(), &[]).expect("spawn adapter");
    // Drive init() ourselves so the adapter's supported_ops list is loaded
    // before we ask it about an unknown op.
    let mut adapter = adapter;
    adapter.init().unwrap();
    let mut runner = Runner::new(adapter);
    let f = Fixture {
        id: "unknown-op".into(),
        rfc: None,
        status: aitp_conformance::fixture::FixtureStatus::Core,
        required_for_v0_1: true,
        required_for_core: true,
        feature: None,
        description: "adapter rejects op it does not declare".into(),
        tags: vec![],
        preconditions: serde_json::Value::Null,
        // Canary op that is intentionally NOT in v0.1's vocabulary.
        // Used to confirm the runner SKIPs (rather than FAILs) any
        // fixture asking for an op the adapter doesn't declare.
        // Update this to any other unsupported name if/when v0.2 adds
        // it to the canonical op set.
        input: FixtureInput {
            operation: None,
            variant: FixtureInputVariant::Single(
                json!({"operation": "future_op_reserved_for_v0_2"}),
            ),
        },
        expected: Some(FixtureExpected {
            outcome: "success".into(),
            error_code: None,
            http_status: None,
            side_effects: None,
            renewed_tct_claims: None,
            renewed_jti_differs: None,
            response: None,
        }),
    };
    let r = runner.run(&f);
    assert!(matches!(r, FixtureResult::Skip { .. }), "got: {:?}", r);
}

#[test]
fn verify_tct_against_adapter_fails_for_random_pubkey_aid() {
    // Build a TCT whose `issuer` AID is a *random* pubkey not signed by
    // the corresponding key — TCT signature verification must fail.
    let issuer = aitp::crypto::AitpSigningKey::from_ed25519_seed(&[0xA0; 32]);
    let other = aitp::crypto::AitpSigningKey::from_ed25519_seed(&[0xB0; 32]);
    let subject = aitp::crypto::AitpSigningKey::from_ed25519_seed(&[0xC0; 32]);
    let tct = aitp::tct::TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["x"])
        .ttl(std::time::Duration::from_secs(3600))
        .subject_pubkey(subject.verifying_key())
        .issued_at(aitp::core::Timestamp(1_700_000_000))
        .build()
        .unwrap();
    // Forge the iss claim to a different AID and re-sign nothing — the
    // signature won't verify under the forged issuer's pubkey.
    let payload = aitp::crypto::jws::decode_payload_unverified(tct.token()).unwrap();
    let mut claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    claims["iss"] = serde_json::to_value(other.aid()).unwrap();
    let (header, rest) = tct.token().split_once('.').unwrap();
    let (_, sig) = rest.split_once('.').unwrap();
    let forged = format!(
        "{header}.{}.{sig}",
        aitp::core::base64url::encode(
            &aitp::core::jcs::canonicalize_serializable(&claims).unwrap()
        )
    );

    let adapter =
        SubprocessAdapter::spawn(adapter_path().to_str().unwrap(), &[]).expect("spawn adapter");
    let mut runner = Runner::new(adapter);
    let f = Fixture {
        id: "tct-forged-issuer".into(),
        rfc: Some("RFC-AITP-0005".into()),
        status: aitp_conformance::fixture::FixtureStatus::Core,
        required_for_v0_1: true,
        required_for_core: true,
        feature: None,
        description: "TCT whose issuer AID does not match the signing key fails".into(),
        tags: vec!["tct".into()],
        preconditions: serde_json::Value::Null,
        input: FixtureInput {
            operation: None,
            variant: FixtureInputVariant::Single(json!({
                "operation": "verify_tct",
                "tct_token": forged,
                "expected_audience": subject.aid().as_str(),
                "now": 1_700_000_500i64,
            })),
        },
        expected: Some(FixtureExpected {
            outcome: "failure".into(),
            error_code: Some("TCT_SIGNATURE_INVALID".into()),
            http_status: None,
            side_effects: None,
            renewed_tct_claims: None,
            renewed_jti_differs: None,
            response: None,
        }),
    };
    let r = runner.run(&f);
    assert!(matches!(r, FixtureResult::Pass { .. }), "got: {:?}", r);
}

// ── Tier B/C/D coverage ───────────────────────────────────────────────────
//
// These tests bypass the runner's fixture machinery and drive the
// `Adapter` trait directly with `execute(op, params)`. The runner
// path is exercised by the Tier-A tests above; here we just confirm
// each new op family round-trips through the subprocess protocol.

fn spawn() -> SubprocessAdapter {
    let mut a =
        SubprocessAdapter::spawn(adapter_path().to_str().unwrap(), &[]).expect("spawn adapter");
    a.init().expect("adapter init");
    a
}

fn ok(adapter: &mut SubprocessAdapter, op: &str, params: Value) -> Value {
    use aitp_conformance::adapter::OpResult;
    match adapter.execute(op, params).expect("adapter execute") {
        OpResult::Ok { result, .. } => result,
        OpResult::Err {
            error_code,
            message,
            ..
        } => panic!("op {op} returned error: {error_code} {message}"),
    }
}

#[test]
fn tier_b_generate_keypair_returns_aid_and_pubkey() {
    let mut a = spawn();
    let result = ok(
        &mut a,
        "generate_keypair",
        json!({"seed": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
    );
    assert!(result["handle"].as_str().unwrap().starts_with("kp-"));
    assert!(result["aid"].as_str().unwrap().starts_with("aid:pubkey:"));
    let pk = result["public_key"].as_str().unwrap();
    assert_eq!(pk.len(), 43, "32 bytes -> 43 base64url-unpadded chars");
}

#[test]
fn tier_b_issue_and_verify_tct_round_trip() {
    let mut a = spawn();
    let issuer = ok(
        &mut a,
        "generate_keypair",
        json!({"seed": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
    );
    let subject = ok(
        &mut a,
        "generate_keypair",
        json!({"seed": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"}),
    );
    ok(
        &mut a,
        "set_clock",
        json!({"now_unix_secs": 1_700_000_000i64}),
    );
    let issued = ok(
        &mut a,
        "issue_tct",
        json!({
            "issuer_keypair": issuer["handle"],
            "subject": subject["aid"],
            "audience": subject["aid"],
            "subject_public_key": subject["public_key"],
            "grants": ["demo.echo"],
            "ttl_secs": 3600i64,
            "issued_at": 1_700_000_000i64,
        }),
    );
    let tct = &issued["tct_token"];
    let verify = ok(
        &mut a,
        "verify_tct",
        json!({
            "tct_token": tct,
            "expected_audience": subject["aid"],
            "now": 1_700_000_500i64,
        }),
    );
    assert_eq!(verify["verified"], json!(true));
}

#[test]
fn tier_b_issue_manifest_then_verify_manifest() {
    let mut a = spawn();
    let kp = ok(
        &mut a,
        "generate_keypair",
        json!({"seed": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"}),
    );
    ok(
        &mut a,
        "set_clock",
        json!({"now_unix_secs": 1_700_000_000i64}),
    );
    let issued = ok(
        &mut a,
        "issue_manifest",
        json!({
            "keypair": kp["handle"],
            "handshake_endpoint": "https://a.example.com/handshake",
            "identity_hint": {
                "type": "pinned_key",
                "subject": "alice",
                "public_key": kp["public_key"],
            },
            "accepted_trust_anchors": ["https://idp.example.com"],
            "accepted_identity_types": ["pinned_key"],
            "offered_capabilities": ["demo.echo"],
            "ttl_secs": 3600i64,
            "display_name": "alice",
        }),
    );
    let manifest = &issued["manifest_envelope"]["manifest"];
    let verify = ok(
        &mut a,
        "verify_manifest",
        json!({"manifest": manifest, "now": 1_700_000_500i64}),
    );
    assert_eq!(verify["verified"], json!(true));
}

#[test]
fn tier_b_issue_and_verify_delegation_round_trip() {
    let mut a = spawn();
    let alice = ok(
        &mut a,
        "generate_keypair",
        json!({"seed": "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA"}),
    );
    let bob = ok(
        &mut a,
        "generate_keypair",
        json!({"seed": "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA"}),
    );
    let carol = ok(
        &mut a,
        "generate_keypair",
        json!({"seed": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA"}),
    );
    ok(
        &mut a,
        "set_clock",
        json!({"now_unix_secs": 1_700_000_000i64}),
    );
    // Alice issues TCT to Bob.
    let tct_b = ok(
        &mut a,
        "issue_tct",
        json!({
            "issuer_keypair": alice["handle"],
            "subject": bob["aid"],
            "audience": bob["aid"],
            "subject_public_key": bob["public_key"],
            "grants": ["read", "write"],
            "ttl_secs": 3600i64,
            "issued_at": 1_700_000_000i64,
        }),
    );
    let voucher = &tct_b["grant_voucher"];
    // Bob delegates to Carol (subset of grants).
    let delegation = ok(
        &mut a,
        "issue_delegation_token",
        json!({
            "delegator_keypair": bob["handle"],
            "voucher": voucher,
            "delegatee": carol["aid"],
            "delegatee_public_key": carol["public_key"],
            "scope": ["read"],
            "ttl_secs": 1800i64,
        }),
    );
    let token = &delegation["delegation_token"];
    // Bob publishes his Manifest: Alice verifies the delegation under the
    // key it designates (RFC-AITP-0006 §4 step 1).
    let bob_manifest = ok(
        &mut a,
        "issue_manifest",
        json!({
            "keypair": bob["handle"],
            "handshake_endpoint": "https://b.example.com/handshake",
            "identity_hint": {
                "type": "pinned_key",
                "subject": "bob",
                "public_key": bob["public_key"],
            },
            "accepted_trust_anchors": ["https://idp.example.com"],
            "ttl_secs": 3600i64,
        }),
    );
    // Alice (the original issuer) verifies the delegation.
    let verify = ok(
        &mut a,
        "verify_delegation_token",
        json!({
            "delegation_token": token,
            "verifier_aid": alice["aid"],
            "issuer_manifests": [bob_manifest["manifest_envelope"]],
            "now": 1_700_000_500i64,
        }),
    );
    assert_eq!(verify["verified"], json!(true));
}

#[test]
fn tier_b_sign_envelope_then_verify_envelope() {
    let mut a = spawn();
    let kp = ok(
        &mut a,
        "generate_keypair",
        json!({"seed": "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGA"}),
    );
    ok(
        &mut a,
        "set_clock",
        json!({"now_unix_secs": 1_700_000_000i64}),
    );
    let signed = ok(
        &mut a,
        "sign_envelope",
        json!({
            "keypair": kp["handle"],
            "message_type": "mutual_hello",
            "payload": {"hello": "world"},
        }),
    );
    let envelope = &signed["envelope"];
    let verify = ok(&mut a, "verify_envelope", json!({"envelope": envelope}));
    assert_eq!(verify["verified"], json!(true));
}

/// A declared op that refuses one input at run time with
/// `OP_NOT_SUPPORTED` surfaces as `AdapterError::OpNotSupported`, so the
/// runner SKIPs that fixture instead of failing it (same as the
/// in-process adapter).
#[test]
fn runtime_op_not_supported_maps_to_skip_error() {
    use aitp_conformance::adapter::AdapterError;
    let mut a = spawn();
    let kp = ok(
        &mut a,
        "generate_keypair",
        json!({"seed": "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHA"}),
    );
    let signed = ok(
        &mut a,
        "sign_envelope",
        json!({
            "keypair": kp["handle"],
            "message_type": "mutual_hello",
            "payload": {"hello": "world"},
        }),
    );
    // `verify_handshake_payload` is declared, but a non-kat `self_aid`
    // is a case the adapter does not support.
    let r = a.execute(
        "verify_handshake_payload",
        json!({"envelope": signed["envelope"], "self_aid": kp["aid"]}),
    );
    assert!(
        matches!(r, Err(AdapterError::OpNotSupported(_))),
        "got: {r:?}"
    );
}

#[test]
fn tier_c_revoke_tct_makes_subsequent_verify_fail() {
    let mut a = spawn();
    let issuer = ok(
        &mut a,
        "generate_keypair",
        json!({"seed": "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHA"}),
    );
    let subject = ok(
        &mut a,
        "generate_keypair",
        json!({"seed": "IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII"}),
    );
    ok(
        &mut a,
        "set_clock",
        json!({"now_unix_secs": 1_700_000_000i64}),
    );
    let issued = ok(
        &mut a,
        "issue_tct",
        json!({
            "issuer_keypair": issuer["handle"],
            "subject": subject["aid"],
            "audience": subject["aid"],
            "subject_public_key": subject["public_key"],
            "grants": ["demo.echo"],
            "ttl_secs": 3600i64,
            "issued_at": 1_700_000_000i64,
        }),
    );
    let tct = &issued["tct_token"];
    let jti = issued["tct_claims"]["jti"].as_str().unwrap().to_string();

    // Pre-revocation: verify passes.
    let pre = ok(
        &mut a,
        "verify_tct",
        json!({"tct_token": tct, "expected_audience": subject["aid"], "now": 1_700_000_500i64}),
    );
    assert_eq!(pre["verified"], json!(true));

    // Revoke and verify fails.
    ok(&mut a, "revoke_tct", json!({"jti": jti}));
    use aitp_conformance::adapter::OpResult;
    let post = a
        .execute(
            "verify_tct",
            json!({"tct_token": tct, "expected_audience": subject["aid"], "now": 1_700_000_500i64}),
        )
        .unwrap();
    match post {
        OpResult::Err { error_code, .. } => assert_eq!(error_code, "TCT_REVOKED"),
        OpResult::Ok { .. } => panic!("expected verify_tct to fail after revoke_tct"),
    }
}

#[test]
fn tier_d_set_clock_then_verify_with_default_now_uses_override() {
    // Issue a TCT with `issued_at` set far in the past, and a 60-second
    // TTL. With the wall clock, verify would say "expired"; with
    // `set_clock` rolled back to the issuance time, it should pass.
    let mut a = spawn();
    let issuer = ok(
        &mut a,
        "generate_keypair",
        json!({"seed": "JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJA"}),
    );
    let subject = ok(
        &mut a,
        "generate_keypair",
        json!({"seed": "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKA"}),
    );
    ok(
        &mut a,
        "set_clock",
        json!({"now_unix_secs": 1_700_000_000i64}),
    );
    let issued = ok(
        &mut a,
        "issue_tct",
        json!({
            "issuer_keypair": issuer["handle"],
            "subject": subject["aid"],
            "audience": subject["aid"],
            "subject_public_key": subject["public_key"],
            "grants": ["x"],
            "ttl_secs": 60i64,
            "issued_at": 1_700_000_000i64,
        }),
    );
    let tct = &issued["tct_token"];
    // No explicit `now` — adapter uses its set_clock value, which is
    // still 1_700_000_000, well within the TTL.
    let verify = ok(
        &mut a,
        "verify_tct",
        json!({"tct_token": tct, "expected_audience": subject["aid"]}),
    );
    assert_eq!(verify["verified"], json!(true));
}

#[test]
fn tier_d_dump_session_reports_state() {
    let mut a = spawn();
    let dump = ok(&mut a, "dump_session", json!({}));
    assert_eq!(dump["session_count"], json!(0));
    assert_eq!(dump["keypair_count"], json!(0));
    assert_eq!(dump["revoked_jti_count"], json!(0));
    ok(
        &mut a,
        "generate_keypair",
        json!({"seed": "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLA"}),
    );
    let dump = ok(&mut a, "dump_session", json!({}));
    assert_eq!(dump["keypair_count"], json!(1));
}

#[test]
fn responder_full_handshake_via_two_adapter_processes() {
    // The most rigorous responder-side test: spin up two independent
    // subprocess adapters, configure one as initiator and one as
    // responder, exchange envelopes through the test, and assert both
    // sides hold cross-issued TCTs at the end. This is the
    // closest-to-production-shape conformance check the runner can
    // exercise without a real network.

    let mut alice = spawn();
    let mut bob = spawn();

    // Pin the clock on both so all signed objects reproduce.
    ok(
        &mut alice,
        "set_clock",
        json!({"now_unix_secs": 1_700_000_000i64}),
    );
    ok(
        &mut bob,
        "set_clock",
        json!({"now_unix_secs": 1_700_000_000i64}),
    );

    // Each adapter holds its own keypair.
    let alice_kp = ok(
        &mut alice,
        "generate_keypair",
        json!({"seed": "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMA"}),
    );
    let bob_kp = ok(
        &mut bob,
        "generate_keypair",
        json!({"seed": "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNA"}),
    );

    // Mint each peer's manifest.
    let alice_manifest = ok(
        &mut alice,
        "issue_manifest",
        json!({
            "keypair": alice_kp["handle"],
            "handshake_endpoint": "https://alice.example.com/handshake",
            "identity_hint": {
                "type": "pinned_key",
                "subject": "alice",
                "public_key": alice_kp["public_key"],
            },
            "accepted_trust_anchors": ["https://idp.example.com"],
            "accepted_identity_types": ["pinned_key"],
            "offered_capabilities": ["demo.echo"],
            "ttl_secs": 3600i64,
            "display_name": "alice",
        }),
    );
    let alice_m = &alice_manifest["manifest_envelope"]["manifest"];
    let bob_manifest = ok(
        &mut bob,
        "issue_manifest",
        json!({
            "keypair": bob_kp["handle"],
            "handshake_endpoint": "https://bob.example.com/handshake",
            "identity_hint": {
                "type": "pinned_key",
                "subject": "bob",
                "public_key": bob_kp["public_key"],
            },
            "accepted_trust_anchors": ["https://idp.example.com"],
            "accepted_identity_types": ["pinned_key"],
            "offered_capabilities": ["demo.echo"],
            "ttl_secs": 3600i64,
            "display_name": "bob",
        }),
    );
    let bob_m = &bob_manifest["manifest_envelope"]["manifest"];

    // Bob: start a responder session, awaiting Alice's HELLO.
    let bob_session = ok(
        &mut bob,
        "start_handshake",
        json!({
            "role": "responder",
            "keypair": bob_kp["handle"],
            "manifest": bob_m,
            "requested_grants": ["demo.echo"],
        }),
    );
    let bob_sid = bob_session["session_id"].as_str().unwrap().to_string();

    // Alice: start an initiator session, knowing Bob's manifest.
    let alice_session = ok(
        &mut alice,
        "start_handshake",
        json!({
            "role": "initiator",
            "keypair": alice_kp["handle"],
            "manifest": alice_m,
            "peer_manifest": bob_m,
            "requested_grants": ["demo.echo"],
        }),
    );
    let alice_sid = alice_session["session_id"].as_str().unwrap().to_string();
    let hello_envelope = alice_session["envelope"].clone();

    let bob_ack = ok(
        &mut bob,
        "process_handshake_message",
        json!({"session_id": bob_sid, "envelope": hello_envelope}),
    );
    let hello_ack_envelope = bob_ack["next_envelope"].clone();
    assert_eq!(bob_ack["completed"], json!(false));

    let alice_commit = ok(
        &mut alice,
        "process_handshake_message",
        json!({"session_id": alice_sid, "envelope": hello_ack_envelope}),
    );
    let commit_envelope = alice_commit["next_envelope"].clone();
    assert_eq!(alice_commit["completed"], json!(false));

    let bob_done = ok(
        &mut bob,
        "process_handshake_message",
        json!({"session_id": bob_sid, "envelope": commit_envelope}),
    );
    let commit_ack_envelope = bob_done["next_envelope"].clone();
    assert_eq!(bob_done["completed"], json!(true));
    let bob_holds = &bob_done["held_tct"];
    assert_eq!(bob_holds["tct_claims"]["iss"], json!(alice_kp["aid"]));
    assert_eq!(bob_holds["tct_claims"]["sub"], json!(bob_kp["aid"]));

    let alice_done = ok(
        &mut alice,
        "process_handshake_message",
        json!({"session_id": alice_sid, "envelope": commit_ack_envelope}),
    );
    assert_eq!(alice_done["completed"], json!(true));
    let alice_holds = &alice_done["held_tct"];
    assert_eq!(alice_holds["tct_claims"]["iss"], json!(bob_kp["aid"]));
    assert_eq!(alice_holds["tct_claims"]["sub"], json!(alice_kp["aid"]));
}

/// Records every op request on its way to the real adapter.
struct Recording<A> {
    inner: A,
    requests: std::rc::Rc<std::cell::RefCell<Vec<(String, Value)>>>,
}

impl<A: Adapter> Adapter for Recording<A> {
    fn init(
        &mut self,
    ) -> Result<aitp_conformance::adapter::AdapterInfo, aitp_conformance::adapter::AdapterError>
    {
        self.inner.init()
    }
    fn execute(
        &mut self,
        op: &str,
        params: Value,
    ) -> Result<aitp_conformance::adapter::OpResult, aitp_conformance::adapter::AdapterError> {
        self.requests
            .borrow_mut()
            .push((op.to_string(), params.clone()));
        self.inner.execute(op, params)
    }
    fn shutdown(&mut self) -> Result<(), aitp_conformance::adapter::AdapterError> {
        self.inner.shutdown()
    }
}

type Requests = std::rc::Rc<std::cell::RefCell<Vec<(String, Value)>>>;

fn recording_runner() -> (Runner<Recording<SubprocessAdapter>>, Requests) {
    let inner =
        SubprocessAdapter::spawn(adapter_path().to_str().unwrap(), &[]).expect("spawn adapter");
    let requests = Requests::default();
    let adapter = Recording {
        inner,
        requests: requests.clone(),
    };
    (Runner::new(adapter), requests)
}

/// JSON paths of every `*_claims` key in `v`, at any depth.
fn companion_paths(v: &Value, path: &str, out: &mut Vec<String>) {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                let p = format!("{path}.{k}");
                if k.ends_with("_claims") {
                    out.push(p.clone());
                }
                companion_paths(child, &p, out);
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                companion_paths(child, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
}

fn assert_no_companions(requests: &Requests, context: &str) {
    let mut found = Vec::new();
    for (op, params) in requests.borrow().iter() {
        companion_paths(params, op, &mut found);
    }
    assert!(
        found.is_empty(),
        "{context}: companions reached the adapter: {found:?}"
    );
}

/// No `*_claims` minting companion reaches the adapter, at any depth:
/// not in an envelope payload, a session-bundle participant, a
/// sequence step (or the context merged into it), or a precondition.
#[test]
fn claims_companions_never_reach_the_adapter() {
    let tct_claims = json!({
        "ver": "aitp/0.3",
        "jti": "660e8400-e29b-41d4-a716-446655440106",
        "iss": "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
        "sub": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
        "aud": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
        "iat": 1711900000,
        "exp": 1711903600,
        "grants": ["macp.mode.task.v1"],
        "cnf": { "jkt": "9ZP03Nu8GrXPAUkbKNxHOKBzxPX83SShgFkRNK-f2lw" }
    });
    let fixtures = [
        json!({
            "id": "companions-envelope-and-bundle",
            "description": "companions in an envelope payload and bundle participants",
            "preconditions": { "verify_jcs": { "input": {}, "x_claims": {} } },
            "input": {
                "operation": "verify_jcs",
                "tct": "__JWS_TCT__",
                "tct_claims": tct_claims,
                "envelope": { "payload": { "tct": "__JWS_TCT__", "tct_claims": tct_claims } },
                "session_bundle": {
                    "participants": [{ "tct": "__JWS_TCT__", "tct_claims": tct_claims }]
                },
                "input": {}
            },
            "expected": { "outcome": "success" }
        }),
        json!({
            "id": "companions-sequence",
            "description": "companions in sequence context and steps",
            "input": {
                "operation": "verify_jcs",
                "tct_token": "__JWS_TCT__",
                "tct_token_claims": tct_claims,
                "sequence": [{
                    "step": 1,
                    "input": {},
                    "chain": ["__JWS_TCT__"],
                    "chain_claims": [tct_claims],
                    "expected": { "outcome": "success" }
                }]
            },
            "expected": { "outcome": "success" }
        }),
    ];
    for f in fixtures {
        let f: Fixture = serde_json::from_value(f).expect("fixture parses");
        let (mut runner, requests) = recording_runner();
        runner.run(&f);
        assert!(
            requests.borrow().iter().any(|(op, _)| op == "verify_jcs"),
            "{}: the op never ran",
            f.id
        );
        assert_no_companions(&requests, &f.id);
    }
}

/// The same check over the whole spec corpus, every feature on, when
/// `AITP_CONFORMANCE_FIXTURES` names its directory (CI's `conformance`
/// job sets it to the pinned spec checkout).
#[test]
fn claims_companions_never_reach_the_adapter_across_the_corpus() {
    let Some(dir) = std::env::var_os("AITP_CONFORMANCE_FIXTURES") else {
        eprintln!("AITP_CONFORMANCE_FIXTURES unset; skipping the corpus walk");
        return;
    };
    let fixtures = aitp_conformance::fixture::FixtureLoader::load_dir(std::path::Path::new(&dir))
        .expect("load the fixture corpus");
    let with_companions = fixtures
        .iter()
        .filter(|f| {
            let mut found = Vec::new();
            companion_paths(
                &serde_json::to_value(&f.input).unwrap_or_default(),
                "",
                &mut found,
            );
            !found.is_empty()
        })
        .count();
    assert!(
        with_companions > 0,
        "no fixture in {dir:?} has a companion to strip"
    );
    for f in &fixtures {
        let (runner, requests) = recording_runner();
        let mut runner = [
            "experimental-multihop-delegation",
            "experimental-session-bundle",
            "experimental-spiffe-identity",
            "aitp-pinned-admission",
            "aitp-self-attestation",
        ]
        .into_iter()
        .fold(runner, |r, feature| r.with_feature(feature));
        runner.run(f);
        assert_no_companions(&requests, &f.id);
    }
}
