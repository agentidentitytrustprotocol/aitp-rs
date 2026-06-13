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
            "{} not found — run `cargo build -p aitp-rs-adapter` first",
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
            side_effects: None,
        }),
    };
    let r = runner.run(&f);
    assert!(matches!(r, FixtureResult::Pass { .. }), "got: {:?}", r);
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
            side_effects: None,
        }),
    };
    let r = runner.run(&f);
    assert!(matches!(r, FixtureResult::Skip { .. }), "got: {:?}", r);
}

#[test]
fn verify_tct_against_adapter_fails_for_random_pubkey_aid() {
    // Build a TCT whose `issuer` AID is a *random* pubkey not signed by
    // the corresponding key — TCT signature verification must fail.
    let issuer = aitp_crypto::AitpSigningKey::from_seed(&[0xA0; 32]);
    let other = aitp_crypto::AitpSigningKey::from_seed(&[0xB0; 32]);
    let subject = aitp_crypto::AitpSigningKey::from_seed(&[0xC0; 32]);
    let tct = aitp_tct::TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["x"])
        .ttl_secs(3600)
        .subject_pubkey(subject.verifying_key())
        .issued_at(aitp_core::Timestamp(1_700_000_000))
        .build()
        .unwrap();
    // Forge the iss claim to a different AID and re-sign nothing — the
    // signature won't verify under the forged issuer's pubkey.
    let payload = aitp_crypto::jws::decode_payload_unverified(&tct.token).unwrap();
    let mut claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    claims["iss"] = serde_json::to_value(other.aid()).unwrap();
    let (header, rest) = tct.token.split_once('.').unwrap();
    let (_, sig) = rest.split_once('.').unwrap();
    let forged = format!(
        "{header}.{}.{sig}",
        aitp_core::base64url::encode(&aitp_core::jcs::canonicalize_serializable(&claims).unwrap())
    );

    let adapter =
        SubprocessAdapter::spawn(adapter_path().to_str().unwrap(), &[]).expect("spawn adapter");
    let mut runner = Runner::new(adapter);
    let f = Fixture {
        id: "tct-forged-issuer".into(),
        rfc: Some("RFC-AITP-0005".into()),
        status: aitp_conformance::fixture::FixtureStatus::Core,
        required_for_v0_1: true,
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
            side_effects: None,
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
    // Alice (the original issuer) verifies the delegation.
    let verify = ok(
        &mut a,
        "verify_delegation_token",
        json!({
            "delegation_token": token,
            "verifier_aid": alice["aid"],
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
