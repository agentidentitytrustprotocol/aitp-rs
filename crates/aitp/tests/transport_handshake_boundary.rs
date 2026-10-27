//! P13 — boundary checks on the handshake server.
//!
//! Asserts that wrong Content-Type, malformed JSON, stale timestamp,
//! replayed message_id, and unknown message_type all yield AITP error
//! envelopes (`{ "error": { "code": "...", "message": "..." } }`).

#![cfg(all(feature = "http-client", feature = "http-server"))]

use aitp::core::{MessageType, Sender, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp::transport::{sign_envelope_with, HandshakeServer};
use serde_json::Value;
use tokio::net::TcpListener;
use uuid::Uuid;

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn manifest_for(key: &AitpSigningKey, name: &str) -> aitp::manifest::Manifest {
    ManifestBuilder::new(key)
        .display_name(name)
        .handshake_endpoint("https://example.com/aitp/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: name.into(),
            issuer: None,
            public_key: Some(aitp::core::base64url::encode(
                &key.verifying_key()
                    .try_to_ed25519_bytes()
                    .expect("key was constructed as Ed25519, never P-256"),
            )),
        })
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .build()
        .unwrap()
}

async fn spawn_server() -> u16 {
    let server_key = AitpSigningKey::from_seed(&[0xCC; 32]);
    let manifest = manifest_for(&server_key, "responder");
    let server = HandshakeServer::new(
        server_key,
        manifest,
        vec!["https://idp.example.com".parse().unwrap()],
        NoOpResolver,
        vec!["demo.echo".into()],
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, server.router()).await.ok();
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    port
}

async fn assert_error_code(resp: reqwest::Response, expected: &str) {
    assert_eq!(resp.status().as_u16(), 400, "expected 400 for {expected}");
    let body: Value = resp.json().await.unwrap();
    let code = body
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str())
        .unwrap_or_default();
    assert_eq!(code, expected, "got body: {body}");
}

#[tokio::test]
async fn wrong_content_type_returns_invalid_envelope() {
    let port = spawn_server().await;
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .header(reqwest::header::CONTENT_TYPE, "text/plain")
        .body("hello")
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "INVALID_ENVELOPE").await;
}

#[tokio::test]
async fn malformed_json_returns_invalid_envelope() {
    let port = spawn_server().await;
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "INVALID_ENVELOPE").await;
}

#[tokio::test]
async fn stale_timestamp_returns_timestamp_expired() {
    let port = spawn_server().await;
    let key = AitpSigningKey::from_seed(&[0xAB; 32]);
    let mut envelope = sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({}),
        Uuid::new_v4(),
        Timestamp(Timestamp::now().0 - 7200), // 2 h in the past
    )
    .unwrap();
    envelope.sender = Sender {
        agent_id: key.aid().clone(),
    };
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .json(&envelope)
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "TIMESTAMP_EXPIRED").await;
}

#[tokio::test]
async fn replayed_message_id_returns_replay_detected() {
    let port = spawn_server().await;
    let key = AitpSigningKey::from_seed(&[0xAD; 32]);
    let mid = Uuid::new_v4();
    let envelope = sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({}),
        mid,
        Timestamp::now(),
    )
    .unwrap();
    let url = format!("http://127.0.0.1:{port}/aitp/handshake/hello");
    let client = reqwest::Client::new();
    // First call: rejected for malformed payload (because we sent {})
    // — but the message_id IS recorded before payload parsing in the
    // boundary path. Re-sending the same envelope should now hit the
    // replay deny list before payload parsing.
    let _ = client.post(&url).json(&envelope).send().await.unwrap();
    let resp = client.post(&url).json(&envelope).send().await.unwrap();
    assert_error_code(resp, "REPLAY_DETECTED").await;
}

#[tokio::test]
async fn unknown_envelope_version_returns_unknown_version() {
    // RFC-AITP-0001 §5.6: "Verifiers receiving an unknown `version`
    // MUST respond with `UNKNOWN_VERSION`." We simulate a forward-
    // version client by hand-rolling the envelope JSON; the server
    // should reject before any payload parsing.
    let port = spawn_server().await;
    let key = AitpSigningKey::from_seed(&[0xCF; 32]);
    let mut envelope = sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({}),
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .unwrap();
    envelope.version = "aitp/9.9".into();
    // The signature won't match the new version — that's OK; the
    // version check fires before signature verification.
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .json(&envelope)
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "UNKNOWN_VERSION").await;
}

/// Phase 7b headline test (issue #140): a real HTTP POST carrying an
/// envelope with an unknown top-level member must be rejected with
/// `UNKNOWN_FIELD`, not the generic `INVALID_ENVELOPE` a bare
/// `serde_json::from_slice::<AitpEnvelope>` would have produced. No
/// conformance fixture covers the live HTTP server, so this integration
/// test is the only thing that pins the behavior on this surface.
#[tokio::test]
async fn unknown_top_level_envelope_member_returns_unknown_field() {
    let port = spawn_server().await;
    let key = AitpSigningKey::from_seed(&[0xD0; 32]);
    let envelope = sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({}),
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .unwrap();
    let mut wire = serde_json::to_value(&envelope).unwrap();
    wire.as_object_mut()
        .unwrap()
        .insert("coordinator_note".to_string(), serde_json::json!("rogue"));
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&wire).unwrap())
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "UNKNOWN_FIELD").await;
}

/// RFC-AITP-0001 §5.4.5 / issue #140: a duplicate top-level key in the
/// posted envelope body must be rejected as malformed, not silently
/// collapsed to its last occurrence by `serde_json::Value` and accepted.
/// Deliberately raw text (not built via `serde_json::json!`/`Value`,
/// which cannot even represent a duplicate key) posted straight to the
/// live HTTP surface `receive_envelope` guards.
#[tokio::test]
async fn duplicate_top_level_envelope_member_is_rejected_not_silently_accepted() {
    let port = spawn_server().await;
    let key = AitpSigningKey::from_seed(&[0xD2; 32]);
    let envelope = sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({}),
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .unwrap();
    let good = serde_json::to_string(&envelope).unwrap();
    let needle = "\"version\":\"aitp/0.3\",";
    assert!(good.contains(needle), "fixture shape changed: {good}");
    let dup_body = good.replacen(needle, &format!("{needle}{needle}"), 1);

    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(dup_body)
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "INVALID_ENVELOPE").await;
}

/// Same defect, but nested inside the handshake payload rather than at
/// the envelope's own top level — proving the raw-bytes guard in
/// `receive_envelope` protects the WHOLE document, including
/// everything the `MUTUAL_HELLO` payload's own `check_members` call
/// later navigates as an already-parsed `serde_json::Value`.
#[tokio::test]
async fn duplicate_key_nested_inside_hello_payload_is_rejected_not_silently_accepted() {
    let port = spawn_server().await;
    let key = AitpSigningKey::from_seed(&[0xD3; 32]);
    let envelope = sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({"pop_nonce": "AAAAAAAAAAAAAAAAAAAAAA"}),
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .unwrap();
    let good = serde_json::to_string(&envelope).unwrap();
    let needle = "\"pop_nonce\":\"AAAAAAAAAAAAAAAAAAAAAA\"";
    assert!(good.contains(needle), "fixture shape changed: {good}");
    let dup_body = good.replacen(needle, &format!("{needle},{needle}"), 1);

    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(dup_body)
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "INVALID_ENVELOPE").await;
}

/// AC 2: a *structurally valid* envelope (no unknown envelope-level
/// member) whose `mutual_hello` payload carries an unknown sibling
/// member must likewise be reported as `UNKNOWN_FIELD` — the member-set
/// check on `MutualHelloPayload` runs before typed deserialization, so
/// the required fields being absent never masks the unknown-field
/// rejection.
#[tokio::test]
async fn unknown_hello_payload_sibling_member_returns_unknown_field() {
    let port = spawn_server().await;
    let key = AitpSigningKey::from_seed(&[0xD1; 32]);
    let envelope = sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({ "rogue_sibling": true }),
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .unwrap();
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .json(&envelope)
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "UNKNOWN_FIELD").await;
}

/// AC 3 (regression pin): an envelope that is both forward-versioned AND
/// structurally clean (every top-level member is schema-declared,
/// payload has no unknown sibling) reports `UNKNOWN_VERSION`.
/// Complements `unknown_envelope_version_returns_unknown_version` above
/// and `version_is_checked_before_member_set_and_signature` below.
#[tokio::test]
async fn forward_version_structurally_clean_envelope_returns_unknown_version_not_unknown_field() {
    let port = spawn_server().await;
    let key = AitpSigningKey::from_seed(&[0xD2; 32]);
    let mut envelope = sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({}),
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .unwrap();
    envelope.version = "aitp/9.9".into();
    // Round-trip through a raw `Value` (rather than relying on
    // `AitpEnvelope`'s own `Serialize`) to exercise exactly the wire
    // shape `parse_envelope_wire` sees — every top-level key present,
    // none extra, `version` merely holding a forward value.
    let wire = serde_json::to_value(&envelope).unwrap();
    assert_eq!(
        wire.as_object().unwrap().keys().count(),
        7,
        "envelope must carry exactly its declared top-level members \
         (version, message_type, message_id, timestamp, sender, payload, \
         signature) with `extensions` omitted (absent, not `{{}}`) — a \
         drifted count would invalidate the 'structurally clean' premise \
         of this test"
    );
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&wire).unwrap())
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "UNKNOWN_VERSION").await;
}

/// RFC-AITP-0001 §5.4 envelope check order over HTTP: `version` is
/// checked before the member set and the signature (env-010), so an
/// unknown version beside an unknown sibling member and a broken
/// signature is `UNKNOWN_VERSION`; a correctly signed `aitp/0.2`
/// envelope is `UNKNOWN_VERSION` too (env-011, strict cutover); with the
/// version known, the unknown member is `UNKNOWN_FIELD`.
#[tokio::test]
async fn version_is_checked_before_member_set_and_signature() {
    let port = spawn_server().await;
    let key = AitpSigningKey::from_seed(&[0xD3; 32]);
    let post = |wire: serde_json::Value| async move {
        reqwest::Client::new()
            .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&wire).unwrap())
            .send()
            .await
            .unwrap()
    };
    let fresh = || {
        sign_envelope_with(
            &key,
            MessageType::MutualHello,
            serde_json::json!({}),
            Uuid::new_v4(),
            Timestamp::now(),
        )
        .unwrap()
    };

    let mut wire = serde_json::to_value(fresh()).unwrap();
    wire["version"] = "aitp/9.9".into();
    wire["trace_id"] = "rogue".into();
    assert_error_code(post(wire).await, "UNKNOWN_VERSION").await;

    // Correctly signed under the v2 input, but at the previous revision.
    let mut prev = fresh();
    prev.version = "aitp/0.2".into();
    let d = aitp::core::envelope::envelope_signing_digest(&prev).unwrap();
    prev.signature = key
        .sign_jcs(&aitp::crypto::Digest32::from_bytes(d))
        .into_string();
    assert_error_code(
        post(serde_json::to_value(&prev).unwrap()).await,
        "UNKNOWN_VERSION",
    )
    .await;

    let mut known = serde_json::to_value(fresh()).unwrap();
    known["trace_id"] = "rogue".into();
    assert_error_code(post(known).await, "UNKNOWN_FIELD").await;
}

/// POST `wire` to the hello route with `content_type`.
async fn post_hello(port: u16, content_type: &str, wire: &Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .header(reqwest::header::CONTENT_TYPE, content_type)
        .body(serde_json::to_vec(wire).unwrap())
        .send()
        .await
        .unwrap()
}

/// A signed MUTUAL_HELLO as wire JSON, `age_secs` in the past.
fn hello_wire(seed: u8, mid: Uuid, age_secs: i64) -> Value {
    let key = AitpSigningKey::from_seed(&[seed; 32]);
    let envelope = sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({}),
        mid,
        Timestamp(Timestamp::now().0 - age_secs),
    )
    .unwrap();
    serde_json::to_value(&envelope).unwrap()
}

/// Issue #255, RFC-AITP-0009 §3.1 / RFC-AITP-0001 §5.4: the replay deny
/// list runs before `version` and the member set, so a replayed
/// `message_id` is `REPLAY_DETECTED` even when the copy is also
/// malformed or carries an unknown or absent `version`.
#[tokio::test]
async fn replay_is_checked_before_version_and_structure() {
    let port = spawn_server().await;
    let mid = Uuid::new_v4();
    let first = hello_wire(0xE0, mid, 0);
    // Fresh: recorded, then rejected later for its empty payload.
    let resp = post_hello(port, "application/json", &first).await;
    assert_error_code(resp, "INVALID_ENVELOPE").await;

    let mut unknown_member = first.clone();
    unknown_member["trace_id"] = "rogue".into();
    let mut unknown_version = first.clone();
    unknown_version["version"] = "aitp/9.9".into();
    let mut no_version = first.clone();
    no_version.as_object_mut().unwrap().remove("version");
    let mut no_signature = first.clone();
    no_signature.as_object_mut().unwrap().remove("signature");
    for wire in [unknown_member, unknown_version, no_version, no_signature] {
        let resp = post_hello(port, "application/json", &wire).await;
        assert_error_code(resp, "REPLAY_DETECTED").await;
    }
    // Content-Type comes after the §3.1 replay step too.
    let resp = post_hello(port, "text/plain", &first).await;
    assert_error_code(resp, "REPLAY_DETECTED").await;
}

/// Issue #255: the timestamp window runs before `version` and the
/// member set, so a stale envelope is `TIMESTAMP_EXPIRED` even when it is
/// also malformed, has an unknown or absent `version`, or arrives with
/// the wrong Content-Type.
#[tokio::test]
async fn timestamp_window_is_checked_before_version_and_structure() {
    let port = spawn_server().await;
    let stale = || hello_wire(0xE1, Uuid::new_v4(), 7200);

    let mut unknown_member = stale();
    unknown_member["trace_id"] = "rogue".into();
    let mut unknown_version = stale();
    unknown_version["version"] = "aitp/9.9".into();
    let mut no_version = stale();
    no_version.as_object_mut().unwrap().remove("version");
    let mut bad_type = stale();
    bad_type["message_type"] = "not_a_type".into();
    let mut bad_sender = stale();
    bad_sender["sender"] = serde_json::json!({"agent_id": "nope"});
    for wire in [
        unknown_member,
        unknown_version,
        no_version,
        bad_type,
        bad_sender,
    ] {
        let resp = post_hello(port, "application/json", &wire).await;
        assert_error_code(resp, "TIMESTAMP_EXPIRED").await;
    }
    let resp = post_hello(port, "text/plain", &stale()).await;
    assert_error_code(resp, "TIMESTAMP_EXPIRED").await;
    // `i64::MIN` is far outside the window, not an overflow.
    let mut extreme = stale();
    extreme["timestamp"] = i64::MIN.into();
    let resp = post_hello(port, "application/json", &extreme).await;
    assert_error_code(resp, "TIMESTAMP_EXPIRED").await;
    // Issue #261: a negative `timestamp` is also a schema violation
    // (`minimum: 0`), but it is readable, so the window (step 3) sees it
    // first and it stays TIMESTAMP_EXPIRED, even with other structure
    // defects alongside.
    let mut negative = stale();
    negative["timestamp"] = (-1).into();
    negative["payload"] = serde_json::json!([]);
    negative["signature"] = "short".into();
    let resp = post_hello(port, "application/json", &negative).await;
    assert_error_code(resp, "TIMESTAMP_EXPIRED").await;
}

/// Issue #261: inside the window, the `aitp-envelope.schema.json` rules
/// for `payload`, `signature` and `extensions` fail the RFC-AITP-0001
/// §5.4 structure step (`INVALID_ENVELOPE`), and an unknown `version`
/// still wins over them.
#[tokio::test]
async fn schema_rule_defects_are_invalid_envelope_after_version() {
    let port = spawn_server().await;
    let fresh = || hello_wire(0xE3, Uuid::new_v4(), 0);
    let mut array_payload = fresh();
    array_payload["payload"] = serde_json::json!([1]);
    let mut bad_signature = fresh();
    bad_signature["signature"] = "not-86-chars".into();
    let mut null_extensions = fresh();
    null_extensions["extensions"] = Value::Null;
    for wire in [&array_payload, &bad_signature, &null_extensions] {
        let resp = post_hello(port, "application/json", wire).await;
        assert_error_code(resp, "INVALID_ENVELOPE").await;
    }
    let mut unknown_version = fresh();
    unknown_version["version"] = "aitp/9.9".into();
    unknown_version["payload"] = serde_json::json!([1]);
    unknown_version["signature"] = "not-86-chars".into();
    let resp = post_hello(port, "application/json", &unknown_version).await;
    assert_error_code(resp, "UNKNOWN_VERSION").await;
}

/// Issue #255: a `timestamp` or `message_id` that cannot be read skips
/// its §3.1 step and is reported by the RFC-AITP-0001 §5.4 steps, in
/// their order: `UNKNOWN_VERSION` first (an absent `version` included),
/// then `INVALID_ENVELOPE`.
#[tokio::test]
async fn unreadable_timestamp_or_message_id_falls_through_to_structure() {
    let port = spawn_server().await;
    let fresh = || hello_wire(0xE2, Uuid::new_v4(), 0);

    let mut no_ts = fresh();
    no_ts.as_object_mut().unwrap().remove("timestamp");
    let mut string_ts = fresh();
    string_ts["timestamp"] = "1711900000".into();
    let mut float_ts = fresh();
    float_ts["timestamp"] = serde_json::json!(1.5);
    let mut bad_mid = fresh();
    bad_mid["message_id"] = "not-a-uuid".into();
    for wire in [&no_ts, &string_ts, &float_ts, &bad_mid] {
        let resp = post_hello(port, "application/json", wire).await;
        assert_error_code(resp, "INVALID_ENVELOPE").await;
    }

    let mut no_ts_no_version = fresh();
    no_ts_no_version
        .as_object_mut()
        .unwrap()
        .remove("timestamp");
    no_ts_no_version.as_object_mut().unwrap().remove("version");
    let resp = post_hello(port, "application/json", &no_ts_no_version).await;
    assert_error_code(resp, "UNKNOWN_VERSION").await;

    let mut no_version = fresh();
    no_version.as_object_mut().unwrap().remove("version");
    let resp = post_hello(port, "application/json", &no_version).await;
    assert_error_code(resp, "UNKNOWN_VERSION").await;
}

#[tokio::test]
async fn unknown_message_type_returns_invalid_envelope() {
    let port = spawn_server().await;
    let key = AitpSigningKey::from_seed(&[0xAE; 32]);
    // Construct a TCT-typed envelope sent to the hello endpoint.
    let envelope = sign_envelope_with(
        &key,
        MessageType::Tct,
        serde_json::json!({}),
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .unwrap();
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .json(&envelope)
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "INVALID_ENVELOPE").await;
}

// ── Pluggable replay store (ReplayGuard) ────────────────────────────────
//
// Prove the server routes envelope replay detection through the injected
// `ReplayGuard` rather than a hardcoded in-memory map — the seam a
// clustered deployment relies on (RFC-AITP-0001 §5.5).

use aitp::transport::ReplayGuard;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

/// Records every key it is asked about; `verdict` fixes what it returns.
struct RecordingGuard {
    seen: Mutex<Vec<String>>,
    verdict: bool,
}

impl ReplayGuard for RecordingGuard {
    fn check_and_record(&self, key: &str, _ttl: StdDuration) -> bool {
        self.seen.lock().unwrap().push(key.to_string());
        self.verdict
    }
}

async fn spawn_server_with_guard(guard: Arc<dyn ReplayGuard>) -> u16 {
    let server_key = AitpSigningKey::from_seed(&[0xCC; 32]);
    let manifest = manifest_for(&server_key, "responder");
    let server = HandshakeServer::new(
        server_key,
        manifest,
        vec!["https://idp.example.com".parse().unwrap()],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    .with_replay_guard(guard);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, server.router()).await.ok();
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    port
}

#[tokio::test]
async fn injected_replay_guard_sees_the_message_id() {
    let guard = Arc::new(RecordingGuard {
        seen: Mutex::new(Vec::new()),
        verdict: true, // report everything as fresh
    });
    let port = spawn_server_with_guard(guard.clone()).await;

    let key = AitpSigningKey::from_seed(&[0xB1; 32]);
    let mid = Uuid::new_v4();
    let envelope = sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({}),
        mid,
        Timestamp::now(),
    )
    .unwrap();
    let _ = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .json(&envelope)
        .send()
        .await
        .unwrap();

    let seen = guard.seen.lock().unwrap();
    assert!(
        seen.iter().any(|k| k == &mid.to_string()),
        "injected guard must be consulted with the envelope message_id; saw {seen:?}"
    );
}

#[tokio::test]
async fn injected_replay_guard_verdict_is_honored() {
    // A guard that reports every key as a replay must cause even the
    // *first* envelope to be rejected — proving the server's decision
    // comes from the guard, not an internal (empty) map.
    let guard = Arc::new(RecordingGuard {
        seen: Mutex::new(Vec::new()),
        verdict: false, // everything is a "replay"
    });
    let port = spawn_server_with_guard(guard).await;

    let key = AitpSigningKey::from_seed(&[0xB2; 32]);
    let envelope = sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({}),
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .unwrap();
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .json(&envelope)
        .send()
        .await
        .unwrap();
    assert_error_code(resp, "REPLAY_DETECTED").await;
}
