//! Tests for the envelope signer/verifier.
//!
//! `aitp-envelope` produces and checks every AITP message's *outer*
//! signature, and is reused verbatim by the language bindings, so a
//! dropped signing-input field here is a protocol-wide sender-spoofing /
//! replay bypass. Since aitp/0.3 every member except `signature` feeds
//! the signing digest (`version`, `message_type`, `message_id`,
//! `timestamp`, `sender.agent_id`, `payload`, `extensions`); each gets a
//! tamper test proving verification rejects when it changes.

use aitp_core::{
    envelope_signing_digest, AitpEnvelope, ExtensionsMap, MessageType, Sender, Timestamp,
};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey, CryptoError, Signature};
use aitp_envelope::{
    sign_envelope, sign_envelope_with, sign_prepared_envelope, sign_prepared_envelope_async,
    verify_envelope_signature,
};
use uuid::Uuid;

fn key(seed: u8) -> AitpSigningKey {
    AitpSigningKey::from_seed(&[seed; 32])
}

fn sample_payload() -> serde_json::Value {
    serde_json::json!({ "hello": "world", "n": 7 })
}

fn signed(key: &AitpSigningKey) -> AitpEnvelope {
    sign_envelope_with(
        key,
        MessageType::MutualHello,
        sample_payload(),
        Uuid::new_v4(),
        Timestamp(1_700_000_000),
    )
    .expect("sign")
}

#[test]
fn round_trips() {
    let k = key(1);
    let env = signed(&k);
    verify_envelope_signature(&env, &k.verifying_key()).expect("valid envelope verifies");
}

#[test]
fn signature_is_over_caller_supplied_message_id_and_timestamp() {
    // The crate's reason to exist: the signature must bind the
    // *caller-supplied* (message_id, timestamp), not freshly generated
    // ones, so a payload's pinned-key identity proof — bound to the same
    // pair — stays verifiable.
    let k = key(2);
    let mid = Uuid::new_v4();
    let ts = Timestamp(1_700_000_123);
    let env =
        sign_envelope_with(&k, MessageType::MutualHello, sample_payload(), mid, ts).expect("sign");

    assert_eq!(env.message_id, mid);
    assert_eq!(env.timestamp, ts);

    // Re-derive the digest from an independently built envelope over the
    // caller's pair and confirm the signature verifies against it.
    let unsigned = AitpEnvelope {
        version: aitp_core::PROTOCOL_VERSION.into(),
        message_type: MessageType::MutualHello,
        message_id: mid,
        timestamp: ts,
        sender: Sender {
            agent_id: k.aid().clone(),
        },
        payload: sample_payload(),
        extensions: None,
        signature: String::new(),
    };
    let digest = envelope_signing_digest(&unsigned).expect("digest");
    let sig = Signature::parse(&env.signature).expect("parse sig");
    k.verifying_key()
        .verify_jcs(&aitp_crypto::Digest32::from(digest), &sig)
        .expect("signature is over the caller-supplied mid/ts");
}

#[test]
fn tampered_payload_is_rejected() {
    let k = key(3);
    let mut env = signed(&k);
    env.payload = serde_json::json!({ "hello": "world", "n": 8 }); // n: 7 -> 8
    assert!(matches!(
        verify_envelope_signature(&env, &k.verifying_key()),
        Err(CryptoError::SignatureInvalid)
    ));
}

#[test]
fn tampered_message_id_is_rejected() {
    let k = key(4);
    let mut env = signed(&k);
    env.message_id = Uuid::new_v4();
    assert!(matches!(
        verify_envelope_signature(&env, &k.verifying_key()),
        Err(CryptoError::SignatureInvalid)
    ));
}

#[test]
fn tampered_timestamp_is_rejected() {
    let k = key(5);
    let mut env = signed(&k);
    env.timestamp = Timestamp(env.timestamp.0 + 1);
    assert!(matches!(
        verify_envelope_signature(&env, &k.verifying_key()),
        Err(CryptoError::SignatureInvalid)
    ));
}

#[test]
fn spoofed_sender_aid_is_rejected() {
    // Swap the sender field to another AID but keep the original
    // signature: verifying against the *claimed* (new) sender key must
    // fail, because the digest covers the sender AID.
    let alice = key(6);
    let mallory = key(7);
    let mut env = signed(&alice);
    env.sender = Sender {
        agent_id: mallory.aid().clone(),
    };
    assert!(matches!(
        verify_envelope_signature(&env, &mallory.verifying_key()),
        Err(CryptoError::SignatureInvalid)
    ));
}

#[test]
fn wrong_verifying_key_is_rejected() {
    let alice = key(8);
    let bob = key(9);
    let env = signed(&alice);
    // Genuine Alice envelope, but verified with Bob's key.
    assert!(matches!(
        verify_envelope_signature(&env, &bob.verifying_key()),
        Err(CryptoError::SignatureInvalid)
    ));
}

#[test]
fn malformed_signature_string_is_rejected() {
    let k = key(10);
    let mut env = signed(&k);
    env.signature = "not valid base64!!".into();
    assert!(matches!(
        verify_envelope_signature(&env, &k.verifying_key()),
        Err(CryptoError::SignatureMalformed(_))
    ));
}

#[test]
fn sign_envelope_generates_fresh_unique_ids_that_verify() {
    let k = key(11);
    let a = sign_envelope(&k, MessageType::Tct, sample_payload()).expect("sign a");
    let b = sign_envelope(&k, MessageType::Tct, sample_payload()).expect("sign b");
    assert_ne!(a.message_id, b.message_id, "each call gets a fresh uuid");
    verify_envelope_signature(&a, &k.verifying_key()).expect("a verifies");
    verify_envelope_signature(&b, &k.verifying_key()).expect("b verifies");
}

#[test]
fn sender_field_matches_signing_key() {
    let k = key(12);
    let env = signed(&k);
    assert_eq!(&env.sender.agent_id, k.aid());
    // And the sender key resolves back from the AID for verification.
    let pk = AitpVerifyingKey::from_aid(&env.sender.agent_id).expect("key from aid");
    verify_envelope_signature(&env, &pk).expect("verifies via aid-derived key");
}

// ── P-256 (ES256) sender suite ──────────────────────────────────────────
//
// The signer/verifier are suite-agnostic — they sign the same digest
// with whatever `AitpSigningKey` they're handed. AITP supports both
// Ed25519 and P-256 identities end-to-end, so a P-256-signed envelope
// must round-trip and reject tampering exactly like Ed25519.

fn p256_key(seed: u8) -> AitpSigningKey {
    AitpSigningKey::from_p256_seed(&[seed; 32]).expect("p256 key from seed")
}

#[test]
fn p256_envelope_round_trips() {
    let k = p256_key(0x30);
    let env = signed(&k);
    assert!(k.aid().as_str().starts_with("aid:pubkey:"));
    // Resolve the verifying key straight from the AID (as a receiver
    // would) and verify.
    let pk = AitpVerifyingKey::from_aid(&env.sender.agent_id).expect("p256 key from aid");
    verify_envelope_signature(&env, &pk).expect("p256 envelope verifies");
}

#[test]
fn p256_tampered_payload_is_rejected() {
    let k = p256_key(0x31);
    let mut env = signed(&k);
    env.payload = serde_json::json!({ "hello": "tampered" });
    let err = verify_envelope_signature(&env, &k.verifying_key()).unwrap_err();
    assert!(
        matches!(
            err,
            CryptoError::SignatureInvalid | CryptoError::SignatureMalformed(_)
        ),
        "tampered P-256 envelope must not verify, got {err:?}"
    );
}

fn debug_trace() -> ExtensionsMap {
    let mut ext = ExtensionsMap::new();
    ext.insert(
        "com.example/debug_trace",
        serde_json::json!({"request_id": "abc"}),
    );
    ext
}

#[test]
fn attaching_extensions_after_signing_invalidates_the_signature() {
    // aitp/0.3 (RFC-AITP-0001 §5.4): the signing input is
    // "aitp-envelope-v2" || 0x00 || JCS(envelope minus signature), so
    // `extensions` is sender-authenticated. Drive the real production
    // path: sign an envelope, then attach a populated `extensions` map
    // to the *already-signed* value, and confirm verification fails.
    // Under aitp/0.2's pipe input this verified (spec env-008).
    let k = key(0x40);
    let mut env = signed(&k);
    env.extensions = Some(debug_trace());
    assert!(matches!(
        verify_envelope_signature(&env, &k.verifying_key()),
        Err(CryptoError::SignatureInvalid)
    ));
}

#[test]
fn absent_and_empty_extensions_are_different_signing_inputs() {
    let k = key(0x41);
    let mut env = signed(&k);
    env.extensions = Some(ExtensionsMap::new());
    assert!(matches!(
        verify_envelope_signature(&env, &k.verifying_key()),
        Err(CryptoError::SignatureInvalid)
    ));
}

#[test]
fn prepared_envelope_with_extensions_signs_and_verifies() {
    let k = key(0x42);
    let mut env = AitpEnvelope {
        version: aitp_core::PROTOCOL_VERSION.into(),
        message_type: MessageType::Tct,
        message_id: Uuid::new_v4(),
        timestamp: Timestamp(1_700_000_000),
        sender: Sender {
            agent_id: k.aid().clone(),
        },
        payload: sample_payload(),
        extensions: Some(debug_trace()),
        signature: "ignored on input".into(),
    };
    env = sign_prepared_envelope(&k, env).expect("sign");
    verify_envelope_signature(&env, &k.verifying_key()).expect("verifies with extensions");

    // Removing or editing the extensions afterwards breaks it.
    let mut removed = env.clone();
    removed.extensions = None;
    assert!(verify_envelope_signature(&removed, &k.verifying_key()).is_err());
    let mut edited = env.clone();
    edited.extensions.as_mut().unwrap().insert(
        "com.example/debug_trace",
        serde_json::json!({"request_id": "xyz"}),
    );
    assert!(verify_envelope_signature(&edited, &k.verifying_key()).is_err());
}

#[test]
fn sign_prepared_envelope_refuses_bad_inputs() {
    let k = key(0x43);
    let good = sign_envelope_with(
        &k,
        MessageType::Tct,
        sample_payload(),
        Uuid::new_v4(),
        Timestamp(1),
    )
    .unwrap();
    let mut old_version = good.clone();
    old_version.version = "aitp/0.2".into();
    assert!(sign_prepared_envelope(&k, old_version)
        .unwrap_err()
        .contains("version"));
    let mut other_sender = good.clone();
    other_sender.sender.agent_id = key(0x44).aid().clone();
    assert!(sign_prepared_envelope(&k, other_sender)
        .unwrap_err()
        .contains("sender.agent_id"));
    let mut non_v4 = good;
    non_v4.message_id = Uuid::from_u128(0x0189_0a5d_ac96_774b_bcce_b302_099a_8057);
    assert!(sign_prepared_envelope(&k, non_v4)
        .unwrap_err()
        .contains("message_id"));
}

#[tokio::test]
async fn async_prepared_signing_matches_sync() {
    let k = key(0x45);
    let env = AitpEnvelope {
        version: aitp_core::PROTOCOL_VERSION.into(),
        message_type: MessageType::Tct,
        message_id: Uuid::new_v4(),
        timestamp: Timestamp(1_700_000_000),
        sender: Sender {
            agent_id: k.aid().clone(),
        },
        payload: sample_payload(),
        extensions: Some(debug_trace()),
        signature: String::new(),
    };
    let sync = sign_prepared_envelope(&k, env.clone()).unwrap();
    let async_ = sign_prepared_envelope_async(&k, env).await.unwrap();
    assert_eq!(sync, async_);
}

#[test]
fn tampered_message_type_is_rejected() {
    let k = key(0x46);
    let mut env = signed(&k);
    env.message_type = MessageType::Error;
    assert!(matches!(
        verify_envelope_signature(&env, &k.verifying_key()),
        Err(CryptoError::SignatureInvalid)
    ));
}

#[test]
fn tampered_version_is_rejected() {
    let k = key(0x47);
    let mut env = signed(&k);
    env.version = "aitp/0.2".into();
    assert!(matches!(
        verify_envelope_signature(&env, &k.verifying_key()),
        Err(CryptoError::SignatureInvalid)
    ));
}

#[test]
fn ed25519_key_does_not_verify_p256_envelope() {
    // Cross-suite mismatch: an Ed25519 verifying key handed a
    // P-256-signed envelope must reject rather than accept.
    let p = p256_key(0x32);
    let env = signed(&p);
    let ed = key(0x33);
    let err = verify_envelope_signature(&env, &ed.verifying_key()).unwrap_err();
    assert!(
        matches!(
            err,
            CryptoError::SignatureInvalid | CryptoError::SignatureMalformed(_)
        ),
        "Ed25519 key must not verify a P-256 envelope, got {err:?}"
    );
}
