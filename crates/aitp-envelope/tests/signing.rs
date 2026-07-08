//! Tests for the envelope signer/verifier.
//!
//! `aitp-envelope` produces and checks every AITP message's *outer*
//! signature, and is reused verbatim by the language bindings, so a
//! dropped signing-input field here is a protocol-wide sender-spoofing /
//! replay bypass. Each field that feeds the signing digest
//! (`message_id`, `timestamp`, `sender.agent_id`, `payload`) gets a
//! tamper test proving verification rejects when it changes.

use aitp_core::{envelope_signing_digest, AitpEnvelope, MessageType, Sender, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey, CryptoError, Signature};
use aitp_envelope::{sign_envelope, sign_envelope_with, verify_envelope_signature};
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

    // Re-derive the digest from the caller's pair and confirm the
    // envelope signature verifies against it directly.
    let digest = envelope_signing_digest(&mid, ts, k.aid(), &env.payload).expect("digest");
    let sig = Signature::parse(&env.signature).expect("parse sig");
    k.verifying_key()
        .verify(&digest, &sig)
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
