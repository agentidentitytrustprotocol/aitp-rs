//! Pinned-key proof-input KAT regression test.
//!
//! RFC-AITP-0002 §3.1's pinned-key proof input erroneously described the
//! `timestamp` field as an 8-byte big-endian signed integer
//! (`timestamp_be_8_bytes`) in earlier prose. Per the §3.1 erratum (spec
//! issue #17), the timestamp MUST be encoded as its base-10 ASCII-decimal
//! string, matching how `message_id` is already string-encoded in the
//! same construction. `aitp-rs` used to encode it as 8-byte big-endian
//! binary instead — this was never caught by the conformance suite
//! because the one fixture exercising this path (`id-007`) is rejected
//! earlier, at the trust-store gate (RFC-AITP-0002 §3.2 step 1), before
//! the signature is ever checked.
//!
//! The `kat-pinned-key-proof-001` vector (added upstream at spec commit
//! `43f9d3937238a2cf9d727c9b5ca1b631060ecbc8`) reuses `id-007`'s real
//! tuple and its existing `kat-keypair-003` Ed25519 signature verbatim,
//! making the ASCII-decimal encoding machine-checkable rather than a
//! matter of prose interpretation.

use aitp_core::{base64url, Aid, Timestamp};
use aitp_crypto::{AitpVerifyingKey, Signature};
use aitp_handshake::identity_pinned::pinned_key_proof_input;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Deserialize)]
struct KatFile {
    vectors: Vec<KatEntry>,
}

#[derive(Deserialize)]
struct KatEntry {
    id: String,
    #[serde(default)]
    sender_aid: Option<String>,
    #[serde(default)]
    receiver_aid: Option<String>,
    #[serde(default)]
    message_id: Option<String>,
    #[serde(default)]
    timestamp: Option<i64>,
    #[serde(default)]
    pop_nonce: Option<String>,
    #[serde(default)]
    proof_input_hex: Option<String>,
    #[serde(default)]
    proof_input_len_bytes: Option<usize>,
    #[serde(default)]
    sha256_hex: Option<String>,
    #[serde(default)]
    sha256_b64url: Option<String>,
    #[serde(default)]
    signer_aid: Option<String>,
    #[serde(default)]
    signature_b64url: Option<String>,
}

fn load_kat() -> KatEntry {
    let path = format!(
        "{}/../../tests/schemas/known-answer/jcs-sha256.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).expect("read jcs-sha256.json");
    let file: KatFile = serde_json::from_str(&raw).expect("parse jcs-sha256.json");
    file.vectors
        .into_iter()
        .find(|v| v.id == "kat-pinned-key-proof-001")
        .expect("kat-pinned-key-proof-001 vector must exist in vendored schemas")
}

/// Positive direction: rebuilding the proof input via
/// `pinned_key_proof_input` from the vector's own fields must reproduce
/// the vector's pinned bytes, digest, and signature exactly.
#[test]
fn pinned_key_proof_input_matches_spec_kat() {
    let kat = load_kat();

    let sender_aid = Aid::parse(kat.sender_aid.as_ref().unwrap()).expect("sender_aid parses");
    let receiver_aid = Aid::parse(kat.receiver_aid.as_ref().unwrap()).expect("receiver_aid parses");
    let message_id = Uuid::parse_str(kat.message_id.as_ref().unwrap()).expect("message_id parses");
    let timestamp = Timestamp(kat.timestamp.expect("timestamp present"));
    let pop_nonce = kat.pop_nonce.as_ref().unwrap();

    let input = pinned_key_proof_input(
        &sender_aid,
        &receiver_aid,
        &message_id,
        timestamp,
        pop_nonce,
    )
    .expect("proof input builds");

    let expected_input =
        hex::decode(kat.proof_input_hex.as_ref().unwrap()).expect("kat proof_input_hex parses");
    assert_eq!(
        hex::encode(&input),
        hex::encode(&expected_input),
        "proof_input bytes must equal the spec's pinned bytes (ASCII-decimal timestamp)"
    );

    if let Some(expected_len) = kat.proof_input_len_bytes {
        assert_eq!(
            input.len(),
            expected_len,
            "proof_input length must equal the spec's pinned length"
        );
    }

    let digest = Sha256::digest(&input);
    let expected_digest =
        hex::decode(kat.sha256_hex.as_ref().unwrap()).expect("kat sha256_hex parses");
    assert_eq!(
        digest.as_slice(),
        expected_digest.as_slice(),
        "sha256 of proof_input must equal the spec's pinned digest"
    );
    if let Some(expected_b64url) = kat.sha256_b64url.as_ref() {
        assert_eq!(
            &base64url::encode(digest.as_slice()),
            expected_b64url,
            "sha256_b64url must match the spec's pinned digest"
        );
    }

    let signer_aid = Aid::parse(kat.signer_aid.as_ref().unwrap()).expect("signer_aid parses");
    let pubkey = AitpVerifyingKey::from_aid(&signer_aid).expect("signer_aid resolves to pubkey");
    let sig =
        Signature::parse(kat.signature_b64url.as_ref().unwrap()).expect("kat signature parses");
    pubkey
        .verify(&digest, &sig)
        .expect("kat signature verifies over sha256(ASCII-decimal proof_input)");
}

/// Negative direction — the assertion that actually proves the fix.
/// Rebuild the proof input with the timestamp packed as 8-byte
/// big-endian binary (the OLD/wrong encoding) spliced into the same
/// position instead of the ASCII-decimal string, and confirm the
/// pinned signature does NOT verify against that variant. Without this
/// check, an implementation that accepted either encoding would pass a
/// positive-only test while still being wire-incompatible with any
/// verifier that only accepts one form.
#[test]
fn old_big_endian_timestamp_encoding_does_not_verify() {
    let kat = load_kat();

    let sender_aid = kat.sender_aid.as_ref().unwrap();
    let receiver_aid = kat.receiver_aid.as_ref().unwrap();
    let message_id = kat.message_id.as_ref().unwrap();
    let timestamp = kat.timestamp.expect("timestamp present");
    let pop_nonce = kat.pop_nonce.as_ref().unwrap();
    let pop_nonce_bytes = base64url::decode_strict(pop_nonce).expect("pop_nonce decodes");

    // Manually rebuild the same five-field construction, but with the
    // timestamp packed as 8-byte big-endian binary instead of its
    // ASCII-decimal string form.
    let mut bad_input = Vec::new();
    bad_input.extend_from_slice(b"aitp-pinned-key-v1\0");
    bad_input.extend_from_slice(sender_aid.as_bytes());
    bad_input.push(0);
    bad_input.extend_from_slice(receiver_aid.as_bytes());
    bad_input.push(0);
    bad_input.extend_from_slice(message_id.as_bytes());
    bad_input.push(0);
    bad_input.extend_from_slice(&timestamp.to_be_bytes());
    bad_input.push(0);
    bad_input.extend_from_slice(&pop_nonce_bytes);

    // Sanity: this is genuinely a different byte string than the
    // spec-pinned ASCII-decimal one, not an accidental match.
    let expected_input =
        hex::decode(kat.proof_input_hex.as_ref().unwrap()).expect("kat proof_input_hex parses");
    assert_ne!(
        bad_input, expected_input,
        "the old big-endian variant must differ from the pinned ASCII-decimal proof_input"
    );

    let bad_digest = Sha256::digest(&bad_input);

    let signer_aid = Aid::parse(kat.signer_aid.as_ref().unwrap()).expect("signer_aid parses");
    let pubkey = AitpVerifyingKey::from_aid(&signer_aid).expect("signer_aid resolves to pubkey");
    let sig =
        Signature::parse(kat.signature_b64url.as_ref().unwrap()).expect("kat signature parses");

    assert!(
        pubkey.verify(&bad_digest, &sig).is_err(),
        "pinned signature must NOT verify over the old big-endian-timestamp encoding"
    );
}
