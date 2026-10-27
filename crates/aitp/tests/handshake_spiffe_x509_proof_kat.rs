//! `kat-spiffe-x509-proof-001`: the RFC-AITP-0002 §6.4.1 X509-SVID proof
//! input. The signer is kat-keypair-003 acting as the leaf key; the
//! sender AID is kat-keypair-002, so the leaf key is not the AID key.
#![cfg(feature = "experimental-spiffe-identity")]

use aitp::core::{Aid, Timestamp};
use aitp::crypto::{AitpVerifyingKey, Digest32, Signature};
use aitp::handshake::identity_pinned::pinned_key_proof_input;
use aitp::handshake::spiffe_x509_proof_input;
use serde_json::Value;
use uuid::Uuid;

fn load_kat() -> Value {
    let path = format!(
        "{}/../../tests/schemas/known-answer/jcs-sha256.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).expect("read jcs-sha256.json");
    let file: Value = serde_json::from_str(&raw).expect("parse jcs-sha256.json");
    file["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .find(|v| v["id"] == "kat-spiffe-x509-proof-001")
        .expect("kat-spiffe-x509-proof-001 vector must exist in vendored schemas")
        .clone()
}

fn str_of<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k}"))
}

struct Tuple {
    sender: Aid,
    receiver: Aid,
    message_id: Uuid,
    timestamp: Timestamp,
    pop_nonce: String,
}

fn tuple(kat: &Value) -> Tuple {
    Tuple {
        sender: Aid::parse(str_of(kat, "sender_aid")).unwrap(),
        receiver: Aid::parse(str_of(kat, "receiver_aid")).unwrap(),
        message_id: Uuid::parse_str(str_of(kat, "message_id")).unwrap(),
        timestamp: Timestamp(kat["timestamp"].as_i64().unwrap()),
        pop_nonce: str_of(kat, "pop_nonce").to_owned(),
    }
}

#[test]
fn spiffe_x509_proof_matches_spec_kat() {
    let kat = load_kat();
    let t = tuple(&kat);
    let input = spiffe_x509_proof_input(
        &t.sender,
        &t.receiver,
        &t.message_id,
        t.timestamp,
        &t.pop_nonce,
    )
    .unwrap();
    assert_eq!(hex::encode(&input), str_of(&kat, "proof_input_hex"));
    assert_eq!(
        input.len() as u64,
        kat["proof_input_len_bytes"].as_u64().unwrap()
    );
    let digest = Digest32::sha256(&input);
    assert_eq!(hex::encode(digest.as_bytes()), str_of(&kat, "sha256_hex"));

    let sig = Signature::parse(str_of(&kat, "signature_b64url")).unwrap();
    let signer =
        AitpVerifyingKey::from_aid(&Aid::parse(str_of(&kat, "signer_aid")).unwrap()).unwrap();
    signer
        .verify_jcs(&digest, &sig)
        .expect("verifies under the leaf key");

    // Not under the sender AID's key.
    let sender_key = AitpVerifyingKey::from_aid(&t.sender).unwrap();
    assert!(sender_key.verify_jcs(&digest, &sig).is_err());

    // Domain separation: not over the §3.1 pinned-key input of the same tuple.
    let pinned = pinned_key_proof_input(
        &t.sender,
        &t.receiver,
        &t.message_id,
        t.timestamp,
        &t.pop_nonce,
    )
    .unwrap();
    assert!(signer.verify_jcs(&Digest32::sha256(&pinned), &sig).is_err());
}
