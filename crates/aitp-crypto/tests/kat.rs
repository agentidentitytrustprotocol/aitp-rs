//! Known-answer tests against the spec's pinned vectors at
//! `tests/schemas/known-answer/`. These confirm `aitp-crypto` produces
//! byte-identical Ed25519 derivations and JWK thumbprints to the
//! reference values defined by the AITP spec.

use aitp_crypto::{compute_jwk_thumbprint, AitpSigningKey};
use serde_json::Value;
use std::path::PathBuf;

fn kat_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("tests/schemas/known-answer")
        .join(name)
}

fn load(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(kat_path(name)).expect("read kat")).expect("parse kat")
}

#[test]
fn keypair_kat_seed_to_pubkey_to_aid() {
    let kat = load("keypairs.json");
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty(), "keypairs.json has no vectors");
    for v in vectors {
        let id = v["id"].as_str().unwrap();
        let seed_hex = v["seed_hex"].as_str().unwrap();
        let expected_pubkey = v["pubkey_b64url"].as_str().unwrap();
        let expected_aid = v["aid"].as_str().unwrap();

        let seed_bytes = hex::decode(seed_hex).unwrap();
        assert_eq!(seed_bytes.len(), 32, "{id}: seed must be 32 bytes");
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);

        let key = AitpSigningKey::from_seed(&seed);
        let actual_pubkey = aitp_core::base64url::encode(&key.verifying_key().to_bytes());
        assert_eq!(
            actual_pubkey, expected_pubkey,
            "{id}: pubkey mismatch (seed → pubkey derivation)"
        );
        assert_eq!(
            key.aid().as_str(),
            expected_aid,
            "{id}: AID mismatch (pubkey → AID derivation)"
        );
    }
}

#[test]
fn jwk_thumbprint_kat() {
    let kat = load("jwk-thumbprints.json");
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty(), "jwk-thumbprints.json has no vectors");

    // Cross-reference: load keypairs to resolve `keypair_ref`.
    let keypairs = load("keypairs.json");
    let kp_vectors = keypairs["vectors"].as_array().unwrap();

    for v in vectors {
        let id = v["id"].as_str().unwrap();
        let kp_ref = v["keypair_ref"].as_str().unwrap();
        let expected_jkt = v["jkt"].as_str().unwrap();

        let kp = kp_vectors
            .iter()
            .find(|k| k["id"].as_str() == Some(kp_ref))
            .unwrap_or_else(|| panic!("{id}: keypair_ref {kp_ref} not in keypairs.json"));
        let pubkey_b64 = kp["pubkey_b64url"].as_str().unwrap();
        let pubkey_bytes = aitp_core::base64url::decode_strict(pubkey_b64).unwrap();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pubkey_bytes);

        let actual_jkt = compute_jwk_thumbprint(&pk);
        assert_eq!(actual_jkt, expected_jkt, "{id}: JWK thumbprint mismatch");
    }
}
