//! Known-answer tests against the spec's pinned vectors at
//! `tests/schemas/known-answer/`. These confirm `aitp-crypto` produces
//! byte-identical Ed25519 derivations and JWK thumbprints to the
//! reference values defined by the AITP spec.

use aitp_crypto::{AitpSigningKey, SignatureAlgorithm};
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
        // Non-Ed25519 entries (e.g. kat-keypair-005-p256) use a
        // different seed encoding (`private_scalar_hex` for ECDSA)
        // and aren't derived through `AitpSigningKey::from_seed`.
        // Skip them; algorithm-specific KAT tests live with the
        // matching verifier.
        let Some(seed_hex) = v["seed_hex"].as_str() else {
            continue;
        };
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

/// P-256 keypair KAT (`kat-keypair-005-p256`). The Ed25519
/// `keypair_kat_*` above skips P-256 because the seed encoding differs
/// (a raw private scalar, not an Ed25519 seed). This pins the
/// scalar → SEC1-compressed pubkey → AID derivation for P-256 and
/// exercises the algorithm-tagged signing path (RFC-AITP-0001 §5.4.3),
/// so a silent regression in the P-256 verifier is caught against the
/// spec's drift-checked vector.
#[test]
fn p256_keypair_kat_scalar_pubkey_aid_and_signature() {
    let kat = load("keypairs.json");
    let vectors = kat["vectors"].as_array().expect("vectors array");
    let v = vectors
        .iter()
        .find(|v| v["id"].as_str() == Some("kat-keypair-005-p256"))
        .expect("kat-keypair-005-p256 present in keypairs.json");

    // For P-256 the 32-byte big-endian private scalar *is* the seed.
    let scalar_hex = v["private_scalar_hex"].as_str().unwrap();
    let scalar = hex::decode(scalar_hex).unwrap();
    assert_eq!(scalar.len(), 32, "P-256 private scalar must be 32 bytes");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&scalar);

    let key = AitpSigningKey::from_p256_seed(&seed).expect("valid P-256 scalar");

    // scalar → SEC1-compressed pubkey → AID, pinned byte-for-byte.
    let actual_pubkey = aitp_core::base64url::encode(&key.verifying_key().to_compressed());
    assert_eq!(
        actual_pubkey,
        v["pubkey_b64url"].as_str().unwrap(),
        "P-256 SEC1-compressed pubkey derivation"
    );
    assert_eq!(
        key.aid().as_str(),
        v["aid"].as_str().unwrap(),
        "P-256 AID derivation"
    );

    // The P-256 signing path produces an algorithm-tagged signature
    // (`p256.<b64u>`) that the matching verifier accepts.
    let msg = b"aitp p256 known-answer test message";
    let sig = key.sign(msg);
    assert!(
        matches!(sig.algorithm(), SignatureAlgorithm::P256),
        "P-256 key must produce a P-256-tagged signature"
    );
    assert!(
        sig.as_str().starts_with("p256."),
        "tagged wire form `p256.<86b64u>` (got {:?})",
        sig.as_str()
    );
    key.verifying_key()
        .verify(msg, &sig)
        .expect("P-256 signature must self-verify");
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

        // 32 bytes → Ed25519 raw pubkey (OKP form); 33 bytes → P-256
        // SEC1-compressed (EC form). The algorithm-agile dispatch in
        // AitpVerifyingKey::to_jwk_thumbprint covers both.
        let vk = aitp_crypto::AitpVerifyingKey::from_compressed(&pubkey_bytes)
            .unwrap_or_else(|e| panic!("{id}: pubkey parse failed: {e}"));
        let actual_jkt = vk.to_jwk_thumbprint().unwrap();
        assert_eq!(actual_jkt, expected_jkt, "{id}: JWK thumbprint mismatch");
    }
}
