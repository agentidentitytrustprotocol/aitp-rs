//! RFC-AITP-0001 §5.4.6 (single hash) and §5.4.7 (strict verify)
//! known-answer vectors, read from the vendored spec files under
//! `tests/schemas/known-answer/`. The spec computed the values with
//! pyca/cryptography; reproducing them with RustCrypto is the
//! two-implementation cross-check.

use aitp_core::Aid;
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey, Digest32, Signature};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;
use std::path::PathBuf;

const VENDORED: &[&str] = &[
    "jcs-sha256.json",
    "keypairs.json",
    "signature-strictness.json",
];

fn load(path: PathBuf) -> Vec<Value> {
    let doc: Value = serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");
    doc["vectors"].as_array().unwrap().clone()
}

fn vendored_vectors() -> Vec<Value> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/schemas/known-answer");
    VENDORED.iter().flat_map(|f| load(dir.join(f))).collect()
}

fn vector(id: &str) -> Value {
    vendored_vectors()
        .into_iter()
        .find(|v| v["id"] == id)
        .unwrap_or_else(|| panic!("vector {id} missing"))
}

fn p256_key() -> AitpSigningKey {
    AitpSigningKey::from_p256_seed(&[0x05; 32]).unwrap()
}

fn digest_of(v: &Value) -> Digest32 {
    let bytes: [u8; 32] = hex::decode(v["sha256_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    Digest32::from_bytes(bytes)
}

fn sig(v: &Value, field: &str) -> Signature {
    Signature::parse(v[field].as_str().unwrap()).unwrap()
}

#[test]
fn p256_jcs_sign_is_single_hash() {
    let v = vector("kat-p256-jcs-sign-001");
    let preimage = hex::decode(v["preimage_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        aitp_core::jcs::canonicalize(&v["preimage_json"]).unwrap(),
        preimage,
        "preimage_hex is JCS(preimage_json)"
    );
    let d = Digest32::sha256(&preimage);
    assert_eq!(d, digest_of(&v));

    let key = p256_key();
    assert_eq!(key.aid().as_str(), v["signer_aid"].as_str().unwrap());
    let signed = key.sign_jcs(&d);
    assert_eq!(signed.as_str(), v["signature"].as_str().unwrap());

    let vk = key.verifying_key();
    vk.verify_jcs(&d, &signed)
        .expect("single-hash signature verifies");
    assert!(
        vk.verify_jcs(&d, &sig(&v, "double_hash_signature_MUST_NOT_verify"))
            .is_err(),
        "the 0.13.x double-hash signature must not verify"
    );
    assert!(
        vk.verify_jcs(&d, &sig(&v, "high_s_sibling_MUST_NOT_verify"))
            .is_err(),
        "high-S sibling must not verify (§5.4.7)"
    );
}

#[test]
fn p256_raw_sign_is_es256_over_the_message() {
    // §5.4.6: "equivalently, ES256 over the pre-hash input".
    let v = vector("kat-p256-jcs-sign-001");
    let preimage = hex::decode(v["preimage_hex"].as_str().unwrap()).unwrap();
    let raw = p256_key().sign_raw(&preimage);
    let expected = Base64UrlUnpadded::decode_vec(&v["signature"].as_str().unwrap()[5..]).unwrap();
    assert_eq!(raw.as_slice(), expected.as_slice());
    p256_key()
        .verifying_key()
        .verify_raw(&preimage, &raw)
        .expect("ES256 verifies");
}

#[test]
fn p256_pinned_key_proof_002_reproduces_proposal_value() {
    let v = vector("kat-pinned-key-proof-002-p256");
    let input = hex::decode(v["proof_input_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        input.len() as u64,
        v["proof_input_len_bytes"].as_u64().unwrap()
    );
    let d = Digest32::sha256(&input);
    assert_eq!(d, digest_of(&v));
    let proof = p256_key().sign_jcs(&d);
    assert_eq!(proof.as_str(), v["signature"].as_str().unwrap());
    assert_eq!(
        &proof.as_str()[5..],
        v["signature_b64url"].as_str().unwrap()
    );
    p256_key()
        .verifying_key()
        .verify_jcs(&d, &sig(&v, "signature"))
        .expect("committed proof verifies");
    assert!(p256_key()
        .verifying_key()
        .verify_jcs(&d, &sig(&v, "double_hash_signature_MUST_NOT_verify"))
        .is_err());
}

#[test]
fn ed25519_tagged_pinned_key_proof_003() {
    let v = vector("kat-pinned-key-proof-003-tagged-ed25519");
    let input = hex::decode(v["proof_input_hex"].as_str().unwrap()).unwrap();
    let d = Digest32::sha256(&input);
    assert_eq!(d, digest_of(&v));
    let key = AitpSigningKey::from_ed25519_seed(&[0xff; 32]);
    let untagged = v["signature_b64url"].as_str().unwrap();
    assert_eq!(key.sign_jcs(&d).as_str(), untagged);
    // RFC-AITP-0002 §3.1: an ed25519 sender MAY emit `ed25519.<sig>`;
    // both forms MUST verify.
    let vk = key.verifying_key();
    for form in [untagged.to_string(), format!("ed25519.{untagged}")] {
        vk.verify_jcs(&d, &Signature::parse(&form).unwrap())
            .unwrap_or_else(|e| panic!("{form}: {e}"));
    }
    // The AID bytes enter proof_input: -001's untagged-AID proof does
    // not verify over -003's input.
    let p001 = vector("kat-pinned-key-proof-001");
    assert!(vk
        .verify_jcs(
            &d,
            &Signature::parse(p001["signature_b64url"].as_str().unwrap()).unwrap()
        )
        .is_err());
}

#[test]
fn manifest_pop_002_p256() {
    let v = vector("kat-manifest-pop-002-p256");
    let decoded = hex::decode(v["decoded_hex"].as_str().unwrap()).unwrap();
    let d = Digest32::sha256(&decoded);
    assert_eq!(d, digest_of(&v));
    let key = p256_key();
    assert_eq!(key.sign_jcs(&d).as_str(), v["signature"].as_str().unwrap());
    assert!(key
        .verifying_key()
        .verify_jcs(&d, &sig(&v, "double_hash_signature_MUST_NOT_verify"))
        .is_err());
}

#[test]
fn tagged_keypair_001_parses_to_same_key() {
    let v = vector("kat-keypair-001-tagged");
    let tagged = Aid::parse(v["aid"].as_str().unwrap()).unwrap();
    let untagged = Aid::parse(v["untagged_aid"].as_str().unwrap()).unwrap();
    let a = AitpVerifyingKey::from_aid(&tagged).unwrap();
    let b = AitpVerifyingKey::from_aid(&untagged).unwrap();
    assert_eq!(a, b, "the tag does not change the key");
    assert_eq!(
        AitpSigningKey::from_ed25519_seed(&[0; 32]).verifying_key(),
        a
    );
}

#[test]
fn sig_001_ed25519_small_order_key_rejected() {
    let v = vector("sig-001-ed25519-small-order-key-rejected");
    let pk: [u8; 32] = Base64UrlUnpadded::decode_vec(v["public_key_b64url"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let msg = hex::decode(v["message_hex"].as_str().unwrap()).unwrap();
    let raw = Base64UrlUnpadded::decode_vec(v["signature_b64url"].as_str().unwrap()).unwrap();
    // A small-order key may parse, but must never verify anything.
    if let Ok(vk) = AitpVerifyingKey::from_bytes(&pk) {
        assert!(vk.verify_raw(&msg, &raw).is_err());
        let d = Digest32::from_bytes(msg.clone().try_into().unwrap());
        let s = Signature::parse(v["signature_b64url"].as_str().unwrap()).unwrap();
        assert!(vk.verify_jcs(&d, &s).is_err());
    }
}

#[test]
fn sig_002_ed25519_noncanonical_s_rejected() {
    let v = vector("sig-002-ed25519-noncanonical-s-rejected");
    let vk = AitpVerifyingKey::from_aid(&Aid::parse(v["signer_aid"].as_str().unwrap()).unwrap())
        .unwrap();
    let d = Digest32::from_bytes(
        hex::decode(v["message_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    vk.verify_jcs(
        &d,
        &Signature::parse(v["valid_signature_b64url"].as_str().unwrap()).unwrap(),
    )
    .expect("canonical signature verifies");
    assert!(vk
        .verify_jcs(
            &d,
            &Signature::parse(v["signature_b64url"].as_str().unwrap()).unwrap()
        )
        .is_err());
}

#[test]
fn sig_003_p256_high_s_rejected() {
    let v = vector("sig-003-p256-high-s-rejected");
    let vk = p256_key().verifying_key();
    let d = digest_of(&v);
    vk.verify_jcs(&d, &sig(&v, "low_s_signature")).unwrap();
    assert!(vk.verify_jcs(&d, &sig(&v, "signature")).is_err());
    let raw = Base64UrlUnpadded::decode_vec(&v["signature"].as_str().unwrap()[5..]).unwrap();
    // verify_raw shares the strict path.
    let preimage = hex::decode(
        vector("kat-p256-jcs-sign-001")["preimage_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert!(vk.verify_raw(&preimage, &raw).is_err());
}

/// §5.4.7: R or S equal to zero, or >= n, MUST be rejected, on both the
/// tagged-wire and the raw (JWS) path.
#[test]
fn p256_out_of_range_scalars_rejected() {
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let key = p256_key();
    let vk = key.verifying_key();
    let d = Digest32::sha256(b"range");
    let good = key.sign_raw(b"range");
    let (r, s) = (&good[..32], &good[32..]);
    let mut cases: Vec<[u8; 64]> = Vec::new();
    for (nr, ns) in [
        ([0u8; 32].as_slice(), s),
        (r, [0u8; 32].as_slice()),
        (N.as_slice(), s),
        (r, N.as_slice()),
        ([0xffu8; 32].as_slice(), s),
        (r, [0xffu8; 32].as_slice()),
    ] {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(nr);
        b[32..].copy_from_slice(ns);
        cases.push(b);
    }
    for c in cases {
        assert!(vk.verify_raw(b"range", &c).is_err());
        let wire =
            Signature::parse(&format!("p256.{}", Base64UrlUnpadded::encode_string(&c))).unwrap();
        assert!(vk.verify_jcs(&d, &wire).is_err());
    }
}

/// Spec PR A's signed examples for kat-keypair-005-p256, verified as
/// committed (the TCT, Manifest and snapshot are checked through the
/// real verifiers in their own crates).
#[test]
fn committed_p256_envelope_verifies_and_double_hash_does_not() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../tests/schemas/known-answer/signed-examples/envelope/kat-keypair-005-envelope.json",
    );
    let v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(v["signing_input"], "sig_input");
    let env: aitp_core::AitpEnvelope = serde_json::from_value(v["envelope"].clone()).unwrap();
    let digest = aitp_core::envelope::envelope_signing_digest(
        &env.message_id,
        env.timestamp,
        &env.sender.agent_id,
        &env.payload,
    )
    .unwrap();
    assert_eq!(
        hex::encode(digest),
        v["sig_input_sha256_hex"].as_str().unwrap()
    );
    assert_eq!(
        Digest32::sha256(v["sig_input"].as_str().unwrap().as_bytes()).as_bytes(),
        &digest
    );
    let d = Digest32::from_bytes(digest);
    let vk = AitpVerifyingKey::from_aid(&env.sender.agent_id).unwrap();
    assert_eq!(vk, p256_key().verifying_key());
    vk.verify_jcs(&d, &Signature::parse(&env.signature).unwrap())
        .expect("committed P-256 envelope verifies");
    assert_eq!(p256_key().sign_jcs(&d).as_str(), env.signature);
    let dh = v["_must_not_verify"]["double_hash_signature"]
        .as_str()
        .unwrap();
    assert!(vk.verify_jcs(&d, &Signature::parse(dh).unwrap()).is_err());
}
