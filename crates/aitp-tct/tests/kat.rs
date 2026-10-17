//! Builder-level known-answer test: `TctBuilder` + voucher minting
//! reproduce the spec's signed-example vectors byte-for-byte from the
//! pinned KAT seeds (kat-keypair-001/-002). This pins the full claim
//! construction (jkt derivation, claim set, JCS payload, header bytes),
//! not just the raw JWS mechanics covered in `aitp-crypto`.

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_tct::TctBuilder;
use serde_json::Value;
use std::path::PathBuf;
use uuid::Uuid;

fn vector(rel: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("tests/schemas/known-answer/signed-examples")
        .join(rel);
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|e| panic!("read {rel}: {e}")))
        .expect("parse vector")
}

#[test]
fn builder_reproduces_tct_signed_example() {
    let v = vector("tct/kat-keypair-001-issues-002.json");
    let input = &v["_kat_input"];

    let issuer = AitpSigningKey::from_seed(&[0u8; 32]); // kat-keypair-001
    let subject = AitpSigningKey::from_seed(&core::array::from_fn(|i| i as u8)); // kat-keypair-002

    let issued = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(
            input["grants"]
                .as_array()
                .unwrap()
                .iter()
                .map(|g| g.as_str().unwrap().to_string()),
        )
        .ttl_secs(input["ttl_secs"].as_i64().unwrap())
        .subject_pubkey(subject.verifying_key())
        .issued_at(Timestamp(input["iat"].as_i64().unwrap()))
        .jti(Uuid::parse_str(input["jti"].as_str().unwrap()).unwrap())
        .build()
        .expect("builder ok");

    assert_eq!(
        issued.token,
        v["tct_token"].as_str().unwrap(),
        "builder-minted TCT diverges from the spec signed-example"
    );
    assert_eq!(
        serde_json::to_value(&issued.claims).unwrap(),
        v["decoded_claims"],
        "decoded claims diverge from the vector"
    );
}

#[test]
fn builder_reproduces_voucher_signed_example() {
    let v = vector("grant-voucher/kat-voucher-001.json");
    let input = &v["_kat_input"];

    let issuer = AitpSigningKey::from_seed(&[0u8; 32]); // kat-keypair-001
    let subject = AitpSigningKey::from_seed(&core::array::from_fn(|i| i as u8)); // kat-keypair-002

    // The voucher KAT's companion TCT is jti …440001 with two grants.
    let issued = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(
            input["grants"]
                .as_array()
                .unwrap()
                .iter()
                .map(|g| g.as_str().unwrap().to_string()),
        )
        .ttl_secs(input["ttl_secs"].as_i64().unwrap())
        .subject_pubkey(subject.verifying_key())
        .issued_at(Timestamp(input["iat"].as_i64().unwrap()))
        .jti(Uuid::parse_str(input["src_jti"].as_str().unwrap()).unwrap())
        .build()
        .expect("builder ok");

    assert_eq!(
        issued.voucher.as_deref().unwrap(),
        v["voucher_token"].as_str().unwrap(),
        "builder-minted voucher diverges from the spec signed-example"
    );
}

/// Spec PR A: the ES256 TCT (kat-keypair-005-p256 issues to
/// kat-keypair-002) verifies as committed, the builder reproduces it
/// byte for byte (RFC 6979, low-S), and the double-hash token does not
/// verify.
#[test]
fn p256_tct_signed_example_verifies_and_reproduces() {
    use aitp_tct::{verify_tct, TctError, TctVerifyContext};
    let v = vector("tct/kat-keypair-005-issues-002.json");
    let input = &v["_kat_input"];
    let issuer = AitpSigningKey::from_p256_seed(&[0x05; 32]).unwrap();
    let subject = AitpSigningKey::from_seed(&core::array::from_fn(|i| i as u8));
    let token = v["tct_token"].as_str().unwrap();

    let ctx = TctVerifyContext::builder(
        subject.aid(),
        issuer.aid(),
        Timestamp(input["iat"].as_i64().unwrap() + 100),
    )
    .skip_manifest_expiry_cap_dangerous()
    .accept_unchecked_revocation_dangerous()
    .build()
    .unwrap();
    let verified = verify_tct(token, &ctx).expect("committed ES256 TCT verifies");
    assert_eq!(
        serde_json::to_value(&verified.claims).unwrap(),
        v["decoded_claims"]
    );
    let dh = v["_must_not_verify"]["double_hash_jws"].as_str().unwrap();
    let r = verify_tct(dh, &ctx);
    assert!(
        matches!(
            r,
            Err(TctError::SignatureInvalid
                | TctError::Crypto(aitp_crypto::CryptoError::SignatureInvalid))
        ),
        "{r:?}"
    );

    let issued = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(
            input["grants"]
                .as_array()
                .unwrap()
                .iter()
                .map(|g| g.as_str().unwrap().to_string()),
        )
        .ttl_secs(input["ttl_secs"].as_i64().unwrap())
        .subject_pubkey(subject.verifying_key())
        .issued_at(Timestamp(input["iat"].as_i64().unwrap()))
        .jti(Uuid::parse_str(input["jti"].as_str().unwrap()).unwrap())
        .build()
        .expect("builder ok");
    assert_eq!(issued.token, token);
}
