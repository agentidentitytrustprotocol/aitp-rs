//! Compact-JWS known-answer tests against the spec's pinned
//! signed-example vectors at
//! `tests/schemas/known-answer/signed-examples/` (RFC-AITP-0001
//! §5.4.5).
//!
//! Two properties are pinned, in both directions:
//!
//! 1. **Byte-stable minting** — re-minting from the fixed seeds and
//!    claims reproduces the exact compact-JWS strings the spec
//!    published.
//! 2. **Off-the-shelf interop** — every token we mint verifies with a
//!    stock JOSE library (`jsonwebtoken`) given only the issuer public
//!    key, and the stock library corroborates our `alg: none`
//!    rejection. The differential oracle is a dev-dependency only.

use aitp_crypto::{jws, AitpSigningKey};
use serde_json::Value;
use std::path::PathBuf;

fn vector(rel: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("tests/schemas/known-answer/signed-examples")
        .join(rel);
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|e| panic!("read {rel}: {e}")))
        .expect("parse signed-example vector")
}

fn seed(n: u8) -> AitpSigningKey {
    // kat-keypair-001: 0x00*32; -002: 00 01 02 …; -003: 0xff*32.
    let bytes: [u8; 32] = match n {
        1 => [0u8; 32],
        2 => core::array::from_fn(|i| i as u8),
        3 => [0xffu8; 32],
        _ => unreachable!(),
    };
    AitpSigningKey::from_seed(&bytes)
}

#[test]
fn tct_kat_reproduces_spec_token_byte_for_byte() {
    let v = vector("tct/kat-keypair-001-issues-002.json");
    let expected = v["tct_token"].as_str().unwrap();
    let claims = &v["decoded_claims"];

    let issuer = seed(1);
    let minted = jws::sign_compact(&issuer, jws::TYP_TCT, claims).unwrap();
    assert_eq!(minted, expected, "TCT mint must be byte-stable");

    // And it verifies under the issuer AID with the strict verifier.
    let payload = jws::verify_compact(issuer.aid(), jws::TYP_TCT, expected).unwrap();
    let decoded: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(&decoded, claims);
}

#[test]
fn voucher_kat_reproduces_spec_token_byte_for_byte() {
    let v = vector("grant-voucher/kat-voucher-001.json");
    let expected = v["voucher_token"].as_str().unwrap();
    let issuer = seed(1);
    let minted = jws::sign_compact(&issuer, jws::TYP_GRANT_VOUCHER, &v["decoded_claims"]).unwrap();
    assert_eq!(minted, expected, "voucher mint must be byte-stable");
    jws::verify_compact(issuer.aid(), jws::TYP_GRANT_VOUCHER, expected).unwrap();
}

#[test]
fn delegation_kat_reproduces_spec_token_byte_for_byte() {
    let v = vector("delegation/single-hop-001-002-003.json");
    let expected = v["delegation_token"].as_str().unwrap();
    // Delegator of the single-hop KAT is kat-keypair-002 (subject B).
    let delegator = seed(2);
    let minted = jws::sign_compact(&delegator, jws::TYP_DELEGATION, &v["decoded_claims"]).unwrap();
    assert_eq!(minted, expected, "delegation mint must be byte-stable");
    jws::verify_compact(delegator.aid(), jws::TYP_DELEGATION, expected).unwrap();

    // The embedded voucher claim is the voucher KAT verbatim.
    let voucher_kat = vector("grant-voucher/kat-voucher-001.json");
    assert_eq!(
        v["decoded_claims"]["voucher"].as_str().unwrap(),
        voucher_kat["voucher_token"].as_str().unwrap(),
        "embedded voucher must be carried verbatim"
    );
}

/// Differential oracle: a stock JOSE library verifies our tokens given
/// only the issuer public key — the migration's headline property.
#[test]
fn stock_jose_library_verifies_kat_tokens() {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};

    for (rel, token_field, issuer) in [
        ("tct/kat-keypair-001-issues-002.json", "tct_token", seed(1)),
        (
            "grant-voucher/kat-voucher-001.json",
            "voucher_token",
            seed(1),
        ),
        (
            "delegation/single-hop-001-002-003.json",
            "delegation_token",
            seed(2),
        ),
    ] {
        let v = vector(rel);
        let token = v[token_field].as_str().unwrap();

        let pubkey = match issuer.verifying_key().try_to_ed25519_bytes() {
            Some(b) => b,
            None => unreachable!("KAT issuers are Ed25519"),
        };
        let key = DecodingKey::from_ed_der(&pubkey);
        let mut validation = Validation::new(Algorithm::EdDSA);
        // We're checking the signature path; claim semantics (exp, aud)
        // are enforced by the AITP verifiers under test elsewhere.
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        let decoded = jsonwebtoken::decode::<Value>(token, &key, &validation)
            .unwrap_or_else(|e| panic!("{rel}: stock JOSE verify failed: {e}"));
        assert_eq!(
            &decoded.claims, &v["decoded_claims"],
            "{rel}: stock JOSE decoded claims must match the vector"
        );
    }
}

/// Differential oracle in the rejecting direction: `alg: none` and
/// cross-algorithm headers die in both stacks.
#[test]
fn stock_jose_library_corroborates_alg_none_rejection() {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};

    let v = vector("tct/kat-keypair-001-issues-002.json");
    let token = v["tct_token"].as_str().unwrap();
    let (_, rest) = token.split_once('.').unwrap();
    let evil_header = aitp_core::base64url::encode(b"{\"alg\":\"none\",\"typ\":\"aitp-tct+jwt\"}");
    let evil = format!("{evil_header}.{rest}");

    let issuer = seed(1);
    // Ours: rejected on the alg pin, before signature work.
    assert!(matches!(
        jws::verify_compact(issuer.aid(), jws::TYP_TCT, &evil),
        Err(aitp_crypto::CryptoError::AlgMismatch(_))
    ));

    // Stock library: also rejected.
    let pubkey = issuer.verifying_key().try_to_ed25519_bytes().unwrap();
    let key = DecodingKey::from_ed_der(&pubkey);
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    assert!(jsonwebtoken::decode::<Value>(&evil, &key, &validation).is_err());
}
