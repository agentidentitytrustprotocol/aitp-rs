//! KAT tripwire for `aitp_handshake::verify_jws_signature`, with a
//! `jsonwebtoken` differential leg.
//!
//! # Why this test exists
//!
//! Issue #99 dropped `jsonwebtoken` from every runtime dependency
//! graph: EdDSA/ES256 verification now goes through `aitp-crypto`'s
//! own KAT-tested primitives, and RS256 goes directly through `ring`
//! (`aitp_handshake::verify_jws_signature`, in `crates/aitp-handshake/
//! src/jwk.rs`). A compile-time guarantee is worth little for crypto
//! wiring — only actually running a verification against known-answer
//! fixtures proves the three algorithms are wired up correctly, not
//! just that the types line up.
//!
//! Two places in this workspace dispatch to `verify_jws_signature`,
//! and between them they reach three algorithms:
//!
//! * `aitp_transport_http::dpop` — EdDSA, ES256, RS256.
//! * `aitp_handshake::identity_oidc` — whatever the OIDC provider's
//!   JWKS advertises, which in practice is overwhelmingly RS256.
//!
//! The rest of the suite only ever exercises the **EdDSA** path (the
//! mock OIDC issuer and the JWS differential-oracle KATs are both
//! Ed25519), so ES256 and RS256 verification is otherwise never
//! executed. This test closes that gap deliberately and by name, so it
//! does not evaporate the next time those fixtures are reworked.
//!
//! `jsonwebtoken` is kept as a **dev-only** differential oracle: each
//! fixture is also verified independently through `jsonwebtoken` 9, so
//! a bug in our own `ring`/`aitp-crypto` wiring that happened to accept
//! or reject the wrong thing would show up as a disagreement between
//! the two, not just a single implementation's opinion of itself.
//!
//! # What it asserts
//!
//! For each of the three algorithms: a known-good JWT verifies via
//! both `verify_jws_signature` and `jsonwebtoken`, and the same JWT
//! with one signature byte flipped is rejected by both. The negative
//! half matters as much as the positive one — a backend stubbed out to
//! return `Ok(())` would sail through a verify-only test.
//!
//! # Fixtures
//!
//! Static, self-contained, and generated once with Python's
//! `cryptography` package (fresh Ed25519 / P-256 / RSA-2048 keypairs,
//! signing over `base64url(header) + "." + base64url(claims)`). They are
//! test-only key material with no other use and never need regenerating;
//! to make new ones, sign the two-segment signing input with a fresh key
//! and record the public key's raw bytes / affine coordinates / RSA
//! modulus and exponent as unpadded base64url.

use aitp_handshake::{verify_jws_signature, JwkKeyMaterial, JwkPublicKey, JwsAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::Value;

const EDDSA_JWT: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3RyaXB3aXJlLmludmFsaWQiLCJzdWIiOiJhaXRwLWpvc2UtYmFja2VuZC10cmlwd2lyZSJ9.5KYBY-Y_hC4RvKCy0UOr66xcqpSSgu9JpQ7G1aS8_Z0RYZihOTDaegzCu959ZZwDie3k5VtAdRk906svfdAtCg";
/// Raw 32-byte Ed25519 public key, unpadded base64url.
const EDDSA_PUBKEY_B64: &str = "WEYA2ZMs-lBzwES7chTdHrRI3h3brBd4jdEywnZjfd4";

const ES256_JWT: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3RyaXB3aXJlLmludmFsaWQiLCJzdWIiOiJhaXRwLWpvc2UtYmFja2VuZC10cmlwd2lyZSJ9.tx8H3ygtKFqVYI1kEqbHK4GoO-u1KhT__DKhTJvQviBqtaygpP-BV6cbI5bgBC3l9Fy_C85vWkGiJaeHiK0vWw";
const ES256_X: &str = "XjOwiXKtAwtMdglp3uEU3kjcp8MJd02ldldhytwfJdA";
const ES256_Y: &str = "FmJYi_tMz18SzSYFl3IfJWYZFnjw3hZO5L4fc2ePPBw";

const RS256_JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3RyaXB3aXJlLmludmFsaWQiLCJzdWIiOiJhaXRwLWpvc2UtYmFja2VuZC10cmlwd2lyZSJ9.tJk3nPvvLVSHNlZXqf8MXHVn7wpfdoirs12-c0wexhGroh7sJPYkIEKMqxnTyWGt6NTvkW85hfAVQjeAu34hgVvrY2XQiWW9mAacTkU_GDq0K0RJfNFkuDBD8_ytf8hr6NRDkORzywIE0-KupyPhhKdrKSVD9xGu6e1gctzKYa_M7uNqEGEmaukQp0fKtjd9NJNENfYsomdKNGo9-WoPB-yk1zHLLJN6LgPG9jXuQdf48kEj10spLIYoRYQhyW1CuM8kKwv5O7GRIWFMMKBbL8fHnJzCGJM1xZve4muTinh28dXwbFyCQW9pvXWYqkJTEYTf2i3iB419Zn5wbPLIKg";
const RS256_N: &str = "z6rcqhtRYntm4SFUCZ3jb6bYNp6P1ZiK1Yg1GpZg3vCXnoiUdPc6-xb6obP3yLFFQ7B-Kd6qYO5mZfWk265__QZwbSmNffrWZPfVgiLkljJfukGZJ22iALk5VzMvSa14ghDHwtnqck0bWtYulCOfhFmP4D_5HjBruZ3pnBnqsmSmS8GMB_pXJ05Aniw3k-5lseKbWwL-8-te0xZcVm1Pxr7slPqBl75wp5h8T4XQ0g-UgElPNykbe3MoIYbdCmoH_-Z_yJ5jL6vUnz6SNpHVz2Qr17NoiXtuGUNYa6vwnLOy8imLdYh8qdVJQpHuQcXSwcOkdfcutiOH_goSBOpSsQ";
const RS256_E: &str = "AQAB";

/// Corrupt the JWT's signature segment, leaving it the same length and
/// still valid base64url.
///
/// The edited character is in the *middle* of the segment on purpose. In
/// the final character of a base64url-encoded 64-byte signature only the
/// top two bits are significant, so a flip there can be swallowed as
/// trailing padding — the token would then be rejected (or not) by the
/// base64 decoder rather than by the signature check, which is not what
/// this test is trying to prove.
fn tamper(jwt: &str) -> String {
    let (head, sig) = jwt.rsplit_once('.').expect("jwt has three segments");
    let mut chars: Vec<char> = sig.chars().collect();
    let mid = chars.len() / 2;
    chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    assert_ne!(sig, tampered, "tamper() must actually change the signature");
    format!("{head}.{tampered}")
}

/// Split a compact JWT into `(signing_input_bytes, signature_bytes)`.
fn split_jwt(jwt: &str) -> (Vec<u8>, Vec<u8>) {
    let (signing_input, sig_b64) = jwt.rsplit_once('.').expect("jwt has three segments");
    let sig = aitp_core::base64url::decode_strict(sig_b64).expect("valid base64url signature");
    (signing_input.as_bytes().to_vec(), sig)
}

/// Assert both `aitp_handshake::verify_jws_signature` and `jsonwebtoken`
/// (the differential oracle) agree: the real JWT verifies, and a
/// tampered copy is rejected.
fn assert_backend_live(
    alg: JwsAlgorithm,
    jwt: &str,
    key: &JwkPublicKey,
    jsonwebtoken_alg: Algorithm,
    jsonwebtoken_key: &DecodingKey,
) {
    let (signing_input, sig) = split_jwt(jwt);

    // Positive, our own backend.
    verify_jws_signature(key, alg.as_str(), &signing_input, &sig)
        .unwrap_or_else(|e| panic!("{alg}: verify_jws_signature rejected a valid token: {e}"));

    // Negative, our own backend.
    let tampered = tamper(jwt);
    let (tampered_input, tampered_sig) = split_jwt(&tampered);
    assert!(
        verify_jws_signature(key, alg.as_str(), &tampered_input, &tampered_sig).is_err(),
        "{alg}: verify_jws_signature accepted a token with a corrupted signature"
    );

    // Differential oracle: jsonwebtoken 9 (dev-dependency only) must
    // agree on both directions.
    let validation = {
        let mut v = Validation::new(jsonwebtoken_alg);
        v.validate_exp = false;
        v.validate_aud = false;
        v.required_spec_claims.clear();
        v
    };
    let decoded = jsonwebtoken::decode::<Value>(jwt, jsonwebtoken_key, &validation)
        .unwrap_or_else(|e| panic!("{alg}: jsonwebtoken failed to verify a valid token: {e}"));
    assert_eq!(
        decoded.claims["sub"], "aitp-jose-backend-tripwire",
        "{alg}: decoded the wrong claims"
    );
    assert!(
        jsonwebtoken::decode::<Value>(&tampered, jsonwebtoken_key, &validation).is_err(),
        "{alg}: jsonwebtoken accepted a token with a corrupted signature"
    );
}

#[test]
fn jose_backend_verifies_eddsa() {
    let pubkey = aitp_core::base64url::decode_strict_exact::<32>(EDDSA_PUBKEY_B64)
        .expect("fixture pubkey is 32 base64url-encoded bytes");
    let key = JwkPublicKey {
        kid: None,
        alg: JwsAlgorithm::EdDSA,
        key: JwkKeyMaterial::Ed25519 { x: pubkey },
    };
    assert_backend_live(
        JwsAlgorithm::EdDSA,
        EDDSA_JWT,
        &key,
        Algorithm::EdDSA,
        &DecodingKey::from_ed_der(&pubkey),
    );
}

#[test]
fn jose_backend_verifies_es256() {
    let x = aitp_core::base64url::decode_strict_exact::<32>(ES256_X).expect("fixture x");
    let y = aitp_core::base64url::decode_strict_exact::<32>(ES256_Y).expect("fixture y");
    let key = JwkPublicKey {
        kid: None,
        alg: JwsAlgorithm::ES256,
        key: JwkKeyMaterial::P256 { x, y },
    };
    let jsonwebtoken_key =
        DecodingKey::from_ec_components(ES256_X, ES256_Y).expect("fixture P-256 components");
    assert_backend_live(
        JwsAlgorithm::ES256,
        ES256_JWT,
        &key,
        Algorithm::ES256,
        &jsonwebtoken_key,
    );
}

#[test]
fn jose_backend_verifies_rs256() {
    let n = aitp_core::base64url::decode_strict(RS256_N).expect("fixture n");
    let e = aitp_core::base64url::decode_strict(RS256_E).expect("fixture e");
    let key = JwkPublicKey {
        kid: None,
        alg: JwsAlgorithm::RS256,
        key: JwkKeyMaterial::Rsa { n, e },
    };
    let jsonwebtoken_key =
        DecodingKey::from_rsa_components(RS256_N, RS256_E).expect("fixture RSA components");
    assert_backend_live(
        JwsAlgorithm::RS256,
        RS256_JWT,
        &key,
        Algorithm::RS256,
        &jsonwebtoken_key,
    );
}
