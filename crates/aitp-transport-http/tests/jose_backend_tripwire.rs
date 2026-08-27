//! Runtime tripwire for the `jsonwebtoken` crypto backend.
//!
//! # Why this test exists
//!
//! `jsonwebtoken` 9.x carries its own `ring`-backed crypto. From 10.x
//! onwards it does not: the caller must enable exactly one backend
//! feature (`rust_crypto` or `aws_lc_rs`), and with none selected the
//! crate still **compiles** but every `sign`/`verify` call **panics at
//! runtime** with "Could not automatically determine the process-level
//! CryptoProvider". A compile-time guarantee is therefore worth nothing
//! here — only actually running a verification proves the backend is
//! wired up.
//!
//! Two places in this workspace dispatch to `jsonwebtoken` for
//! signature verification, and between them they reach three
//! algorithms:
//!
//! * `aitp_transport_http::dpop` — EdDSA, ES256, RS256.
//! * `aitp_handshake::identity_oidc` — whatever the OIDC provider's JWKS
//!   advertises, which in practice is overwhelmingly RS256.
//!
//! The rest of the suite only ever exercises the **EdDSA** path (the
//! mock OIDC issuer and the JWS differential-oracle KATs are both
//! Ed25519), so ES256 and RS256 verification through `jsonwebtoken` is
//! otherwise never executed. This test closes that gap deliberately and
//! by name, so it does not evaporate the next time those fixtures are
//! reworked.
//!
//! # What it asserts
//!
//! For each of the three algorithms: a known-good JWT verifies, and the
//! same JWT with one signature byte flipped is rejected. The negative
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

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::Value;

const EDDSA_JWT: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3RyaXB3aXJlLmludmFsaWQiLCJzdWIiOiJhaXRwLWpvc2UtYmFja2VuZC10cmlwd2lyZSJ9.5KYBY-Y_hC4RvKCy0UOr66xcqpSSgu9JpQ7G1aS8_Z0RYZihOTDaegzCu959ZZwDie3k5VtAdRk906svfdAtCg";
/// Raw 32-byte Ed25519 public key, unpadded base64url. `from_ed_der` is
/// misleadingly named — it wants the raw point, not SPKI DER.
const EDDSA_PUBKEY_B64: &str = "WEYA2ZMs-lBzwES7chTdHrRI3h3brBd4jdEywnZjfd4";

const ES256_JWT: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3RyaXB3aXJlLmludmFsaWQiLCJzdWIiOiJhaXRwLWpvc2UtYmFja2VuZC10cmlwd2lyZSJ9.tx8H3ygtKFqVYI1kEqbHK4GoO-u1KhT__DKhTJvQviBqtaygpP-BV6cbI5bgBC3l9Fy_C85vWkGiJaeHiK0vWw";
const ES256_X: &str = "XjOwiXKtAwtMdglp3uEU3kjcp8MJd02ldldhytwfJdA";
const ES256_Y: &str = "FmJYi_tMz18SzSYFl3IfJWYZFnjw3hZO5L4fc2ePPBw";

const RS256_JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3RyaXB3aXJlLmludmFsaWQiLCJzdWIiOiJhaXRwLWpvc2UtYmFja2VuZC10cmlwd2lyZSJ9.tJk3nPvvLVSHNlZXqf8MXHVn7wpfdoirs12-c0wexhGroh7sJPYkIEKMqxnTyWGt6NTvkW85hfAVQjeAu34hgVvrY2XQiWW9mAacTkU_GDq0K0RJfNFkuDBD8_ytf8hr6NRDkORzywIE0-KupyPhhKdrKSVD9xGu6e1gctzKYa_M7uNqEGEmaukQp0fKtjd9NJNENfYsomdKNGo9-WoPB-yk1zHLLJN6LgPG9jXuQdf48kEj10spLIYoRYQhyW1CuM8kKwv5O7GRIWFMMKBbL8fHnJzCGJM1xZve4muTinh28dXwbFyCQW9pvXWYqkJTEYTf2i3iB419Zn5wbPLIKg";
const RS256_N: &str = "z6rcqhtRYntm4SFUCZ3jb6bYNp6P1ZiK1Yg1GpZg3vCXnoiUdPc6-xb6obP3yLFFQ7B-Kd6qYO5mZfWk265__QZwbSmNffrWZPfVgiLkljJfukGZJ22iALk5VzMvSa14ghDHwtnqck0bWtYulCOfhFmP4D_5HjBruZ3pnBnqsmSmS8GMB_pXJ05Aniw3k-5lseKbWwL-8-te0xZcVm1Pxr7slPqBl75wp5h8T4XQ0g-UgElPNykbe3MoIYbdCmoH_-Z_yJ5jL6vUnz6SNpHVz2Qr17NoiXtuGUNYa6vwnLOy8imLdYh8qdVJQpHuQcXSwcOkdfcutiOH_goSBOpSsQ";
const RS256_E: &str = "AQAB";

/// The fixtures carry no `exp`/`aud`; this test is about the signature
/// path only, so turn the claim policy off and leave claim semantics to
/// the AITP verifiers that own them.
fn signature_only(alg: Algorithm) -> Validation {
    let mut validation = Validation::new(alg);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    validation
}

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

fn assert_backend_live(alg: Algorithm, jwt: &str, key: &DecodingKey) {
    let validation = signature_only(alg);

    // Positive: a real signature must verify. If no crypto backend is
    // compiled in, this line panics rather than returning `Err`.
    let decoded = jsonwebtoken::decode::<Value>(jwt, key, &validation)
        .unwrap_or_else(|e| panic!("{alg:?}: jsonwebtoken failed to verify a valid token: {e}"));
    assert_eq!(
        decoded.claims["sub"], "aitp-jose-backend-tripwire",
        "{alg:?}: decoded the wrong claims"
    );

    // Negative: a tampered signature must be rejected. Catches a backend
    // that "verifies" everything.
    assert!(
        jsonwebtoken::decode::<Value>(&tamper(jwt), key, &validation).is_err(),
        "{alg:?}: jsonwebtoken accepted a token with a corrupted signature"
    );
}

#[test]
fn jose_backend_verifies_eddsa() {
    let pubkey = aitp_core::base64url::decode_strict_exact::<32>(EDDSA_PUBKEY_B64)
        .expect("fixture pubkey is 32 base64url-encoded bytes");
    assert_backend_live(
        Algorithm::EdDSA,
        EDDSA_JWT,
        &DecodingKey::from_ed_der(&pubkey),
    );
}

#[test]
fn jose_backend_verifies_es256() {
    let key = DecodingKey::from_ec_components(ES256_X, ES256_Y).expect("fixture P-256 components");
    assert_backend_live(Algorithm::ES256, ES256_JWT, &key);
}

#[test]
fn jose_backend_verifies_rs256() {
    let key = DecodingKey::from_rsa_components(RS256_N, RS256_E).expect("fixture RSA components");
    assert_backend_live(Algorithm::RS256, RS256_JWT, &key);
}
