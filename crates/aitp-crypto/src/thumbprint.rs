//! RFC 7638 JWK thumbprint computation, pinned to the AITP profile.
//!
//! AITP pins the JWK input format (RFC-AITP-0002 §2.2.1) so that two
//! implementations always agree on the thumbprint of the same key.
//! Both Ed25519 (OKP) and P-256 (EC) keys are supported; the input
//! shape and member ordering match the corresponding RFC 7638 §3.2
//! required members.

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};

/// Compute the RFC 7638 JWK thumbprint for an Ed25519 public key.
///
/// The JWK input is pinned to:
///
/// ```json
/// {"crv":"Ed25519","kty":"OKP","x":"<aid-identifier>"}
/// ```
///
/// Members are in lexicographic order, no whitespace. Returns the
/// base64url-unpadded SHA-256 digest of these bytes.
pub fn compute_jwk_thumbprint(pubkey_bytes: &[u8; 32]) -> String {
    let x = Base64UrlUnpadded::encode_string(pubkey_bytes);
    let canonical_jwk = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, x);
    let digest = Sha256::digest(canonical_jwk.as_bytes());
    Base64UrlUnpadded::encode_string(&digest)
}

/// Compute the RFC 7638 JWK thumbprint for a P-256 ECDSA public key
/// from its affine coordinates.
///
/// The JWK input is pinned to:
///
/// ```json
/// {"crv":"P-256","kty":"EC","x":"<b64u(x, 32 bytes)>","y":"<b64u(y, 32 bytes)>"}
/// ```
///
/// `x` and `y` are the affine coordinates as 32-byte big-endian
/// unsigned integers (the standard JWK convention; RFC 7518 §6.2.1.2
/// / §6.2.1.3). Members are in lexicographic order (`crv`, `kty`,
/// `x`, `y`), no whitespace, matching the RFC 7638 §3.2 required
/// members for an EC public key. Returns the base64url-unpadded
/// SHA-256 digest of these bytes.
///
/// Callers that hold a `p256::ecdsa::VerifyingKey` should obtain
/// `(x, y)` from `to_encoded_point(false)` and strip the leading
/// `0x04` SEC1 prefix; see [`crate::AitpVerifyingKey::to_jwk_thumbprint`]
/// for the algorithm-agile entry point.
pub fn compute_jwk_thumbprint_p256(x: &[u8; 32], y: &[u8; 32]) -> String {
    let x_b64 = Base64UrlUnpadded::encode_string(x);
    let y_b64 = Base64UrlUnpadded::encode_string(y);
    let canonical_jwk = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        x_b64, y_b64
    );
    let digest = Sha256::digest(canonical_jwk.as_bytes());
    Base64UrlUnpadded::encode_string(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test for the JWK thumbprint computation.
    ///
    /// The expected value is to be pinned in RFC-AITP-0002 once the spec adds
    /// known-answer tests (SPEC-006). Until then, this test only verifies
    /// that the format is well-formed and reproducible.
    #[test]
    fn thumbprint_is_reproducible() {
        let key = [0xABu8; 32];
        let t1 = compute_jwk_thumbprint(&key);
        let t2 = compute_jwk_thumbprint(&key);
        assert_eq!(t1, t2);
        // SHA-256 → 32 bytes → 43 base64url-unpadded chars.
        assert_eq!(t1.len(), 43);
    }

    #[test]
    fn p256_thumbprint_is_reproducible_and_well_formed() {
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let t1 = compute_jwk_thumbprint_p256(&x, &y);
        let t2 = compute_jwk_thumbprint_p256(&x, &y);
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 43);
    }

    #[test]
    fn p256_thumbprint_distinct_from_ed25519_for_same_x() {
        // Sanity: the kty/crv discriminators in the canonical JWK
        // change the hash input, so a P-256 thumbprint for (x, y=0..0)
        // never collides with an Ed25519 thumbprint of the same `x`.
        let x = [0x11u8; 32];
        let y = [0x00u8; 32];
        let p256_t = compute_jwk_thumbprint_p256(&x, &y);
        let ed_t = compute_jwk_thumbprint(&x);
        assert_ne!(p256_t, ed_t);
    }

    #[test]
    fn p256_thumbprint_canonical_form_is_lex_sorted_no_whitespace() {
        // The RFC 7638 canonical form for an EC public key MUST have
        // exactly the four required members in lexicographic order:
        // crv, kty, x, y — with no whitespace. Recompute the bytes
        // independently here as a spec-shape regression guard.
        let x = [0x33u8; 32];
        let y = [0x44u8; 32];
        let ours = compute_jwk_thumbprint_p256(&x, &y);

        let x_b64 = Base64UrlUnpadded::encode_string(&x);
        let y_b64 = Base64UrlUnpadded::encode_string(&y);
        let canonical = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            x_b64, y_b64
        );
        let expected = Base64UrlUnpadded::encode_string(&Sha256::digest(canonical.as_bytes()));
        assert_eq!(ours, expected);
    }
}
