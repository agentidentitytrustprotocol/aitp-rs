//! RFC 7638 JWK thumbprint computation, pinned to the AITP profile.
//!
//! AITP pins the JWK input format (RFC-AITP-0002 §2.2.1) so that two
//! implementations always agree on the thumbprint of the same key.

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
}
