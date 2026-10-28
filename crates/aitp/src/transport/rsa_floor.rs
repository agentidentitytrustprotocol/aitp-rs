//! The RSA modulus floor for the OIDC keys a JWKS fetch returns.

/// Minimum accepted RSA modulus size, in bits, for third-party
/// (OIDC) verification keys. 2048 bits is the floor NIST
/// SP 800-131A and every mainstream IdP have required for years;
/// anything smaller is a weak-key acceptance bug.
pub(crate) const MIN_RSA_MODULUS_BITS: usize = 2048;

/// Whether a base64url-encoded RSA modulus (`n`) meets
/// [`MIN_RSA_MODULUS_BITS`].
///
/// The JWK `n` parameter is the big-endian modulus with no leading zero
/// octets (RFC 7518 §6.3.1), so its decoded byte length maps directly to
/// the key size. We strip any leading zero bytes defensively before
/// measuring, and count bits from the most-significant set bit so a
/// modulus that is one bit short of 2048 is still rejected. Returns
/// `false` if `n` is not valid base64url.
pub(crate) fn rsa_modulus_bits_ok(n_b64: &str) -> bool {
    let Ok(bytes) = crate::core::base64url::decode_strict(n_b64) else {
        return false;
    };
    let first_set = bytes.iter().position(|&b| b != 0);
    let Some(first) = first_set else {
        return false; // all-zero / empty modulus
    };
    let significant = &bytes[first..];
    // Bits = 8 * (full bytes after the top one) + bit-width of the top byte.
    let top = significant[0];
    let top_bits = 8 - top.leading_zeros() as usize;
    let bits = top_bits + (significant.len() - 1) * 8;
    bits >= MIN_RSA_MODULUS_BITS
}

#[cfg(test)]
mod rsa_floor_tests {
    use super::rsa_modulus_bits_ok;
    use crate::core::base64url::encode;

    fn n_of_bytes(len: usize, top: u8) -> String {
        let mut v = vec![0xffu8; len];
        v[0] = top;
        encode(&v)
    }

    #[test]
    fn accepts_2048_and_larger() {
        assert!(rsa_modulus_bits_ok(&n_of_bytes(256, 0x80))); // exactly 2048
        assert!(rsa_modulus_bits_ok(&n_of_bytes(384, 0x80))); // 3072
        assert!(rsa_modulus_bits_ok(&n_of_bytes(512, 0x01))); // 4096-ish, low top byte
    }

    #[test]
    fn rejects_below_2048() {
        assert!(!rsa_modulus_bits_ok(&n_of_bytes(128, 0x80))); // 1024
        assert!(!rsa_modulus_bits_ok(&n_of_bytes(255, 0xff))); // 2040 — one byte short
                                                               // 256 bytes but top byte 0x01 => 2041 bits, still short of 2048.
        assert!(!rsa_modulus_bits_ok(&n_of_bytes(256, 0x01)));
    }

    #[test]
    fn ignores_leading_zero_padding() {
        // 0x00 || 256 significant bytes (top 0x80) = 2048-bit modulus.
        let mut v = vec![0u8, 0x80];
        v.extend(std::iter::repeat_n(0xffu8, 255));
        assert!(rsa_modulus_bits_ok(&encode(&v)));
    }

    #[test]
    fn rejects_garbage_and_empty() {
        assert!(!rsa_modulus_bits_ok("!!!not-base64!!!"));
        assert!(!rsa_modulus_bits_ok(""));
        assert!(!rsa_modulus_bits_ok(&encode(&[0u8; 300])));
    }
}
