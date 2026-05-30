//! Strict unpadded base64url codec (RFC 4648 §5).
//!
//! AITP requires unpadded base64url throughout. RFC-AITP-0001 §5.4 forbids
//! `=` padding on the wire — these helpers encode without padding and reject
//! padded input on decode.

use base64ct::{Base64UrlUnpadded, Encoding};

/// Errors from strict base64url decoding.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Base64UrlError {
    /// Input contained `=` padding, which is forbidden in AITP.
    #[error("base64url padding is forbidden in AITP")]
    PaddingNotAllowed,

    /// Input contained characters outside the base64url alphabet.
    #[error("invalid base64url character")]
    InvalidChar,

    /// Decoded length did not match the expected length for the value.
    #[error("invalid length")]
    InvalidLength,
}

/// Encode bytes as unpadded base64url.
pub fn encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Decode unpadded base64url; rejects `=` padding.
pub fn decode_strict(s: &str) -> Result<Vec<u8>, Base64UrlError> {
    if s.contains('=') {
        return Err(Base64UrlError::PaddingNotAllowed);
    }
    Base64UrlUnpadded::decode_vec(s).map_err(|_| Base64UrlError::InvalidChar)
}

/// Decode and assert the resulting length.
pub fn decode_strict_exact<const N: usize>(s: &str) -> Result<[u8; N], Base64UrlError> {
    let bytes = decode_strict(s)?;
    if bytes.len() != N {
        return Err(Base64UrlError::InvalidLength);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_padded_input() {
        assert_eq!(
            decode_strict("AA=="),
            Err(Base64UrlError::PaddingNotAllowed)
        );
    }

    #[test]
    fn round_trips_arbitrary_bytes() {
        let cases: &[&[u8]] = &[&[], b"a", b"hello", &[0xff; 32], &[0x00; 64]];
        for input in cases {
            let s = encode(input);
            assert!(!s.contains('='));
            assert_eq!(decode_strict(&s).unwrap(), *input);
        }
    }

    #[test]
    fn rejects_invalid_chars() {
        assert!(matches!(
            decode_strict("AA!A"),
            Err(Base64UrlError::InvalidChar)
        ));
    }

    #[test]
    fn decode_strict_exact_enforces_length() {
        let s = encode(&[0u8; 16]);
        assert!(decode_strict_exact::<16>(&s).is_ok());
        assert_eq!(
            decode_strict_exact::<32>(&s),
            Err(Base64UrlError::InvalidLength)
        );
    }
}
