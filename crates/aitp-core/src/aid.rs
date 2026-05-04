//! AITP Agent Identifier (AID).
//!
//! In v0.1, the only supported method is `pubkey` and the identifier is the
//! unpadded base64url encoding of a 32-byte raw Ed25519 public key — exactly
//! 43 base64url characters.

use crate::AID_PUBKEY_IDENTIFIER_LEN;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use std::fmt;

/// `aid:pubkey:` — the only AID prefix supported in v0.1.
const AID_PUBKEY_PREFIX: &str = "aid:pubkey:";

/// A validated AITP Agent Identifier.
///
/// Construct via [`Aid::parse`] or [`Aid::from_ed25519`]. Holding an `Aid` is
/// proof that the value passed v0.1 format validation: the string starts with
/// `aid:pubkey:` and the identifier component is exactly 43 base64url chars.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Aid(String);

impl Aid {
    /// Parse and validate an AID string.
    ///
    /// Accepts only `aid:pubkey:<43-char-base64url>` in v0.1.
    pub fn parse(s: &str) -> Result<Self, AidParseError> {
        let rest = s.strip_prefix("aid:").ok_or(AidParseError::MissingScheme)?;
        let (method, identifier) = rest.split_once(':').ok_or(AidParseError::MissingScheme)?;
        if method != "pubkey" {
            return Err(AidParseError::UnsupportedMethod(method.to_string()));
        }
        if identifier.len() != AID_PUBKEY_IDENTIFIER_LEN {
            return Err(AidParseError::WrongLength(identifier.len()));
        }
        if !identifier.bytes().all(is_base64url_byte) {
            return Err(AidParseError::InvalidChars);
        }
        // Confirm the identifier actually decodes to 32 bytes — guards
        // against valid-looking strings that map to an over- or under-sized
        // payload.
        let mut buf = [0u8; 32];
        Base64UrlUnpadded::decode(identifier, &mut buf).map_err(|_| AidParseError::InvalidChars)?;
        Ok(Self(s.to_string()))
    }

    /// Construct an AID from a raw 32-byte Ed25519 public key.
    pub fn from_ed25519(pubkey: &[u8; 32]) -> Self {
        let identifier = Base64UrlUnpadded::encode_string(pubkey);
        debug_assert_eq!(identifier.len(), AID_PUBKEY_IDENTIFIER_LEN);
        Self(format!("{}{}", AID_PUBKEY_PREFIX, identifier))
    }

    /// Return the 43-character identifier component (everything after `aid:pubkey:`).
    pub fn identifier(&self) -> &str {
        &self.0[AID_PUBKEY_PREFIX.len()..]
    }

    /// Decode the identifier back to the raw 32-byte Ed25519 public key.
    ///
    /// Cannot fail because [`Aid::parse`] / [`Aid::from_ed25519`] validate the
    /// identifier on construction.
    pub fn to_ed25519_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        Base64UrlUnpadded::decode(self.identifier(), &mut out)
            .expect("Aid is validated on construction; identifier MUST decode to 32 bytes");
        out
    }

    /// Return the full `aid:pubkey:...` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Aid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Aid {
    type Error = AidParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Aid::parse(&s)
    }
}

impl From<Aid> for String {
    fn from(a: Aid) -> String {
        a.0
    }
}

/// Reasons an AID string can be rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AidParseError {
    /// Missing the `aid:` URI scheme prefix.
    #[error("AID does not start with 'aid:'")]
    MissingScheme,

    /// Method other than `pubkey` (e.g. `did`, `x509`) — not supported in v0.1.
    #[error("AID method '{0}' is not supported in v0.1; expected 'pubkey'")]
    UnsupportedMethod(String),

    /// Identifier length is not 43 (raw Ed25519 base64url-unpadded).
    #[error(
        "AID identifier must be exactly {} characters; got {0}",
        AID_PUBKEY_IDENTIFIER_LEN
    )]
    WrongLength(usize),

    /// Identifier contains characters outside the base64url alphabet.
    #[error("AID identifier contains non-base64url characters")]
    InvalidChars,
}

fn is_base64url_byte(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pubkey() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn rejects_missing_scheme() {
        assert!(matches!(
            Aid::parse("pubkey:abc"),
            Err(AidParseError::MissingScheme)
        ));
    }

    #[test]
    fn rejects_unsupported_method() {
        let s = format!("aid:did:{}", "A".repeat(AID_PUBKEY_IDENTIFIER_LEN));
        assert!(matches!(
            Aid::parse(&s),
            Err(AidParseError::UnsupportedMethod(m)) if m == "did"
        ));
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(matches!(
            Aid::parse(&format!("aid:pubkey:{}", "A".repeat(42))),
            Err(AidParseError::WrongLength(42))
        ));
        assert!(matches!(
            Aid::parse(&format!("aid:pubkey:{}", "A".repeat(44))),
            Err(AidParseError::WrongLength(44))
        ));
    }

    #[test]
    fn rejects_padding() {
        // 43 chars including a `=` is not valid base64url-unpadded.
        let mut s = "A".repeat(42);
        s.push('=');
        assert!(matches!(
            Aid::parse(&format!("aid:pubkey:{}", s)),
            Err(AidParseError::InvalidChars)
        ));
    }

    #[test]
    fn rejects_invalid_chars() {
        let mut id = "A".repeat(42);
        id.push('!');
        assert!(matches!(
            Aid::parse(&format!("aid:pubkey:{}", id)),
            Err(AidParseError::InvalidChars)
        ));
    }

    #[test]
    fn round_trips_pubkey_bytes() {
        let pk = sample_pubkey();
        let aid = Aid::from_ed25519(&pk);
        assert!(aid.as_str().starts_with("aid:pubkey:"));
        assert_eq!(aid.identifier().len(), AID_PUBKEY_IDENTIFIER_LEN);
        assert_eq!(aid.to_ed25519_bytes(), pk);
    }

    #[test]
    fn parse_accepts_valid_aid() {
        let aid = Aid::from_ed25519(&sample_pubkey());
        let parsed = Aid::parse(aid.as_str()).unwrap();
        assert_eq!(parsed, aid);
    }

    #[test]
    fn serde_round_trip() {
        let aid = Aid::from_ed25519(&sample_pubkey());
        let json = serde_json::to_string(&aid).unwrap();
        let back: Aid = serde_json::from_str(&json).unwrap();
        assert_eq!(back, aid);
    }
}
