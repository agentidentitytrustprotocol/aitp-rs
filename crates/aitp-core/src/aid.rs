//! AITP Agent Identifier (AID).
//!
//! v0.2 accepts both the legacy v0.1 grammar
//! (`aid:pubkey:<43-char-b64url>`, Ed25519 implicit) and the
//! algorithm-tagged grammar
//! (`aid:pubkey:<alg>:<identifier>` where `<alg>` is `ed25519` or
//! `p256`). Per RFC-AITP-0001 §5.3 the legacy and the tagged-ed25519
//! forms are *trust-equivalent* but not byte-equal in canonical
//! signing bytes, so each AID lifecycle picks one form and stays
//! with it.

use crate::AID_PUBKEY_IDENTIFIER_LEN;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use std::fmt;

/// `aid:pubkey:` prefix — common to both legacy and tagged forms.
const AID_PUBKEY_PREFIX: &str = "aid:pubkey:";

/// Algorithm-tagged AID prefix for Ed25519.
const AID_PUBKEY_ED25519_PREFIX: &str = "aid:pubkey:ed25519:";

/// Algorithm-tagged AID prefix for ECDSA P-256.
const AID_PUBKEY_P256_PREFIX: &str = "aid:pubkey:p256:";

/// Identifier length for a SEC1-compressed P-256 public key
/// (33 raw bytes → 44 unpadded base64url chars).
const AID_P256_IDENTIFIER_LEN: usize = 44;

/// Algorithm of the public key bound to an AID.
///
/// Marked `#[non_exhaustive]` so future suites (e.g. Ed448, post-quantum
/// candidates) can be added in a minor release without forcing
/// downstream code to upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AidAlgorithm {
    /// Ed25519 (RFC 8032). Identifier is the 32-byte raw public key.
    Ed25519,
    /// ECDSA on P-256 with SHA-256. Identifier is the 33-byte SEC1
    /// compressed point.
    P256,
}

impl AidAlgorithm {
    /// Wire tag (`ed25519`, `p256`).
    pub fn as_str(&self) -> &'static str {
        match self {
            AidAlgorithm::Ed25519 => "ed25519",
            AidAlgorithm::P256 => "p256",
        }
    }
}

/// A validated AITP Agent Identifier.
///
/// Construct via [`Aid::parse`] or [`Aid::from_ed25519`]. Holding an `Aid` is
/// proof that the value passed format validation: the string starts with
/// `aid:pubkey:` and the identifier component is the expected length and
/// alphabet for its algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Aid(String);

impl Aid {
    /// Parse and validate an AID string. Accepts:
    ///
    /// - **Legacy v0.1 (untagged)**: `aid:pubkey:<43-char-b64url>` —
    ///   interpreted as Ed25519.
    /// - **v0.2 tagged Ed25519**: `aid:pubkey:ed25519:<43-char-b64url>`.
    /// - **v0.2 tagged P-256**: `aid:pubkey:p256:<44-char-b64url>` (SEC1
    ///   compressed point).
    pub fn parse(s: &str) -> Result<Self, AidParseError> {
        if let Some(identifier) = s.strip_prefix(AID_PUBKEY_ED25519_PREFIX) {
            validate_ed25519_identifier(identifier)?;
            return Ok(Self(s.to_string()));
        }
        if let Some(identifier) = s.strip_prefix(AID_PUBKEY_P256_PREFIX) {
            validate_p256_identifier(identifier)?;
            return Ok(Self(s.to_string()));
        }
        if let Some(identifier) = s.strip_prefix(AID_PUBKEY_PREFIX) {
            // Legacy v0.1 form (untagged → Ed25519 implicit).
            // identifier must NOT contain `:` (which would indicate a
            // tag we didn't recognize above).
            if identifier.contains(':') {
                let (method, _) = identifier.split_once(':').unwrap();
                return Err(AidParseError::UnsupportedMethod(format!("pubkey:{method}")));
            }
            validate_ed25519_identifier(identifier)?;
            return Ok(Self(s.to_string()));
        }
        // Doesn't start with `aid:pubkey:` — surface the right error.
        if let Some(rest) = s.strip_prefix("aid:") {
            let method = rest.split(':').next().unwrap_or("");
            return Err(AidParseError::UnsupportedMethod(method.to_string()));
        }
        Err(AidParseError::MissingScheme)
    }

    /// Construct a legacy (untagged) Ed25519 AID from a raw 32-byte public key.
    /// Kept for backward-compat; new code should prefer
    /// [`Aid::from_ed25519_tagged`] which emits the v0.2 algorithm-tagged
    /// form.
    pub fn from_ed25519(pubkey: &[u8; 32]) -> Self {
        let identifier = Base64UrlUnpadded::encode_string(pubkey);
        debug_assert_eq!(identifier.len(), AID_PUBKEY_IDENTIFIER_LEN);
        Self(format!("{AID_PUBKEY_PREFIX}{identifier}"))
    }

    /// Construct an algorithm-tagged Ed25519 AID (v0.2 form).
    pub fn from_ed25519_tagged(pubkey: &[u8; 32]) -> Self {
        let identifier = Base64UrlUnpadded::encode_string(pubkey);
        debug_assert_eq!(identifier.len(), AID_PUBKEY_IDENTIFIER_LEN);
        Self(format!("{AID_PUBKEY_ED25519_PREFIX}{identifier}"))
    }

    /// Construct a P-256 AID from a 33-byte SEC1 compressed point.
    pub fn from_p256(compressed_point: &[u8; 33]) -> Self {
        let identifier = Base64UrlUnpadded::encode_string(compressed_point);
        debug_assert_eq!(identifier.len(), AID_P256_IDENTIFIER_LEN);
        Self(format!("{AID_PUBKEY_P256_PREFIX}{identifier}"))
    }

    /// Algorithm bound to this AID, derived from the prefix.
    pub fn algorithm(&self) -> AidAlgorithm {
        if self.0.starts_with(AID_PUBKEY_P256_PREFIX) {
            AidAlgorithm::P256
        } else {
            AidAlgorithm::Ed25519
        }
    }

    /// Return the identifier component (everything after the
    /// algorithm prefix). For legacy AIDs this is everything after
    /// `aid:pubkey:` (43 chars); for tagged AIDs it's everything
    /// after `aid:pubkey:<alg>:`.
    pub fn identifier(&self) -> &str {
        if let Some(id) = self.0.strip_prefix(AID_PUBKEY_ED25519_PREFIX) {
            id
        } else if let Some(id) = self.0.strip_prefix(AID_PUBKEY_P256_PREFIX) {
            id
        } else {
            &self.0[AID_PUBKEY_PREFIX.len()..]
        }
    }

    /// Decode the identifier back to the raw 32-byte Ed25519 public key.
    /// Panics if the AID is not an Ed25519 AID. Use
    /// [`Aid::algorithm`] to discriminate first.
    pub fn to_ed25519_bytes(&self) -> [u8; 32] {
        assert!(
            matches!(self.algorithm(), AidAlgorithm::Ed25519),
            "Aid::to_ed25519_bytes called on non-Ed25519 AID"
        );
        let mut out = [0u8; 32];
        Base64UrlUnpadded::decode(self.identifier(), &mut out)
            .expect("Aid is validated on construction; identifier MUST decode to 32 bytes");
        out
    }

    /// Decode the identifier back to the 33-byte SEC1 compressed
    /// P-256 public key. Panics if the AID is not a P-256 AID.
    pub fn to_p256_bytes(&self) -> [u8; 33] {
        assert!(
            matches!(self.algorithm(), AidAlgorithm::P256),
            "Aid::to_p256_bytes called on non-P-256 AID"
        );
        let mut out = [0u8; 33];
        Base64UrlUnpadded::decode(self.identifier(), &mut out)
            .expect("Aid is validated on construction; identifier MUST decode to 33 bytes");
        out
    }

    /// Decode the identifier back to the AID's algorithm-agile
    /// compressed public-key bytes — 32 bytes for Ed25519 (raw
    /// pubkey) or 33 bytes for P-256 (SEC1-compressed). This is the
    /// canonical encoding embedded in `TctBinding.cnf` /
    /// `DelegationBinding.cnf` for algorithm-agile signing-key
    /// bindings; callers verifying a `cnf` against an AID should
    /// byte-compare against this value rather than the legacy
    /// Ed25519-only [`Self::to_ed25519_bytes`].
    pub fn pubkey_compressed_bytes(&self) -> Vec<u8> {
        match self.algorithm() {
            AidAlgorithm::Ed25519 => self.to_ed25519_bytes().to_vec(),
            AidAlgorithm::P256 => self.to_p256_bytes().to_vec(),
        }
    }

    /// Return the full AID string verbatim.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_ed25519_identifier(identifier: &str) -> Result<(), AidParseError> {
    if identifier.len() != AID_PUBKEY_IDENTIFIER_LEN {
        return Err(AidParseError::WrongLength(identifier.len()));
    }
    if !identifier.bytes().all(is_base64url_byte) {
        return Err(AidParseError::InvalidChars);
    }
    let mut buf = [0u8; 32];
    Base64UrlUnpadded::decode(identifier, &mut buf).map_err(|_| AidParseError::InvalidChars)?;
    Ok(())
}

fn validate_p256_identifier(identifier: &str) -> Result<(), AidParseError> {
    if identifier.len() != AID_P256_IDENTIFIER_LEN {
        return Err(AidParseError::WrongLength(identifier.len()));
    }
    if !identifier.bytes().all(is_base64url_byte) {
        return Err(AidParseError::InvalidChars);
    }
    let mut buf = [0u8; 33];
    Base64UrlUnpadded::decode(identifier, &mut buf).map_err(|_| AidParseError::InvalidChars)?;
    // SEC1 compressed-point byte MUST be 0x02 or 0x03 (sign bit on
    // the y-coordinate). Anything else is malformed.
    if buf[0] != 0x02 && buf[0] != 0x03 {
        return Err(AidParseError::InvalidChars);
    }
    Ok(())
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
///
/// Marked `#[non_exhaustive]`: new parse-failure modes added by future
/// AID grammar revisions land as new variants without a major bump.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
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

    #[test]
    fn parse_accepts_tagged_ed25519() {
        let pk = sample_pubkey();
        let tagged = Aid::from_ed25519_tagged(&pk);
        assert!(tagged.as_str().starts_with("aid:pubkey:ed25519:"));
        assert_eq!(tagged.algorithm(), AidAlgorithm::Ed25519);
        let parsed = Aid::parse(tagged.as_str()).unwrap();
        assert_eq!(parsed, tagged);
        // The legacy untagged AID over the same pubkey is a
        // different string — they're trust-equivalent but not
        // byte-equal in canonical signing bytes (RFC-AITP-0001 §5.3).
        let legacy = Aid::from_ed25519(&pk);
        assert_ne!(tagged.as_str(), legacy.as_str());
    }

    #[test]
    fn parse_accepts_p256_kat() {
        // kat-keypair-005-p256: private_scalar = 0x05*32, pubkey =
        // 0x0307810ea974cea5773e63b897f37e3be9a09e7a5fe9b971a44d1065ac2a3a9311
        // (SEC1 compressed point).
        let aid_str = "aid:pubkey:p256:AweBDql0zqV3PmO4l_N-O-mgnnpf6blxpE0QZawqOpMR";
        let aid = Aid::parse(aid_str).unwrap();
        assert_eq!(aid.algorithm(), AidAlgorithm::P256);
        let pubkey = aid.to_p256_bytes();
        // First byte is the sign bit (0x02 or 0x03 for SEC1 compressed).
        assert_eq!(pubkey[0], 0x03);
    }

    #[test]
    fn p256_round_trip() {
        let mut pubkey = [0u8; 33];
        pubkey[0] = 0x02;
        pubkey[1] = 0xAB;
        let aid = Aid::from_p256(&pubkey);
        let parsed = Aid::parse(aid.as_str()).unwrap();
        assert_eq!(parsed.algorithm(), AidAlgorithm::P256);
        assert_eq!(parsed.to_p256_bytes(), pubkey);
    }

    #[test]
    fn p256_rejects_wrong_sec1_tag() {
        // 0x04 = uncompressed point — we only accept 0x02/0x03
        // (compressed forms). 33 raw bytes encode to 44 b64url chars.
        let mut pubkey = [0u8; 33];
        pubkey[0] = 0x04;
        let identifier = Base64UrlUnpadded::encode_string(&pubkey);
        let aid_str = format!("aid:pubkey:p256:{identifier}");
        assert!(Aid::parse(&aid_str).is_err());
    }

    #[test]
    fn rejects_unknown_algorithm_tag() {
        // `aid:pubkey:rsa4096:...` is not in the registry.
        let identifier = Base64UrlUnpadded::encode_string(&[0xFFu8; 33]);
        let aid_str = format!("aid:pubkey:rsa4096:{identifier}");
        assert!(Aid::parse(&aid_str).is_err());
    }
}
