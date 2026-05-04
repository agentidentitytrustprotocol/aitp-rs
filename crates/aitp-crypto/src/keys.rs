//! Ed25519 signing keys and verifying keys.

use crate::CryptoError;
use aitp_core::{Aid, ED25519_SIGNATURE_BASE64URL_LEN};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{
    Signature as DalekSignature, Signer, SigningKey as DalekSigningKey,
    VerifyingKey as DalekVerifyingKey,
};

/// An Ed25519 signing key, with cached AID derivation.
///
/// `ed25519_dalek::SigningKey` implements `ZeroizeOnDrop`, so the secret
/// scalar is wiped from memory when this value is dropped.
pub struct AitpSigningKey {
    inner: DalekSigningKey,
    aid: Aid,
}

impl AitpSigningKey {
    /// Generate a fresh keypair using OS randomness.
    pub fn generate() -> Self {
        let inner = DalekSigningKey::generate(&mut rand::rngs::OsRng);
        let aid = Aid::from_ed25519(&inner.verifying_key().to_bytes());
        Self { inner, aid }
    }

    /// Construct from a raw 32-byte seed.
    ///
    /// Useful for tests with pinned key material and for restoring a key
    /// from secure storage. Production callers SHOULD use [`Self::generate`].
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let inner = DalekSigningKey::from_bytes(seed);
        let aid = Aid::from_ed25519(&inner.verifying_key().to_bytes());
        Self { inner, aid }
    }

    /// Return the AID derived from this key's public component.
    pub fn aid(&self) -> &Aid {
        &self.aid
    }

    /// Return the corresponding verifying (public) key.
    pub fn verifying_key(&self) -> AitpVerifyingKey {
        AitpVerifyingKey(self.inner.verifying_key())
    }

    /// Sign a message (typically the JCS canonicalization of an AITP object).
    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.inner.sign(message);
        Signature(Base64UrlUnpadded::encode_string(&sig.to_bytes()))
    }
}

impl std::fmt::Debug for AitpSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AitpSigningKey")
            .field("aid", &self.aid)
            .finish_non_exhaustive()
    }
}

/// An Ed25519 verifying (public) key.
#[derive(Debug, Clone)]
pub struct AitpVerifyingKey(DalekVerifyingKey);

impl AitpVerifyingKey {
    /// Construct from the 32-byte raw public key embedded in an AID.
    pub fn from_aid(aid: &Aid) -> Result<Self, CryptoError> {
        let bytes = aid.to_ed25519_bytes();
        DalekVerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|e| CryptoError::AidNotEd25519(e.to_string()))
    }

    /// Construct from raw 32-byte public-key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        DalekVerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|e| CryptoError::KeyParseFailed(e.to_string()))
    }

    /// Verify a signature over `message`.
    ///
    /// Uses `verify_strict`, which rejects non-canonical signatures and
    /// weak public keys (low-order points, identity element). Cross-impl
    /// interop depends on this — non-strict verification accepts
    /// signatures that other implementations reject, leading to silent
    /// validity disagreements.
    pub fn verify(&self, message: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        let raw = Base64UrlUnpadded::decode_vec(sig.as_str())
            .map_err(|_| CryptoError::SignatureInvalid)?;
        if raw.len() != 64 {
            return Err(CryptoError::SignatureInvalid);
        }
        let mut buf = [0u8; 64];
        buf.copy_from_slice(&raw);
        let dalek_sig = DalekSignature::from_bytes(&buf);
        self.0
            .verify_strict(message, &dalek_sig)
            .map_err(|_| CryptoError::SignatureInvalid)
    }

    /// Compute the RFC 7638 JWK thumbprint per RFC-AITP-0002 §2.2.1.
    pub fn to_jwk_thumbprint(&self) -> String {
        crate::thumbprint::compute_jwk_thumbprint(&self.to_bytes())
    }

    /// The 32-byte raw public key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// An Ed25519 signature in unpadded base64url form (86 characters).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(String);

impl Signature {
    /// Parse a signature string.
    ///
    /// Validates: no `=` padding, exactly 86 characters, every byte in the
    /// base64url alphabet.
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        if s.contains('=') {
            return Err(CryptoError::SignatureMalformed(
                "padding is forbidden".into(),
            ));
        }
        if s.len() != ED25519_SIGNATURE_BASE64URL_LEN {
            return Err(CryptoError::SignatureMalformed(format!(
                "expected {} characters, got {}",
                ED25519_SIGNATURE_BASE64URL_LEN,
                s.len()
            )));
        }
        if !s.bytes().all(is_base64url_byte) {
            return Err(CryptoError::SignatureMalformed(
                "non-base64url character".into(),
            ));
        }
        Ok(Self(s.to_string()))
    }

    /// Return the base64url-unpadded string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the underlying string.
    pub fn into_string(self) -> String {
        self.0
    }
}

fn is_base64url_byte(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

const _: () = {
    assert!(ED25519_SIGNATURE_BASE64URL_LEN == 86);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_seed_yields_deterministic_aid() {
        let key = AitpSigningKey::from_seed(&[7u8; 32]);
        let again = AitpSigningKey::from_seed(&[7u8; 32]);
        assert_eq!(key.aid(), again.aid());
    }

    #[test]
    fn signs_and_verifies_round_trip() {
        let key = AitpSigningKey::from_seed(&[1u8; 32]);
        let msg = b"hello aitp";
        let sig = key.sign(msg);
        assert_eq!(sig.as_str().len(), ED25519_SIGNATURE_BASE64URL_LEN);
        let vk = key.verifying_key();
        vk.verify(msg, &sig).expect("signature should verify");
        assert!(vk.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn verifying_key_from_aid_round_trips() {
        let key = AitpSigningKey::from_seed(&[42u8; 32]);
        let vk = AitpVerifyingKey::from_aid(key.aid()).unwrap();
        assert_eq!(vk.to_bytes(), key.verifying_key().to_bytes());
    }

    #[test]
    fn signature_parse_rejects_padding() {
        let s = "A".repeat(85) + "=";
        assert!(matches!(
            Signature::parse(&s),
            Err(CryptoError::SignatureMalformed(_))
        ));
    }

    #[test]
    fn signature_parse_rejects_wrong_length() {
        assert!(matches!(
            Signature::parse(&"A".repeat(85)),
            Err(CryptoError::SignatureMalformed(_))
        ));
        assert!(matches!(
            Signature::parse(&"A".repeat(87)),
            Err(CryptoError::SignatureMalformed(_))
        ));
    }

    #[test]
    fn signature_parse_rejects_invalid_chars() {
        let mut s = "A".repeat(85);
        s.push('!');
        assert!(matches!(
            Signature::parse(&s),
            Err(CryptoError::SignatureMalformed(_))
        ));
    }
}
