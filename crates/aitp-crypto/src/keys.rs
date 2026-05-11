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
        // Reject `p256.`-tagged signatures here: this verifier holds
        // an Ed25519 key. Crypto-agility callers MUST resolve the
        // verifier from the signing AID's algorithm tag first.
        if !matches!(sig.algorithm(), SignatureAlgorithm::Ed25519) {
            return Err(CryptoError::SignatureInvalid);
        }
        // Decode the b64url payload (everything after the optional
        // algorithm tag — `Signature::payload` strips it).
        let raw = Base64UrlUnpadded::decode_vec(sig.payload())
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

/// A signature in the AITP wire format.
///
/// v0.2 wire format (RFC-AITP-0001 §5.4.3) accepts three forms:
///
/// - **Legacy v0.1 (untagged)** — 86 unpadded base64url chars,
///   implicitly Ed25519.
/// - **Tagged Ed25519** — `ed25519.<86-char-b64url>`.
/// - **Tagged P-256** — `p256.<86-char-b64url>` (R || S, 64 bytes
///   total).
///
/// The wrapper stores the verbatim wire string; the algorithm tag,
/// if present, is part of the canonical bytes. Use
/// [`Signature::algorithm`] to dispatch on which verifier to call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(String);

/// Signature algorithm tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// Ed25519 (RFC 8032). Legacy untagged signatures default to this.
    Ed25519,
    /// ECDSA on P-256 with SHA-256.
    P256,
}

impl Signature {
    /// Parse a signature string. Accepts both the legacy v0.1
    /// untagged form and the v0.2 algorithm-tagged forms.
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        if s.contains('=') {
            return Err(CryptoError::SignatureMalformed(
                "padding is forbidden".into(),
            ));
        }
        // Tagged forms: `ed25519.<86char>` or `p256.<86char>`.
        if let Some(rest) = s.strip_prefix("ed25519.") {
            validate_b64url_signature(rest)?;
            return Ok(Self(s.to_string()));
        }
        if let Some(rest) = s.strip_prefix("p256.") {
            validate_b64url_signature(rest)?;
            return Ok(Self(s.to_string()));
        }
        // Untagged v0.1 form.
        validate_b64url_signature(s)?;
        Ok(Self(s.to_string()))
    }

    /// Return the base64url-unpadded string verbatim (including
    /// any algorithm tag).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the underlying string.
    pub fn into_string(self) -> String {
        self.0
    }

    /// Algorithm of this signature, derived from the wire tag (or
    /// defaulting to Ed25519 when untagged).
    pub fn algorithm(&self) -> SignatureAlgorithm {
        if self.0.starts_with("p256.") {
            SignatureAlgorithm::P256
        } else {
            SignatureAlgorithm::Ed25519
        }
    }

    /// Return the base64url payload portion (everything after the
    /// algorithm tag, or the entire string for untagged
    /// signatures). 86 characters by construction.
    pub fn payload(&self) -> &str {
        if let Some(p) = self.0.strip_prefix("ed25519.") {
            p
        } else if let Some(p) = self.0.strip_prefix("p256.") {
            p
        } else {
            &self.0
        }
    }
}

fn validate_b64url_signature(payload: &str) -> Result<(), CryptoError> {
    if payload.len() != ED25519_SIGNATURE_BASE64URL_LEN {
        return Err(CryptoError::SignatureMalformed(format!(
            "expected {} payload characters, got {}",
            ED25519_SIGNATURE_BASE64URL_LEN,
            payload.len()
        )));
    }
    if !payload.bytes().all(is_base64url_byte) {
        return Err(CryptoError::SignatureMalformed(
            "non-base64url character".into(),
        ));
    }
    Ok(())
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

    #[test]
    fn signature_parse_accepts_tagged_ed25519() {
        let payload = "A".repeat(86);
        let s = format!("ed25519.{payload}");
        let sig = Signature::parse(&s).unwrap();
        assert_eq!(sig.algorithm(), SignatureAlgorithm::Ed25519);
        assert_eq!(sig.payload(), payload);
        assert_eq!(sig.as_str(), s);
    }

    #[test]
    fn signature_parse_accepts_tagged_p256() {
        let payload = "B".repeat(86);
        let s = format!("p256.{payload}");
        let sig = Signature::parse(&s).unwrap();
        assert_eq!(sig.algorithm(), SignatureAlgorithm::P256);
        assert_eq!(sig.payload(), payload);
    }

    #[test]
    fn signature_parse_rejects_unknown_tag() {
        // `rsa.<86chars>` — unknown algorithm tag means total length
        // != 86 chars so the untagged-form length check fires.
        let s = format!("rsa.{}", "A".repeat(86));
        assert!(matches!(
            Signature::parse(&s),
            Err(CryptoError::SignatureMalformed(_))
        ));
    }

    #[test]
    fn untagged_signature_defaults_to_ed25519() {
        let s = "A".repeat(86);
        let sig = Signature::parse(&s).unwrap();
        assert_eq!(sig.algorithm(), SignatureAlgorithm::Ed25519);
        assert_eq!(sig.payload(), &s);
    }

    #[test]
    fn ed25519_verify_rejects_p256_tagged_signature() {
        // An Ed25519 verifier MUST reject a `p256.`-tagged
        // signature: the algorithm is part of the binding and we
        // don't auto-fall-back to verifying as Ed25519.
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let s = format!("p256.{}", "A".repeat(86));
        let sig = Signature::parse(&s).unwrap();
        assert!(key.verifying_key().verify(b"msg", &sig).is_err());
    }
}
