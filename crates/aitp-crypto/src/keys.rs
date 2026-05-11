//! Ed25519 and P-256 ECDSA signing/verifying keys.
//!
//! `AitpSigningKey` is Ed25519-only (the only signing algorithm in v0.1).
//! `AitpVerifyingKey` is an algorithm-agile enum: Ed25519 keys come from
//! the legacy untagged AID form and the `aid:pubkey:ed25519:<43>` form;
//! P-256 keys come from `aid:pubkey:p256:<44>`. Verifier dispatch is
//! driven by the algorithm tag on the [`Signature`] passed to
//! [`AitpVerifyingKey::verify`].

use crate::CryptoError;
use aitp_core::{Aid, AidAlgorithm, ED25519_SIGNATURE_BASE64URL_LEN};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{
    Signature as DalekSignature, Signer, SigningKey as DalekSigningKey,
    VerifyingKey as DalekVerifyingKey,
};
use p256::ecdsa::{
    signature::Verifier as P256Verifier, Signature as P256Signature,
    VerifyingKey as P256VerifyingKey,
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
        AitpVerifyingKey::Ed25519(self.inner.verifying_key())
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

/// An AITP verifying (public) key. Algorithm-agile: holds either an
/// Ed25519 key (the v0.1 default) or a P-256 ECDSA key (post-v0.1
/// algorithm-agile wire format, RFC-AITP-0001 §5.4.3).
#[derive(Debug, Clone)]
pub enum AitpVerifyingKey {
    /// Ed25519 public key.
    Ed25519(DalekVerifyingKey),
    /// P-256 (secp256r1) ECDSA public key, parsed from a SEC1-
    /// compressed encoding.
    P256(P256VerifyingKey),
}

impl AitpVerifyingKey {
    /// Construct from the public key embedded in an AID. Dispatches by
    /// [`AidAlgorithm`].
    pub fn from_aid(aid: &Aid) -> Result<Self, CryptoError> {
        match aid.algorithm() {
            AidAlgorithm::Ed25519 => {
                let bytes = aid.to_ed25519_bytes();
                DalekVerifyingKey::from_bytes(&bytes)
                    .map(Self::Ed25519)
                    .map_err(|e| CryptoError::AidNotEd25519(e.to_string()))
            }
            AidAlgorithm::P256 => {
                let bytes = aid.to_p256_bytes();
                P256VerifyingKey::from_sec1_bytes(&bytes)
                    .map(Self::P256)
                    .map_err(|e| CryptoError::KeyParseFailed(e.to_string()))
            }
        }
    }

    /// Construct an Ed25519 verifier from raw 32-byte public-key bytes.
    /// (Convenience for callers carrying explicit Ed25519 bytes — e.g.
    /// the TCT `cnf` field.)
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        DalekVerifyingKey::from_bytes(bytes)
            .map(Self::Ed25519)
            .map_err(|e| CryptoError::KeyParseFailed(e.to_string()))
    }

    /// Verify a signature over `message`.
    ///
    /// Ed25519 path uses `verify_strict` to reject non-canonical
    /// signatures and weak public keys (low-order points, identity).
    /// P-256 path verifies an `R || S` (64-byte) raw signature against
    /// `SHA-256(message)`. The algorithm tag on the [`Signature`] MUST
    /// match the verifier's algorithm — mismatched algorithm/key
    /// combinations are rejected (algorithm confusion defense).
    pub fn verify(&self, message: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        match (self, sig.algorithm()) {
            (Self::Ed25519(vk), SignatureAlgorithm::Ed25519) => {
                let raw = Base64UrlUnpadded::decode_vec(sig.payload())
                    .map_err(|_| CryptoError::SignatureInvalid)?;
                if raw.len() != 64 {
                    return Err(CryptoError::SignatureInvalid);
                }
                let mut buf = [0u8; 64];
                buf.copy_from_slice(&raw);
                let dalek_sig = DalekSignature::from_bytes(&buf);
                vk.verify_strict(message, &dalek_sig)
                    .map_err(|_| CryptoError::SignatureInvalid)
            }
            (Self::P256(vk), SignatureAlgorithm::P256) => {
                let raw = Base64UrlUnpadded::decode_vec(sig.payload())
                    .map_err(|_| CryptoError::SignatureInvalid)?;
                if raw.len() != 64 {
                    return Err(CryptoError::SignatureInvalid);
                }
                // p256::ecdsa::Signature accepts R||S as 64 bytes.
                let p256_sig = P256Signature::from_slice(&raw)
                    .map_err(|_| CryptoError::SignatureInvalid)?;
                vk.verify(message, &p256_sig)
                    .map_err(|_| CryptoError::SignatureInvalid)
            }
            // Algorithm-confusion guard: refuse to verify a P-256
            // signature with an Ed25519 key, and vice versa.
            _ => Err(CryptoError::SignatureInvalid),
        }
    }

    /// Compute the RFC 7638 JWK thumbprint per RFC-AITP-0002 §2.2.1.
    /// Only defined for Ed25519 keys in v0.1; P-256 callers should
    /// derive a JWK thumbprint from the SEC1-compressed bytes via
    /// `aitp_crypto::thumbprint`.
    pub fn to_jwk_thumbprint(&self) -> Result<String, CryptoError> {
        match self {
            Self::Ed25519(vk) => Ok(crate::thumbprint::compute_jwk_thumbprint(&vk.to_bytes())),
            Self::P256(_) => Err(CryptoError::KeyParseFailed(
                "JWK thumbprint for P-256 not implemented; use thumbprint module directly".into(),
            )),
        }
    }

    /// The 32-byte raw Ed25519 public key. **Panics** if this is a
    /// P-256 key — callers that may hold either should branch on
    /// [`Self::algorithm`] or use [`Self::to_compressed`].
    pub fn to_bytes(&self) -> [u8; 32] {
        match self {
            Self::Ed25519(vk) => vk.to_bytes(),
            Self::P256(_) => {
                panic!("AitpVerifyingKey::to_bytes called on P-256 key; use to_compressed()")
            }
        }
    }

    /// The encoded public key bytes — 32 bytes for Ed25519, 33 bytes
    /// SEC1-compressed for P-256. Use this instead of
    /// [`Self::to_bytes`] when handling algorithm-agile flows.
    pub fn to_compressed(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(vk) => vk.to_bytes().to_vec(),
            Self::P256(vk) => vk.to_encoded_point(true).as_bytes().to_vec(),
        }
    }

    /// Which algorithm this key represents.
    pub fn algorithm(&self) -> AidAlgorithm {
        match self {
            Self::Ed25519(_) => AidAlgorithm::Ed25519,
            Self::P256(_) => AidAlgorithm::P256,
        }
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

    #[test]
    fn p256_verifier_round_trip() {
        use p256::ecdsa::{signature::Signer as _, SigningKey as P256SigningKey};
        // Deterministic P-256 keypair for KAT-style assertions.
        let signing_key = P256SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let p256_pk = signing_key.verifying_key();
        let pk_compressed = p256_pk.to_encoded_point(true);
        let pk_bytes = pk_compressed.as_bytes();
        assert_eq!(pk_bytes.len(), 33);
        let mut pk_arr = [0u8; 33];
        pk_arr.copy_from_slice(pk_bytes);

        let aid = aitp_core::Aid::from_p256(&pk_arr);
        let verifier = AitpVerifyingKey::from_aid(&aid).expect("P-256 AID parses");
        assert_eq!(verifier.algorithm(), AidAlgorithm::P256);
        assert_eq!(verifier.to_compressed(), pk_bytes);

        let msg = b"aitp p256 round-trip";
        let sig: p256::ecdsa::Signature = signing_key.sign(msg);
        let sig_bytes = sig.to_bytes();
        let sig_b64 = Base64UrlUnpadded::encode_string(&sig_bytes);
        let wire = format!("p256.{sig_b64}");
        let parsed = Signature::parse(&wire).unwrap();
        assert_eq!(parsed.algorithm(), SignatureAlgorithm::P256);

        verifier.verify(msg, &parsed).expect("P-256 signature verifies");
        assert!(verifier.verify(b"tampered", &parsed).is_err());
    }

    #[test]
    fn p256_verify_rejects_ed25519_signature() {
        use p256::ecdsa::SigningKey as P256SigningKey;
        let signing_key = P256SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let pk = signing_key.verifying_key();
        let pk_compressed = pk.to_encoded_point(true);
        let mut pk_arr = [0u8; 33];
        pk_arr.copy_from_slice(pk_compressed.as_bytes());
        let aid = aitp_core::Aid::from_p256(&pk_arr);
        let verifier = AitpVerifyingKey::from_aid(&aid).unwrap();
        // Try to verify an Ed25519 signature against the P-256 key.
        let ed_key = AitpSigningKey::from_seed(&[1u8; 32]);
        let ed_sig = ed_key.sign(b"msg");
        assert!(verifier.verify(b"msg", &ed_sig).is_err());
    }
}
