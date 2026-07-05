//! Ed25519 and P-256 ECDSA signing/verifying keys.
//!
//! Both `AitpSigningKey` and `AitpVerifyingKey` are algorithm-agile enums.
//! Ed25519 keys come from the legacy untagged AID form and the
//! `aid:pubkey:ed25519:<43>` form; P-256 keys come from
//! `aid:pubkey:p256:<44>`. Verifier dispatch is driven by the algorithm tag
//! on the [`Signature`] passed to [`AitpVerifyingKey::verify`]; signer
//! dispatch is driven by the variant of [`AitpSigningKey`] in hand.
//!
//! Untagged Ed25519 signatures are produced by Ed25519 signing keys for
//! wire compatibility with v0.1 verifiers; P-256 signing keys always emit
//! `p256.<86-char-b64url>` tagged signatures (RFC-AITP-0001 §5.4.3).

use crate::CryptoError;
use aitp_core::{Aid, AidAlgorithm, ED25519_SIGNATURE_BASE64URL_LEN};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{
    Signature as DalekSignature, Signer as Ed25519Signer, SigningKey as DalekSigningKey,
    VerifyingKey as DalekVerifyingKey,
};
use p256::ecdsa::{
    signature::{Signer as P256Signer, Verifier as P256Verifier},
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};

/// An AITP signing key. Algorithm-agile: holds either an Ed25519 key (the
/// v0.1 default) or a P-256 ECDSA key (post-v0.1 algorithm-agile wire
/// format, RFC-AITP-0001 §5.4.3).
///
/// Both `ed25519_dalek::SigningKey` and `p256::ecdsa::SigningKey` zeroize
/// their secret scalar on drop, so this value's secret material is wiped
/// from memory when the enum is dropped.
pub enum AitpSigningKey {
    /// Ed25519 signing key with cached AID derivation.
    Ed25519 {
        /// The underlying ed25519-dalek key (secret + public). Zeroized on drop.
        inner: DalekSigningKey,
        /// AID derived from the public key. Cached at construction time.
        aid: Aid,
    },
    /// P-256 (secp256r1) ECDSA signing key with cached AID derivation. The
    /// AID embeds the SEC1-compressed (33-byte) public key.
    P256 {
        /// The underlying p256 ECDSA signing key. Zeroized on drop.
        inner: P256SigningKey,
        /// AID derived from the SEC1-compressed public key. Cached at construction time.
        aid: Aid,
    },
}

impl AitpSigningKey {
    /// Generate a fresh Ed25519 keypair using OS randomness. Equivalent to
    /// [`Self::generate_ed25519`] — the default suite for v0.1 deployments.
    pub fn generate() -> Self {
        Self::generate_ed25519()
    }

    /// Generate a fresh Ed25519 keypair using OS randomness.
    pub fn generate_ed25519() -> Self {
        let inner = DalekSigningKey::generate(&mut rand::rngs::OsRng);
        let aid = Aid::from_ed25519(&inner.verifying_key().to_bytes());
        Self::Ed25519 { inner, aid }
    }

    /// Generate a fresh P-256 keypair using OS randomness.
    pub fn generate_p256() -> Self {
        let inner = P256SigningKey::random(&mut rand::rngs::OsRng);
        let aid = Self::p256_aid_for(&inner);
        Self::P256 { inner, aid }
    }

    /// Construct an Ed25519 signing key from a raw 32-byte seed. Always
    /// succeeds (every 32-byte value is a valid Ed25519 seed). Equivalent
    /// to [`Self::from_ed25519_seed`].
    ///
    /// Useful for tests with pinned key material and for restoring a key
    /// from secure storage. Production callers SHOULD use [`Self::generate`].
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::from_ed25519_seed(seed)
    }

    /// Construct an Ed25519 signing key from a raw 32-byte seed. Always
    /// succeeds (every 32-byte value is a valid Ed25519 seed).
    pub fn from_ed25519_seed(seed: &[u8; 32]) -> Self {
        let inner = DalekSigningKey::from_bytes(seed);
        let aid = Aid::from_ed25519(&inner.verifying_key().to_bytes());
        Self::Ed25519 { inner, aid }
    }

    /// Construct a P-256 signing key from a 32-byte private scalar.
    ///
    /// Returns `Err(CryptoError::KeyParseFailed(_))` for the (vanishingly
    /// rare) inputs that are not a valid P-256 private scalar (zero or
    /// >= curve order). Production callers SHOULD use [`Self::generate_p256`].
    pub fn from_p256_seed(seed: &[u8; 32]) -> Result<Self, CryptoError> {
        let inner = P256SigningKey::from_bytes(seed.into())
            .map_err(|e| CryptoError::KeyParseFailed(e.to_string()))?;
        let aid = Self::p256_aid_for(&inner);
        Ok(Self::P256 { inner, aid })
    }

    /// Return the AID derived from this key's public component.
    pub fn aid(&self) -> &Aid {
        match self {
            Self::Ed25519 { aid, .. } => aid,
            Self::P256 { aid, .. } => aid,
        }
    }

    /// Return the corresponding verifying (public) key.
    pub fn verifying_key(&self) -> AitpVerifyingKey {
        match self {
            Self::Ed25519 { inner, .. } => AitpVerifyingKey::Ed25519(inner.verifying_key()),
            Self::P256 { inner, .. } => AitpVerifyingKey::P256(*inner.verifying_key()),
        }
    }

    /// Which signing algorithm this key implements.
    pub fn algorithm(&self) -> AidAlgorithm {
        match self {
            Self::Ed25519 { .. } => AidAlgorithm::Ed25519,
            Self::P256 { .. } => AidAlgorithm::P256,
        }
    }

    /// Sign a message (typically the JCS canonicalization of an AITP
    /// object).
    ///
    /// Ed25519 signing emits the **untagged** legacy v0.1 form (86
    /// base64url characters with no algorithm prefix) for wire
    /// compatibility with v0.1 verifiers. P-256 signing always emits the
    /// tagged `p256.<86-char-b64url>` form per RFC-AITP-0001 §5.4.3 — a
    /// v0.1 verifier rejects it on the tag, an algorithm-agile verifier
    /// dispatches on it.
    pub fn sign(&self, message: &[u8]) -> Signature {
        match self {
            Self::Ed25519 { inner, .. } => {
                let sig = <DalekSigningKey as Ed25519Signer<DalekSignature>>::sign(inner, message);
                Signature(Base64UrlUnpadded::encode_string(&sig.to_bytes()))
            }
            Self::P256 { inner, .. } => {
                // RFC6979 deterministic-k fixes the nonce; low-S
                // normalization fixes the signature's canonical form.
                // Together they make the wire output fully reproducible
                // for a given (key, message) AND non-malleable — the
                // verifier rejects the high-S sibling (see
                // `verify_p256_raw`).
                let sig = p256_sign_low_s(inner, message);
                let encoded = Base64UrlUnpadded::encode_string(&sig.to_bytes());
                Signature(format!("p256.{encoded}"))
            }
        }
    }

    /// Sign `message` and return the raw 64-byte signature with no
    /// base64url encoding and no algorithm tag. Used by the compact-JWS
    /// profile (RFC-AITP-0001 §5.4.5), where the algorithm rides in the
    /// protected header `alg` parameter and the signature is the third
    /// JWS segment. Ed25519 signs the message directly (RFC 8032);
    /// ES256 hashes with SHA-256 internally and emits the JOSE raw
    /// `R || S` fixed-length encoding (RFC 7518 §3.4).
    pub(crate) fn sign_raw(&self, message: &[u8]) -> [u8; 64] {
        match self {
            Self::Ed25519 { inner, .. } => {
                let sig = <DalekSigningKey as Ed25519Signer<DalekSignature>>::sign(inner, message);
                sig.to_bytes()
            }
            Self::P256 { inner, .. } => p256_sign_low_s(inner, message).to_bytes().into(),
        }
    }

    fn p256_aid_for(inner: &P256SigningKey) -> Aid {
        let encoded = inner.verifying_key().to_encoded_point(true);
        let bytes = encoded.as_bytes();
        debug_assert_eq!(bytes.len(), 33, "P-256 SEC1-compressed must be 33 bytes");
        let mut arr = [0u8; 33];
        arr.copy_from_slice(bytes);
        Aid::from_p256(&arr)
    }
}

impl std::fmt::Debug for AitpSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AitpSigningKey")
            .field("algorithm", &self.algorithm())
            .field("aid", &self.aid())
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
                // Guarded by the `Ed25519` discriminant — `try_*` is Some.
                let bytes = aid
                    .try_to_ed25519_bytes()
                    .expect("Ed25519 arm guarded by algorithm()");
                DalekVerifyingKey::from_bytes(&bytes)
                    .map(Self::Ed25519)
                    .map_err(|e| CryptoError::AidNotEd25519(e.to_string()))
            }
            AidAlgorithm::P256 => {
                let bytes = aid
                    .try_to_p256_bytes()
                    .expect("P-256 arm guarded by algorithm()");
                P256VerifyingKey::from_sec1_bytes(&bytes)
                    .map(Self::P256)
                    .map_err(|e| CryptoError::KeyParseFailed(e.to_string()))
            }
            // `AidAlgorithm` is `#[non_exhaustive]`; a future variant
            // added to `aitp-core` would otherwise silently compile as
            // an unreachable arm. Surface it as a clean parse error
            // so a forgotten dispatch update fails fast in tests.
            other => Err(CryptoError::KeyParseFailed(format!(
                "AID algorithm {other:?} not supported by this AitpVerifyingKey build"
            ))),
        }
    }

    /// Construct an Ed25519 verifier from raw 32-byte public-key bytes.
    /// (Convenience for callers carrying explicit Ed25519 bytes — e.g.
    /// the TCT `cnf` field on an Ed25519 subject.)
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        DalekVerifyingKey::from_bytes(bytes)
            .map(Self::Ed25519)
            .map_err(|e| CryptoError::KeyParseFailed(e.to_string()))
    }

    /// Construct an algorithm-agile verifier from the AITP compressed
    /// public-key encoding: **32 bytes ⇒ Ed25519 raw pubkey**, **33
    /// bytes ⇒ P-256 SEC1-compressed**. This is the encoding embedded
    /// in `TctBinding.cnf` / `DelegationBinding.cnf` for
    /// algorithm-agile signing-key bindings, and the canonical output
    /// of [`Self::to_compressed`].
    ///
    /// Other lengths are rejected as `KeyParseFailed` — callers
    /// SHOULD NOT pass uncompressed (65-byte) SEC1 encodings here,
    /// since that form is not what flows on the wire.
    pub fn from_compressed(bytes: &[u8]) -> Result<Self, CryptoError> {
        match bytes.len() {
            32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                Self::from_bytes(&arr)
            }
            33 => P256VerifyingKey::from_sec1_bytes(bytes)
                .map(Self::P256)
                .map_err(|e| CryptoError::KeyParseFailed(e.to_string())),
            other => Err(CryptoError::KeyParseFailed(format!(
                "unsupported compressed pubkey length: {other} (expected 32 for Ed25519 or 33 for P-256 SEC1-compressed)",
            ))),
        }
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
                verify_p256_raw(vk, message, &raw)
            }
            // Algorithm-confusion guard: refuse to verify a P-256
            // signature with an Ed25519 key, and vice versa.
            _ => Err(CryptoError::SignatureInvalid),
        }
    }

    /// Verify a raw 64-byte signature over `message`, with the
    /// algorithm fixed by this key's variant. Used by the compact-JWS
    /// profile (RFC-AITP-0001 §5.4.5), where the `alg` header has
    /// already been pinned against the signer AID before this call.
    /// Ed25519 uses `verify_strict`; ES256 expects the JOSE raw
    /// `R || S` fixed-length encoding (RFC 7518 §3.4).
    pub(crate) fn verify_raw(&self, message: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        if sig.len() != 64 {
            return Err(CryptoError::SignatureInvalid);
        }
        match self {
            Self::Ed25519(vk) => {
                let mut buf = [0u8; 64];
                buf.copy_from_slice(sig);
                let dalek_sig = DalekSignature::from_bytes(&buf);
                vk.verify_strict(message, &dalek_sig)
                    .map_err(|_| CryptoError::SignatureInvalid)
            }
            Self::P256(vk) => verify_p256_raw(vk, message, sig),
        }
    }

    /// Compute the RFC 7638 JWK thumbprint per RFC-AITP-0002 §2.2.1.
    ///
    /// Ed25519 (`OKP`) keys hash `{"crv":"Ed25519","kty":"OKP","x":...}`;
    /// P-256 (`EC`) keys hash `{"crv":"P-256","kty":"EC","x":...,"y":...}`
    /// with the affine coordinates as 32-byte big-endian unsigned
    /// integers (RFC 7518 §6.2.1.2 / §6.2.1.3, RFC 7638 §3.2). Both
    /// canonical forms are lex-ordered with no whitespace.
    pub fn to_jwk_thumbprint(&self) -> Result<String, CryptoError> {
        match self {
            Self::Ed25519(vk) => Ok(crate::thumbprint::compute_jwk_thumbprint(&vk.to_bytes())),
            Self::P256(vk) => {
                // SEC1 uncompressed: 0x04 || x(32) || y(32). For any valid
                // P-256 public key (which excludes the point at infinity)
                // this is always 65 bytes.
                let pt = vk.to_encoded_point(false);
                let bytes = pt.as_bytes();
                if bytes.len() != 65 || bytes[0] != 0x04 {
                    return Err(CryptoError::KeyParseFailed(format!(
                        "P-256 verifying key did not encode to SEC1 uncompressed form (len={}, tag={:#x})",
                        bytes.len(),
                        bytes.first().copied().unwrap_or(0),
                    )));
                }
                let mut x = [0u8; 32];
                let mut y = [0u8; 32];
                x.copy_from_slice(&bytes[1..33]);
                y.copy_from_slice(&bytes[33..65]);
                Ok(crate::thumbprint::compute_jwk_thumbprint_p256(&x, &y))
            }
        }
    }

    /// The 32-byte raw Ed25519 public key. **Panics** if this is a
    /// P-256 key — callers that may hold either should branch on
    /// [`Self::algorithm`] or use [`Self::try_to_ed25519_bytes`] /
    /// [`Self::to_compressed`].
    ///
    /// Prefer [`Self::try_to_ed25519_bytes`] for new code: it returns
    /// `None` for P-256 instead of panicking, so an algorithm-agile
    /// caller cannot inadvertently crash the process.
    pub fn to_bytes(&self) -> [u8; 32] {
        match self {
            Self::Ed25519(vk) => vk.to_bytes(),
            Self::P256(_) => {
                panic!("AitpVerifyingKey::to_bytes called on P-256 key; use to_compressed() or try_to_ed25519_bytes()")
            }
        }
    }

    /// The 32-byte raw Ed25519 public key, or `None` if this is a
    /// P-256 key.
    ///
    /// Non-panicking counterpart to [`Self::to_bytes`]. Callers that
    /// require Ed25519-shaped bytes (e.g. the v0.1 pinned-key identity
    /// wire format, which encodes the raw 32-byte public key) should
    /// use this and return a structured error on `None` rather than
    /// risking a process-wide panic from an algorithm-agile path.
    pub fn try_to_ed25519_bytes(&self) -> Option<[u8; 32]> {
        match self {
            Self::Ed25519(vk) => Some(vk.to_bytes()),
            Self::P256(_) => None,
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

/// Sign `message` with P-256/ES256 and return a signature normalized to
/// the **low-S** canonical form. The `p256` signer produces RFC 6979
/// deterministic-k signatures but does NOT guarantee low-S; roughly half
/// come out high-S. Normalizing here makes our mints canonical and keeps
/// them acceptable to the strict [`verify_p256_raw`] path.
fn p256_sign_low_s(inner: &P256SigningKey, message: &[u8]) -> P256Signature {
    let sig: P256Signature = <P256SigningKey as P256Signer<P256Signature>>::sign(inner, message);
    // `normalize_s()` returns `Some(low_s)` iff the input was high-S.
    sig.normalize_s().unwrap_or(sig)
}

/// Verify a raw `R || S` (64-byte) ES256 signature, enforcing the
/// **low-S** canonical form (RFC-AITP-0001 §5.4.3 wire determinism; the
/// hardening posture from RFC-AITP-0009 §4).
///
/// ECDSA signatures are malleable: for any valid `(r, s)`, the pair
/// `(r, n − s)` is an equally valid signature over the same message.
/// The `p256` crate's verifier accepts both, so without this check a
/// captured token's signature could be mutated into a second valid
/// encoding of identical claims. Our own mints are always low-S
/// (RFC 6979 deterministic-k produces the low-S form), so rejecting
/// high-S costs nothing on the honest path and removes the malleability
/// on the wire. `normalize_s()` returns `Some` only when the input was
/// high-S — i.e. non-canonical — so we reject exactly that case.
fn verify_p256_raw(vk: &P256VerifyingKey, message: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
    if sig.len() != 64 {
        return Err(CryptoError::SignatureInvalid);
    }
    // p256::ecdsa::Signature accepts R||S as 64 bytes.
    let p256_sig = P256Signature::from_slice(sig).map_err(|_| CryptoError::SignatureInvalid)?;
    if p256_sig.normalize_s().is_some() {
        // High-S (non-canonical / malleated) — reject.
        return Err(CryptoError::SignatureInvalid);
    }
    vk.verify(message, &p256_sig)
        .map_err(|_| CryptoError::SignatureInvalid)
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
///
/// Marked `#[non_exhaustive]` so future signature suites (mirroring
/// future [`aitp_core::AidAlgorithm`] additions) can be added without
/// a major bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
        // Match the canonical low-S form our signer emits; the raw
        // p256 Signer does not normalize, so ~half of keys/messages
        // would otherwise yield a high-S vector the verifier rejects.
        let sig: p256::ecdsa::Signature = signing_key.sign(msg);
        let sig = sig.normalize_s().unwrap_or(sig);
        let sig_bytes = sig.to_bytes();
        let sig_b64 = Base64UrlUnpadded::encode_string(&sig_bytes);
        let wire = format!("p256.{sig_b64}");
        let parsed = Signature::parse(&wire).unwrap();
        assert_eq!(parsed.algorithm(), SignatureAlgorithm::P256);

        verifier
            .verify(msg, &parsed)
            .expect("P-256 signature verifies");
        assert!(verifier.verify(b"tampered", &parsed).is_err());
    }

    #[test]
    fn p256_high_s_signature_is_rejected() {
        // ECDSA malleability: a valid low-S signature (r, s) has an
        // equally-valid high-S sibling (r, n - s) over the same
        // message. Our verifier must accept the canonical low-S form
        // and reject the high-S mutation, so a captured token cannot
        // be re-encoded on the wire.
        use p256::ecdsa::{signature::Signer as _, Signature as P256Sig, SigningKey};

        let signing_key = SigningKey::from_bytes(&[11u8; 32].into()).unwrap();
        let pk = signing_key.verifying_key();
        let pk_arr: [u8; 33] = pk
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("33-byte compressed point");
        let aid = aitp_core::Aid::from_p256(&pk_arr);
        let verifier = AitpVerifyingKey::from_aid(&aid).unwrap();

        let msg = b"aitp p256 low-S enforcement";
        // RFC 6979 deterministic-k signing emits the low-S form.
        let low_s: P256Sig = signing_key.sign(msg);
        assert!(
            low_s.normalize_s().is_none(),
            "signer must emit low-S canonical form"
        );

        // Build the malleated high-S sibling: (r, -s).
        let (r, s) = low_s.split_scalars();
        let high_s = P256Sig::from_scalars(r, -s).expect("valid high-S signature");
        assert!(
            high_s.normalize_s().is_some(),
            "constructed sibling must be high-S"
        );

        let low_wire = format!(
            "p256.{}",
            Base64UrlUnpadded::encode_string(&low_s.to_bytes())
        );
        let high_wire = format!(
            "p256.{}",
            Base64UrlUnpadded::encode_string(&high_s.to_bytes())
        );

        verifier
            .verify(msg, &Signature::parse(&low_wire).unwrap())
            .expect("low-S signature verifies");
        assert!(
            verifier
                .verify(msg, &Signature::parse(&high_wire).unwrap())
                .is_err(),
            "high-S (malleated) signature must be rejected"
        );

        // Same guarantee on the compact-JWS raw path.
        assert!(verifier.verify_raw(msg, &low_s.to_bytes()).is_ok());
        assert!(verifier.verify_raw(msg, &high_s.to_bytes()).is_err());
    }

    #[test]
    fn p256_signing_key_round_trip() {
        let key = AitpSigningKey::generate_p256();
        assert_eq!(key.algorithm(), AidAlgorithm::P256);
        assert!(matches!(key.aid().algorithm(), AidAlgorithm::P256));

        let msg = b"aitp p256 signing key round-trip";
        let sig = key.sign(msg);
        assert_eq!(sig.algorithm(), SignatureAlgorithm::P256);
        assert!(sig.as_str().starts_with("p256."));

        let vk = key.verifying_key();
        vk.verify(msg, &sig).expect("p256 round-trip verifies");
        assert!(vk.verify(b"tampered", &sig).is_err());

        // The cached AID matches one freshly derived from from_aid.
        let derived = AitpVerifyingKey::from_aid(key.aid()).unwrap();
        assert_eq!(derived.to_compressed(), vk.to_compressed());
    }

    #[test]
    fn p256_from_seed_is_deterministic() {
        let a = AitpSigningKey::from_p256_seed(&[5u8; 32]).expect("valid p256 seed");
        let b = AitpSigningKey::from_p256_seed(&[5u8; 32]).expect("valid p256 seed");
        assert_eq!(a.aid(), b.aid());
        let msg = b"deterministic";
        // RFC6979 makes the signatures deterministic too.
        assert_eq!(a.sign(msg).as_str(), b.sign(msg).as_str());
    }

    #[test]
    fn try_to_ed25519_bytes_returns_some_for_ed25519_and_none_for_p256() {
        let ed = AitpSigningKey::from_seed(&[9u8; 32]);
        let p256 = AitpSigningKey::generate_p256();
        let ed_bytes = ed.verifying_key().try_to_ed25519_bytes();
        let p256_bytes = p256.verifying_key().try_to_ed25519_bytes();
        assert!(ed_bytes.is_some());
        assert_eq!(ed_bytes.unwrap().len(), 32);
        assert!(
            p256_bytes.is_none(),
            "P-256 key must not yield Ed25519-shaped bytes"
        );
    }

    #[test]
    fn ed25519_signing_key_produces_untagged_signature() {
        // Wire compatibility: Ed25519 signing must still emit the legacy
        // untagged 86-char form so v0.1 verifiers accept it.
        let key = AitpSigningKey::generate();
        let sig = key.sign(b"compat");
        assert!(!sig.as_str().starts_with("ed25519."));
        assert!(!sig.as_str().starts_with("p256."));
        assert_eq!(sig.as_str().len(), ED25519_SIGNATURE_BASE64URL_LEN);
    }

    #[test]
    fn p256_jwk_thumbprint_round_trip() {
        // P-256 keys now produce a JWK thumbprint over the
        // RFC 7638 §3.2 EC form; check it round-trips and is the
        // same value the AID-derived verifier sees.
        let key = AitpSigningKey::generate_p256();
        let from_signer = key.verifying_key().to_jwk_thumbprint().expect("p256 jkt");
        let from_aid = AitpVerifyingKey::from_aid(key.aid())
            .unwrap()
            .to_jwk_thumbprint()
            .expect("p256 jkt via aid");
        assert_eq!(from_signer, from_aid);
        assert_eq!(from_signer.len(), 43);
    }

    #[test]
    fn p256_jwk_thumbprint_matches_thumbprint_module() {
        // The AitpVerifyingKey::to_jwk_thumbprint dispatch must agree
        // with calling the thumbprint module directly with the same
        // affine coordinates.
        use p256::ecdsa::SigningKey as P256SigningKey;
        let signer = P256SigningKey::from_bytes(&[3u8; 32].into()).unwrap();
        let pk = signer.verifying_key();
        let pt = pk.to_encoded_point(false);
        let bytes = pt.as_bytes();
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], 0x04);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..65]);

        let expected = crate::thumbprint::compute_jwk_thumbprint_p256(&x, &y);
        let actual = AitpVerifyingKey::P256(*pk).to_jwk_thumbprint().unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn p256_and_ed25519_thumbprints_disagree_even_with_identical_seed() {
        // Same 32-byte seed under each suite produces different keys
        // (and obviously different JWKs), so the thumbprints must
        // differ — a sanity check against accidental conflation.
        let seed = [0x9Cu8; 32];
        let ed = AitpSigningKey::from_ed25519_seed(&seed);
        let p = AitpSigningKey::from_p256_seed(&seed).unwrap();
        let ed_t = ed.verifying_key().to_jwk_thumbprint().unwrap();
        let p_t = p.verifying_key().to_jwk_thumbprint().unwrap();
        assert_ne!(ed_t, p_t);
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
