//! Owned JWK representation and JWS signature verification, decoupled
//! from any JOSE library (issue #99: dropping the `jsonwebtoken`
//! runtime dependency).
//!
//! [`JwkPublicKey`] carries only plain key material — raw Ed25519 or
//! NIST-curve coordinates, or RSA modulus/exponent bytes — so this
//! crate's public API is not pinned to any particular JOSE crate's
//! version. Ed25519 and P-256 verification go through `aitp-crypto`'s
//! own KAT-tested primitives; RSA (PKCS#1 v1.5 and PSS) and P-384 go
//! through `ring`, which is already in the dependency tree via
//! `rustls`; P-521, which `ring` lacks, goes through RustCrypto's
//! `p521`, the same family as `aitp-crypto`'s `p256`.

use aitp_core::base64url;
use aitp_crypto::{AitpVerifyingKey, CryptoError};
use std::str::FromStr;

/// Supported JWS signature algorithms.
///
/// The closed set [`verify_jws_signature`] can verify: EdDSA plus the
/// nine algorithms JWT-SVID §2.1 allows (RFC-AITP-0002 §6.3). A JWK
/// whose own `alg` is anything else is rejected during parsing
/// ([`JwkPublicKey::from_jwk_json`]), not silently accepted here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwsAlgorithm {
    /// EdDSA (Ed25519), RFC 8037.
    EdDSA,
    /// ECDSA on P-256 with SHA-256, RFC 7518 §3.4.
    ES256,
    /// ECDSA on P-384 with SHA-384, RFC 7518 §3.4.
    ES384,
    /// ECDSA on P-521 with SHA-512, RFC 7518 §3.4.
    ES512,
    /// RSASSA-PKCS1-v1_5 with SHA-256, RFC 7518 §3.3.
    RS256,
    /// RSASSA-PKCS1-v1_5 with SHA-384, RFC 7518 §3.3.
    RS384,
    /// RSASSA-PKCS1-v1_5 with SHA-512, RFC 7518 §3.3.
    RS512,
    /// RSASSA-PSS with SHA-256 and MGF1-SHA-256, RFC 7518 §3.5.
    PS256,
    /// RSASSA-PSS with SHA-384 and MGF1-SHA-384, RFC 7518 §3.5.
    PS384,
    /// RSASSA-PSS with SHA-512 and MGF1-SHA-512, RFC 7518 §3.5.
    PS512,
}

impl JwsAlgorithm {
    /// The JOSE `alg` header value for this algorithm.
    pub fn as_str(&self) -> &'static str {
        match self {
            JwsAlgorithm::EdDSA => "EdDSA",
            JwsAlgorithm::ES256 => "ES256",
            JwsAlgorithm::ES384 => "ES384",
            JwsAlgorithm::ES512 => "ES512",
            JwsAlgorithm::RS256 => "RS256",
            JwsAlgorithm::RS384 => "RS384",
            JwsAlgorithm::RS512 => "RS512",
            JwsAlgorithm::PS256 => "PS256",
            JwsAlgorithm::PS384 => "PS384",
            JwsAlgorithm::PS512 => "PS512",
        }
    }

    /// Whether this algorithm can be used with `key`'s type: EdDSA with
    /// Ed25519, each ES* with its own curve, RS* and PS* with RSA.
    pub fn fits(&self, key: &JwkKeyMaterial) -> bool {
        matches!(
            (self, key),
            (JwsAlgorithm::EdDSA, JwkKeyMaterial::Ed25519 { .. })
                | (JwsAlgorithm::ES256, JwkKeyMaterial::P256 { .. })
                | (JwsAlgorithm::ES384, JwkKeyMaterial::P384 { .. })
                | (JwsAlgorithm::ES512, JwkKeyMaterial::P521 { .. })
                | (
                    JwsAlgorithm::RS256
                        | JwsAlgorithm::RS384
                        | JwsAlgorithm::RS512
                        | JwsAlgorithm::PS256
                        | JwsAlgorithm::PS384
                        | JwsAlgorithm::PS512,
                    JwkKeyMaterial::Rsa { .. }
                )
        )
    }
}

impl std::fmt::Display for JwsAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for JwsAlgorithm {
    type Err = JwkParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "EdDSA" => Ok(JwsAlgorithm::EdDSA),
            "ES256" => Ok(JwsAlgorithm::ES256),
            "ES384" => Ok(JwsAlgorithm::ES384),
            "ES512" => Ok(JwsAlgorithm::ES512),
            "RS256" => Ok(JwsAlgorithm::RS256),
            "RS384" => Ok(JwsAlgorithm::RS384),
            "RS512" => Ok(JwsAlgorithm::RS512),
            "PS256" => Ok(JwsAlgorithm::PS256),
            "PS384" => Ok(JwsAlgorithm::PS384),
            "PS512" => Ok(JwsAlgorithm::PS512),
            other => Err(JwkParseError::Unsupported(format!(
                "unsupported JWS algorithm: {other}"
            ))),
        }
    }
}

/// Owned public-key material for a [`JwkPublicKey`].
///
/// All fields are public key material (never secret): Ed25519's raw
/// 32-byte point, a NIST curve's affine `(x, y)` coordinates, or an RSA
/// modulus/exponent pair — each exactly as carried on the wire in an
/// RFC 7517 JWK, just base64url-decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwkKeyMaterial {
    /// Ed25519 (`OKP`/`Ed25519`) public key: the raw 32-byte point.
    Ed25519 {
        /// Raw Ed25519 public key bytes.
        x: [u8; 32],
    },
    /// P-256 (`EC`/`P-256`) public key: affine coordinates.
    P256 {
        /// Big-endian x-coordinate.
        x: [u8; 32],
        /// Big-endian y-coordinate.
        y: [u8; 32],
    },
    /// P-384 (`EC`/`P-384`) public key: affine coordinates.
    P384 {
        /// Big-endian x-coordinate.
        x: [u8; 48],
        /// Big-endian y-coordinate.
        y: [u8; 48],
    },
    /// P-521 (`EC`/`P-521`) public key: affine coordinates.
    P521 {
        /// Big-endian x-coordinate.
        x: [u8; 66],
        /// Big-endian y-coordinate.
        y: [u8; 66],
    },
    /// RSA public key: modulus and public exponent.
    Rsa {
        /// Big-endian modulus (`n`), no leading zero padding beyond
        /// what the source JWK carried.
        n: Vec<u8>,
        /// Big-endian public exponent (`e`).
        e: Vec<u8>,
    },
}

/// A single JWK entry returned by [`crate::JwksResolver`] — owned key
/// material with no dependency on any JOSE library's types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwkPublicKey {
    /// Key identifier matching the JWT header `kid`.
    pub kid: Option<String>,
    /// The JWK's own `alg` member, which pins the key to that one
    /// algorithm (RFC 7517 §4.4). `None` allows any algorithm that
    /// [fits](JwsAlgorithm::fits) the key type.
    pub alg: Option<JwsAlgorithm>,
    /// The public key material itself.
    pub key: JwkKeyMaterial,
}

/// Errors parsing an RFC 7517 JWK JSON value into a [`JwkPublicKey`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwkParseError {
    /// JWK JSON was missing a required member or a member had the
    /// wrong shape/length.
    #[error("malformed JWK: {0}")]
    Malformed(String),
    /// JWK's `kty`/`crv`/`alg` combination is not one this workspace
    /// verifies (see [`JwsAlgorithm`]).
    #[error("unsupported JWK: {0}")]
    Unsupported(String),
}

impl JwkPublicKey {
    /// Parse a single RFC 7517 JWK JSON value into an owned
    /// [`JwkPublicKey`].
    ///
    /// Supports exactly the key types this workspace verifies:
    ///
    /// - `kty: "OKP"`, `crv: "Ed25519"` — requires a 32-byte `x`.
    /// - `kty: "EC"`, `crv: "P-256"`, `"P-384"` or `"P-521"` — requires
    ///   `x` and `y` of the curve's field size (32, 48 or 66 bytes).
    /// - `kty: "RSA"` — requires `n` and `e`.
    ///
    /// An `alg` member, when present, must name a [`JwsAlgorithm`] that
    /// fits the key type, and then pins the key to it. JWKS entries
    /// need not carry `alg`; the JOSE header's `alg` is checked against
    /// the key by [`verify_jws_signature`].
    ///
    /// This is the single shared parser consolidating what used to be
    /// hand-rolled, duplicated JWK parsing in `aitp-transport-http`
    /// (JWKS fetch) and both language
    /// bindings.
    ///
    /// Does **not** apply any key-strength policy (e.g. an RSA modulus
    /// floor) — that is a transport-specific hardening decision left to
    /// the caller (see `aitp-transport-http::common::rsa_modulus_bits_ok`).
    pub fn from_jwk_json(value: &serde_json::Value) -> Result<Self, JwkParseError> {
        let kid = value.get("kid").and_then(|v| v.as_str()).map(String::from);
        let kty = value
            .get("kty")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JwkParseError::Malformed("jwk missing kty".into()))?;
        let crv = || value.get("crv").and_then(|v| v.as_str()).unwrap_or("");
        let key = match kty {
            "OKP" => {
                if crv() != "Ed25519" {
                    return Err(JwkParseError::Unsupported(format!("OKP crv={}", crv())));
                }
                let x = to_array::<32>(&decode_member(value, "x")?, "OKP x")?;
                JwkKeyMaterial::Ed25519 { x }
            }
            "EC" => match crv() {
                "P-256" => JwkKeyMaterial::P256 {
                    x: to_array(&decode_member(value, "x")?, "EC x")?,
                    y: to_array(&decode_member(value, "y")?, "EC y")?,
                },
                "P-384" => JwkKeyMaterial::P384 {
                    x: to_array(&decode_member(value, "x")?, "EC x")?,
                    y: to_array(&decode_member(value, "y")?, "EC y")?,
                },
                "P-521" => JwkKeyMaterial::P521 {
                    x: to_array(&decode_member(value, "x")?, "EC x")?,
                    y: to_array(&decode_member(value, "y")?, "EC y")?,
                },
                other => return Err(JwkParseError::Unsupported(format!("EC crv={other}"))),
            },
            "RSA" => JwkKeyMaterial::Rsa {
                n: decode_member(value, "n")?,
                e: decode_member(value, "e")?,
            },
            other => return Err(JwkParseError::Unsupported(format!("kty={other}"))),
        };
        let alg = match value.get("alg") {
            None => None,
            Some(serde_json::Value::String(s)) => {
                let alg = JwsAlgorithm::from_str(s)?;
                if !alg.fits(&key) {
                    return Err(JwkParseError::Unsupported(format!(
                        "alg={alg} with kty={kty}"
                    )));
                }
                Some(alg)
            }
            Some(_) => return Err(JwkParseError::Malformed("jwk alg is not a string".into())),
        };
        Ok(Self { kid, alg, key })
    }
}

fn decode_member(value: &serde_json::Value, member: &str) -> Result<Vec<u8>, JwkParseError> {
    let s = value
        .get(member)
        .and_then(|v| v.as_str())
        .ok_or_else(|| JwkParseError::Malformed(format!("jwk missing {member}")))?;
    base64url::decode_strict(s).map_err(|e| JwkParseError::Malformed(format!("{member}: {e}")))
}

fn to_array<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], JwkParseError> {
    if bytes.len() != N {
        return Err(JwkParseError::Malformed(format!(
            "{what} must decode to {N} bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

/// Errors verifying a JWS signature against a [`JwkPublicKey`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwsVerifyError {
    /// The JOSE header's `alg` is unknown, does not fit the key type,
    /// or differs from the key's own pinned `alg` (the alg-confusion
    /// guard `jsonwebtoken`'s `Validation::new(alg)` used to provide).
    #[error("JWS header alg {header:?} cannot be used with this key")]
    AlgMismatch {
        /// The `alg` value from the JOSE header.
        header: String,
    },
    /// The key material itself failed to parse into a usable verifier
    /// (e.g. an EC point not on the curve).
    #[error("key material invalid: {0}")]
    InvalidKey(#[from] CryptoError),
    /// Cryptographic signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,
}

/// Verify a compact-JWS-shaped signature (`signing_input` = the
/// base64url header and payload segments joined by `.`, `sig` = the
/// raw decoded signature bytes) against `key`.
///
/// `header_alg` MUST name a [`JwsAlgorithm`] that [fits](JwsAlgorithm::fits)
/// the key type and, when the JWK pinned one, equals `key.alg`;
/// otherwise verification fails with [`JwsVerifyError::AlgMismatch`].
/// This is the algorithm-confusion defense: the header can choose a
/// hash or padding for the key it names, never a different key type.
///
/// Dispatch:
/// - EdDSA — `aitp_crypto::AitpVerifyingKey::from_bytes` +
///   `verify_raw_jose` (dalek `verify_strict`, rejecting non-canonical
///   signatures).
/// - ES256 — `AitpVerifyingKey::from_p256_affine` + `verify_raw_jose`.
/// - ES384 — `ring`'s `ECDSA_P384_SHA384_FIXED`.
/// - ES512 — RustCrypto `p521` (`ring` has no P-521).
/// - RS256/384/512 — `ring`'s `RSA_PKCS1_2048_8192_SHA*`, the path
///   `jsonwebtoken` 9's RS256 used internally. Verification is not
///   affected by RUSTSEC-2023-0071 (the Marvin timing sidechannel
///   affects RSA decryption and signing, not verification).
/// - PS256/384/512 — `ring`'s `RSA_PSS_2048_8192_SHA*`.
///
/// High-S ECDSA signatures are accepted on every curve. This verifies
/// third-party JOSE (IdP ID tokens, JWT-SVIDs) per RFC 7515/7518;
/// RFC-AITP-0001 §5.4.7 low-S covers AITP signing inputs only. The
/// token bytes are therefore malleable, so replay caches key on the
/// bound nonce or `jti`, never on the raw token.
pub fn verify_jws_signature(
    key: &JwkPublicKey,
    header_alg: &str,
    signing_input: &[u8],
    sig: &[u8],
) -> Result<(), JwsVerifyError> {
    let mismatch = || JwsVerifyError::AlgMismatch {
        header: header_alg.to_string(),
    };
    let alg = JwsAlgorithm::from_str(header_alg).map_err(|_| mismatch())?;
    if !alg.fits(&key.key) || key.alg.is_some_and(|pinned| pinned != alg) {
        return Err(mismatch());
    }
    let ring_verify = |algorithm: &'static dyn ring::signature::VerificationAlgorithm,
                       public_key: &[u8]| {
        ring::signature::UnparsedPublicKey::new(algorithm, public_key)
            .verify(signing_input, sig)
            .map_err(|_| JwsVerifyError::SignatureInvalid)
    };
    match &key.key {
        JwkKeyMaterial::Ed25519 { x } => {
            let vk = AitpVerifyingKey::from_bytes(x)?;
            vk.verify_raw_jose(signing_input, sig)
                .map_err(|_| JwsVerifyError::SignatureInvalid)
        }
        JwkKeyMaterial::P256 { x, y } => {
            let vk = AitpVerifyingKey::from_p256_affine(x, y)?;
            vk.verify_raw_jose(signing_input, sig)
                .map_err(|_| JwsVerifyError::SignatureInvalid)
        }
        JwkKeyMaterial::P384 { x, y } => ring_verify(
            &ring::signature::ECDSA_P384_SHA384_FIXED,
            &uncompressed_point(x, y),
        ),
        JwkKeyMaterial::P521 { x, y } => verify_p521(x, y, signing_input, sig),
        JwkKeyMaterial::Rsa { n, e } => {
            use ring::signature as rs;
            let params: &'static rs::RsaParameters = match alg {
                JwsAlgorithm::RS256 => &rs::RSA_PKCS1_2048_8192_SHA256,
                JwsAlgorithm::RS384 => &rs::RSA_PKCS1_2048_8192_SHA384,
                JwsAlgorithm::RS512 => &rs::RSA_PKCS1_2048_8192_SHA512,
                JwsAlgorithm::PS256 => &rs::RSA_PSS_2048_8192_SHA256,
                JwsAlgorithm::PS384 => &rs::RSA_PSS_2048_8192_SHA384,
                JwsAlgorithm::PS512 => &rs::RSA_PSS_2048_8192_SHA512,
                _ => return Err(mismatch()),
            };
            rs::RsaPublicKeyComponents {
                n: n.as_slice(),
                e: e.as_slice(),
            }
            .verify(params, signing_input, sig)
            .map_err(|_| JwsVerifyError::SignatureInvalid)
        }
    }
}

/// SEC1 uncompressed encoding `0x04 || x || y`.
fn uncompressed_point(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    point
}

/// ES512: ECDSA on P-521 over SHA-512 with a 132-byte `r || s`.
fn verify_p521(
    x: &[u8; 66],
    y: &[u8; 66],
    signing_input: &[u8],
    sig: &[u8],
) -> Result<(), JwsVerifyError> {
    use p521::ecdsa::signature::Verifier as _;
    let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(&uncompressed_point(x, y))
        .map_err(|e| CryptoError::KeyParseFailed(format!("P-521 point: {e}")))?;
    let sig =
        p521::ecdsa::Signature::from_slice(sig).map_err(|_| JwsVerifyError::SignatureInvalid)?;
    vk.verify(signing_input, &sig)
        .map_err(|_| JwsVerifyError::SignatureInvalid)
}

/// Test-only signers for every [`JwsAlgorithm`] but EdDSA, shared by
/// these tests and the JWT-SVID tests in `identity_spiffe`.
#[cfg(test)]
pub(crate) mod test_signers {
    use super::{JwkPublicKey, JwsAlgorithm};
    use base64ct::{Base64UrlUnpadded, Encoding};
    use ring::signature::{self as rs, KeyPair as _};

    /// A throwaway RSA-2048 key, generated for these tests only.
    const RSA_PKCS8: &[u8] = include_bytes!("../tests/fixtures/rsa2048-test-only.pk8");

    /// Returns the JOSE signature over a signing input.
    pub(crate) type Sign = Box<dyn Fn(&[u8]) -> Vec<u8>>;

    /// A key for `alg`: its public JWK (no `alg`, so unpinned) and its
    /// [`Sign`] function.
    pub(crate) fn signer(alg: JwsAlgorithm) -> (serde_json::Value, Sign) {
        let b64 = |b: &[u8]| Base64UrlUnpadded::encode_string(b);
        let rng = ring::rand::SystemRandom::new();
        match alg {
            JwsAlgorithm::ES256 | JwsAlgorithm::ES384 => {
                let (signing, crv, n) = if alg == JwsAlgorithm::ES256 {
                    (&rs::ECDSA_P256_SHA256_FIXED_SIGNING, "P-256", 32)
                } else {
                    (&rs::ECDSA_P384_SHA384_FIXED_SIGNING, "P-384", 48)
                };
                let pkcs8 = rs::EcdsaKeyPair::generate_pkcs8(signing, &rng).unwrap();
                let kp = rs::EcdsaKeyPair::from_pkcs8(signing, pkcs8.as_ref(), &rng).unwrap();
                let point = kp.public_key().as_ref().to_vec();
                let jwk = serde_json::json!({"kty": "EC", "crv": crv,
                    "x": b64(&point[1..1 + n]), "y": b64(&point[1 + n..])});
                (
                    jwk,
                    Box::new(move |m| kp.sign(&rng, m).unwrap().as_ref().to_vec()),
                )
            }
            JwsAlgorithm::ES512 => {
                use p521::ecdsa::signature::Signer as _;
                let mut scalar = [0u8; 66];
                scalar[65] = 7;
                let sk = p521::ecdsa::SigningKey::from_slice(&scalar).unwrap();
                let point = p521::ecdsa::VerifyingKey::from(&sk).to_sec1_point(false);
                let point = point.as_bytes();
                let jwk = serde_json::json!({"kty": "EC", "crv": "P-521",
                    "x": b64(&point[1..67]), "y": b64(&point[67..])});
                (
                    jwk,
                    Box::new(move |m| {
                        let sig: p521::ecdsa::Signature = sk.sign(m);
                        sig.to_bytes().to_vec()
                    }),
                )
            }
            JwsAlgorithm::EdDSA => unreachable!("EdDSA keys come from aitp-crypto"),
            rsa => {
                let padding: &'static dyn rs::RsaEncoding = match rsa {
                    JwsAlgorithm::RS256 => &rs::RSA_PKCS1_SHA256,
                    JwsAlgorithm::RS384 => &rs::RSA_PKCS1_SHA384,
                    JwsAlgorithm::RS512 => &rs::RSA_PKCS1_SHA512,
                    JwsAlgorithm::PS256 => &rs::RSA_PSS_SHA256,
                    JwsAlgorithm::PS384 => &rs::RSA_PSS_SHA384,
                    _ => &rs::RSA_PSS_SHA512,
                };
                let kp = rs::RsaKeyPair::from_pkcs8(RSA_PKCS8).unwrap();
                let public: rs::RsaPublicKeyComponents<Vec<u8>> = kp.public().into();
                let jwk =
                    serde_json::json!({"kty": "RSA", "n": b64(&public.n), "e": b64(&public.e)});
                (
                    jwk,
                    Box::new(move |m| {
                        let mut sig = vec![0u8; kp.public().modulus_len()];
                        kp.sign(padding, &rng, m, &mut sig).unwrap();
                        sig
                    }),
                )
            }
        }
    }

    /// The nine JWT-SVID algorithms (RFC-AITP-0002 §6.3).
    #[cfg_attr(not(feature = "experimental-spiffe-identity"), allow(dead_code))]
    pub(crate) const JWT_SVID_ALGS: [JwsAlgorithm; 9] = [
        JwsAlgorithm::RS256,
        JwsAlgorithm::RS384,
        JwsAlgorithm::RS512,
        JwsAlgorithm::ES256,
        JwsAlgorithm::ES384,
        JwsAlgorithm::ES512,
        JwsAlgorithm::PS256,
        JwsAlgorithm::PS384,
        JwsAlgorithm::PS512,
    ];

    /// `signer`'s JWK, parsed.
    pub(crate) fn parsed(jwk: &serde_json::Value) -> JwkPublicKey {
        JwkPublicKey::from_jwk_json(jwk).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitp_crypto::AitpSigningKey;
    use base64ct::{Base64UrlUnpadded, Encoding};

    fn signing_input_and_sig(key: &AitpSigningKey, alg: &str) -> (Vec<u8>, [u8; 64]) {
        let header = format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#);
        let payload = r#"{"sub":"test"}"#;
        let signing_input = format!(
            "{}.{}",
            Base64UrlUnpadded::encode_string(header.as_bytes()),
            Base64UrlUnpadded::encode_string(payload.as_bytes()),
        );
        // JWS signs the signing input itself (EdDSA / ES256), not the
        // AITP `Digest32`.
        let arr = key.sign_raw(signing_input.as_bytes());
        (signing_input.into_bytes(), arr)
    }

    #[test]
    fn from_jwk_json_parses_okp() {
        let x = Base64UrlUnpadded::encode_string(&[7u8; 32]);
        let jwk = serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": x, "kid": "k1"});
        let parsed = JwkPublicKey::from_jwk_json(&jwk).unwrap();
        assert_eq!(parsed.kid.as_deref(), Some("k1"));
        assert_eq!(parsed.alg, None);
        assert_eq!(parsed.key, JwkKeyMaterial::Ed25519 { x: [7u8; 32] });
    }

    #[test]
    fn from_jwk_json_parses_ec_p256() {
        let x = Base64UrlUnpadded::encode_string(&[1u8; 32]);
        let y = Base64UrlUnpadded::encode_string(&[2u8; 32]);
        let jwk = serde_json::json!({"kty": "EC", "crv": "P-256", "x": x, "y": y});
        let parsed = JwkPublicKey::from_jwk_json(&jwk).unwrap();
        assert_eq!(parsed.alg, None);
        assert_eq!(
            parsed.key,
            JwkKeyMaterial::P256 {
                x: [1u8; 32],
                y: [2u8; 32]
            }
        );
    }

    #[test]
    fn from_jwk_json_parses_rsa() {
        let n = Base64UrlUnpadded::encode_string(&[0x80u8; 256]);
        let e = Base64UrlUnpadded::encode_string(&[1, 0, 1]);
        let jwk = serde_json::json!({"kty": "RSA", "n": n, "e": e});
        let parsed = JwkPublicKey::from_jwk_json(&jwk).unwrap();
        assert_eq!(parsed.alg, None);
        assert_eq!(
            parsed.key,
            JwkKeyMaterial::Rsa {
                n: vec![0x80u8; 256],
                e: vec![1, 0, 1]
            }
        );
    }

    #[test]
    fn from_jwk_json_rejects_unsupported_kty() {
        let jwk = serde_json::json!({"kty": "oct", "k": "abc"});
        assert!(matches!(
            JwkPublicKey::from_jwk_json(&jwk),
            Err(JwkParseError::Unsupported(_))
        ));
    }

    #[test]
    fn from_jwk_json_rejects_wrong_okp_x_length() {
        let x = Base64UrlUnpadded::encode_string(&[7u8; 16]);
        let jwk = serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": x});
        assert!(matches!(
            JwkPublicKey::from_jwk_json(&jwk),
            Err(JwkParseError::Malformed(_))
        ));
    }

    #[test]
    fn verify_jws_signature_eddsa_round_trip() {
        let key = AitpSigningKey::from_seed(&[9u8; 32]);
        let x = key
            .verifying_key()
            .try_to_ed25519_bytes()
            .expect("ed25519 key");
        let jwk = JwkPublicKey {
            kid: None,
            alg: None,
            key: JwkKeyMaterial::Ed25519 { x },
        };
        let (signing_input, sig) = signing_input_and_sig(&key, "EdDSA");
        verify_jws_signature(&jwk, "EdDSA", &signing_input, &sig).expect("valid signature");

        let mut bad_sig = sig;
        bad_sig[0] ^= 0xff;
        assert!(verify_jws_signature(&jwk, "EdDSA", &signing_input, &bad_sig).is_err());
    }

    /// A third-party JOSE token (an IdP ID token) is
    /// verified per RFC 7515/7518. §5.4.7 low-S is scoped to AITP
    /// signing inputs, so a high-S ES256 signature from an IdP verifies
    /// here, while the AITP JWS path (`verify_raw`) still rejects it.
    #[test]
    fn verify_jws_signature_accepts_high_s_es256() {
        let key = AitpSigningKey::from_p256_seed(&[5; 32]).unwrap();
        let point =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.verifying_key().to_compressed())
                .unwrap()
                .to_sec1_point(false);
        let jwk = JwkPublicKey {
            kid: None,
            alg: None,
            key: JwkKeyMaterial::P256 {
                x: point.as_bytes()[1..33].try_into().unwrap(),
                y: point.as_bytes()[33..65].try_into().unwrap(),
            },
        };
        let (signing_input, sig) = signing_input_and_sig(&key, "ES256");
        let twin = aitp_crypto::testing::p256_high_s_twin(sig);
        assert_ne!(twin, sig);
        verify_jws_signature(&jwk, "ES256", &signing_input, &sig).expect("low-S");
        verify_jws_signature(&jwk, "ES256", &signing_input, &twin)
            .expect("an IdP's high-S ES256 signature is valid JOSE");
        assert!(
            key.verifying_key()
                .verify_raw(&signing_input, &twin)
                .is_err(),
            "AITP-minted JWS stays strict (§5.4.7)"
        );
        // Lenient on S only: a wrong signature still fails.
        let mut bad = twin;
        bad[0] ^= 1;
        assert!(verify_jws_signature(&jwk, "ES256", &signing_input, &bad).is_err());
        let mut zero_s = sig;
        zero_s[32..].fill(0);
        assert!(verify_jws_signature(&jwk, "ES256", &signing_input, &zero_s).is_err());
    }

    #[test]
    fn verify_jws_signature_rejects_alg_mismatch() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let x = key
            .verifying_key()
            .try_to_ed25519_bytes()
            .expect("ed25519 key");
        let jwk = JwkPublicKey {
            kid: None,
            alg: None,
            key: JwkKeyMaterial::Ed25519 { x },
        };
        let (signing_input, sig) = signing_input_and_sig(&key, "EdDSA");
        // The JWK is Ed25519, but the header claims RS256 — must be
        // rejected on the alg pin, not silently verified as EdDSA.
        let err = verify_jws_signature(&jwk, "RS256", &signing_input, &sig).unwrap_err();
        assert!(matches!(err, JwsVerifyError::AlgMismatch { .. }));
    }

    /// Signs a JWS signing input under `alg` with a fresh key, verifies
    /// it, then checks that a flipped signature byte and a tampered
    /// input both fail.
    fn round_trip(alg: JwsAlgorithm) {
        let (jwk, sign) = test_signers::signer(alg);
        let key = test_signers::parsed(&jwk);
        let input = format!(
            "{}.{}",
            Base64UrlUnpadded::encode_string(format!(r#"{{"alg":"{alg}"}}"#).as_bytes()),
            Base64UrlUnpadded::encode_string(br#"{"sub":"test"}"#),
        );
        let sig = sign(input.as_bytes());
        verify_jws_signature(&key, alg.as_str(), input.as_bytes(), &sig)
            .unwrap_or_else(|e| panic!("{alg}: {e}"));
        let mut bad = sig.clone();
        bad[sig.len() / 2] ^= 1;
        assert!(matches!(
            verify_jws_signature(&key, alg.as_str(), input.as_bytes(), &bad),
            Err(JwsVerifyError::SignatureInvalid)
        ));
        let tampered = format!("{input}x");
        assert!(matches!(
            verify_jws_signature(&key, alg.as_str(), tampered.as_bytes(), &sig),
            Err(JwsVerifyError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_jws_signature_rs256() {
        round_trip(JwsAlgorithm::RS256);
    }

    #[test]
    fn verify_jws_signature_rs384() {
        round_trip(JwsAlgorithm::RS384);
    }

    #[test]
    fn verify_jws_signature_rs512() {
        round_trip(JwsAlgorithm::RS512);
    }

    #[test]
    fn verify_jws_signature_es256() {
        round_trip(JwsAlgorithm::ES256);
    }

    #[test]
    fn verify_jws_signature_es384() {
        round_trip(JwsAlgorithm::ES384);
    }

    #[test]
    fn verify_jws_signature_es512() {
        round_trip(JwsAlgorithm::ES512);
    }

    #[test]
    fn verify_jws_signature_ps256() {
        round_trip(JwsAlgorithm::PS256);
    }

    #[test]
    fn verify_jws_signature_ps384() {
        round_trip(JwsAlgorithm::PS384);
    }

    #[test]
    fn verify_jws_signature_ps512() {
        round_trip(JwsAlgorithm::PS512);
    }

    /// The header picks the hash and padding for an RSA key, but an
    /// RS256 signature does not verify as RS384 or PS256.
    #[test]
    fn rsa_signature_verifies_only_under_its_own_alg() {
        let (jwk, sign) = test_signers::signer(JwsAlgorithm::RS256);
        let key = test_signers::parsed(&jwk);
        let sig = sign(b"a.b");
        verify_jws_signature(&key, "RS256", b"a.b", &sig).unwrap();
        for other in ["RS384", "RS512", "PS256", "PS384", "PS512"] {
            assert!(matches!(
                verify_jws_signature(&key, other, b"a.b", &sig),
                Err(JwsVerifyError::SignatureInvalid)
            ));
        }
    }

    #[test]
    fn header_alg_must_fit_the_key_type() {
        let (jwk, sign) = test_signers::signer(JwsAlgorithm::ES256);
        let key = test_signers::parsed(&jwk);
        let sig = sign(b"a.b");
        for header in [
            "ES384", "ES512", "RS256", "PS256", "EdDSA", "HS256", "none", "",
        ] {
            assert!(
                matches!(
                    verify_jws_signature(&key, header, b"a.b", &sig),
                    Err(JwsVerifyError::AlgMismatch { .. })
                ),
                "{header:?}"
            );
        }
    }

    /// A JWK's own `alg` pins it (RFC 7517 §4.4).
    #[test]
    fn jwk_alg_member_pins_the_key() {
        let (mut jwk, sign) = test_signers::signer(JwsAlgorithm::PS384);
        jwk["alg"] = "PS384".into();
        let key = test_signers::parsed(&jwk);
        assert_eq!(key.alg, Some(JwsAlgorithm::PS384));
        verify_jws_signature(&key, "PS384", b"a.b", &sign(b"a.b")).unwrap();
        let rs256 = test_signers::signer(JwsAlgorithm::RS256).1(b"a.b");
        assert!(matches!(
            verify_jws_signature(&key, "RS256", b"a.b", &rs256),
            Err(JwsVerifyError::AlgMismatch { .. })
        ));
    }

    #[test]
    fn from_jwk_json_rejects_alg_that_does_not_fit() {
        let (mut jwk, _) = test_signers::signer(JwsAlgorithm::RS256);
        for alg in ["ES256", "EdDSA", "HS256", "none"] {
            jwk["alg"] = alg.into();
            assert!(
                matches!(
                    JwkPublicKey::from_jwk_json(&jwk),
                    Err(JwkParseError::Unsupported(_))
                ),
                "{alg}"
            );
        }
        jwk["alg"] = 7.into();
        assert!(matches!(
            JwkPublicKey::from_jwk_json(&jwk),
            Err(JwkParseError::Malformed(_))
        ));
    }

    #[test]
    fn from_jwk_json_parses_ec_p384_and_p521() {
        let x = Base64UrlUnpadded::encode_string(&[1u8; 48]);
        let jwk = serde_json::json!({"kty": "EC", "crv": "P-384", "x": x, "y": x});
        assert!(matches!(
            JwkPublicKey::from_jwk_json(&jwk).unwrap().key,
            JwkKeyMaterial::P384 { .. }
        ));
        let x = Base64UrlUnpadded::encode_string(&[1u8; 66]);
        let jwk = serde_json::json!({"kty": "EC", "crv": "P-521", "x": x, "y": x});
        assert!(matches!(
            JwkPublicKey::from_jwk_json(&jwk).unwrap().key,
            JwkKeyMaterial::P521 { .. }
        ));
        // A P-384 coordinate on a P-521 key is malformed, not truncated.
        let x = Base64UrlUnpadded::encode_string(&[1u8; 48]);
        let jwk = serde_json::json!({"kty": "EC", "crv": "P-521", "x": x, "y": x});
        assert!(matches!(
            JwkPublicKey::from_jwk_json(&jwk),
            Err(JwkParseError::Malformed(_))
        ));
    }
}
