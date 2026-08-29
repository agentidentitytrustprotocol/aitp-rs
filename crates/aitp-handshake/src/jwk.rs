//! Owned JWK representation and JWS signature verification, decoupled
//! from any JOSE library (issue #99: dropping the `jsonwebtoken`
//! runtime dependency).
//!
//! [`JwkPublicKey`] carries only plain key material — raw Ed25519/P-256
//! coordinates or RSA modulus/exponent bytes — so this crate's public
//! API is not pinned to any particular JOSE crate's version. Ed25519
//! and P-256 verification go through `aitp-crypto`'s own KAT-tested
//! primitives; RS256 verification goes through `ring`, which is
//! already in the dependency tree transitively via `rustls` and is the
//! same code path `jsonwebtoken` 9's RS256 verification used
//! internally — no crypto behavior change, only the wrapper is
//! removed.

use aitp_core::base64url;
use aitp_crypto::{AitpVerifyingKey, CryptoError};
use std::str::FromStr;

/// Supported JWS signature algorithms for OIDC ID tokens and DPoP
/// proofs.
///
/// Deliberately a closed set of three: these are the only algorithms
/// [`verify_jws_signature`] knows how to verify. A JWKS or DPoP proof
/// advertising anything else is rejected during parsing
/// ([`JwkPublicKey::from_jwk_json`]), not silently accepted here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwsAlgorithm {
    /// EdDSA (Ed25519), RFC 8037.
    EdDSA,
    /// ECDSA on P-256 with SHA-256, RFC 7518 §3.4.
    ES256,
    /// RSASSA-PKCS1-v1_5 with SHA-256, RFC 7518 §3.3.
    RS256,
}

impl JwsAlgorithm {
    /// The JOSE `alg` header value for this algorithm.
    pub fn as_str(&self) -> &'static str {
        match self {
            JwsAlgorithm::EdDSA => "EdDSA",
            JwsAlgorithm::ES256 => "ES256",
            JwsAlgorithm::RS256 => "RS256",
        }
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
            "RS256" => Ok(JwsAlgorithm::RS256),
            other => Err(JwkParseError::Unsupported(format!(
                "unsupported JWS algorithm: {other}"
            ))),
        }
    }
}

/// Owned public-key material for a [`JwkPublicKey`].
///
/// All fields are public key material (never secret): Ed25519's raw
/// 32-byte point, P-256's affine `(x, y)` coordinates, or an RSA
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
    /// Key identifier matching the JWT/DPoP-proof header `kid`.
    pub kid: Option<String>,
    /// Algorithm (`EdDSA`, `ES256`, `RS256`).
    pub alg: JwsAlgorithm,
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
    /// Supports exactly the three key types this workspace verifies:
    ///
    /// - `kty: "OKP"`, `crv: "Ed25519"` — requires a 32-byte `x`.
    /// - `kty: "EC"`, `crv: "P-256"` — requires 32-byte `x` and `y`.
    /// - `kty: "RSA"` — requires `n` and `e`.
    ///
    /// The algorithm is inferred from `kty`/`crv` rather than trusting
    /// any `alg` member the JWK itself carries (JWKS entries are not
    /// required to carry `alg`, and a JOSE header's `alg` is checked
    /// separately by [`verify_jws_signature`]).
    ///
    /// This is the single shared parser consolidating what used to be
    /// hand-rolled, duplicated JWK parsing in `aitp-transport-http`
    /// (JWKS fetch, DPoP proof verification) and both language
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
        match kty {
            "OKP" => {
                let crv = value.get("crv").and_then(|v| v.as_str()).unwrap_or("");
                if crv != "Ed25519" {
                    return Err(JwkParseError::Unsupported(format!("OKP crv={crv}")));
                }
                let x = decode_member(value, "x")?;
                let x = to_array::<32>(&x, "OKP x")?;
                Ok(Self {
                    kid,
                    alg: JwsAlgorithm::EdDSA,
                    key: JwkKeyMaterial::Ed25519 { x },
                })
            }
            "EC" => {
                let crv = value.get("crv").and_then(|v| v.as_str()).unwrap_or("");
                if crv != "P-256" {
                    return Err(JwkParseError::Unsupported(format!("EC crv={crv}")));
                }
                let x = to_array::<32>(&decode_member(value, "x")?, "EC x")?;
                let y = to_array::<32>(&decode_member(value, "y")?, "EC y")?;
                Ok(Self {
                    kid,
                    alg: JwsAlgorithm::ES256,
                    key: JwkKeyMaterial::P256 { x, y },
                })
            }
            "RSA" => {
                let n = decode_member(value, "n")?;
                let e = decode_member(value, "e")?;
                Ok(Self {
                    kid,
                    alg: JwsAlgorithm::RS256,
                    key: JwkKeyMaterial::Rsa { n, e },
                })
            }
            other => Err(JwkParseError::Unsupported(format!("kty={other}"))),
        }
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

/// Errors verifying a JWS/DPoP signature against a [`JwkPublicKey`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwsVerifyError {
    /// The JOSE header's `alg` does not match the key's own algorithm
    /// (the alg-confusion guard `jsonwebtoken`'s `Validation::new(alg)`
    /// used to provide).
    #[error("JWS header alg {header:?} does not match key alg {key}")]
    AlgMismatch {
        /// The `alg` value from the JOSE header.
        header: String,
        /// The algorithm this key implements.
        key: JwsAlgorithm,
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
/// `header_alg` MUST equal `key.alg.as_str()` or verification fails
/// with [`JwsVerifyError::AlgMismatch`] — this reproduces the
/// alg-pinning `jsonwebtoken`'s `Validation::new(key.alg)` used to
/// provide, and is the algorithm-confusion defense: a JWKS entry's
/// algorithm is never inferred from an attacker-controlled header.
///
/// Dispatch by key type:
/// - EdDSA — `aitp_crypto::AitpVerifyingKey::from_bytes` + `verify_raw`
///   (dalek `verify_strict`, rejecting non-canonical signatures).
/// - ES256 — `AitpVerifyingKey::from_p256_affine` + `verify_raw`.
/// - RS256 — `ring::signature::RsaPublicKeyComponents::verify` with
///   `RSA_PKCS1_2048_8192_SHA256`, the same verification path
///   `jsonwebtoken` 9's RS256 support used internally. Verification is
///   not affected by RUSTSEC-2023-0071 (the Marvin timing sidechannel
///   affects RSA *decryption*/signing padding checks, not signature
///   verification), so moving verification-only usage off `rsa` 0.9
///   onto `ring` removes the advisory without any behavior change.
pub fn verify_jws_signature(
    key: &JwkPublicKey,
    header_alg: &str,
    signing_input: &[u8],
    sig: &[u8],
) -> Result<(), JwsVerifyError> {
    if header_alg != key.alg.as_str() {
        return Err(JwsVerifyError::AlgMismatch {
            header: header_alg.to_string(),
            key: key.alg,
        });
    }
    match &key.key {
        JwkKeyMaterial::Ed25519 { x } => {
            let vk = AitpVerifyingKey::from_bytes(x)?;
            vk.verify_raw(signing_input, sig)
                .map_err(|_| JwsVerifyError::SignatureInvalid)
        }
        JwkKeyMaterial::P256 { x, y } => {
            let vk = AitpVerifyingKey::from_p256_affine(x, y)?;
            vk.verify_raw(signing_input, sig)
                .map_err(|_| JwsVerifyError::SignatureInvalid)
        }
        JwkKeyMaterial::Rsa { n, e } => {
            let public_key = ring::signature::RsaPublicKeyComponents {
                n: n.as_slice(),
                e: e.as_slice(),
            };
            public_key
                .verify(
                    &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                    signing_input,
                    sig,
                )
                .map_err(|_| JwsVerifyError::SignatureInvalid)
        }
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
        // `AitpSigningKey::sign` emits the wire (base64url, possibly
        // algorithm-tagged) form; for an Ed25519 key that's the
        // untagged 64-byte raw signature the JWS raw-signature profile
        // also uses, so decode it back to raw bytes for
        // `verify_jws_signature`, which takes the raw form directly.
        let sig = key.sign(signing_input.as_bytes());
        let raw = Base64UrlUnpadded::decode_vec(sig.payload()).expect("valid base64url payload");
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&raw);
        (signing_input.into_bytes(), arr)
    }

    #[test]
    fn from_jwk_json_parses_okp() {
        let x = Base64UrlUnpadded::encode_string(&[7u8; 32]);
        let jwk = serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": x, "kid": "k1"});
        let parsed = JwkPublicKey::from_jwk_json(&jwk).unwrap();
        assert_eq!(parsed.kid.as_deref(), Some("k1"));
        assert_eq!(parsed.alg, JwsAlgorithm::EdDSA);
        assert_eq!(parsed.key, JwkKeyMaterial::Ed25519 { x: [7u8; 32] });
    }

    #[test]
    fn from_jwk_json_parses_ec_p256() {
        let x = Base64UrlUnpadded::encode_string(&[1u8; 32]);
        let y = Base64UrlUnpadded::encode_string(&[2u8; 32]);
        let jwk = serde_json::json!({"kty": "EC", "crv": "P-256", "x": x, "y": y});
        let parsed = JwkPublicKey::from_jwk_json(&jwk).unwrap();
        assert_eq!(parsed.alg, JwsAlgorithm::ES256);
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
        assert_eq!(parsed.alg, JwsAlgorithm::RS256);
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
            alg: JwsAlgorithm::EdDSA,
            key: JwkKeyMaterial::Ed25519 { x },
        };
        let (signing_input, sig) = signing_input_and_sig(&key, "EdDSA");
        verify_jws_signature(&jwk, "EdDSA", &signing_input, &sig).expect("valid signature");

        let mut bad_sig = sig;
        bad_sig[0] ^= 0xff;
        assert!(verify_jws_signature(&jwk, "EdDSA", &signing_input, &bad_sig).is_err());
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
            alg: JwsAlgorithm::EdDSA,
            key: JwkKeyMaterial::Ed25519 { x },
        };
        let (signing_input, sig) = signing_input_and_sig(&key, "EdDSA");
        // The JWK is Ed25519, but the header claims RS256 — must be
        // rejected on the alg pin, not silently verified as EdDSA.
        let err = verify_jws_signature(&jwk, "RS256", &signing_input, &sig).unwrap_err();
        assert!(matches!(err, JwsVerifyError::AlgMismatch { .. }));
    }
}
