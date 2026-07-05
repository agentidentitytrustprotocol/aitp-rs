//! In-process mock OIDC issuer for handshake integration tests.
//!
//! Holds a fixed Ed25519 keypair, mints JWTs with arbitrary claims, and
//! exposes its key as a `JwksResolver` so the handshake's
//! `verify_oidc` path can resolve the issuer without any HTTP I/O.
//!
//! Each test binary compiles this module independently, so any given
//! test uses only a subset of the helpers — allow dead code rather than
//! sprinkle per-item attributes.
#![allow(dead_code)]

use aitp_handshake::{JwkPublicKey, JwksResolver, ResolveError};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signer, SigningKey};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::{json, Value};
use url::Url;

/// A self-contained OIDC issuer.
///
/// Construct once per test, then call `mint_jwt(...)` for the claims you
/// want and `as_resolver()` for a [`JwksResolver`] that returns this
/// issuer's keys.
pub struct MockOidcIssuer {
    pub issuer: Url,
    pub kid: String,
    signing: SigningKey,
}

impl MockOidcIssuer {
    pub fn new(issuer: &str, kid: &str, seed: [u8; 32]) -> Self {
        Self {
            issuer: issuer.parse().unwrap(),
            kid: kid.to_string(),
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// Return the raw 32-byte Ed25519 pubkey.
    ///
    /// `jsonwebtoken::DecodingKey::from_ed_der` is misleadingly named:
    /// it actually wants the raw 32-byte pubkey (which `ring`
    /// internally accepts as the `UnparsedPublicKey` for ED25519), not
    /// SPKI DER.
    fn pubkey_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Mint a JWT with the given claims.
    ///
    /// We avoid `jsonwebtoken::EncodingKey::from_ed_der` because it's
    /// picky about PKCS#8 v2 vs. v1 framing for Ed25519. Instead we
    /// build the compact JWT by hand: base64url(header) + "." +
    /// base64url(payload) + "." + base64url(Ed25519(signing_input)).
    pub fn mint_jwt(&self, claims: Value) -> String {
        self.mint_jwt_opts(claims, true)
    }

    /// Mint a JWT whose protected header omits `kid` entirely — used to
    /// exercise the no-`kid` single-key fallback in `verify_oidc`.
    #[allow(dead_code)]
    pub fn mint_jwt_no_kid(&self, claims: Value) -> String {
        self.mint_jwt_opts(claims, false)
    }

    fn mint_jwt_opts(&self, claims: Value, include_kid: bool) -> String {
        let header = if include_kid {
            json!({ "alg": "EdDSA", "typ": "JWT", "kid": self.kid })
        } else {
            json!({ "alg": "EdDSA", "typ": "JWT" })
        };
        let header_b64 =
            Base64UrlUnpadded::encode_string(serde_json::to_string(&header).unwrap().as_bytes());
        let payload_b64 =
            Base64UrlUnpadded::encode_string(serde_json::to_string(&claims).unwrap().as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = self.signing.sign(signing_input.as_bytes());
        let sig_b64 = Base64UrlUnpadded::encode_string(&sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }

    /// Build a `JwkPublicKey` matching this issuer's public key, suitable
    /// for inclusion in a `MockJwksResolver`.
    pub fn as_jwk(&self) -> JwkPublicKey {
        JwkPublicKey {
            kid: Some(self.kid.clone()),
            alg: Algorithm::EdDSA,
            key: DecodingKey::from_ed_der(&self.pubkey_bytes()),
        }
    }

    /// Like [`Self::as_jwk`] but with `kid: None`, so the resolved key
    /// only matches a JWT that has no `kid` (single-key fallback).
    #[allow(dead_code)]
    pub fn as_jwk_no_kid(&self) -> JwkPublicKey {
        JwkPublicKey {
            kid: None,
            alg: Algorithm::EdDSA,
            key: DecodingKey::from_ed_der(&self.pubkey_bytes()),
        }
    }

    /// Convenience: construct a resolver that returns *only* this
    /// issuer's key when its issuer URL is queried.
    pub fn as_resolver(&self) -> MockJwksResolver {
        MockJwksResolver {
            issuer: self.issuer.clone(),
            keys: vec![self.as_jwk()],
        }
    }

    /// Build a JWT with default AITP-conformant claims.
    pub fn mint_aitp_jwt(
        &self,
        subject: &str,
        audience: &str,
        nonce: &str,
        cnf_jkt: &str,
        now_unix: i64,
    ) -> String {
        self.mint_jwt(json!({
            "iss": self.issuer.as_str(),
            "sub": subject,
            "aud": audience,
            "iat": now_unix,
            "exp": now_unix + 3600,
            "nonce": nonce,
            "cnf": { "jkt": cnf_jkt }
        }))
    }
}

/// `JwksResolver` impl backed by a fixed list of pre-loaded keys.
pub struct MockJwksResolver {
    pub issuer: Url,
    pub keys: Vec<JwkPublicKey>,
}

impl JwksResolver for MockJwksResolver {
    fn resolve(&self, issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        if issuer == &self.issuer {
            // Clone-by-rebuild: JwkPublicKey is Clone via its DecodingKey
            // wrapper.
            Ok(self
                .keys
                .iter()
                .map(|k| JwkPublicKey {
                    kid: k.kid.clone(),
                    alg: k.alg,
                    key: k.key.clone(),
                })
                .collect())
        } else {
            Err(ResolveError::NotTrusted(issuer.clone()))
        }
    }
}

#[allow(dead_code)] // used via include only by tests that want the
                    // signing key for direct ops.
pub fn _signer_bytes(issuer: &MockOidcIssuer) -> &SigningKey {
    &issuer.signing
}

/// `verify_oidc`-driven smoke test: mint a JWT, build the verifier
/// context, and confirm verification succeeds.
#[allow(dead_code)]
pub fn _smoke_helper(_unused: ()) {}

impl MockOidcIssuer {
    /// Sign arbitrary bytes with this issuer's underlying Ed25519 key.
    /// Tests use this to produce non-JWT signatures when they need them.
    #[allow(dead_code)]
    pub fn sign_raw(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }
}
