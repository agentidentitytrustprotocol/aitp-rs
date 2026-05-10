//! OIDC identity-proof verification (RFC-AITP-0002 §2).

use crate::error::HandshakeError;
use crate::identity::IdentityDescriptor;
use aitp_core::Aid;
use aitp_crypto::AitpVerifyingKey;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashSet;
use url::Url;

/// Trait implementations resolve an issuer URI to a set of acceptable
/// signing keys. The handshake crate is sync; the HTTP transport crate
/// provides an async-fronted impl.
///
/// Implementations MAY return Ed25519 (`OKP`) keys, RSA keys, or both.
/// Each key is identified by a `kid` and an algorithm.
pub trait JwksResolver {
    /// Return the set of acceptable signing keys for `issuer`.
    fn resolve(&self, issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError>;
}

/// A single JWK entry returned by [`JwksResolver`].
#[derive(Clone)]
pub struct JwkPublicKey {
    /// Key identifier matching the JWT header `kid`.
    pub kid: Option<String>,
    /// Algorithm (`EdDSA`, `RS256`, …).
    pub alg: Algorithm,
    /// Decoding key material in `jsonwebtoken`'s representation.
    pub key: DecodingKey,
}

impl std::fmt::Debug for JwkPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwkPublicKey")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            // DecodingKey deliberately does not implement Debug — its
            // internals can hold key material.
            .finish_non_exhaustive()
    }
}

/// Errors from JWKS resolution.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// Issuer URI is not in the acceptable trust anchors.
    #[error("issuer not trusted: {0}")]
    NotTrusted(Url),
    /// Network or parse error reaching the issuer's JWKS endpoint.
    #[error("could not resolve issuer keys: {0}")]
    NetworkError(String),
    /// JWKS body was malformed.
    #[error("malformed JWKS: {0}")]
    Malformed(String),
}

/// Inputs for verifying an OIDC identity proof.
pub struct OidcVerifyContext<'a> {
    /// The verifier's own AID (used as the expected `aud` claim).
    pub expected_audience: &'a Aid,
    /// The fresh `pop_nonce` sent with the corresponding handshake message.
    pub expected_nonce: &'a str,
    /// Accepted OIDC issuers (compared as wire strings; the
    /// canonical bytes the OIDC issuer signed must match).
    pub trust_anchors: &'a [aitp_core::RawUrl],
    /// JWKS resolver bridging to the issuer.
    pub jwks_resolver: &'a dyn JwksResolver,
    /// Subject AID (whose key the JWT's `cnf.jkt` MUST match).
    pub subject_aid: &'a Aid,
    /// Freshness window for the `iat` claim, in seconds. RFC-AITP-0002
    /// §2.2 says ±300s; this lets tests pin a tighter window.
    pub iat_tolerance_secs: i64,
    /// Current time for `iat` / `exp` evaluation.
    pub now_unix_secs: i64,
}

/// Verify an OIDC identity proof per RFC-AITP-0002 §2.3.
pub fn verify_oidc(
    proof: &IdentityDescriptor,
    ctx: &OidcVerifyContext<'_>,
) -> Result<(), HandshakeError> {
    let issuer = proof
        .issuer
        .as_ref()
        .ok_or_else(|| HandshakeError::Identity("oidc descriptor missing issuer".into()))?;

    if !ctx
        .trust_anchors
        .iter()
        .any(|a| a.as_str() == issuer.as_str())
    {
        return Err(HandshakeError::IncompatibleTrustAnchors);
    }

    let header = jsonwebtoken::decode_header(&proof.proof)
        .map_err(|e| HandshakeError::Identity(format!("malformed JWT header: {e}")))?;

    // Parse the wire issuer string into a `url::Url` for the JWKS
    // resolver, which is transport-layer and does need a normalized
    // URL. Falls back to a structural error if the issuer string
    // isn't a valid URL.
    let issuer_url = issuer
        .parse_url()
        .map_err(|e| HandshakeError::Identity(format!("issuer not a URL: {e}")))?;
    let candidates = ctx
        .jwks_resolver
        .resolve(&issuer_url)
        .map_err(|e| HandshakeError::Identity(format!("jwks resolve failed: {e}")))?;

    let key = match (&header.kid, candidates.iter().find(|k| k.kid == header.kid)) {
        (_, Some(k)) => k,
        (None, _) if candidates.len() == 1 => &candidates[0],
        _ => return Err(HandshakeError::Identity("no matching JWK".into())),
    };

    let mut validation = Validation::new(key.alg);
    let mut audiences = HashSet::new();
    audiences.insert(ctx.expected_audience.as_str().to_string());
    validation.aud = Some(audiences);
    let mut issuers = HashSet::new();
    issuers.insert(issuer.as_str().to_string());
    validation.iss = Some(issuers);
    validation.required_spec_claims = ["iss", "sub", "aud", "exp", "iat"]
        .into_iter()
        .map(String::from)
        .collect();
    // We drive `exp` and `iat` validation manually against
    // `ctx.now_unix_secs` so tests can pin a fixed clock. jsonwebtoken's
    // built-in `exp` check uses the system clock unconditionally, which
    // breaks fixture-based testing.
    validation.validate_exp = false;
    validation.validate_nbf = false;

    let token = jsonwebtoken::decode::<OidcClaims>(&proof.proof, &key.key, &validation)
        .map_err(|e| HandshakeError::Identity(format!("jwt invalid: {e}")))?;
    let claims = token.claims;

    if claims.sub != proof.subject {
        return Err(HandshakeError::Identity("sub mismatch".into()));
    }

    if claims.exp <= ctx.now_unix_secs {
        return Err(HandshakeError::Identity("jwt exp in the past".into()));
    }
    if (ctx.now_unix_secs - claims.iat).abs() > ctx.iat_tolerance_secs {
        return Err(HandshakeError::Identity("iat outside tolerance".into()));
    }

    let nonce = claims
        .nonce
        .as_deref()
        .ok_or_else(|| HandshakeError::Identity("missing nonce claim".into()))?;
    if nonce != ctx.expected_nonce {
        return Err(HandshakeError::Identity("nonce mismatch".into()));
    }

    let cnf = claims
        .cnf
        .as_ref()
        .ok_or_else(|| HandshakeError::Identity("missing cnf claim".into()))?;
    let expected_jkt = AitpVerifyingKey::from_aid(ctx.subject_aid)
        .map_err(|_| HandshakeError::Identity("subject AID not Ed25519".into()))?
        .to_jwk_thumbprint();
    if cnf.jkt != expected_jkt {
        return Err(HandshakeError::Identity("cnf.jkt mismatch".into()));
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct OidcClaims {
    sub: String,
    iat: i64,
    exp: i64,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    cnf: Option<Cnf>,
}

#[derive(Debug, Deserialize)]
struct Cnf {
    jkt: String,
}
