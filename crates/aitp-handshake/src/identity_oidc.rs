//! OIDC identity-proof verification (RFC-AITP-0002 §2).

use crate::error::HandshakeError;
use crate::identity::IdentityDescriptor;
use crate::jwk::{verify_jws_signature, JwkPublicKey};
use aitp_core::Aid;
use aitp_crypto::AitpVerifyingKey;
use serde::Deserialize;
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

/// Errors from JWKS resolution.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
    /// Configured fail mode is `SoftFail` with no safe-grants subset —
    /// there is no safe way to degrade, so resolution fails closed
    /// (RFC-AITP-0007).
    #[error("no pinned keys available and SoftFail has no safe_grants")]
    NoPinnedKeys,
    /// Configured fail mode is `SoftFail` with a non-empty safe-grants
    /// subset. The plain `resolve()` path fails closed and returns this
    /// error: entering a degraded session restricted to that subset
    /// requires explicitly opting in via the resolver's
    /// `resolve_outcome()` method, which surfaces the safe-grant subset
    /// to the caller. Returning an empty key set from `resolve()` would
    /// be wire-indistinguishable from `FailOpen` and would silently drop
    /// the safe-grants signal (RFC-AITP-0007 §3.2). A caller that sees
    /// this error from `resolve()` MUST switch to `resolve_outcome()`
    /// rather than treating it as an unrecoverable failure.
    #[error("SoftFail degradation requires resolve_outcome(); plain resolve() fails closed")]
    SoftFailRequiresOutcome,
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
    // RFC-AITP-0002 §identity-descriptor: for `oidc`, `public_key` MUST
    // be absent — the agent's key is already encoded in the AID, and a
    // second copy creates ambiguity over what the JWT's `cnf.jkt` binds.
    // v0.1 verifiers MUST reject an OIDC descriptor carrying it.
    if proof.public_key.is_some() {
        return Err(HandshakeError::Identity(
            "oidc descriptor must not carry public_key".into(),
        ));
    }

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

    // Strict manual JWT parse: three dot-separated segments, no more
    // and no fewer. Replaces `jsonwebtoken::decode_header` /
    // `jsonwebtoken::decode` (issue #99: dropping the `jsonwebtoken`
    // runtime dependency).
    let segments: Vec<&str> = proof.proof.split('.').collect();
    if segments.len() != 3 {
        return Err(HandshakeError::Identity(format!(
            "malformed JWT: expected 3 dot-separated segments, got {}",
            segments.len()
        )));
    }
    let (header_b64, payload_b64, sig_b64) = (segments[0], segments[1], segments[2]);

    let header_bytes = aitp_core::base64url::decode_strict(header_b64)
        .map_err(|e| HandshakeError::Identity(format!("malformed JWT header b64: {e}")))?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| HandshakeError::Identity(format!("malformed JWT header json: {e}")))?;

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

    let sig_bytes = aitp_core::base64url::decode_strict(sig_b64)
        .map_err(|e| HandshakeError::Identity(format!("malformed JWT signature b64: {e}")))?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    verify_jws_signature(key, &header.alg, signing_input.as_bytes(), &sig_bytes)
        .map_err(|e| HandshakeError::Identity(format!("jwt signature invalid: {e}")))?;

    let payload_bytes = aitp_core::base64url::decode_strict(payload_b64)
        .map_err(|e| HandshakeError::Identity(format!("malformed JWT payload b64: {e}")))?;
    let claims: OidcClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| HandshakeError::Identity(format!("malformed JWT claims: {e}")))?;

    // Reproduces jsonwebtoken's built-in `iss`/`aud` validation, now
    // that the crate is gone: the JWT's own `iss` must equal the
    // issuer declared (and already trust-anchor-checked) on the
    // identity descriptor, and `aud` must contain our AID.
    if claims.iss != issuer.as_str() {
        return Err(HandshakeError::Identity("iss mismatch".into()));
    }
    if !claims.aud.contains(ctx.expected_audience.as_str()) {
        return Err(HandshakeError::Identity("aud mismatch".into()));
    }

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
        .map_err(|e| HandshakeError::Identity(format!("subject AID parse failed: {e}")))?
        .to_jwk_thumbprint()
        .map_err(|e| HandshakeError::Identity(format!("subject AID jkt failed: {e}")))?;
    if cnf.jkt != expected_jkt {
        return Err(HandshakeError::Identity("cnf.jkt mismatch".into()));
    }

    Ok(())
}

/// Minimal JWT protected-header shape needed for JWK selection and
/// algorithm pinning. Replaces `jsonwebtoken::Header`.
#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcClaims {
    iss: String,
    sub: String,
    aud: Aud,
    iat: i64,
    exp: i64,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    cnf: Option<Cnf>,
}

/// The `aud` claim per RFC 7519 §4.1.3: either a single string or an
/// array of strings. Matches if the expected audience is present
/// either way — the same semantics `jsonwebtoken`'s built-in `aud`
/// validation enforced.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Aud {
    Single(String),
    Multi(Vec<String>),
}

impl Aud {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Aud::Single(s) => s == expected,
            Aud::Multi(v) => v.iter().any(|s| s == expected),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Cnf {
    jkt: String,
}
