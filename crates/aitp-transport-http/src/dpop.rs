//! DPoP (RFC 9449) — Demonstrating Proof of Possession.
//!
//! The DPoP scheme binds an OAuth access token to a public key
//! known only to its legitimate holder. Every protected request
//! carries a fresh JWT-shaped *proof* (`DPoP` header), signed by
//! the holder's key, that asserts the client method and URL of the
//! request and includes a unique `jti`. The resource server
//! verifies the proof's signature, checks the proof binding to
//! the request, deduplicates the `jti` against a replay cache,
//! and confirms the access token's `cnf.jkt` thumbprint matches
//! the proof's signing key.
//!
//! AITP v0.1 OIDC handshakes accept identity tokens with static
//! `cnf.jkt` bindings (RFC-AITP-0002 §2.3); DPoP is additive — it
//! lets an IdP and resource server agree to require a per-request
//! proof on top of the static binding.
//!
//! # Use
//!
//! ```rust,ignore
//! use aitp_transport_http::dpop::{
//!     DpopHeader, DpopReplayCache, verify_dpop_proof_full, DpopVerifyContext,
//! };
//!
//! let cache = DpopReplayCache::default();
//! let header = DpopHeader::parse(authz_value, dpop_value)?;
//! let proof = verify_dpop_proof_full(&header, &DpopVerifyContext {
//!     expected_method: "POST",
//!     expected_url: "https://api.example.com/resource",
//!     expected_jkt: "9ZP03Nu8GrXPAUkbKNxHOKBzxPX83SShgFkRNK-f2lw",
//!     expected_access_token: Some(header.access_token.as_bytes()),
//!     replay_cache: &cache,
//!     iat_tolerance_secs: 60,
//!     now_unix_secs: now,
//! })?;
//! // proof.jti is now reserved in the cache for the configured TTL.
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// DPoP proof JWT body (RFC 9449 §4.2). Carried in a `DPoP` header
/// alongside the access token.
///
/// The verifier checks:
/// 1. JWT header `typ == "dpop+jwt"` and `alg == "EdDSA"` (or the
///    IdP-permitted set).
/// 2. JWT signature against the embedded `jwk`.
/// 3. `jti` not seen before (replay cache).
/// 4. `htm` matches request method, `htu` matches request URL.
/// 5. `iat` within tolerance.
/// 6. Resource server: `cnf.jkt` of the access token equals the JWK
///    thumbprint of the proof's `jwk` header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DpopProof {
    /// Unique JWT id for replay protection.
    pub jti: String,
    /// HTTP method.
    pub htm: String,
    /// HTTP target URI (without fragment).
    pub htu: String,
    /// Issued-at timestamp.
    pub iat: i64,
    /// Optional access-token hash (`ath` claim) — present on
    /// resource-server proofs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    /// Optional server-supplied nonce (RFC 9449 §8). When the
    /// resource server has issued a `DPoP-Nonce` header in a
    /// previous response, the next proof MUST echo it back here.
    /// The verifier rejects proofs whose `nonce` doesn't equal
    /// the most recent value the server emitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// Parsed split of an `Authorization: DPoP <token>` plus the
/// accompanying `DPoP: <proof-jwt>` header pair.
#[derive(Debug, Clone)]
pub struct DpopHeader {
    /// The DPoP-bound access token from `Authorization`.
    pub access_token: String,
    /// The DPoP proof JWT from the `DPoP` header.
    pub proof_jwt: String,
}

/// Errors from DPoP parsing/verification.
///
/// Marked `#[non_exhaustive]` so adding new variants is not a
/// breaking change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DpopError {
    /// Header missing or malformed.
    #[error("malformed DPoP header")]
    MalformedHeader,
    /// Proof JWT cannot be parsed (header, claims, or split).
    #[error("malformed DPoP proof: {0}")]
    MalformedProof(String),
    /// JWT header `typ` is not `dpop+jwt`.
    #[error("DPoP proof typ != dpop+jwt")]
    WrongJwtType,
    /// JWT header `alg` is not in the accepted set.
    #[error("DPoP proof uses unsupported alg: {0}")]
    UnsupportedAlgorithm(String),
    /// JWT header is missing the embedded `jwk`.
    #[error("DPoP proof header missing 'jwk'")]
    MissingJwk,
    /// Proof signature verification failed.
    #[error("DPoP proof signature invalid")]
    InvalidProofSignature,
    /// `htm`/`htu`/`iat` mismatch with the request.
    #[error("DPoP request binding mismatch: {0}")]
    RequestBindingMismatch(String),
    /// `iat` is older or newer than the configured tolerance.
    #[error("DPoP iat outside tolerance window")]
    IatOutOfWindow,
    /// Replay cache hit — `jti` already seen.
    #[error("DPoP replay detected")]
    Replay,
    /// `cnf.jkt` of access token does not match proof's JWK thumbprint.
    #[error("DPoP confirmation thumbprint mismatch")]
    ConfirmationMismatch,
    /// `ath` claim missing on a proof that was supposed to bind to
    /// an access token (resource-server flow). RFC 9449 §4.1
    /// requires `ath` whenever a proof accompanies an access token.
    #[error("DPoP proof missing 'ath' claim")]
    MissingAth,
    /// `ath` claim present but its value does not equal
    /// `base64url(sha256(access_token))`.
    #[error("DPoP 'ath' does not match access token hash")]
    AthMismatch,
    /// Server expected a `nonce` claim but the proof omitted it.
    #[error("DPoP proof missing 'nonce' claim")]
    MissingNonce,
    /// `nonce` claim present but does not match the
    /// server-supplied value.
    #[error("DPoP 'nonce' does not match server-supplied value")]
    NonceMismatch,
}

impl DpopHeader {
    /// Parse `(authorization_header_value, dpop_header_value)` into a
    /// [`DpopHeader`]. The `Authorization` header MUST be of the form
    /// `DPoP <access-token>` (space-separated). The `DPoP` header is
    /// the proof JWT verbatim.
    pub fn parse(authorization: &str, dpop: &str) -> Result<Self, DpopError> {
        let mut split = authorization.splitn(2, ' ');
        let scheme = split.next().ok_or(DpopError::MalformedHeader)?;
        if !scheme.eq_ignore_ascii_case("DPoP") {
            return Err(DpopError::MalformedHeader);
        }
        let token = split.next().ok_or(DpopError::MalformedHeader)?;
        if token.is_empty() || dpop.is_empty() {
            return Err(DpopError::MalformedHeader);
        }
        Ok(Self {
            access_token: token.to_string(),
            proof_jwt: dpop.to_string(),
        })
    }
}

/// Replay cache for DPoP `jti` values. A successful proof
/// verification reserves the `jti` for the configured TTL; a
/// duplicate `jti` within the window returns
/// [`DpopError::Replay`].
///
/// Sized to match the `seen_message_ids` cache in
/// [`crate::server`]: bounded by traffic in the window, swept on
/// every check.
pub struct DpopReplayCache {
    guard: std::sync::Arc<dyn crate::replay_store::ReplayGuard>,
    ttl: Duration,
}

impl DpopReplayCache {
    /// Build a cache with a custom TTL, backed by the default
    /// in-memory [`ReplayGuard`](crate::replay_store::ReplayGuard).
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            guard: std::sync::Arc::new(crate::replay_store::InMemoryReplayGuard::new()),
            ttl,
        }
    }

    /// Build a cache backed by a caller-supplied
    /// [`ReplayGuard`](crate::replay_store::ReplayGuard) — e.g. a shared
    /// Redis store so DPoP replay detection holds across a clustered
    /// deployment (see [`crate::replay_store`]).
    pub fn with_guard(
        guard: std::sync::Arc<dyn crate::replay_store::ReplayGuard>,
        ttl: Duration,
    ) -> Self {
        Self { guard, ttl }
    }

    /// Record `jti`, returning [`DpopError::Replay`] if it was already
    /// presented within the TTL window.
    pub fn record(&self, jti: &str) -> Result<(), DpopError> {
        if self.guard.check_and_record(jti, self.ttl) {
            Ok(())
        } else {
            Err(DpopError::Replay)
        }
    }
}

impl Default for DpopReplayCache {
    fn default() -> Self {
        // Match the AITP envelope replay window
        // (RFC-AITP-0001 §5.5): 5 minutes.
        Self::with_ttl(Duration::from_secs(300))
    }
}

/// Inputs to [`verify_dpop_proof_full`] — what the resource server
/// expects the proof to bind to and the policy knobs.
pub struct DpopVerifyContext<'a> {
    /// HTTP method of the request being authorized (e.g. `"POST"`).
    pub expected_method: &'a str,
    /// Full request URL **without the fragment**, normalized to
    /// match what a well-behaved client would put in `htu`.
    pub expected_url: &'a str,
    /// Access-token-bound JWK thumbprint (RFC 7638) the proof's
    /// embedded JWK must hash to.
    pub expected_jkt: &'a str,
    /// Access token bytes, when this proof is being verified at a
    /// resource server. When `Some`, the verifier requires the
    /// proof's `ath` claim to equal `base64url(sha256(token))`
    /// (RFC 9449 §4.1) — otherwise an attacker who exfiltrates an
    /// access token can mint their own DPoP proofs.
    /// Set to `None` only when verifying a proof at the
    /// authorization server (where the proof is presented without
    /// an access token).
    pub expected_access_token: Option<&'a [u8]>,
    /// `jti` replay cache. The verifier reserves the `jti` on
    /// success.
    pub replay_cache: &'a DpopReplayCache,
    /// Permitted absolute drift (seconds) between the proof's
    /// `iat` and the verifier's clock. RFC 9449 §4.3 leaves this
    /// to deployment policy; 60 seconds is a common default.
    pub iat_tolerance_secs: i64,
    /// Resource server's clock as Unix seconds.
    pub now_unix_secs: i64,
    /// Server-supplied nonce the proof MUST echo (RFC 9449 §8).
    /// `None` disables the check; `Some(value)` requires
    /// `proof.nonce == value`. Production deployments at high
    /// risk of replay use this to force every proof to be paired
    /// with a recent server-issued nonce.
    pub expected_nonce: Option<&'a str>,
}

/// Full DPoP proof verification (RFC 9449 §4.3).
///
/// Steps:
/// 1. Parse the proof's JWT header, extract `typ`, `alg`, and the
///    embedded `jwk`.
/// 2. Verify the signature using the JWK as the public key.
/// 3. Decode claims; check `htm`, `htu`, `iat`, and `jti` are
///    present.
/// 4. Confirm `htm` and `htu` match the request, `iat` is within
///    the tolerance window, and `jti` has not been seen.
/// 5. Compute the JWK's RFC 7638 thumbprint and compare against
///    `expected_jkt`.
///
/// On success the parsed [`DpopProof`] is returned and `jti` is
/// reserved in the replay cache.
pub fn verify_dpop_proof_full(
    header: &DpopHeader,
    ctx: &DpopVerifyContext<'_>,
) -> Result<DpopProof, DpopError> {
    let proof_jwt = header.proof_jwt.trim();

    // Step 1: split the JWT into header.payload.signature without
    // verifying yet — we need the embedded JWK before we can
    // verify.
    let parts: Vec<&str> = proof_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(DpopError::MalformedProof(
            "expected three dot-separated segments".into(),
        ));
    }
    let header_bytes = b64url_decode(parts[0])
        .map_err(|e| DpopError::MalformedProof(format!("header b64: {e}")))?;
    let header_json: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| DpopError::MalformedProof(format!("header json: {e}")))?;

    if header_json
        .get("typ")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        != "dpop+jwt"
    {
        return Err(DpopError::WrongJwtType);
    }
    let alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DpopError::MalformedProof("alg missing".into()))?;
    let jwk = header_json.get("jwk").ok_or(DpopError::MissingJwk)?.clone();

    // Step 2: build a DecodingKey from the embedded JWK and run
    // jsonwebtoken's full verifier against the proof.
    let decoding_key = jwk_to_decoding_key(&jwk, alg)?;
    let jwt_alg = match alg {
        "EdDSA" => jsonwebtoken::Algorithm::EdDSA,
        "ES256" => jsonwebtoken::Algorithm::ES256,
        "RS256" => jsonwebtoken::Algorithm::RS256,
        other => return Err(DpopError::UnsupportedAlgorithm(other.to_string())),
    };
    let mut validation = jsonwebtoken::Validation::new(jwt_alg);
    // RFC 9449 proofs do not carry `aud`; disable audience and
    // expiry validation — we enforce iat-window separately.
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let token =
        jsonwebtoken::decode::<DpopProof>(proof_jwt, &decoding_key, &validation).map_err(|e| {
            // Differentiate signature failure from claim parse failure
            // so callers can tell why a proof was refused.
            use jsonwebtoken::errors::ErrorKind::*;
            match e.kind() {
                InvalidSignature => DpopError::InvalidProofSignature,
                _ => DpopError::MalformedProof(format!("decode: {e}")),
            }
        })?;
    let proof = token.claims;

    // Step 3: bind to request.
    if !proof.htm.eq_ignore_ascii_case(ctx.expected_method) {
        return Err(DpopError::RequestBindingMismatch(format!(
            "htm = {}, expected {}",
            proof.htm, ctx.expected_method
        )));
    }
    if proof.htu != ctx.expected_url {
        return Err(DpopError::RequestBindingMismatch(format!(
            "htu = {}, expected {}",
            proof.htu, ctx.expected_url
        )));
    }
    let drift = (ctx.now_unix_secs - proof.iat).abs();
    if drift > ctx.iat_tolerance_secs {
        return Err(DpopError::IatOutOfWindow);
    }

    // Step 4: replay defense.
    if proof.jti.is_empty() {
        return Err(DpopError::MalformedProof("jti empty".into()));
    }
    ctx.replay_cache.record(&proof.jti)?;

    // Step 5: cnf.jkt thumbprint check.
    let actual_jkt = jwk_thumbprint(&jwk)?;
    if actual_jkt != ctx.expected_jkt {
        return Err(DpopError::ConfirmationMismatch);
    }

    // Step 6: ath binding (RFC 9449 §4.1). Required whenever a
    // proof accompanies an access token, optional on the
    // authorization-server flow. Skipping this check would let an
    // attacker who has stolen an access token forge proofs against
    // any URL.
    if let Some(token_bytes) = ctx.expected_access_token {
        let ath = match &proof.ath {
            Some(s) => s,
            None => return Err(DpopError::MissingAth),
        };
        let expected = b64url_encode(&Sha256::digest(token_bytes));
        if ath != &expected {
            return Err(DpopError::AthMismatch);
        }
    }

    // Step 7: server-supplied nonce check (RFC 9449 §8). When the
    // verifier expects a specific nonce, the proof must echo it
    // back. This binds proofs to a recent server-issued nonce so
    // an attacker can't replay a captured proof against a
    // different request.
    if let Some(expected_nonce) = ctx.expected_nonce {
        let nonce = match &proof.nonce {
            Some(n) => n,
            None => return Err(DpopError::MissingNonce),
        };
        if nonce != expected_nonce {
            return Err(DpopError::NonceMismatch);
        }
    }

    Ok(proof)
}

/// Compatibility shim that preserves the rc.1 four-argument
/// signature. The full verifier lives at
/// [`verify_dpop_proof_full`].
///
/// **Deprecated.** This shim is unsafe in two ways:
///
/// - It builds a fresh per-call [`DpopReplayCache`], so replay
///   defense is effectively disabled — every proof is "new" to
///   a freshly constructed cache.
/// - It cannot verify the `ath` access-token-binding claim,
///   because the access-token bytes are not in the argument
///   list. RFC 9449 §4.1 requires this binding at every
///   resource-server check.
///
/// Production callers MUST use [`verify_dpop_proof_full`] with a
/// long-lived cache and [`DpopVerifyContext::expected_access_token`]
/// populated.
#[deprecated(
    since = "0.1.0-rc.2",
    note = "Use verify_dpop_proof_full: the 4-arg shim disables replay defense and cannot verify the ath access-token binding."
)]
pub fn verify_dpop_proof(
    header: &DpopHeader,
    expected_method: &str,
    expected_url: &str,
    expected_jkt: &str,
) -> Result<DpopProof, DpopError> {
    let cache = DpopReplayCache::default();
    let ctx = DpopVerifyContext {
        expected_method,
        expected_url,
        expected_jkt,
        expected_access_token: None,
        expected_nonce: None,
        replay_cache: &cache,
        iat_tolerance_secs: 60,
        now_unix_secs: chrono::Utc::now().timestamp(),
    };
    verify_dpop_proof_full(header, &ctx)
}

/// Build a `jsonwebtoken::DecodingKey` from a JWK value.
fn jwk_to_decoding_key(
    jwk: &serde_json::Value,
    alg: &str,
) -> Result<jsonwebtoken::DecodingKey, DpopError> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DpopError::MalformedProof("jwk.kty missing".into()))?;
    match (kty, alg) {
        ("OKP", "EdDSA") => {
            let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
            if crv != "Ed25519" {
                return Err(DpopError::UnsupportedAlgorithm(format!("OKP:{crv}")));
            }
            let x_b64 = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| DpopError::MalformedProof("jwk.x missing".into()))?;
            let x_bytes = b64url_decode(x_b64)
                .map_err(|e| DpopError::MalformedProof(format!("jwk.x b64: {e}")))?;
            Ok(jsonwebtoken::DecodingKey::from_ed_der(&x_bytes))
        }
        ("EC", "ES256") => {
            let x = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| DpopError::MalformedProof("jwk.x missing".into()))?;
            let y = jwk
                .get("y")
                .and_then(|v| v.as_str())
                .ok_or_else(|| DpopError::MalformedProof("jwk.y missing".into()))?;
            jsonwebtoken::DecodingKey::from_ec_components(x, y)
                .map_err(|e| DpopError::MalformedProof(format!("ec components: {e}")))
        }
        ("RSA", "RS256") => {
            let n = jwk
                .get("n")
                .and_then(|v| v.as_str())
                .ok_or_else(|| DpopError::MalformedProof("jwk.n missing".into()))?;
            let e = jwk
                .get("e")
                .and_then(|v| v.as_str())
                .ok_or_else(|| DpopError::MalformedProof("jwk.e missing".into()))?;
            // Reject weak RSA keys (RFC-AITP-0009 §4): a DPoP proof
            // carrying a <2048-bit RSA public key must not be honored.
            if !crate::common::rsa_modulus_bits_ok(n) {
                return Err(DpopError::UnsupportedAlgorithm(format!(
                    "RSA modulus below the {}-bit minimum",
                    crate::common::MIN_RSA_MODULUS_BITS
                )));
            }
            jsonwebtoken::DecodingKey::from_rsa_components(n, e)
                .map_err(|e| DpopError::MalformedProof(format!("rsa components: {e}")))
        }
        (kty, alg) => Err(DpopError::UnsupportedAlgorithm(format!("{kty}:{alg}"))),
    }
}

/// Compute the RFC 7638 JWK thumbprint of a JWK value, returning
/// the unpadded base64url SHA-256 digest. Per §3.2 the input is
/// the canonical JSON of only the required members for the
/// `kty`-specific schema, with members ordered lexicographically
/// by Unicode code point of the key.
///
/// Uses `serde_json::to_string` with a `BTreeMap` (the default
/// `serde_json::Map` representation when the `preserve_order`
/// feature is off) so values are JSON-escaped properly even if a
/// JWK member contains a `"` or backslash. Keys are inserted in
/// lexicographic order to match RFC 7638's canonical form.
fn jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, DpopError> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DpopError::MalformedProof("jwk.kty missing".into()))?;
    let mut members: std::collections::BTreeMap<&'static str, &str> =
        std::collections::BTreeMap::new();
    match kty {
        "OKP" => {
            members.insert("crv", jwk.get("crv").and_then(|v| v.as_str()).unwrap_or(""));
            members.insert("kty", "OKP");
            members.insert("x", jwk.get("x").and_then(|v| v.as_str()).unwrap_or(""));
        }
        "EC" => {
            members.insert("crv", jwk.get("crv").and_then(|v| v.as_str()).unwrap_or(""));
            members.insert("kty", "EC");
            members.insert("x", jwk.get("x").and_then(|v| v.as_str()).unwrap_or(""));
            members.insert("y", jwk.get("y").and_then(|v| v.as_str()).unwrap_or(""));
        }
        "RSA" => {
            members.insert("e", jwk.get("e").and_then(|v| v.as_str()).unwrap_or(""));
            members.insert("kty", "RSA");
            members.insert("n", jwk.get("n").and_then(|v| v.as_str()).unwrap_or(""));
        }
        other => {
            return Err(DpopError::UnsupportedAlgorithm(format!(
                "jwk thumbprint: kty {other}"
            )))
        }
    }
    let canonical_json = serde_json::to_string(&members)
        .map_err(|e| DpopError::MalformedProof(format!("thumbprint serialize: {e}")))?;
    let digest = Sha256::digest(canonical_json.as_bytes());
    Ok(b64url_encode(&digest))
}

/// Unpadded base64url decode (RFC 7515 §2). Delegated to
/// `aitp_core::base64url` which already enforces strict
/// no-padding decoding used elsewhere in the workspace.
fn b64url_decode(input: &str) -> Result<Vec<u8>, String> {
    aitp_core::base64url::decode_strict(input).map_err(|e| e.to_string())
}

fn b64url_encode(input: &[u8]) -> String {
    aitp_core::base64url::encode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dpop_authorization_header() {
        let h = DpopHeader::parse("DPoP eyJhbGc.aBc.dEf", "eyJhbGc.proofBody.proofSig").unwrap();
        assert_eq!(h.access_token, "eyJhbGc.aBc.dEf");
        assert_eq!(h.proof_jwt, "eyJhbGc.proofBody.proofSig");
    }

    #[test]
    fn rejects_wrong_scheme() {
        let err = DpopHeader::parse("Bearer eyJ", "eyJ").unwrap_err();
        assert!(matches!(err, DpopError::MalformedHeader));
    }

    #[test]
    fn rejects_empty_proof() {
        let err = DpopHeader::parse("DPoP eyJ", "").unwrap_err();
        assert!(matches!(err, DpopError::MalformedHeader));
    }

    #[test]
    fn malformed_proof_rejected() {
        let h = DpopHeader::parse("DPoP foo", "not.a.jwt.with.too.many.dots").unwrap();
        let cache = DpopReplayCache::default();
        let err = verify_dpop_proof_full(
            &h,
            &DpopVerifyContext {
                expected_method: "POST",
                expected_url: "https://x",
                expected_jkt: "jkt",
                expected_access_token: None,
                expected_nonce: None,
                replay_cache: &cache,
                iat_tolerance_secs: 60,
                now_unix_secs: 0,
            },
        )
        .unwrap_err();
        assert!(matches!(err, DpopError::MalformedProof(_)));
    }

    #[test]
    fn replay_cache_dedups() {
        let cache = DpopReplayCache::with_ttl(std::time::Duration::from_secs(60));
        cache.record("first").unwrap();
        let err = cache.record("first").unwrap_err();
        assert!(matches!(err, DpopError::Replay));
        cache.record("second").unwrap();
    }

    #[test]
    fn replay_cache_expires() {
        let cache = DpopReplayCache::with_ttl(std::time::Duration::from_millis(10));
        cache.record("ephemeral").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        // Same JTI is now allowed because the prior entry expired.
        cache.record("ephemeral").unwrap();
    }

    #[test]
    fn jwk_thumbprint_okp_matches_rfc_example() {
        // RFC 7638 doesn't ship an OKP example, but the
        // canonicalization is byte-for-byte the same as for any
        // single-pubkey JWK. Verify our implementation produces
        // a consistent string for a fixed input.
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        });
        let t = jwk_thumbprint(&jwk).unwrap();
        // Expected: SHA-256 over the canonical
        // {"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
        // — pinned for regression.
        assert_eq!(t, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }

    #[test]
    fn rsa_jwk_below_2048_is_rejected() {
        use aitp_core::base64url::encode;
        // 1024-bit modulus (128 bytes, top bit set): a valid RSA key
        // shape but below the security floor.
        let mut weak_n = vec![0xffu8; 128];
        weak_n[0] = 0x80;
        let weak = serde_json::json!({
            "kty": "RSA",
            "n": encode(&weak_n),
            "e": "AQAB",
        });
        // Note: `DecodingKey` (the Ok type) has no `Debug`, so match
        // on the result directly rather than `unwrap_err()`.
        match jwk_to_decoding_key(&weak, "RS256") {
            Err(DpopError::UnsupportedAlgorithm(m)) => {
                assert!(m.contains("2048"), "expected weak-RSA rejection, got: {m}");
            }
            Err(other) => panic!("expected UnsupportedAlgorithm, got: {other:?}"),
            Ok(_) => panic!("weak 1024-bit RSA key must be rejected"),
        }

        // 2048-bit modulus clears the floor (parsing proceeds past the
        // size gate; from_rsa_components then does its own validation).
        let mut ok_n = vec![0xffu8; 256];
        ok_n[0] = 0x80;
        let ok = serde_json::json!({
            "kty": "RSA",
            "n": encode(&ok_n),
            "e": "AQAB",
        });
        // Must NOT be the size-floor error (it may still fail deeper
        // parsing, but never on the modulus-size gate).
        if let Err(DpopError::UnsupportedAlgorithm(m)) = jwk_to_decoding_key(&ok, "RS256") {
            assert!(
                !m.contains("2048"),
                "2048-bit modulus must clear the size floor, got: {m}"
            );
        }
    }

    #[test]
    fn full_verify_round_trip() {
        // End-to-end: mint a real DPoP proof with an Ed25519 key,
        // then run the verifier and confirm it accepts.
        use aitp_core::base64url;
        use ed25519_dalek::Signer;

        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pk = signing.verifying_key();
        let pk_b64 = base64url::encode(&pk.to_bytes());
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": pk_b64,
        });
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "EdDSA",
            "jwk": jwk.clone(),
        });
        let claims = serde_json::json!({
            "jti": "test-jti-001",
            "htm": "POST",
            "htu": "https://api.example.com/resource",
            "iat": 1_700_000_000_i64,
        });
        let header_b64 = base64url::encode(&serde_json::to_vec(&header).unwrap());
        let claims_b64 = base64url::encode(&serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header_b64}.{claims_b64}");
        let sig = signing.sign(signing_input.as_bytes());
        let sig_b64 = base64url::encode(&sig.to_bytes());
        let proof_jwt = format!("{signing_input}.{sig_b64}");

        let cache = DpopReplayCache::default();
        let expected_jkt = jwk_thumbprint(&jwk).unwrap();
        let h = DpopHeader {
            access_token: "ignored".into(),
            proof_jwt,
        };
        let proof = verify_dpop_proof_full(
            &h,
            &DpopVerifyContext {
                expected_method: "POST",
                expected_url: "https://api.example.com/resource",
                expected_jkt: &expected_jkt,
                expected_access_token: None,
                expected_nonce: None,
                replay_cache: &cache,
                iat_tolerance_secs: i64::MAX / 2,
                now_unix_secs: 1_700_000_000,
            },
        )
        .unwrap();
        assert_eq!(proof.jti, "test-jti-001");
        assert_eq!(proof.htm, "POST");

        // Replay defense: re-running the same proof MUST fail.
        let err = verify_dpop_proof_full(
            &h,
            &DpopVerifyContext {
                expected_method: "POST",
                expected_url: "https://api.example.com/resource",
                expected_jkt: &expected_jkt,
                expected_access_token: None,
                expected_nonce: None,
                replay_cache: &cache,
                iat_tolerance_secs: i64::MAX / 2,
                now_unix_secs: 1_700_000_000,
            },
        )
        .unwrap_err();
        assert!(matches!(err, DpopError::Replay));
    }

    #[test]
    fn full_verify_rejects_wrong_method() {
        use aitp_core::base64url;
        use ed25519_dalek::Signer;

        let signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let pk = signing.verifying_key();
        let pk_b64 = base64url::encode(&pk.to_bytes());
        let jwk = serde_json::json!({"kty":"OKP","crv":"Ed25519","x":pk_b64});
        let header = serde_json::json!({"typ":"dpop+jwt","alg":"EdDSA","jwk": jwk.clone()});
        let claims = serde_json::json!({
            "jti": "wrong-method-test",
            "htm": "GET",
            "htu": "https://api.example.com/resource",
            "iat": 1_700_000_000_i64,
        });
        let header_b64 = base64url::encode(&serde_json::to_vec(&header).unwrap());
        let claims_b64 = base64url::encode(&serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header_b64}.{claims_b64}");
        let sig = signing.sign(signing_input.as_bytes());
        let sig_b64 = base64url::encode(&sig.to_bytes());
        let proof_jwt = format!("{signing_input}.{sig_b64}");

        let cache = DpopReplayCache::default();
        let expected_jkt = jwk_thumbprint(&jwk).unwrap();
        let h = DpopHeader {
            access_token: "x".into(),
            proof_jwt,
        };
        let err = verify_dpop_proof_full(
            &h,
            &DpopVerifyContext {
                expected_method: "POST", // proof says GET
                expected_url: "https://api.example.com/resource",
                expected_jkt: &expected_jkt,
                expected_access_token: None,
                expected_nonce: None,
                replay_cache: &cache,
                iat_tolerance_secs: i64::MAX / 2,
                now_unix_secs: 1_700_000_000,
            },
        )
        .unwrap_err();
        assert!(matches!(err, DpopError::RequestBindingMismatch(_)));
    }

    /// Mint a proof JWT bound to a specific access token, optionally
    /// with the `ath` claim populated. Returns the JWT string.
    fn mint_proof_with_ath(
        seed: u8,
        method: &str,
        url: &str,
        jti: &str,
        iat: i64,
        ath: Option<&str>,
    ) -> (String, String) {
        use aitp_core::base64url;
        use ed25519_dalek::Signer;

        let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let pk = signing.verifying_key();
        let pk_b64 = base64url::encode(&pk.to_bytes());
        let jwk = serde_json::json!({"kty":"OKP","crv":"Ed25519","x":pk_b64});
        let header = serde_json::json!({"typ":"dpop+jwt","alg":"EdDSA","jwk": jwk.clone()});
        let mut claims = serde_json::json!({
            "jti": jti,
            "htm": method,
            "htu": url,
            "iat": iat,
        });
        if let Some(a) = ath {
            claims["ath"] = serde_json::Value::String(a.into());
        }
        let header_b64 = base64url::encode(&serde_json::to_vec(&header).unwrap());
        let claims_b64 = base64url::encode(&serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header_b64}.{claims_b64}");
        let sig = signing.sign(signing_input.as_bytes());
        let sig_b64 = base64url::encode(&sig.to_bytes());
        let proof = format!("{signing_input}.{sig_b64}");
        let jkt = jwk_thumbprint(&jwk).unwrap();
        (proof, jkt)
    }

    #[test]
    fn full_verify_with_correct_ath() {
        // Compute the expected ath = base64url(sha256(token)) and
        // mint a proof carrying it. Verifier should accept.
        let token = b"opaque-access-token-bytes";
        let expected_ath = b64url_encode(&Sha256::digest(token));
        let (proof_jwt, jkt) = mint_proof_with_ath(
            9,
            "POST",
            "https://api.example.com/resource",
            "ath-good",
            1_700_000_000,
            Some(&expected_ath),
        );
        let cache = DpopReplayCache::default();
        let header = DpopHeader {
            access_token: String::from_utf8(token.to_vec()).unwrap(),
            proof_jwt,
        };
        verify_dpop_proof_full(
            &header,
            &DpopVerifyContext {
                expected_method: "POST",
                expected_url: "https://api.example.com/resource",
                expected_jkt: &jkt,
                expected_access_token: Some(token),
                expected_nonce: None,
                replay_cache: &cache,
                iat_tolerance_secs: i64::MAX / 2,
                now_unix_secs: 1_700_000_000,
            },
        )
        .unwrap();
    }

    #[test]
    fn full_verify_rejects_missing_ath() {
        // Resource server flow but proof has no `ath` — must reject.
        let (proof_jwt, jkt) = mint_proof_with_ath(
            10,
            "GET",
            "https://api.example.com/r",
            "ath-missing",
            1_700_000_000,
            None,
        );
        let cache = DpopReplayCache::default();
        let header = DpopHeader {
            access_token: "tok".into(),
            proof_jwt,
        };
        let err = verify_dpop_proof_full(
            &header,
            &DpopVerifyContext {
                expected_method: "GET",
                expected_url: "https://api.example.com/r",
                expected_jkt: &jkt,
                expected_access_token: Some(b"tok"),
                expected_nonce: None,
                replay_cache: &cache,
                iat_tolerance_secs: i64::MAX / 2,
                now_unix_secs: 1_700_000_000,
            },
        )
        .unwrap_err();
        assert!(matches!(err, DpopError::MissingAth));
    }

    #[test]
    fn full_verify_rejects_wrong_ath() {
        // Proof has an `ath` but for a *different* token — the
        // exact attack the binding is supposed to defeat.
        let real_token = b"the-real-token";
        let other_ath = b64url_encode(&Sha256::digest(b"wrong-token"));
        let (proof_jwt, jkt) = mint_proof_with_ath(
            11,
            "POST",
            "https://api.example.com/r",
            "ath-wrong",
            1_700_000_000,
            Some(&other_ath),
        );
        let cache = DpopReplayCache::default();
        let header = DpopHeader {
            access_token: "tok".into(),
            proof_jwt,
        };
        let err = verify_dpop_proof_full(
            &header,
            &DpopVerifyContext {
                expected_method: "POST",
                expected_url: "https://api.example.com/r",
                expected_jkt: &jkt,
                expected_access_token: Some(real_token),
                expected_nonce: None,
                replay_cache: &cache,
                iat_tolerance_secs: i64::MAX / 2,
                now_unix_secs: 1_700_000_000,
            },
        )
        .unwrap_err();
        assert!(matches!(err, DpopError::AthMismatch));
    }
}
