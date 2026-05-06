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
//!     replay_cache: &cache,
//!     iat_tolerance_secs: 60,
//!     now_unix_secs: now,
//! })?;
//! // proof.jti is now reserved in the cache for the configured TTL.
//! ```

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

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
#[derive(Debug, thiserror::Error)]
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
    seen: Mutex<HashMap<String, Instant>>,
    ttl: Duration,
}

impl DpopReplayCache {
    /// Build a cache with a custom TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Insert `jti`, returning [`DpopError::Replay`] if it's
    /// already present and unexpired. Sweeps expired entries
    /// before the check so the map is bounded by recent traffic.
    pub fn record(&self, jti: &str) -> Result<(), DpopError> {
        let now = Instant::now();
        let mut seen = self.seen.lock();
        seen.retain(|_, ts| now.duration_since(*ts) < self.ttl);
        if seen.insert(jti.to_string(), now).is_some() {
            return Err(DpopError::Replay);
        }
        Ok(())
    }

    /// Number of unexpired entries currently held. Test-only.
    #[doc(hidden)]
    pub fn len(&self) -> usize {
        let now = Instant::now();
        let seen = self.seen.lock();
        seen.iter()
            .filter(|(_, ts)| now.duration_since(**ts) < self.ttl)
            .count()
    }

    #[doc(hidden)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
    /// `jti` replay cache. The verifier reserves the `jti` on
    /// success.
    pub replay_cache: &'a DpopReplayCache,
    /// Permitted absolute drift (seconds) between the proof's
    /// `iat` and the verifier's clock. RFC 9449 §4.3 leaves this
    /// to deployment policy; 60 seconds is a common default.
    pub iat_tolerance_secs: i64,
    /// Resource server's clock as Unix seconds.
    pub now_unix_secs: i64,
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

    Ok(proof)
}

/// Compatibility shim: the original stub took five positional
/// arguments and returned `DpopError::NotImplemented`. The full
/// verifier now lives at [`verify_dpop_proof_full`]; this wrapper
/// preserves the old signature for any caller still using it,
/// constructing a fresh per-call replay cache and a default
/// 60-second iat tolerance.
///
/// **Avoid in production**: the per-call cache means replay
/// defense is effectively disabled across requests. Use
/// [`verify_dpop_proof_full`] with a long-lived [`DpopReplayCache`].
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
            jsonwebtoken::DecodingKey::from_rsa_components(n, e)
                .map_err(|e| DpopError::MalformedProof(format!("rsa components: {e}")))
        }
        (kty, alg) => Err(DpopError::UnsupportedAlgorithm(format!("{kty}:{alg}"))),
    }
}

/// Compute the RFC 7638 JWK thumbprint of a JWK value, returning
/// the unpadded base64url SHA-256 digest. Per §3.2 the input is
/// the canonical JSON of only the required members for the
/// `kty`-specific schema.
fn jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, DpopError> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DpopError::MalformedProof("jwk.kty missing".into()))?;
    let canonical_json = match kty {
        "OKP" => {
            let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
            let x = jwk.get("x").and_then(|v| v.as_str()).unwrap_or("");
            // Members in lexicographic order per RFC 7638 §3.2.
            format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
        }
        "EC" => {
            let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
            let x = jwk.get("x").and_then(|v| v.as_str()).unwrap_or("");
            let y = jwk.get("y").and_then(|v| v.as_str()).unwrap_or("");
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        "RSA" => {
            let e = jwk.get("e").and_then(|v| v.as_str()).unwrap_or("");
            let n = jwk.get("n").and_then(|v| v.as_str()).unwrap_or("");
            format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
        }
        other => {
            return Err(DpopError::UnsupportedAlgorithm(format!(
                "jwk thumbprint: kty {other}"
            )))
        }
    };
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
        assert_eq!(cache.len(), 2);
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
                replay_cache: &cache,
                iat_tolerance_secs: i64::MAX / 2,
                now_unix_secs: 1_700_000_000,
            },
        )
        .unwrap_err();
        assert!(matches!(err, DpopError::RequestBindingMismatch(_)));
    }
}
