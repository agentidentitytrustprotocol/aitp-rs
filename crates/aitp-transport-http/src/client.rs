//! HTTP client primitives: Manifest fetcher + JWKS resolver.

use aitp_core::{Aid, Timestamp};
use aitp_manifest::{verify_manifest, Manifest, ManifestEnvelope, VerifyManifestContext};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use url::Url;

/// Errors from `ManifestFetcher::fetch`.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// URL was not HTTPS.
    #[error("manifest URL must be HTTPS")]
    InsecureUrl,
    /// reqwest network error.
    #[error("network error: {0}")]
    Network(String),
    /// Response body could not be parsed.
    #[error("malformed json: {0}")]
    MalformedJson(String),
    /// Response did not match `{"manifest": {...}}`.
    #[error("malformed manifest wrapper")]
    MalformedWrapper,
    /// Manifest verification failed.
    #[error("manifest verification failed: {0}")]
    VerificationFailed(#[from] aitp_manifest::ManifestError),
    /// Network request timed out.
    #[error("timeout fetching manifest")]
    Timeout,
    /// Server replied with non-2xx status.
    #[error("upstream returned non-2xx status: {0}")]
    UpstreamStatus(u16),
    /// `Content-Type` header was missing or not `application/json`.
    #[error("upstream returned wrong Content-Type: `{0}`")]
    WrongContentType(String),
    /// Response body exceeded the per-fetch size limit.
    #[error("response exceeded {limit} bytes")]
    OversizedResponse {
        /// Configured limit, bytes.
        limit: usize,
    },
}

/// Maximum acceptable response body size for `/.well-known/aitp-manifest`.
/// 256 KB is generous for a Manifest (typically <10 KB) while rejecting
/// accidental megabyte-sized responses.
pub const DEFAULT_MAX_MANIFEST_BYTES: usize = 256 * 1024;

/// Cache entry — keyed on `Aid`, holding the parsed Manifest plus its
/// own published/expires window. We honor `expires_at` on lookup
/// (RFC-AITP-0003 §4.2) so the cache never serves a Manifest the issuer
/// has marked stale, and we honor `published_at` for inline-replace
/// ordering (newer publish wins).
struct CacheEntry {
    manifest: Manifest,
    published_at: Timestamp,
    expires_at: Timestamp,
}

/// HTTP client that fetches and verifies peer Agent Manifests.
pub struct ManifestFetcher {
    client: reqwest::Client,
    cache: Mutex<HashMap<Aid, CacheEntry>>,
    /// Per-request timeout (default 10s).
    timeout: Duration,
    /// Maximum response body size, bytes.
    max_bytes: usize,
}

impl ManifestFetcher {
    /// Build a fetcher with default reqwest settings.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client builds"),
            cache: Mutex::new(HashMap::new()),
            timeout: Duration::from_secs(10),
            max_bytes: DEFAULT_MAX_MANIFEST_BYTES,
        }
    }

    /// Override the per-request timeout (e.g. for tests).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the per-fetch max body size (default
    /// [`DEFAULT_MAX_MANIFEST_BYTES`]).
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Fetch and verify a Manifest from a peer's well-known endpoint.
    ///
    /// `peer_origin` is something like `https://agent-b.example.com`. The
    /// fetcher GETs `peer_origin.join("/.well-known/aitp-manifest")`,
    /// parses `{"manifest": {...}}`, verifies, caches, and returns.
    pub async fn fetch(&self, peer_origin: &Url) -> Result<Manifest, FetchError> {
        if peer_origin.scheme() != "https" {
            // Allow http://localhost for local dev (demo).
            if !(peer_origin.scheme() == "http"
                && (peer_origin.host_str() == Some("localhost")
                    || peer_origin.host_str() == Some("127.0.0.1")))
            {
                return Err(FetchError::InsecureUrl);
            }
        }
        let url = peer_origin
            .join("/.well-known/aitp-manifest")
            .map_err(|e| FetchError::Network(e.to_string()))?;
        let resp = self
            .client
            .get(url)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    FetchError::Timeout
                } else {
                    FetchError::Network(e.to_string())
                }
            })?;
        let status = resp.status();
        if !status.is_success() {
            return Err(FetchError::UpstreamStatus(status.as_u16()));
        }
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !content_type.starts_with("application/json") {
            return Err(FetchError::WrongContentType(content_type));
        }
        // Drain the response with a hard cap. `bytes()` would buffer the
        // whole body; we want to bail early on oversize.
        let max_bytes = self.max_bytes;
        let mut body: Vec<u8> = Vec::with_capacity(8192);
        let mut stream = resp;
        while let Some(chunk) = stream
            .chunk()
            .await
            .map_err(|e| FetchError::Network(e.to_string()))?
        {
            if body.len() + chunk.len() > max_bytes {
                return Err(FetchError::OversizedResponse { limit: max_bytes });
            }
            body.extend_from_slice(&chunk);
        }
        let env: ManifestEnvelope =
            serde_json::from_slice(&body).map_err(|e| FetchError::MalformedJson(e.to_string()))?;
        verify_manifest(&env.manifest, &VerifyManifestContext::now())?;
        let aid = env.manifest.aid.clone();
        self.insert_cache(aid, env.manifest.clone());
        Ok(env.manifest)
    }

    /// Look up a previously-cached Manifest by AID. Returns `None` when
    /// the cached entry's `expires_at` has passed (RFC-AITP-0003 §4.2):
    /// stale Manifests are not served.
    pub fn cached(&self, aid: &Aid) -> Option<Manifest> {
        let now = Timestamp::now();
        let cache = self.cache.lock().unwrap();
        cache
            .get(aid)
            .filter(|e| e.expires_at.0 > now.0)
            .map(|e| e.manifest.clone())
    }

    /// Replace a cached Manifest with one carried inline in a handshake
    /// payload — but only if the inline copy's `published_at` is
    /// strictly newer than what's already cached. This prevents an
    /// attacker who replays an older signed Manifest from rolling back
    /// the cached view of a peer's policy.
    ///
    /// Returns `true` if the cache was updated.
    pub fn maybe_replace_inline(&self, manifest: Manifest) -> bool {
        let aid = manifest.aid.clone();
        let mut cache = self.cache.lock().unwrap();
        let current_published = cache.get(&aid).map(|e| e.published_at);
        match current_published {
            Some(existing) if manifest.published_at.0 <= existing.0 => false,
            _ => {
                cache.insert(
                    aid,
                    CacheEntry {
                        published_at: manifest.published_at,
                        expires_at: manifest.expires_at,
                        manifest,
                    },
                );
                true
            }
        }
    }

    fn insert_cache(&self, aid: Aid, manifest: Manifest) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(
            aid,
            CacheEntry {
                published_at: manifest.published_at,
                expires_at: manifest.expires_at,
                manifest,
            },
        );
    }
}

impl Default for ManifestFetcher {
    fn default() -> Self {
        Self::new()
    }
}

// ── JWKS ───────────────────────────────────────────────────────────────

/// Errors from `JwksFetcher::resolve`.
#[derive(Debug, thiserror::Error)]
pub enum JwksFetcherError {
    /// URL was not HTTPS.
    #[error("issuer URL must be HTTPS")]
    InsecureUrl,
    /// Network error.
    #[error("network error: {0}")]
    Network(String),
    /// Response body could not be parsed.
    #[error("malformed JSON: {0}")]
    MalformedJson(String),
    /// JWK is unsupported (e.g. `kty` other than `OKP`/`RSA`).
    #[error("unsupported JWK: {0}")]
    UnsupportedJwk(String),
}

/// HTTP client that resolves an OIDC issuer to its JWKS.
///
/// Hardened per RFC-AITP-0007 §2 / Phase 9.4:
/// - HTTPS-only for both discovery and `jwks_uri`. HTTP and HTTP-bearing
///   redirects are rejected outright.
/// - Configurable per-request timeout (default 10 s).
/// - Non-2xx responses produce a structured error rather than a JSON
///   parse failure.
/// - On OIDC discovery failure, falls back to AITP's native
///   `/.well-known/aitp-keys` endpoint (RFC-AITP-0007 §2.3).
pub struct JwksFetcher {
    client: reqwest::Client,
}

impl JwksFetcher {
    /// Build a JWKS fetcher with the default 10s per-request timeout.
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(10))
    }

    /// Build a JWKS fetcher with a custom timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            // `redirect::Policy::none()` rejects ALL redirects, which
            // includes the HTTP-fallback class an attacker could try
            // to use to downgrade a trusted JWKS endpoint. If we ever
            // need redirects, replace with a custom policy that
            // refuses any non-https Location header.
            client: reqwest::Client::builder()
                .timeout(timeout)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client builds"),
        }
    }

    /// Resolve `issuer/.well-known/openid-configuration`, then its
    /// `jwks_uri`, returning every parseable JWK. On any OIDC discovery
    /// failure, falls back to AITP's `<issuer>/.well-known/aitp-keys`.
    pub async fn resolve(
        &self,
        issuer: &Url,
    ) -> Result<Vec<aitp_handshake::JwkPublicKey>, JwksFetcherError> {
        if issuer.scheme() != "https" {
            return Err(JwksFetcherError::InsecureUrl);
        }
        match self.resolve_via_oidc_discovery(issuer).await {
            Ok(keys) => Ok(keys),
            Err(oidc_err) => {
                // Fall back to AITP-native discovery. If that also
                // fails, surface the original OIDC error since callers
                // will more likely recognize it.
                match self.resolve_via_aitp_keys(issuer).await {
                    Ok(keys) => Ok(keys),
                    Err(_) => Err(oidc_err),
                }
            }
        }
    }

    async fn resolve_via_oidc_discovery(
        &self,
        issuer: &Url,
    ) -> Result<Vec<aitp_handshake::JwkPublicKey>, JwksFetcherError> {
        let discovery_url = issuer
            .join("/.well-known/openid-configuration")
            .map_err(|e| JwksFetcherError::Network(e.to_string()))?;
        let discovery: serde_json::Value = self.fetch_https_json(&discovery_url).await?;
        let jwks_uri_str = discovery
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JwksFetcherError::MalformedJson("missing jwks_uri".into()))?;
        let jwks_url = Url::parse(jwks_uri_str)
            .map_err(|e| JwksFetcherError::Network(format!("malformed jwks_uri: {e}")))?;
        if jwks_url.scheme() != "https" {
            return Err(JwksFetcherError::InsecureUrl);
        }
        let jwks: serde_json::Value = self.fetch_https_json(&jwks_url).await?;
        parse_jwks(&jwks)
    }

    async fn resolve_via_aitp_keys(
        &self,
        issuer: &Url,
    ) -> Result<Vec<aitp_handshake::JwkPublicKey>, JwksFetcherError> {
        let url = issuer
            .join("/.well-known/aitp-keys")
            .map_err(|e| JwksFetcherError::Network(e.to_string()))?;
        let body: serde_json::Value = self.fetch_https_json(&url).await?;
        parse_jwks(&body)
    }

    /// Fetch a URL, requiring https://, treating non-2xx as an error,
    /// and parsing the body as JSON. Centralizes the network-side
    /// safety properties so callers don't accidentally drop one.
    async fn fetch_https_json(&self, url: &Url) -> Result<serde_json::Value, JwksFetcherError> {
        if url.scheme() != "https" {
            return Err(JwksFetcherError::InsecureUrl);
        }
        let resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| JwksFetcherError::Network(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(JwksFetcherError::Network(format!(
                "non-2xx response from {url}: {status}"
            )));
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| JwksFetcherError::MalformedJson(e.to_string()))
    }
}

impl Default for JwksFetcher {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_jwks(
    jwks: &serde_json::Value,
) -> Result<Vec<aitp_handshake::JwkPublicKey>, JwksFetcherError> {
    let keys = jwks
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| JwksFetcherError::MalformedJson("missing keys array".into()))?;
    let mut out = Vec::new();
    for jwk in keys {
        let kid = jwk.get("kid").and_then(|v| v.as_str()).map(String::from);
        let kty = jwk
            .get("kty")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JwksFetcherError::MalformedJson("jwk missing kty".into()))?;
        match kty {
            "OKP" => {
                let x = jwk
                    .get("x")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| JwksFetcherError::MalformedJson("OKP jwk missing x".into()))?;
                let bytes = aitp_core::base64url::decode_strict(x)
                    .map_err(|e| JwksFetcherError::UnsupportedJwk(format!("OKP x: {e}")))?;
                if bytes.len() != 32 {
                    return Err(JwksFetcherError::UnsupportedJwk(
                        "OKP x must decode to 32 bytes".into(),
                    ));
                }
                out.push(aitp_handshake::JwkPublicKey {
                    kid,
                    alg: jsonwebtoken::Algorithm::EdDSA,
                    // jsonwebtoken's `from_ed_der` wants the raw 32-byte
                    // pubkey, not SPKI DER (the helper name notwithstanding).
                    key: jsonwebtoken::DecodingKey::from_ed_der(&bytes),
                });
            }
            "RSA" => {
                let n = jwk
                    .get("n")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| JwksFetcherError::MalformedJson("RSA jwk missing n".into()))?;
                let e = jwk
                    .get("e")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| JwksFetcherError::MalformedJson("RSA jwk missing e".into()))?;
                out.push(aitp_handshake::JwkPublicKey {
                    kid,
                    alg: jsonwebtoken::Algorithm::RS256,
                    key: jsonwebtoken::DecodingKey::from_rsa_components(n, e)
                        .map_err(|err| JwksFetcherError::UnsupportedJwk(err.to_string()))?,
                });
            }
            other => {
                return Err(JwksFetcherError::UnsupportedJwk(format!("kty={other}")));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod cache_tests {
    //! P11 — Manifest cache correctness (RFC-AITP-0003 §4.2).
    //!
    //! These tests exercise [`ManifestFetcher`]'s cache surface in
    //! isolation (no real HTTP). They cover the four cases the unified
    //! plan calls out: fresh hit, expired miss, newer-inline replace,
    //! older-inline-no-replace.

    use super::*;
    use aitp_crypto::AitpSigningKey;
    use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};

    fn build_manifest(published_at: Timestamp, expires_at: Timestamp) -> Manifest {
        let key = AitpSigningKey::generate();
        let pubkey_b64 = aitp_core::base64url::encode(&key.verifying_key().to_bytes());
        let mut m = ManifestBuilder::new(&key)
            .handshake_endpoint("https://peer.example.com/aitp/handshake".parse().unwrap())
            .identity_hint(IdentityHint {
                kind: IdentityHintKind::PinnedKey,
                subject: "peer".into(),
                issuer: None,
                public_key: Some(pubkey_b64),
            })
            .offer("test.action")
            .accept_identity_type("pinned_key")
            .display_name("peer")
            .ttl_secs(86400)
            .published_at(published_at)
            .build()
            .unwrap();
        // ttl_secs got applied at build time but published_at was
        // overridden, so re-apply expires_at directly.
        m.expires_at = expires_at;
        m
    }

    #[test]
    fn fresh_cache_hit_returns_manifest() {
        let fetcher = ManifestFetcher::new();
        let now = Timestamp::now();
        let m = build_manifest(now, Timestamp(now.0 + 3600));
        let aid = m.aid.clone();
        fetcher.insert_cache(aid.clone(), m);
        assert!(fetcher.cached(&aid).is_some());
    }

    #[test]
    fn expired_entry_is_not_served() {
        let fetcher = ManifestFetcher::new();
        let now = Timestamp::now();
        let m = build_manifest(Timestamp(now.0 - 7200), Timestamp(now.0 - 1));
        let aid = m.aid.clone();
        fetcher.insert_cache(aid.clone(), m);
        assert!(
            fetcher.cached(&aid).is_none(),
            "expired manifest must not be served"
        );
    }

    #[test]
    fn newer_inline_replaces_older_cached() {
        let fetcher = ManifestFetcher::new();
        let now = Timestamp::now();
        let older = build_manifest(Timestamp(now.0 - 100), Timestamp(now.0 + 3600));
        let aid = older.aid.clone();
        fetcher.insert_cache(aid.clone(), older);
        let newer = build_manifest(Timestamp(now.0), Timestamp(now.0 + 3600));
        // Manifests for the same AID must use the same key — clone the
        // older one's AID into the newer.
        let mut newer = newer;
        newer.aid = aid.clone();
        assert!(fetcher.maybe_replace_inline(newer));
    }

    #[test]
    fn older_inline_does_not_replace_newer_cached() {
        let fetcher = ManifestFetcher::new();
        let now = Timestamp::now();
        let newer = build_manifest(Timestamp(now.0), Timestamp(now.0 + 3600));
        let aid = newer.aid.clone();
        fetcher.insert_cache(aid.clone(), newer);
        let mut older = build_manifest(Timestamp(now.0 - 100), Timestamp(now.0 + 3600));
        older.aid = aid.clone();
        assert!(
            !fetcher.maybe_replace_inline(older),
            "rollback must be rejected"
        );
    }

    #[test]
    fn equal_published_at_does_not_replace() {
        let fetcher = ManifestFetcher::new();
        let now = Timestamp::now();
        let first = build_manifest(Timestamp(now.0), Timestamp(now.0 + 3600));
        let aid = first.aid.clone();
        fetcher.insert_cache(aid.clone(), first);
        let mut same = build_manifest(Timestamp(now.0), Timestamp(now.0 + 7200));
        same.aid = aid;
        // Equal `published_at` is not strictly newer — must not replace.
        assert!(!fetcher.maybe_replace_inline(same));
    }
}
