//! HTTP client primitives: Manifest fetcher + JWKS resolver.

use aitp_core::Aid;
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
}

/// Cache entry — kept until `expires_at`.
struct Cached {
    manifest: Manifest,
}

/// HTTP client that fetches and verifies peer Agent Manifests.
pub struct ManifestFetcher {
    client: reqwest::Client,
    cache: Mutex<HashMap<Aid, Cached>>,
    /// Per-request timeout (default 10s).
    timeout: Duration,
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
        }
    }

    /// Override the per-request timeout (e.g. for tests).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
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
        let body = resp
            .bytes()
            .await
            .map_err(|e| FetchError::Network(e.to_string()))?;
        let env: ManifestEnvelope =
            serde_json::from_slice(&body).map_err(|e| FetchError::MalformedJson(e.to_string()))?;
        verify_manifest(&env.manifest, &VerifyManifestContext::now())?;
        let aid = env.manifest.aid.clone();
        self.cache.lock().unwrap().insert(
            aid.clone(),
            Cached {
                manifest: env.manifest.clone(),
            },
        );
        Ok(env.manifest)
    }

    /// Look up a previously-cached Manifest by AID.
    pub fn cached(&self, aid: &Aid) -> Option<Manifest> {
        self.cache
            .lock()
            .unwrap()
            .get(aid)
            .map(|c| c.manifest.clone())
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
pub struct JwksFetcher {
    client: reqwest::Client,
}

impl JwksFetcher {
    /// Build a JWKS fetcher.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client builds"),
        }
    }

    /// Resolve `issuer/.well-known/openid-configuration`, then its `jwks_uri`,
    /// returning every parseable JWK as a `JwkPublicKey`.
    pub async fn resolve(
        &self,
        issuer: &Url,
    ) -> Result<Vec<aitp_handshake::JwkPublicKey>, JwksFetcherError> {
        if issuer.scheme() != "https" {
            return Err(JwksFetcherError::InsecureUrl);
        }
        let discovery_url = issuer
            .join("/.well-known/openid-configuration")
            .map_err(|e| JwksFetcherError::Network(e.to_string()))?;
        let discovery: serde_json::Value = self
            .client
            .get(discovery_url)
            .send()
            .await
            .map_err(|e| JwksFetcherError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| JwksFetcherError::MalformedJson(e.to_string()))?;
        let jwks_uri = discovery
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JwksFetcherError::MalformedJson("missing jwks_uri".into()))?;
        let jwks: serde_json::Value = self
            .client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| JwksFetcherError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| JwksFetcherError::MalformedJson(e.to_string()))?;
        parse_jwks(&jwks)
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
