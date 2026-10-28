//! HTTP client primitives: Manifest fetcher + JWKS resolver.

use crate::core::{Aid, CheckedJson, Timestamp};
use crate::manifest::{verify_manifest, ManifestVerifyContext, VerifiedManifest};
use crate::transport::client_config::ClientConfig;
use crate::transport::net_guard::HostGuard;
use crate::transport::retry::RetryPolicy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{debug, instrument, warn};
use url::Url;

/// Errors from `ManifestFetcher::fetch`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FetchError {
    /// URL was not HTTPS, or its host is (or resolves to) an address
    /// the configured [`crate::transport::net_guard::HostGuard`] forbids. The
    /// precise guard rejection is logged at `warn` level. (There is no
    /// dedicated guard variant; `FetchError` is exhaustive, so adding
    /// one would be a breaking change.)
    #[error("manifest URL must be HTTPS and resolve to a permitted address")]
    InsecureUrl,
    /// Network error.
    #[error("network error: {0}")]
    Network(#[source] crate::core::BoxError),
    /// Response body could not be parsed.
    #[error("malformed json: {0}")]
    MalformedJson(String),
    /// Response did not match `{"manifest": {...}}`.
    #[error("malformed manifest wrapper")]
    MalformedWrapper,
    /// A top-level or nested member outside the schema-declared member set
    /// (RFC-AITP-0001 §7), found by [`crate::manifest::parse_manifest_wire`]
    /// before any expiry/PoP/signature check. Distinct from
    /// [`FetchError::MalformedJson`] — the body parsed as JSON fine; a
    /// specific member is not one the schema declares.
    #[error("unknown field `{0}`")]
    UnknownField(String),
    /// Manifest verification failed.
    #[error("manifest verification failed: {0}")]
    VerificationFailed(#[from] crate::manifest::ManifestError),
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

/// Whether a [`FetchError`] is transient and worth retrying. Network
/// errors, timeouts, and 5xx upstream statuses are transient; everything
/// else is a content-shape problem the next attempt would also fail.
fn is_transient(err: &FetchError) -> bool {
    match err {
        FetchError::Timeout => true,
        FetchError::Network(_) => true,
        FetchError::UpstreamStatus(s) => *s >= 500,
        FetchError::InsecureUrl
        | FetchError::MalformedJson(_)
        | FetchError::MalformedWrapper
        | FetchError::UnknownField(_)
        | FetchError::WrongContentType(_)
        | FetchError::OversizedResponse { .. }
        | FetchError::VerificationFailed(_) => false,
    }
}

/// Cache entry — keyed on `Aid`, holding the verified Manifest plus its
/// own published/expires window. We honor `expires_at` on lookup
/// (RFC-AITP-0003 §4.2) so the cache never serves a Manifest the issuer
/// has marked stale, and we honor `published_at` for inline-replace
/// ordering (newer publish wins).
struct CacheEntry {
    manifest: VerifiedManifest,
    published_at: Timestamp,
    expires_at: Timestamp,
}

/// HTTP client that fetches and verifies peer Agent Manifests.
///
/// Because `peer_origin` is peer-controlled, every fetch is SSRF-guarded:
/// redirects are rejected outright, the host's resolved addresses are
/// classified by a [`HostGuard`] (link-local/metadata ranges always
/// rejected; private ranges rejected by default — see [`crate::transport::net_guard`]),
/// and for domain hosts the vetted addresses are pinned into the
/// connection so DNS rebinding cannot swap in an unchecked address.
pub struct ManifestFetcher {
    client: reqwest::Client,
    cache: Mutex<HashMap<Aid, CacheEntry>>,
    /// Per-request timeout (default 10s).
    timeout: Duration,
    /// Maximum response body size, bytes.
    max_bytes: usize,
    /// Retry policy for transient network failures (default: no retry).
    retry_policy: RetryPolicy,
    /// Pool/TLS knobs, kept so per-fetch pinned clients inherit them.
    client_cfg: ClientConfig,
    /// SSRF guard applied to every non-localhost-exempt fetch.
    host_guard: HostGuard,
    /// Tolerate `http://localhost` / `http://127.0.0.1` origins and
    /// admit loopback addresses through the guard (local dev). Default
    /// `false`.
    insecure_localhost: bool,
}

impl std::fmt::Debug for ManifestFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManifestFetcher")
            .field("timeout", &self.timeout)
            .field("max_bytes", &self.max_bytes)
            .field("retry_policy", &self.retry_policy)
            .field("host_guard", &self.host_guard)
            .field("insecure_localhost", &self.insecure_localhost)
            .finish_non_exhaustive()
    }
}

impl ManifestFetcher {
    /// Build a fetcher with hardened defaults: 10s timeout, redirects
    /// rejected, default [`HostGuard`].
    pub fn new() -> Self {
        let client_cfg = ClientConfig::default();
        Self {
            client: Self::base_client(Duration::from_secs(10), client_cfg.clone()),
            cache: Mutex::new(HashMap::new()),
            timeout: Duration::from_secs(10),
            max_bytes: DEFAULT_MAX_MANIFEST_BYTES,
            retry_policy: RetryPolicy::none(),
            client_cfg,
            host_guard: HostGuard::default(),
            insecure_localhost: false,
        }
    }

    /// Shared builder recipe: per-request timeout + the no-redirect
    /// safety policy (a peer-controlled origin must not be able to
    /// bounce the fetch elsewhere — same rationale as [`JwksFetcher`]),
    /// then the caller's pool/TLS knobs.
    fn base_client(timeout: Duration, cfg: ClientConfig) -> reqwest::Client {
        let builder = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none());
        cfg.apply(builder).build().expect("reqwest client builds")
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

    /// Override the retry policy. Defaults to [`RetryPolicy::none`]
    /// (single attempt). Only transient failures (timeout, 5xx,
    /// network) are retried; verification or oversize errors are
    /// returned on the first attempt.
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    /// Override the underlying `reqwest` client with a fresh one
    /// built from the supplied [`ClientConfig`] (connection pool +
    /// TLS knobs). The fetcher's per-request timeout and the
    /// no-redirect safety policy are preserved.
    pub fn with_client_config(mut self, cfg: ClientConfig) -> Self {
        self.client = Self::base_client(self.timeout, cfg.clone());
        self.client_cfg = cfg;
        self
    }

    /// Override the SSRF [`HostGuard`] (default:
    /// [`crate::transport::net_guard::GuardMode::DenyPrivate`]). Pass
    /// `HostGuard::new(GuardMode::WarnPrivate)` for intranet peers and
    /// `HostGuard::new(GuardMode::AllowAll)` for air-gapped/test
    /// networks.
    pub fn with_host_guard(mut self, guard: HostGuard) -> Self {
        self.host_guard = guard;
        self
    }

    /// Tolerate `http://localhost` / `http://127.0.0.1` origins and
    /// admit loopback addresses (`127.0.0.0/8`, `::1`) through the host
    /// guard, as [`HostGuard::allow_loopback_dangerous`] does. For local
    /// demos and tests. Without it every origin must be `https://`
    /// (RFC-AITP-0003 §4.1) and the guard's mode decides loopback.
    pub fn with_insecure_localhost_dangerous(mut self) -> Self {
        self.insecure_localhost = true;
        self
    }

    /// Fetch and verify a Manifest from a peer's well-known endpoint.
    ///
    /// `peer_origin` is something like `https://agent-b.example.com`. The
    /// fetcher GETs `peer_origin.join("/.well-known/aitp-manifest")`,
    /// parses `{"manifest": {...}}`, verifies, caches, and returns the
    /// [`VerifiedManifest`].
    #[instrument(level = "debug", skip(self), fields(origin = %peer_origin))]
    pub async fn fetch(&self, peer_origin: &Url) -> Result<VerifiedManifest, FetchError> {
        let mut localhost_exempt = false;
        if peer_origin.scheme() != "https" {
            // `http://localhost` is tolerated for local dev (demo)
            // only when `insecure_localhost` is set (default `false`).
            let is_localhost_http = peer_origin.scheme() == "http"
                && (peer_origin.host_str() == Some("localhost")
                    || peer_origin.host_str() == Some("127.0.0.1"));
            if !(is_localhost_http && self.insecure_localhost) {
                return Err(FetchError::InsecureUrl);
            }
            static LOCALHOST_WARN: std::sync::Once = std::sync::Once::new();
            LOCALHOST_WARN.call_once(|| {
                warn!(
                    "fetching manifests over http://localhost — development \
                     convenience only; never enable \
                     `ManifestFetcher::with_insecure_localhost_dangerous` in production"
                );
            });
            // localhost / 127.0.0.1 is loopback by definition — the
            // flag above already accepted exactly that, so the guard
            // has nothing further to add for this URL.
            localhost_exempt = true;
        }
        let url = peer_origin
            .join("/.well-known/aitp-manifest")
            .map_err(|e| FetchError::Network(e.into()))?;

        // SSRF guard: classify every address the host resolves to, and
        // for domain hosts pin the vetted set into a per-fetch client
        // so the connection cannot be re-resolved (DNS rebinding) to an
        // address that never passed the check. IP-literal hosts involve
        // no DNS, so the shared client is safe for them.
        let pinned_client;
        let client: &reqwest::Client = if localhost_exempt {
            &self.client
        } else {
            let addrs = self
                .host_guard
                .resolve_checked_with(&url, self.insecure_localhost)
                .await
                .map_err(|e| {
                    if e.is_transient() {
                        FetchError::Network(e.into())
                    } else {
                        warn!(error = %e, "manifest fetch rejected by host guard");
                        FetchError::InsecureUrl
                    }
                })?;
            match url.host() {
                Some(url::Host::Domain(domain)) => {
                    pinned_client = self.pinned_client(domain, &addrs);
                    &pinned_client
                }
                _ => &self.client,
            }
        };

        let max_attempts = self.retry_policy.max_attempts();
        let mut last_err: Option<FetchError> = None;
        for attempt in 1..=max_attempts {
            let delay = self.retry_policy.jittered_delay_before(attempt);
            if !delay.is_zero() {
                debug!(?delay, attempt, "manifest fetch retry sleep");
                tokio::time::sleep(delay).await;
            }
            match self.fetch_attempt(client, &url).await {
                Ok(manifest) => {
                    if attempt > 1 {
                        debug!(attempt, "manifest fetch succeeded after retry");
                    }
                    return Ok(manifest);
                }
                Err(e) if is_transient(&e) && attempt < max_attempts => {
                    warn!(attempt, error = %e, "manifest fetch transient error; retrying");
                    last_err = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or(FetchError::Network("unreachable".into())))
    }

    /// Per-fetch client with the guard-vetted addresses pinned for
    /// `domain`, inheriting the fetcher's timeout, no-redirect policy,
    /// and pool/TLS knobs.
    fn pinned_client(&self, domain: &str, addrs: &[SocketAddr]) -> reqwest::Client {
        let builder = reqwest::Client::builder()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(domain, addrs);
        self.client_cfg
            .clone()
            .apply(builder)
            .build()
            .expect("reqwest client builds with pinned addresses")
    }

    /// Single fetch attempt; the retry harness in `fetch` calls this
    /// once per attempt with the (possibly address-pinned) client.
    async fn fetch_attempt(
        &self,
        client: &reqwest::Client,
        url: &Url,
    ) -> Result<VerifiedManifest, FetchError> {
        let resp = client
            .get(url.clone())
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    FetchError::Timeout
                } else {
                    FetchError::Network(e.into())
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
            .map_err(|e| FetchError::Network(e.into()))?
        {
            if body.len() + chunk.len() > max_bytes {
                return Err(FetchError::OversizedResponse { limit: max_bytes });
            }
            body.extend_from_slice(&chunk);
        }
        // RFC-AITP-0001 §5.4.5 / issue #140: a duplicate JSON key anywhere
        // in the manifest response body MUST be rejected, against the
        // ORIGINAL bytes before a `Value` — last-write-wins on a
        // duplicate key — is ever built. `CheckedJson` does both steps.
        let value =
            CheckedJson::from_slice(&body).map_err(|e| FetchError::MalformedJson(e.to_string()))?;
        // RFC-AITP-0003 §6.1: `/.well-known/aitp-manifest` MUST respond
        // with the `{"manifest": {...}}` transport wrapper specifically —
        // unlike `crate::manifest::parse_manifest_wire`, which is
        // deliberately lenient and also accepts a bare unwrapped manifest
        // body (the conformance adapter receives fixtures in both
        // shapes). That leniency does not apply to this HTTP endpoint, so
        // the wrapper is required here before handing off to the lenient
        // parser.
        let inner = match value.as_object() {
            Some(obj) if obj.contains_key("manifest") => value
                .member("manifest")
                .expect("checked contains_key above"),
            _ => return Err(FetchError::MalformedWrapper),
        };
        // RFC-AITP-0001 §7 (issue #140): the member-set check MUST run
        // before any expiry/PoP/signature check (RFC-AITP-0003 §5 step 2).
        // Distinguish an unknown-member rejection from a generic malformed
        // body so callers can tell the two failure classes apart.
        let manifest = crate::manifest::parse_manifest_wire(&inner).map_err(|e| match e {
            crate::manifest::ManifestError::UnknownField(field) => FetchError::UnknownField(field),
            other => FetchError::MalformedJson(other.to_string()),
        })?;
        let verified = verify_manifest(&manifest, &ManifestVerifyContext::now())?;
        self.insert_cache(verified.clone());
        Ok(verified)
    }

    /// Look up a previously-cached Manifest by AID. Returns `None` when
    /// the cached entry's `expires_at` has passed (RFC-AITP-0003 §4.2):
    /// stale Manifests are not served.
    pub fn cached(&self, aid: &Aid) -> Option<VerifiedManifest> {
        let now = Timestamp::now();
        let cache = self.cache.lock();
        let result = cache
            .get(aid)
            .filter(|e| e.expires_at.0 > now.0)
            .map(|e| e.manifest.clone());
        if result.is_some() {
            debug!(%aid, "manifest cache hit");
        } else {
            debug!(%aid, "manifest cache miss");
        }
        result
    }

    /// Cache a verified Manifest received inline (e.g. in a handshake
    /// payload), but only if its `published_at` is strictly newer than
    /// the cached copy's, so an older signed Manifest cannot replace a
    /// newer cached one. It takes a [`VerifiedManifest`], so only a
    /// Manifest that passed [`verify_manifest`] enters the cache.
    ///
    /// Returns `true` if the cache was updated.
    pub fn maybe_replace_inline(&self, manifest: VerifiedManifest) -> bool {
        let aid = manifest.manifest().aid.clone();
        let published_at = manifest.manifest().published_at;
        let mut cache = self.cache.lock();
        let current_published = cache.get(&aid).map(|e| e.published_at);
        match current_published {
            Some(existing) if published_at.0 <= existing.0 => false,
            _ => {
                cache.insert(aid, CacheEntry::new(manifest));
                true
            }
        }
    }

    fn insert_cache(&self, manifest: VerifiedManifest) {
        let aid = manifest.manifest().aid.clone();
        self.cache.lock().insert(aid, CacheEntry::new(manifest));
    }
}

impl CacheEntry {
    fn new(manifest: VerifiedManifest) -> Self {
        Self {
            published_at: manifest.manifest().published_at,
            expires_at: manifest.manifest().expires_at,
            manifest,
        }
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
#[non_exhaustive]
pub enum JwksFetcherError {
    /// URL was not HTTPS.
    #[error("issuer URL must be HTTPS")]
    InsecureUrl,
    /// Network error.
    #[error("network error: {0}")]
    Network(#[source] crate::core::BoxError),
    /// Response body could not be parsed.
    #[error("malformed JSON: {0}")]
    MalformedJson(String),
    /// JWK is unsupported (e.g. `kty` other than `OKP`/`RSA`).
    #[error("unsupported JWK: {0}")]
    UnsupportedJwk(String),
    /// Response body exceeded the configured size cap. Defends against a
    /// hostile (or MITM'd) issuer endpoint returning an unbounded body
    /// during key resolution (RFC-AITP-0009 §3.1 resource exhaustion).
    #[error("response body exceeded {limit} bytes")]
    OversizedResponse {
        /// The configured cap, in bytes.
        limit: usize,
    },
}

/// Default cap on a discovery / JWKS response body (256 KiB). The issuer
/// host is peer-derived during key resolution, so the body is treated as
/// untrusted and read with a hard cap (RFC-AITP-0009 §3.1). Override with
/// [`JwksFetcher::with_max_bytes`].
pub const DEFAULT_MAX_JWKS_BYTES: usize = 256 * 1024;

/// Default OIDC discovery cache TTL (1 hour). The
/// `.well-known/openid-configuration` document changes very rarely;
/// caching the resolved `jwks_uri` for an hour saves one round trip
/// on every JWKS lookup without giving up freshness on real key
/// rotations (the JWKS itself is fetched per call).
pub const DEFAULT_OIDC_DISCOVERY_TTL: Duration = Duration::from_secs(3600);

struct DiscoveryCacheEntry {
    jwks_uri: Url,
    inserted_at: std::time::Instant,
}

/// HTTP client that resolves an OIDC issuer to its JWKS.
///
/// Hardened per RFC-AITP-0007 §2:
/// - HTTPS-only for both discovery and `jwks_uri`. HTTP and HTTP-bearing
///   redirects are rejected outright.
/// - Configurable per-request timeout (default 10 s).
/// - Non-2xx responses produce a structured error rather than a JSON
///   parse failure.
/// - OIDC-vs-non-OIDC is a branch (RFC-AITP-0007 §2.3), not a priority
///   list: the AITP-native `/.well-known/aitp-keys` endpoint is consulted
///   ONLY when OIDC discovery is not validly exposed — never after a
///   valid discovery document yields a usable `jwks_uri`.
/// - Discovery and JWKS bodies are read with a hard size cap
///   ([`DEFAULT_MAX_JWKS_BYTES`]); the issuer host is peer-derived.
/// - Discovery responses are cached for [`DEFAULT_OIDC_DISCOVERY_TTL`];
///   override with [`Self::with_discovery_ttl`].
/// - `iss` claim and the requested issuer URL are compared using a
///   tolerant normalization (lowercase host, single trailing slash
///   stripped) so common IdP shape differences don't fail the check.
/// - On a JWKS `kid` miss, callers can use
///   [`Self::resolve_with_kid_hint`] to trigger a one-shot
///   discovery-cache invalidation + refetch.
pub struct JwksFetcher {
    client: reqwest::Client,
    timeout: Duration,
    discovery_cache: Mutex<HashMap<Url, DiscoveryCacheEntry>>,
    discovery_ttl: Duration,
    max_bytes: usize,
    /// Pool/TLS knobs, kept so per-fetch pinned clients inherit them.
    client_cfg: ClientConfig,
    /// SSRF guard for the (issuer/peer-derived) discovery, `jwks_uri`,
    /// and `/.well-known/aitp-keys` hosts.
    host_guard: HostGuard,
}

impl std::fmt::Debug for JwksFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksFetcher")
            .field("timeout", &self.timeout)
            .field("max_bytes", &self.max_bytes)
            .field("discovery_ttl", &self.discovery_ttl)
            .field("host_guard", &self.host_guard)
            .finish_non_exhaustive()
    }
}

impl JwksFetcher {
    /// Build a JWKS fetcher with the default 10s per-request timeout.
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(10))
    }

    /// Build a JWKS fetcher with a custom timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        let client_cfg = ClientConfig::default();
        Self {
            client: Self::base_client(timeout, client_cfg.clone()),
            timeout,
            discovery_cache: Mutex::new(HashMap::new()),
            discovery_ttl: DEFAULT_OIDC_DISCOVERY_TTL,
            max_bytes: DEFAULT_MAX_JWKS_BYTES,
            client_cfg,
            host_guard: HostGuard::default(),
        }
    }

    /// Shared builder recipe. `redirect::Policy::none()` rejects ALL
    /// redirects, which includes the HTTP-fallback class an attacker
    /// could try to use to downgrade a trusted JWKS endpoint.
    fn base_client(timeout: Duration, cfg: ClientConfig) -> reqwest::Client {
        let builder = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none());
        cfg.apply(builder).build().expect("reqwest client builds")
    }

    /// Override the SSRF [`HostGuard`] (default:
    /// [`crate::transport::net_guard::GuardMode::DenyPrivate`]). Pass
    /// `HostGuard::new(GuardMode::WarnPrivate)` when an IdP or peer key
    /// host is on a private network.
    pub fn with_host_guard(mut self, guard: HostGuard) -> Self {
        self.host_guard = guard;
        self
    }

    /// Per-fetch client with the guard-vetted addresses pinned for
    /// `domain`, inheriting the fetcher's timeout, no-redirect policy,
    /// and pool/TLS knobs.
    fn pinned_client(&self, domain: &str, addrs: &[SocketAddr]) -> reqwest::Client {
        let builder = reqwest::Client::builder()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(domain, addrs);
        self.client_cfg
            .clone()
            .apply(builder)
            .build()
            .expect("reqwest client builds with pinned addresses")
    }

    /// Override the per-response body cap (default
    /// [`DEFAULT_MAX_JWKS_BYTES`]). Applies to both the discovery
    /// document and the JWKS body.
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Override the OIDC discovery cache TTL. Defaults to
    /// [`DEFAULT_OIDC_DISCOVERY_TTL`] (1 hour). Set to
    /// `Duration::ZERO` to disable caching entirely.
    pub fn with_discovery_ttl(mut self, ttl: Duration) -> Self {
        self.discovery_ttl = ttl;
        self
    }

    /// Force a refresh of the cached OIDC discovery document for
    /// `issuer`. Call this after a JWKS lookup yields a kid that
    /// none of the returned keys match — the IdP has rotated keys
    /// and the cached discovery (or its `jwks_uri`) may be stale.
    pub fn invalidate_discovery_cache(&self, issuer: &Url) {
        let normalized = normalize_issuer_url(issuer);
        let mut cache = self.discovery_cache.lock();
        cache.remove(&normalized);
    }

    /// Resolve and return only those JWKs whose `kid` matches the
    /// supplied hint. If no key matches and the discovery cache had
    /// a hit, the cache is invalidated and one fresh fetch is
    /// attempted. Returns an empty Vec if still no match — callers
    /// decide policy.
    ///
    /// Pass `None` to skip kid filtering (equivalent to
    /// [`Self::resolve`]).
    pub async fn resolve_with_kid_hint(
        &self,
        issuer: &Url,
        kid_hint: Option<&str>,
    ) -> Result<Vec<crate::handshake::JwkPublicKey>, JwksFetcherError> {
        let keys = self.resolve(issuer).await?;
        let Some(kid) = kid_hint else {
            return Ok(keys);
        };
        if keys.iter().any(|k| k.kid.as_deref() == Some(kid)) {
            return Ok(keys);
        }
        // Kid miss. The IdP may have rotated; try once more after
        // invalidating discovery.
        tracing::debug!(
            kid,
            issuer = %issuer,
            "JWKS kid miss; invalidating discovery cache and refetching"
        );
        self.invalidate_discovery_cache(issuer);
        self.resolve(issuer).await
    }

    /// Override the underlying `reqwest` client with a fresh one
    /// built from the supplied [`ClientConfig`]. Preserves the per-
    /// request timeout and the no-redirect safety policy.
    pub fn with_client_config(mut self, cfg: ClientConfig) -> Self {
        self.client = Self::base_client(self.timeout, cfg.clone());
        self.client_cfg = cfg;
        self
    }

    /// Resolve `issuer/.well-known/openid-configuration`, then its
    /// `jwks_uri`, returning every parseable JWK. Per RFC-AITP-0007 §2.3
    /// this is a branch, not a priority list: the AITP-native
    /// `<issuer>/.well-known/aitp-keys` fallback is consulted ONLY when
    /// OIDC discovery is not validly exposed (non-2xx, network error,
    /// invalid document, or no usable `jwks_uri`). Once discovery yields
    /// a usable `jwks_uri`, a failure fetching/parsing the JWKS itself is
    /// surfaced directly — the fallback is never used.
    #[instrument(level = "debug", skip(self), fields(issuer = %issuer))]
    pub async fn resolve(
        &self,
        issuer: &Url,
    ) -> Result<Vec<crate::handshake::JwkPublicKey>, JwksFetcherError> {
        if issuer.scheme() != "https" {
            return Err(JwksFetcherError::InsecureUrl);
        }
        // RFC-AITP-0007 §2.3 resolution decision logic is a BRANCH, not a
        // priority list. `resolve_jwks_uri` performs the discovery step
        // (fetch + validate `/.well-known/openid-configuration`); its
        // success means the issuer is a confirmed OIDC issuer with a
        // usable `jwks_uri`.
        match self.resolve_jwks_uri(issuer).await {
            Ok(jwks_url) => {
                // §2.3 rule 1: discovery is reachable and valid, so the
                // implementation MUST follow the OIDC flow and MUST NOT
                // consult `/.well-known/aitp-keys` for this issuer in the
                // same attempt — even if the JWKS fetch/parse below
                // fails. Falling back here would let an attacker who
                // controls the aitp-keys endpoint substitute keys
                // whenever the legitimate `jwks_uri` transiently fails.
                let jwks = self.fetch_https_json(&jwks_url).await?;
                parse_jwks(&jwks)
            }
            Err(discovery_err) => {
                // §2.3 rule 2: discovery is NOT validly exposed (non-2xx,
                // network error, invalid document, or no usable
                // `jwks_uri`), so the AITP-native fallback is permitted.
                // If it also fails, surface the discovery error.
                match self.resolve_via_aitp_keys(issuer).await {
                    Ok(keys) => Ok(keys),
                    Err(_) => Err(discovery_err),
                }
            }
        }
    }

    /// Two-stage `jwks_uri` resolution: cache hit → use cached;
    /// miss or expired → fetch discovery, validate, cache, return.
    async fn resolve_jwks_uri(&self, issuer: &Url) -> Result<Url, JwksFetcherError> {
        let normalized = normalize_issuer_url(issuer);

        // Cache hit?
        if !self.discovery_ttl.is_zero() {
            let cache = self.discovery_cache.lock();
            if let Some(entry) = cache.get(&normalized) {
                if entry.inserted_at.elapsed() < self.discovery_ttl {
                    return Ok(entry.jwks_uri.clone());
                }
            }
        }

        let discovery_url = normalized
            .join("/.well-known/openid-configuration")
            .map_err(|e| JwksFetcherError::Network(e.into()))?;
        let discovery: serde_json::Value = self.fetch_https_json(&discovery_url).await?;

        // §3.5 iss URL normalization: the discovery document's
        // `issuer` claim MUST equal the requested issuer modulo
        // trailing-slash and scheme-case differences (OIDC Core
        // 1.0 §3.1.3.7).
        if let Some(disco_iss_str) = discovery.get("issuer").and_then(|v| v.as_str()) {
            if let Ok(disco_iss) = Url::parse(disco_iss_str) {
                if normalize_issuer_url(&disco_iss) != normalized {
                    return Err(JwksFetcherError::MalformedJson(format!(
                        "discovery issuer mismatch: requested {normalized}, got {disco_iss}"
                    )));
                }
            }
        }

        let jwks_uri_str = discovery
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JwksFetcherError::MalformedJson("missing jwks_uri".into()))?;
        let jwks_url = Url::parse(jwks_uri_str)
            .map_err(|e| JwksFetcherError::Network(format!("malformed jwks_uri: {e}").into()))?;
        if jwks_url.scheme() != "https" {
            return Err(JwksFetcherError::InsecureUrl);
        }

        if !self.discovery_ttl.is_zero() {
            let mut cache = self.discovery_cache.lock();
            cache.insert(
                normalized,
                DiscoveryCacheEntry {
                    jwks_uri: jwks_url.clone(),
                    inserted_at: std::time::Instant::now(),
                },
            );
        }

        Ok(jwks_url)
    }

    async fn resolve_via_aitp_keys(
        &self,
        issuer: &Url,
    ) -> Result<Vec<crate::handshake::JwkPublicKey>, JwksFetcherError> {
        let url = issuer
            .join("/.well-known/aitp-keys")
            .map_err(|e| JwksFetcherError::Network(e.into()))?;
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
        // SSRF guard: every discovery / jwks_uri / aitp-keys host is
        // issuer- or peer-derived, so classify the resolved addresses
        // and (for domain hosts) pin the vetted set into a per-fetch
        // client to close the DNS-rebinding window.
        let addrs = self.host_guard.resolve_checked(url).await.map_err(|e| {
            if e.is_transient() {
                JwksFetcherError::Network(e.into())
            } else {
                warn!(error = %e, "JWKS fetch rejected by host guard");
                JwksFetcherError::InsecureUrl
            }
        })?;
        let pinned_client;
        let client: &reqwest::Client = match url.host() {
            Some(url::Host::Domain(domain)) => {
                pinned_client = self.pinned_client(domain, &addrs);
                &pinned_client
            }
            _ => &self.client,
        };
        let resp = client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| JwksFetcherError::Network(e.into()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(JwksFetcherError::Network(
                format!("non-2xx response from {url}: {status}").into(),
            ));
        }
        // Stream with a hard cap. `resp.json()` would buffer the entire
        // body unbounded; the issuer host is peer-derived during key
        // resolution, so an oversized body is a resource-exhaustion
        // vector (RFC-AITP-0009 §3.1). Bail early on overflow.
        let max_bytes = self.max_bytes;
        let mut body: Vec<u8> = Vec::with_capacity(8192);
        let mut stream = resp;
        while let Some(chunk) = stream
            .chunk()
            .await
            .map_err(|e| JwksFetcherError::Network(e.into()))?
        {
            if body.len() + chunk.len() > max_bytes {
                return Err(JwksFetcherError::OversizedResponse { limit: max_bytes });
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|e| JwksFetcherError::MalformedJson(e.to_string()))
    }
}

impl Default for JwksFetcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalize an issuer URL for cache-key and OIDC `iss`-claim
/// comparison: lowercase scheme, lowercase host, strip a single
/// trailing slash from the path. OIDC Core 1.0 §3.1.3.7 says the
/// `iss` claim must compare with simple string equality, but
/// real-world IdPs differ on whether they include a trailing slash;
/// this normalization is a tolerant superset that lets fields like
/// `https://idp.example.com` and `https://idp.example.com/` resolve
/// to the same cache entry.
pub(crate) fn normalize_issuer_url(url: &Url) -> Url {
    let mut u = url.clone();
    if let Some(host) = u.host_str() {
        let lower = host.to_ascii_lowercase();
        let _ = u.set_host(Some(&lower));
    }
    // url::Url already lowercases the scheme; nothing to do there.
    // Drop a single trailing slash from the path (but keep "/" for
    // the bare-root case).
    let path = u.path().to_string();
    if path.len() > 1 && path.ends_with('/') {
        u.set_path(&path[..path.len() - 1]);
    }
    u
}

fn parse_jwks(
    jwks: &serde_json::Value,
) -> Result<Vec<crate::handshake::JwkPublicKey>, JwksFetcherError> {
    let keys = jwks
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| JwksFetcherError::MalformedJson("missing keys array".into()))?;
    let mut out = Vec::new();
    for jwk in keys {
        // Reject weak RSA keys before trusting the IdP's JWK
        // (RFC-AITP-0009 §4 hardening): a trust-anchored but sloppy IdP
        // advertising a <2048-bit key must not be honored. Checked
        // against the raw base64url `n` directly, since
        // `from_jwk_json` is shared across callers that don't all want
        // this transport-specific hardening policy.
        if jwk.get("kty").and_then(|v| v.as_str()) == Some("RSA") {
            let n = jwk
                .get("n")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JwksFetcherError::MalformedJson("RSA jwk missing n".into()))?;
            if !crate::transport::rsa_floor::rsa_modulus_bits_ok(n) {
                return Err(JwksFetcherError::UnsupportedJwk(format!(
                    "RSA modulus below the {}-bit minimum",
                    crate::transport::rsa_floor::MIN_RSA_MODULUS_BITS
                )));
            }
        }
        let key = crate::handshake::JwkPublicKey::from_jwk_json(jwk).map_err(|e| match e {
            crate::handshake::JwkParseError::Malformed(m) => JwksFetcherError::MalformedJson(m),
            crate::handshake::JwkParseError::Unsupported(m) => JwksFetcherError::UnsupportedJwk(m),
        })?;
        out.push(key);
    }
    Ok(out)
}

#[cfg(test)]
mod normalize_tests {
    //! Unit tests for the §3.5 `iss` URL normalization helper.

    use super::normalize_issuer_url;
    use url::Url;

    #[test]
    fn strips_single_trailing_slash() {
        let a = Url::parse("https://idp.example.com/").unwrap();
        let b = Url::parse("https://idp.example.com").unwrap();
        assert_eq!(normalize_issuer_url(&a), normalize_issuer_url(&b));
    }

    #[test]
    fn keeps_root_slash_for_bare_origin() {
        let a = Url::parse("https://idp.example.com/").unwrap();
        let n = normalize_issuer_url(&a);
        // `url` always emits at least "/" for the path; we don't
        // strip below that.
        assert_eq!(n.path(), "/");
    }

    #[test]
    fn lowercases_host() {
        let a = Url::parse("https://IDP.Example.COM/realm").unwrap();
        let b = Url::parse("https://idp.example.com/realm").unwrap();
        assert_eq!(normalize_issuer_url(&a), normalize_issuer_url(&b));
    }

    #[test]
    fn preserves_path_segments_below_root() {
        let a = Url::parse("https://idp.example.com/realms/foo/").unwrap();
        let b = Url::parse("https://idp.example.com/realms/foo").unwrap();
        assert_eq!(normalize_issuer_url(&a), normalize_issuer_url(&b));
    }

    #[test]
    fn does_not_collapse_query_or_fragment() {
        let a = Url::parse("https://idp.example.com/realm?x=1").unwrap();
        let n = normalize_issuer_url(&a);
        assert_eq!(n.query(), Some("x=1"));
    }
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
    use crate::crypto::AitpSigningKey;
    use crate::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};

    /// A Manifest signed by `key`, published at `published_at` for
    /// `ttl_secs`, verified at its publish time.
    fn verified(key: &AitpSigningKey, published_at: Timestamp, ttl_secs: u64) -> VerifiedManifest {
        let pubkey_b64 = crate::core::base64url::encode(
            &key.verifying_key()
                .try_to_ed25519_bytes()
                .expect("key was constructed as Ed25519, never P-256"),
        );
        let m = ManifestBuilder::new(key)
            .handshake_endpoint("https://peer.example.com/aitp/handshake".parse().unwrap())
            .identity_hint(IdentityHint {
                kind: IdentityHintKind::PinnedKey,
                subject: "peer".into(),
                issuer: None,
                public_key: Some(pubkey_b64),
            })
            .offer("test.action")
            .accept_identity_type(crate::handshake::IdentityKind::PinnedKey)
            .display_name("peer")
            .ttl(std::time::Duration::from_secs(ttl_secs))
            .published_at(published_at)
            .build()
            .unwrap();
        verify_manifest(&m, &ManifestVerifyContext::at(published_at)).unwrap()
    }

    #[test]
    fn fresh_cache_hit_returns_manifest() {
        let fetcher = ManifestFetcher::new();
        let now = Timestamp::now();
        let m = verified(&AitpSigningKey::generate_ed25519(), now, 3600);
        let aid = m.manifest().aid.clone();
        fetcher.insert_cache(m.clone());
        assert_eq!(fetcher.cached(&aid), Some(m));
    }

    #[test]
    fn expired_entry_is_not_served() {
        let fetcher = ManifestFetcher::new();
        let now = Timestamp::now();
        let m = verified(
            &AitpSigningKey::generate_ed25519(),
            Timestamp(now.0 - 7200),
            7199,
        );
        let aid = m.manifest().aid.clone();
        fetcher.insert_cache(m);
        assert!(
            fetcher.cached(&aid).is_none(),
            "expired manifest must not be served"
        );
    }

    #[test]
    fn newer_inline_replaces_older_cached() {
        let fetcher = ManifestFetcher::new();
        let key = AitpSigningKey::generate_ed25519();
        let now = Timestamp::now();
        let older = verified(&key, Timestamp(now.0 - 100), 3600);
        let aid = older.manifest().aid.clone();
        fetcher.insert_cache(older);
        let newer = verified(&key, now, 3600);
        assert!(fetcher.maybe_replace_inline(newer.clone()));
        assert_eq!(fetcher.cached(&aid), Some(newer));
    }

    #[test]
    fn older_inline_does_not_replace_newer_cached() {
        let fetcher = ManifestFetcher::new();
        let key = AitpSigningKey::generate_ed25519();
        let now = Timestamp::now();
        let newer = verified(&key, now, 3600);
        fetcher.insert_cache(newer);
        let older = verified(&key, Timestamp(now.0 - 100), 3600);
        assert!(
            !fetcher.maybe_replace_inline(older),
            "an older published_at must not replace the cached copy"
        );
    }

    #[test]
    fn equal_published_at_does_not_replace() {
        let fetcher = ManifestFetcher::new();
        let key = AitpSigningKey::generate_ed25519();
        let now = Timestamp::now();
        fetcher.insert_cache(verified(&key, now, 3600));
        let same = verified(&key, now, 7200);
        // Equal `published_at` is not strictly newer — must not replace.
        assert!(!fetcher.maybe_replace_inline(same));
    }
}
