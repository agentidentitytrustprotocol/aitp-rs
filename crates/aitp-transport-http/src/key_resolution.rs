//! Key resolution policy (RFC-AITP-0007).
//!
//! Composes a [`PinnedIssuerKeyStore`], a [`JwksFetcher`] and an
//! in-memory cache into a single [`JwksResolver`]. The resolution order
//! is fixed by RFC-AITP-0007 §2:
//!
//! 1. **Cache** (unexpired) — short-circuit, never network.
//! 2. **Pinned issuer key store** — operator-supplied issuer →
//!    `Vec<JwkPublicKey>` mapping. Survives outages.
//! 3. **`/.well-known/aitp-keys`** — AITP-native discovery.
//! 4. **OIDC JWKS** — full `/.well-known/openid-configuration` →
//!    `jwks_uri` walk.
//!
//! The fail mode is configurable per issuer:
//!
//! - [`KeyResolutionFailMode::FailClosed`] — any miss is fatal. This is
//!   the only safe choice for **peer Manifest** resolution: no peer key
//!   means no safe subset to compute, so verification MUST fail.
//! - [`KeyResolutionFailMode::FailOpen`] — return an empty key set on
//!   network failure (callers will then fail at signature verification
//!   anyway). Useful for "we have a pinned key in the store, the network
//!   is just down" deployments.
//! - [`KeyResolutionFailMode::SoftFail`] — log + return empty. Identical
//!   on the wire to FailOpen; observability differs.
//!
//! Peer Manifest resolution failure is **always** fail-closed regardless
//! of policy — a verifying peer with no key cannot compute the
//! safe subset.

use crate::client::JwksFetcher;
use aitp_handshake::{JwkPublicKey, JwksResolver, ResolveError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use url::Url;

/// Fail mode applied when **OIDC issuer** key resolution falls through
/// every source.
///
/// Peer Manifest resolution does not honor this — see module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyResolutionFailMode {
    /// Resolution miss → `ResolveError`. Default.
    FailClosed,
    /// Resolution miss → `Ok(vec![])`. Verification fails at the
    /// signature step instead of at resolution. Useful when an
    /// already-cached pinned key is expected to satisfy verification
    /// even when the network source is unreachable.
    FailOpen,
    /// Same wire behavior as `FailOpen`; reserved for callers that
    /// want a distinct telemetry signal for "network down vs. truly
    /// unknown issuer". The current implementation does not log
    /// directly — wrap with your own observability layer.
    SoftFail,
}

impl Default for KeyResolutionFailMode {
    fn default() -> Self {
        Self::FailClosed
    }
}

/// Operator-supplied pinned mapping issuer URI → trusted JWKs.
///
/// Implementations MUST be sync and cheap to call; the resolver may
/// consult them on every verification. Look-up is by exact URL
/// (canonicalized via `Url`'s comparison). For prefix or pattern
/// matching, wrap your own implementation.
pub trait PinnedIssuerKeyStore: Send + Sync {
    /// Return the pinned key set for `issuer`, or `None` if none.
    fn get(&self, issuer: &Url) -> Option<Vec<JwkPublicKey>>;
}

/// In-memory `PinnedIssuerKeyStore` backed by a `HashMap`.
pub struct StaticPinnedIssuerKeyStore {
    inner: HashMap<Url, Vec<JwkPublicKey>>,
}

impl StaticPinnedIssuerKeyStore {
    /// Build from an issuer → keys mapping.
    pub fn new(map: HashMap<Url, Vec<JwkPublicKey>>) -> Self {
        Self { inner: map }
    }
}

impl PinnedIssuerKeyStore for StaticPinnedIssuerKeyStore {
    fn get(&self, issuer: &Url) -> Option<Vec<JwkPublicKey>> {
        self.inner.get(issuer).cloned()
    }
}

/// Cache entry — keys are valid until `expires_at`.
struct CacheEntry {
    keys: Vec<JwkPublicKey>,
    expires_at: Instant,
}

/// Configurable key resolution policy implementing RFC-AITP-0007.
///
/// Construct with [`Self::builder`].
pub struct KeyResolutionPolicy {
    pinned: Option<Arc<dyn PinnedIssuerKeyStore>>,
    fetcher: Option<Arc<JwksFetcher>>,
    runtime: Option<tokio::runtime::Handle>,
    cache: RwLock<HashMap<Url, CacheEntry>>,
    cache_ttl: Duration,
    fail_mode: KeyResolutionFailMode,
    /// Suppresses [`fetcher`] use; only the pinned store + cache are
    /// consulted. Useful for tests and air-gapped deployments.
    offline: bool,
    /// Inflight resolutions are coalesced through this mutex to avoid
    /// thundering herd on the upstream. Coarse-grained — fine for the
    /// expected access patterns (handful of issuers, not per-request).
    inflight_lock: Mutex<()>,
}

impl KeyResolutionPolicy {
    /// Begin building a policy.
    pub fn builder() -> KeyResolutionPolicyBuilder {
        KeyResolutionPolicyBuilder::default()
    }

    fn cached(&self, issuer: &Url) -> Option<Vec<JwkPublicKey>> {
        let now = Instant::now();
        let cache = self.cache.read().ok()?;
        cache
            .get(issuer)
            .filter(|e| e.expires_at > now)
            .map(|e| e.keys.clone())
    }

    fn store(&self, issuer: &Url, keys: Vec<JwkPublicKey>) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                issuer.clone(),
                CacheEntry {
                    keys,
                    expires_at: Instant::now() + self.cache_ttl,
                },
            );
        }
    }

    /// Apply the configured fail mode to a fall-through.
    fn apply_fail_mode(
        &self,
        issuer: &Url,
        err_msg: String,
    ) -> Result<Vec<JwkPublicKey>, ResolveError> {
        match self.fail_mode {
            KeyResolutionFailMode::FailClosed => Err(ResolveError::NetworkError(format!(
                "key resolution exhausted all sources for {issuer}: {err_msg}"
            ))),
            KeyResolutionFailMode::FailOpen | KeyResolutionFailMode::SoftFail => Ok(Vec::new()),
        }
    }
}

impl JwksResolver for KeyResolutionPolicy {
    fn resolve(&self, issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        // 1. Cache.
        if let Some(keys) = self.cached(issuer) {
            return Ok(keys);
        }

        // Coalesce concurrent resolutions for the same call.
        let _guard = self.inflight_lock.lock().unwrap_or_else(|e| e.into_inner());

        // Re-check cache after acquiring the lock — another caller may
        // have populated it.
        if let Some(keys) = self.cached(issuer) {
            return Ok(keys);
        }

        // 2. Pinned issuer key store.
        if let Some(pinned) = self.pinned.as_ref() {
            if let Some(keys) = pinned.get(issuer) {
                self.store(issuer, keys.clone());
                return Ok(keys);
            }
        }

        if self.offline {
            return self.apply_fail_mode(issuer, "offline mode and no pinned keys".into());
        }

        // 3 + 4. Network: aitp-keys then OIDC JWKS. Both go through the
        // same `JwksFetcher::resolve`, which already encapsulates the
        // OIDC-then-aitp-keys fallback per RFC-AITP-0007 §2.3.
        let Some(fetcher) = self.fetcher.as_ref() else {
            return self.apply_fail_mode(
                issuer,
                "no JwksFetcher configured for network resolution".into(),
            );
        };
        let Some(rt) = self.runtime.as_ref() else {
            return self.apply_fail_mode(
                issuer,
                "no tokio runtime handle configured for network resolution".into(),
            );
        };

        let issuer_for_task = issuer.clone();
        let fetcher_for_task = fetcher.clone();
        let result = tokio::task::block_in_place(|| {
            rt.block_on(async move { fetcher_for_task.resolve(&issuer_for_task).await })
        });

        match result {
            Ok(keys) => {
                self.store(issuer, keys.clone());
                Ok(keys)
            }
            Err(e) => self.apply_fail_mode(issuer, e.to_string()),
        }
    }
}

/// Builder for [`KeyResolutionPolicy`].
#[derive(Default)]
pub struct KeyResolutionPolicyBuilder {
    pinned: Option<Arc<dyn PinnedIssuerKeyStore>>,
    fetcher: Option<Arc<JwksFetcher>>,
    runtime: Option<tokio::runtime::Handle>,
    cache_ttl: Option<Duration>,
    fail_mode: Option<KeyResolutionFailMode>,
    offline: bool,
}

impl KeyResolutionPolicyBuilder {
    /// Configure the pinned issuer key store (RFC-AITP-0007 §2.2).
    pub fn with_pinned_issuer_store(mut self, store: Arc<dyn PinnedIssuerKeyStore>) -> Self {
        self.pinned = Some(store);
        self
    }

    /// Configure the network fetcher and the tokio runtime to call into.
    /// Both are required to enable steps 3 and 4 of the resolution order.
    pub fn with_fetcher(
        mut self,
        fetcher: Arc<JwksFetcher>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        self.fetcher = Some(fetcher);
        self.runtime = Some(runtime);
        self
    }

    /// Override the in-memory cache TTL. Default 10 minutes.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = Some(ttl);
        self
    }

    /// Override the fail mode. Default `FailClosed`.
    pub fn with_fail_mode(mut self, mode: KeyResolutionFailMode) -> Self {
        self.fail_mode = Some(mode);
        self
    }

    /// Disable network resolution entirely; only cache + pinned store
    /// will be consulted. Used by air-gapped deployments and tests.
    pub fn offline(mut self, value: bool) -> Self {
        self.offline = value;
        self
    }

    /// Finalize the policy.
    pub fn build(self) -> KeyResolutionPolicy {
        KeyResolutionPolicy {
            pinned: self.pinned,
            fetcher: self.fetcher,
            runtime: self.runtime,
            cache: RwLock::new(HashMap::new()),
            cache_ttl: self.cache_ttl.unwrap_or(Duration::from_secs(600)),
            fail_mode: self.fail_mode.unwrap_or_default(),
            offline: self.offline,
            inflight_lock: Mutex::new(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::Algorithm;

    fn fake_jwk() -> JwkPublicKey {
        JwkPublicKey {
            kid: Some("k1".into()),
            alg: Algorithm::EdDSA,
            key: jsonwebtoken::DecodingKey::from_ed_der(&[0u8; 32]),
        }
    }

    #[test]
    fn cache_hit_short_circuits() {
        let policy = KeyResolutionPolicy::builder()
            .with_cache_ttl(Duration::from_secs(60))
            .build();
        let issuer: Url = "https://idp.example.com".parse().unwrap();
        policy.store(&issuer, vec![fake_jwk()]);
        let got = policy.resolve(&issuer).unwrap();
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn pinned_store_used_before_network() {
        let mut map = HashMap::new();
        let issuer: Url = "https://idp.example.com".parse().unwrap();
        map.insert(issuer.clone(), vec![fake_jwk()]);
        let policy = KeyResolutionPolicy::builder()
            .with_pinned_issuer_store(Arc::new(StaticPinnedIssuerKeyStore::new(map)))
            .offline(true)
            .build();
        let got = policy.resolve(&issuer).unwrap();
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn fail_closed_when_no_sources() {
        let policy = KeyResolutionPolicy::builder().offline(true).build();
        let issuer: Url = "https://idp.example.com".parse().unwrap();
        let err = policy.resolve(&issuer).unwrap_err();
        match err {
            ResolveError::NetworkError(_) => {}
            _ => panic!("expected NetworkError, got {err:?}"),
        }
    }

    #[test]
    fn fail_open_returns_empty() {
        let policy = KeyResolutionPolicy::builder()
            .offline(true)
            .with_fail_mode(KeyResolutionFailMode::FailOpen)
            .build();
        let issuer: Url = "https://idp.example.com".parse().unwrap();
        let got = policy.resolve(&issuer).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn cache_expiry_evicts() {
        let policy = KeyResolutionPolicy::builder()
            .with_cache_ttl(Duration::from_millis(0))
            .offline(true)
            .build();
        let issuer: Url = "https://idp.example.com".parse().unwrap();
        policy.store(&issuer, vec![fake_jwk()]);
        std::thread::sleep(Duration::from_millis(5));
        // Cache expired → falls through to "no sources" → fail-closed.
        assert!(policy.resolve(&issuer).is_err());
    }
}
