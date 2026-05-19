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
//! - [`KeyResolutionFailMode::SoftFail`] — the plain `resolve()` path
//!   fails closed with [`ResolveError::SoftFailRequiresOutcome`]. A
//!   degraded session restricted to `safe_grants` is reachable only via
//!   [`KeyResolutionPolicy::resolve_outcome`], which surfaces the
//!   subset explicitly. Unlike `FailOpen`, `SoftFail` never returns an
//!   empty key set from `resolve()` — that would silently drop the
//!   safe-grants signal.
//!
//! Peer Manifest resolution failure is **always** fail-closed regardless
//! of policy — a verifying peer with no key cannot compute the
//! safe subset.

use crate::client::JwksFetcher;
use aitp_handshake::{JwkPublicKey, JwksResolver, ResolveError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tracing::debug;
use url::Url;

/// Fail mode applied when **OIDC issuer** key resolution falls through
/// every source.
///
/// Peer Manifest resolution does not honor this — see module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyResolutionFailMode {
    /// Resolution miss → `ResolveError`. Default.
    FailClosed,
    /// Resolution miss → `Ok(vec![])`. Verification fails at the
    /// signature step instead of at resolution. Useful when an
    /// already-cached pinned key is expected to satisfy verification
    /// even when the network source is unreachable.
    FailOpen,
    /// Degraded mode (RFC-AITP-0007 §3.2): when resolution falls
    /// through all sources, the session MAY continue but MUST restrict
    /// its effective grants to `safe_grants`. The plain `resolve()`
    /// path fails closed ([`ResolveError::SoftFailRequiresOutcome`]);
    /// the degraded outcome is reachable only via
    /// [`KeyResolutionPolicy::resolve_outcome`], which returns
    /// [`KeyResolutionOutcome::SoftFailDegraded`] carrying the subset.
    /// This keeps `SoftFail` distinguishable from `FailOpen` — a caller
    /// that only ever calls `resolve()` can never silently enter a
    /// degraded session.
    ///
    /// An empty `safe_grants` vector is rejected as fail-closed —
    /// there is no safe way to degrade if no safe subset has been
    /// declared.
    SoftFail {
        /// Capability identifiers the operator has pre-declared as
        /// safe to honor when the issuer's keys cannot be resolved.
        /// Typically a minimal read-only or status-only subset.
        safe_grants: Vec<String>,
    },
}

/// Outcome of a `resolve_outcome` call.
///
/// Use this when the caller needs to distinguish a clean resolution
/// (where signature verification can proceed) from a soft-fail
/// degradation (where signature verification is impossible but the
/// session may continue with a restricted grant subset).
///
/// [`JwkPublicKey`] is not `PartialEq` (its `DecodingKey` field
/// deliberately hides internals), so this enum doesn't derive
/// equality. Match on the variants instead.
#[derive(Clone, Debug)]
pub enum KeyResolutionOutcome {
    /// Keys resolved cleanly; downstream signature verification
    /// proceeds normally with this set.
    Resolved(Vec<JwkPublicKey>),
    /// Resolution exhausted all sources; the configured
    /// `safe_grants` are the only grants the session should honor.
    /// Signature verification of issuer-signed claims (OIDC JWTs)
    /// MUST be considered failed by the caller.
    SoftFailDegraded {
        /// Subset of capabilities the operator pre-declared as safe.
        safe_grants: Vec<String>,
    },
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
        match &self.fail_mode {
            KeyResolutionFailMode::FailClosed => Err(ResolveError::NetworkError(format!(
                "key resolution exhausted all sources for {issuer}: {err_msg}"
            ))),
            KeyResolutionFailMode::FailOpen => Ok(Vec::new()),
            KeyResolutionFailMode::SoftFail { safe_grants } => {
                if safe_grants.is_empty() {
                    Err(ResolveError::NoPinnedKeys)
                } else {
                    // Fail closed on the plain `resolve()` path. A
                    // degraded session restricted to `safe_grants` is
                    // only reachable via `resolve_outcome()`, which
                    // surfaces the subset explicitly. Returning an
                    // empty key vec here would be wire-indistinguishable
                    // from `FailOpen` and would silently drop the
                    // safe-grants signal (RFC-AITP-0007 §3.2).
                    Err(ResolveError::SoftFailRequiresOutcome)
                }
            }
        }
    }

    /// Resolution with richer outcome semantics. Use this instead of
    /// the bare `JwksResolver::resolve` when the caller needs to
    /// distinguish a clean signature-verifiable resolution from a
    /// soft-fail degradation that restricts grants to a safe subset.
    ///
    /// The contract:
    /// - `KeyResolutionOutcome::Resolved(keys)` — keys were found
    ///   (from cache, pinned store, or network).
    /// - `KeyResolutionOutcome::SoftFailDegraded { safe_grants }` —
    ///   resolution exhausted all sources, the configured fail mode
    ///   is `SoftFail { safe_grants }` with a non-empty subset, and
    ///   the caller MUST restrict the session's effective grants to
    ///   that subset (and treat issuer-signature checks as failed).
    /// - `Err(ResolveError::NoPinnedKeys)` — `SoftFail` with no
    ///   safe-grants subset; fail-closed.
    /// - `Err(_)` — other configured fail-modes (`FailClosed`,
    ///   network errors) bubble up as before.
    pub fn resolve_outcome(&self, issuer: &Url) -> Result<KeyResolutionOutcome, ResolveError> {
        match <Self as JwksResolver>::resolve(self, issuer) {
            Ok(keys) if !keys.is_empty() => Ok(KeyResolutionOutcome::Resolved(keys)),
            // `FailOpen` with no keys: keep the empty-`Resolved`
            // semantics so the caller's downstream signature step
            // fails (matching the legacy behavior).
            Ok(empty) => Ok(KeyResolutionOutcome::Resolved(empty)),
            // `SoftFail` with a non-empty safe-grants subset:
            // `resolve()` fails closed with `SoftFailRequiresOutcome`.
            // `resolve_outcome()` is the one path allowed to enter a
            // degraded session, so it converts that error into the
            // explicit `SoftFailDegraded` outcome carrying the subset.
            Err(ResolveError::SoftFailRequiresOutcome) => match &self.fail_mode {
                KeyResolutionFailMode::SoftFail { safe_grants } if !safe_grants.is_empty() => {
                    Ok(KeyResolutionOutcome::SoftFailDegraded {
                        safe_grants: safe_grants.clone(),
                    })
                }
                // `SoftFailRequiresOutcome` is only produced by the
                // SoftFail-with-non-empty-subset branch of
                // `apply_fail_mode`; this arm is unreachable. Fail
                // closed defensively rather than panicking.
                _ => Err(ResolveError::SoftFailRequiresOutcome),
            },
            Err(e) => Err(e),
        }
    }
}

impl JwksResolver for KeyResolutionPolicy {
    fn resolve(&self, issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        // 1. Cache.
        if let Some(keys) = self.cached(issuer) {
            debug!(%issuer, source = "cache", "JWKS resolved");
            return Ok(keys);
        }

        // Coalesce concurrent resolutions for the same call.
        let _guard = self.inflight_lock.lock().unwrap_or_else(|e| e.into_inner());

        // Re-check cache after acquiring the lock — another caller may
        // have populated it.
        if let Some(keys) = self.cached(issuer) {
            debug!(%issuer, source = "cache", "JWKS resolved (after lock)");
            return Ok(keys);
        }

        // 2. Pinned issuer key store.
        if let Some(pinned) = self.pinned.as_ref() {
            if let Some(keys) = pinned.get(issuer) {
                debug!(%issuer, source = "pinned_store", "JWKS resolved");
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
        let result = match rt.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => {
                // Safe on a multi-thread runtime: `block_in_place`
                // moves the current worker out of the async pool while
                // it blocks, so other tasks keep making progress.
                tokio::task::block_in_place(|| {
                    rt.block_on(async move { fetcher_for_task.resolve(&issuer_for_task).await })
                })
            }
            _ => {
                // Current-thread runtime: `block_in_place` would panic,
                // and a sync→async bridge would deadlock the single
                // worker regardless. Direct the caller to the async
                // path instead of panicking (RFC-AITP-0007 — this is a
                // deployment/runtime misconfiguration, surfaced as a
                // hard error rather than a degraded resolution).
                return Err(ResolveError::NetworkError(
                    "sync JwksResolver::resolve cannot bridge JWKS network I/O into a \
                     current-thread tokio runtime; call AsyncJwksResolver::resolve_async \
                     from async context (e.g. to pre-warm the cache) instead"
                        .into(),
                ));
            }
        };

        match result {
            Ok(keys) => {
                debug!(%issuer, source = "network", "JWKS resolved");
                self.store(issuer, keys.clone());
                Ok(keys)
            }
            Err(e) => self.apply_fail_mode(issuer, e.to_string()),
        }
    }
}

/// Async JWKS resolution — the non-blocking counterpart to
/// [`JwksResolver`].
///
/// The sync `JwksResolver::resolve` bridges into async network I/O via
/// `tokio::task::block_in_place`, which **panics on a current-thread
/// tokio runtime** (and would deadlock there anyway). Async callers —
/// e.g. an axum handler resolving an issuer's keys — should use this
/// trait instead: `resolve_async` awaits the fetch directly on the
/// caller's runtime, with no `block_in_place`.
///
/// A common pattern is to call `resolve_async` once from async context
/// to pre-warm the resolver's cache, after which the sync
/// `JwksResolver::resolve` path (used by the synchronous handshake
/// verification crates) is a pure cache hit and never reaches
/// `block_in_place`.
pub trait AsyncJwksResolver: Send + Sync {
    /// Resolve `issuer`'s JWKS, awaiting any network I/O directly on
    /// the caller's runtime. Resolution order matches
    /// [`JwksResolver::resolve`]: cache → pinned store → network.
    fn resolve_async(
        &self,
        issuer: &Url,
    ) -> impl std::future::Future<Output = Result<Vec<JwkPublicKey>, ResolveError>> + Send;
}

impl AsyncJwksResolver for KeyResolutionPolicy {
    async fn resolve_async(&self, issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        // 1. Cache.
        if let Some(keys) = self.cached(issuer) {
            debug!(%issuer, source = "cache", "JWKS resolved (async)");
            return Ok(keys);
        }

        // 2. Pinned issuer key store. (The async path intentionally
        // skips the `inflight_lock` coalescing used by the sync path —
        // a `std::sync::Mutex` must not be held across an `.await`. The
        // cache below de-duplicates any concurrent resolutions.)
        if let Some(pinned) = self.pinned.as_ref() {
            if let Some(keys) = pinned.get(issuer) {
                debug!(%issuer, source = "pinned_store", "JWKS resolved (async)");
                self.store(issuer, keys.clone());
                return Ok(keys);
            }
        }

        if self.offline {
            return self.apply_fail_mode(issuer, "offline mode and no pinned keys".into());
        }

        // 3 + 4. Network — awaited directly, no `block_in_place`.
        let Some(fetcher) = self.fetcher.as_ref() else {
            return self.apply_fail_mode(
                issuer,
                "no JwksFetcher configured for network resolution".into(),
            );
        };
        match fetcher.resolve(issuer).await {
            Ok(keys) => {
                debug!(%issuer, source = "network", "JWKS resolved (async)");
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
    fn soft_fail_with_safe_grants_returns_degraded_outcome() {
        let policy = KeyResolutionPolicy::builder()
            .offline(true)
            .with_fail_mode(KeyResolutionFailMode::SoftFail {
                safe_grants: vec!["status.read".into()],
            })
            .build();
        let issuer: Url = "https://idp.example.com".parse().unwrap();
        match policy.resolve_outcome(&issuer).unwrap() {
            KeyResolutionOutcome::SoftFailDegraded { safe_grants } => {
                assert_eq!(safe_grants, vec!["status.read"]);
            }
            other => panic!("expected SoftFailDegraded, got {other:?}"),
        }
    }

    #[test]
    fn soft_fail_plain_resolve_fails_closed() {
        // RFC-AITP-0007 §3.2 / BUG-2: the plain `resolve()` path under
        // `SoftFail` with a non-empty subset must fail closed rather
        // than return `Ok(vec![])`. An empty key set would be
        // wire-indistinguishable from `FailOpen` and would let a caller
        // that never calls `resolve_outcome()` silently lose the
        // safe-grants restriction.
        let policy = KeyResolutionPolicy::builder()
            .offline(true)
            .with_fail_mode(KeyResolutionFailMode::SoftFail {
                safe_grants: vec!["status.read".into()],
            })
            .build();
        let issuer: Url = "https://idp.example.com".parse().unwrap();
        let err = policy.resolve(&issuer).unwrap_err();
        assert!(
            matches!(err, ResolveError::SoftFailRequiresOutcome),
            "plain resolve() under SoftFail must fail closed, got {err:?}"
        );
    }

    #[test]
    fn soft_fail_with_empty_safe_grants_is_fail_closed() {
        let policy = KeyResolutionPolicy::builder()
            .offline(true)
            .with_fail_mode(KeyResolutionFailMode::SoftFail {
                safe_grants: Vec::new(),
            })
            .build();
        let issuer: Url = "https://idp.example.com".parse().unwrap();
        let err = policy.resolve(&issuer).unwrap_err();
        assert!(
            matches!(err, ResolveError::NoPinnedKeys),
            "expected NoPinnedKeys, got {err:?}"
        );
    }

    #[test]
    fn resolve_async_uses_pinned_store() {
        let mut map = HashMap::new();
        let issuer: Url = "https://idp.example.com".parse().unwrap();
        map.insert(issuer.clone(), vec![fake_jwk()]);
        let policy = KeyResolutionPolicy::builder()
            .with_pinned_issuer_store(Arc::new(StaticPinnedIssuerKeyStore::new(map)))
            .offline(true)
            .build();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let got = rt
            .block_on(async { policy.resolve_async(&issuer).await })
            .unwrap();
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn resolve_async_fail_closed_when_no_sources() {
        let policy = KeyResolutionPolicy::builder().offline(true).build();
        let issuer: Url = "https://idp.example.com".parse().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(async { policy.resolve_async(&issuer).await })
            .unwrap_err();
        assert!(
            matches!(err, ResolveError::NetworkError(_)),
            "expected NetworkError, got {err:?}"
        );
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
