//! Key resolution policy (RFC-AITP-0007).
//!
//! Composes a [`PinnedIssuerKeyStore`], a [`JwksFetcher`] and an
//! in-memory cache into a single [`JwksResolver`]. Resolution proceeds
//! as follows:
//!
//! 1. **Cache** (unexpired) — short-circuit, never network. A fresh
//!    negative-cache entry likewise short-circuits to the fail mode.
//! 2. **Pinned issuer key store** — operator-supplied issuer →
//!    `Vec<JwkPublicKey>` mapping. Survives outages. In offline mode
//!    resolution stops here.
//! 3. **Network**, via [`JwksFetcher::resolve`]. Per RFC-AITP-0007 §2.3
//!    this is a branch, not a priority list: OIDC discovery
//!    (`/.well-known/openid-configuration` → `jwks_uri`) is tried first;
//!    `/.well-known/aitp-keys` is consulted only when discovery is not
//!    validly exposed. Once discovery yields a usable `jwks_uri`, a JWKS
//!    fetch failure is surfaced and `aitp-keys` is never tried.
//!
//! Step 3 runs only in [`JwksResolver::prefetch`], which is async and
//! stores its result (keys in the cache, a failure in the negative
//! cache). The synchronous [`JwksResolver::resolve`] that the handshake
//! state machine calls runs steps 1 and 2 only; an issuer that was not
//! prefetched gets the fail mode, which under `FailClosed` is a
//! `KEY_RESOLUTION_FAILED` (retryable) handshake error. The HTTP
//! transport prefetches the peer's OIDC issuer before each synchronous
//! step, so `resolve` never blocks a runtime thread on I/O.
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

use crate::core::BoxFuture;
use crate::handshake::{JwkPublicKey, JwksResolver, ResolveError};
use crate::transport::client::JwksFetcher;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;
use url::Url;

/// Fail mode applied when **OIDC issuer** key resolution falls through
/// every source.
///
/// Peer Manifest resolution does not honor this — see module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
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
/// Exhaustive on purpose, like [`crate::tct::RevocationStatus`]. Both
/// variants are `#[non_exhaustive]`, so a release may add a field to
/// either: match them as `Resolved(keys, ..)` and
/// `SoftFailDegraded { safe_grants, .. }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyResolutionOutcome {
    /// Keys resolved cleanly; downstream signature verification
    /// proceeds normally with this set.
    #[non_exhaustive]
    Resolved(Vec<JwkPublicKey>),
    /// Resolution exhausted all sources; the configured
    /// `safe_grants` are the only grants the session should honor.
    /// Signature verification of issuer-signed claims (OIDC JWTs)
    /// MUST be considered failed by the caller.
    #[non_exhaustive]
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
#[derive(Debug)]
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

/// Negative-cache entry — remembers that a recent resolution attempt
/// failed, suppresses retries until `expires_at`. Defends against
/// retry-storm amplification when an upstream JWKS is hard-down: an
/// active deployment would otherwise hit the network on every single
/// signature check until the next successful resolution. The error
/// message is preserved so subsequent callers receive the same
/// structured failure rather than a generic "no keys" placeholder.
struct NegativeCacheEntry {
    message: String,
    expires_at: Instant,
}

/// Default lifetime of a negative-cache entry: cache failed
/// resolutions for 30 seconds. Short enough to recover quickly when
/// the upstream comes back, long enough to amortize per-request
/// retries during a sustained outage. Tunable via
/// [`KeyResolutionPolicyBuilder::with_negative_cache_ttl`]; set to
/// [`Duration::ZERO`] to disable.
pub const DEFAULT_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);

/// Configurable key resolution policy implementing RFC-AITP-0007.
///
/// Construct with [`Self::builder`].
pub struct KeyResolutionPolicy {
    pinned: Option<Arc<dyn PinnedIssuerKeyStore>>,
    fetcher: Option<Arc<JwksFetcher>>,
    cache: RwLock<HashMap<Url, CacheEntry>>,
    cache_ttl: Duration,
    /// Negative cache: short-lived record of recent resolution
    /// failures, used to bound retry rate against a hard-down
    /// upstream. Keyed by issuer URL; entries expire after
    /// `negative_cache_ttl`. Disabled when `negative_cache_ttl` is
    /// [`Duration::ZERO`].
    negative_cache: RwLock<HashMap<Url, NegativeCacheEntry>>,
    negative_cache_ttl: Duration,
    fail_mode: KeyResolutionFailMode,
    /// Suppresses [`fetcher`] use; only the pinned store + cache are
    /// consulted. Useful for tests and air-gapped deployments.
    offline: bool,
}

impl std::fmt::Debug for KeyResolutionPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyResolutionPolicy")
            .field("cache_ttl", &self.cache_ttl)
            .field("negative_cache_ttl", &self.negative_cache_ttl)
            .field("fail_mode", &self.fail_mode)
            .field("offline", &self.offline)
            .finish_non_exhaustive()
    }
}

impl KeyResolutionPolicy {
    /// Begin building a policy.
    pub fn builder() -> KeyResolutionPolicyBuilder {
        KeyResolutionPolicyBuilder::default()
    }

    fn cached(&self, issuer: &Url) -> Option<Vec<JwkPublicKey>> {
        let now = Instant::now();
        let cache = self.cache.read();
        cache
            .get(issuer)
            .filter(|e| e.expires_at > now)
            .map(|e| e.keys.clone())
    }

    fn store(&self, issuer: &Url, keys: Vec<JwkPublicKey>) {
        {
            let mut cache = self.cache.write();
            cache.insert(
                issuer.clone(),
                CacheEntry {
                    keys,
                    expires_at: Instant::now() + self.cache_ttl,
                },
            );
        }
        // A successful resolution invalidates any prior negative-cache
        // entry for the same issuer, so callers see the fresh keys
        // rather than the stale failure record.
        if self.negative_cache_ttl > Duration::ZERO {
            self.negative_cache.write().remove(issuer);
        }
    }

    /// Look up a fresh negative-cache entry for `issuer`. Returns
    /// `Some(err_msg)` if a failed resolution is currently being
    /// suppressed, otherwise `None`. Lazily drops expired entries on
    /// hit; bulk eviction happens on `store_failure`.
    fn cached_failure(&self, issuer: &Url) -> Option<String> {
        if self.negative_cache_ttl == Duration::ZERO {
            return None;
        }
        let now = Instant::now();
        let cache = self.negative_cache.read();
        cache
            .get(issuer)
            .filter(|e| e.expires_at > now)
            .map(|e| e.message.clone())
    }

    /// Record that resolution failed for `issuer`. Suppresses retries
    /// until the negative-cache TTL elapses. No-op when the negative
    /// cache is disabled.
    fn store_failure(&self, issuer: &Url, message: &str) {
        if self.negative_cache_ttl == Duration::ZERO {
            return;
        }
        let mut neg = self.negative_cache.write();
        let now = Instant::now();
        neg.retain(|_, e| e.expires_at > now);
        neg.insert(
            issuer.clone(),
            NegativeCacheEntry {
                message: message.to_string(),
                expires_at: now + self.negative_cache_ttl,
            },
        );
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

impl KeyResolutionPolicy {
    /// Steps 1 and 2: the cache, the negative cache and the pinned store.
    /// `None` means neither holds an answer for `issuer`.
    fn resolve_local(&self, issuer: &Url) -> Option<Result<Vec<JwkPublicKey>, ResolveError>> {
        if let Some(keys) = self.cached(issuer) {
            crate::transport::obs::jwks_cache("hit");
            debug!(%issuer, source = "cache", "JWKS resolved");
            return Some(Ok(keys));
        }
        if let Some(msg) = self.cached_failure(issuer) {
            crate::transport::obs::jwks_cache("negative_hit");
            debug!(%issuer, source = "negative_cache", "JWKS resolution suppressed");
            return Some(self.apply_fail_mode(issuer, format!("negative-cached: {msg}")));
        }
        crate::transport::obs::jwks_cache("miss");
        let keys = self.pinned.as_ref()?.get(issuer)?;
        debug!(%issuer, source = "pinned_store", "JWKS resolved");
        self.store(issuer, keys.clone());
        Some(Ok(keys))
    }
}

impl JwksResolver for KeyResolutionPolicy {
    /// Steps 1 and 2 only; no I/O. An issuer neither cached nor pinned
    /// gets the configured fail mode.
    fn resolve(&self, issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        if let Some(result) = self.resolve_local(issuer) {
            return result;
        }
        let reason = if self.offline {
            "offline mode and no pinned keys"
        } else if self.fetcher.is_none() {
            "no JwksFetcher configured for network resolution"
        } else {
            "issuer keys are not cached; JwksResolver::prefetch fetches them"
        };
        self.apply_fail_mode(issuer, reason.into())
    }

    /// Step 3: fetch `issuer`'s keys over the network unless the cache,
    /// negative cache or pinned store already answers, and store the
    /// result for [`Self::resolve`].
    fn prefetch<'a>(&'a self, issuer: &'a Url) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if self.resolve_local(issuer).is_some() || self.offline {
                return;
            }
            let Some(fetcher) = self.fetcher.as_ref() else {
                return;
            };
            match fetcher.resolve(issuer).await {
                Ok(keys) => {
                    debug!(%issuer, source = "network", "JWKS resolved");
                    self.store(issuer, keys);
                }
                Err(e) => {
                    debug!(%issuer, error = %e, "JWKS fetch failed");
                    self.store_failure(issuer, &e.to_string());
                }
            }
        })
    }
}

/// Builder for [`KeyResolutionPolicy`].
#[derive(Default)]
pub struct KeyResolutionPolicyBuilder {
    pinned: Option<Arc<dyn PinnedIssuerKeyStore>>,
    fetcher: Option<Arc<JwksFetcher>>,
    cache_ttl: Option<Duration>,
    negative_cache_ttl: Option<Duration>,
    fail_mode: Option<KeyResolutionFailMode>,
    offline: bool,
}

impl std::fmt::Debug for KeyResolutionPolicyBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyResolutionPolicyBuilder")
            .field("cache_ttl", &self.cache_ttl)
            .field("negative_cache_ttl", &self.negative_cache_ttl)
            .field("fail_mode", &self.fail_mode)
            .field("offline", &self.offline)
            .finish_non_exhaustive()
    }
}

impl KeyResolutionPolicyBuilder {
    /// Configure the pinned issuer key store (RFC-AITP-0007 §2.2).
    pub fn with_pinned_issuer_store(mut self, store: Arc<dyn PinnedIssuerKeyStore>) -> Self {
        self.pinned = Some(store);
        self
    }

    /// Configure the network fetcher, which enables step 3 of the
    /// resolution order in [`JwksResolver::prefetch`].
    pub fn with_fetcher(mut self, fetcher: Arc<JwksFetcher>) -> Self {
        self.fetcher = Some(fetcher);
        self
    }

    /// Override the in-memory cache TTL. Default 10 minutes.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = Some(ttl);
        self
    }

    /// Override the negative-cache TTL — the window for which a
    /// failed resolution suppresses retries. Default
    /// [`DEFAULT_NEGATIVE_CACHE_TTL`] (30 seconds). Set to
    /// [`Duration::ZERO`] to disable the negative cache and retry
    /// the upstream on every signature check (legacy rc.1 behavior).
    ///
    /// Recommended: keep enabled. Without negative caching, an
    /// upstream JWKS that is hard-down causes every TCT verification
    /// to re-attempt the network, which both slows the local request
    /// path and prolongs the upstream's recovery.
    pub fn with_negative_cache_ttl(mut self, ttl: Duration) -> Self {
        self.negative_cache_ttl = Some(ttl);
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
            cache: RwLock::new(HashMap::new()),
            cache_ttl: self.cache_ttl.unwrap_or(Duration::from_secs(600)),
            negative_cache: RwLock::new(HashMap::new()),
            negative_cache_ttl: self
                .negative_cache_ttl
                .unwrap_or(DEFAULT_NEGATIVE_CACHE_TTL),
            fail_mode: self.fail_mode.unwrap_or_default(),
            offline: self.offline,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{JwkKeyMaterial, JwsAlgorithm};

    fn fake_jwk() -> JwkPublicKey {
        JwkPublicKey {
            kid: Some("k1".into()),
            alg: Some(JwsAlgorithm::EdDSA),
            key: JwkKeyMaterial::Ed25519 { x: [0u8; 32] },
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
    fn negative_cache_short_circuits_repeat_failures() {
        // Verify that a stored failure is returned from the negative
        // cache rather than re-attempting the (absent) network. Uses
        // `offline=true` so any retry would surface a clean error,
        // letting us assert on the cached-failure message.
        let policy = KeyResolutionPolicy::builder()
            .offline(true)
            .with_negative_cache_ttl(Duration::from_secs(30))
            .build();
        let issuer: Url = "https://down.example.com".parse().unwrap();
        // Seed a failure directly so we don't need a live fetcher.
        policy.store_failure(&issuer, "upstream 503");
        let err = policy.resolve(&issuer).unwrap_err();
        let msg = match err {
            ResolveError::NetworkError(s) => s,
            other => panic!("expected NetworkError, got {other:?}"),
        };
        assert!(
            msg.contains("negative-cached"),
            "expected negative-cache message, got: {msg}"
        );
        assert!(
            msg.contains("upstream 503"),
            "expected original failure message preserved, got: {msg}"
        );
    }

    #[test]
    fn negative_cache_can_be_disabled() {
        let policy = KeyResolutionPolicy::builder()
            .offline(true)
            .with_negative_cache_ttl(Duration::ZERO)
            .build();
        let issuer: Url = "https://down.example.com".parse().unwrap();
        policy.store_failure(&issuer, "should be ignored");
        // With ttl=0, store_failure is a no-op; cached_failure returns None.
        assert!(policy.cached_failure(&issuer).is_none());
    }

    #[test]
    fn negative_cache_cleared_by_successful_resolution() {
        let policy = KeyResolutionPolicy::builder()
            .with_cache_ttl(Duration::from_secs(60))
            .with_negative_cache_ttl(Duration::from_secs(60))
            .build();
        let issuer: Url = "https://flapping.example.com".parse().unwrap();
        policy.store_failure(&issuer, "transient 502");
        assert!(policy.cached_failure(&issuer).is_some());
        policy.store(&issuer, vec![fake_jwk()]);
        assert!(
            policy.cached_failure(&issuer).is_none(),
            "a successful resolution must clear the negative-cache entry"
        );
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

    #[tokio::test]
    async fn prefetch_then_resolve_uses_pinned_store() {
        let mut map = HashMap::new();
        let issuer: Url = "https://idp.example.com".parse().unwrap();
        map.insert(issuer.clone(), vec![fake_jwk()]);
        let policy = KeyResolutionPolicy::builder()
            .with_pinned_issuer_store(Arc::new(StaticPinnedIssuerKeyStore::new(map)))
            .offline(true)
            .build();
        policy.prefetch(&issuer).await;
        assert_eq!(policy.cached(&issuer).map(|k| k.len()), Some(1));
        assert_eq!(policy.resolve(&issuer).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn prefetch_fail_closed_when_no_sources() {
        let policy = KeyResolutionPolicy::builder().offline(true).build();
        let issuer: Url = "https://idp.example.com".parse().unwrap();
        policy.prefetch(&issuer).await;
        let err = policy.resolve(&issuer).unwrap_err();
        assert!(
            matches!(err, ResolveError::NetworkError(_)),
            "expected NetworkError, got {err:?}"
        );
    }

    /// With a fetcher configured, the synchronous `resolve` does no I/O:
    /// an issuer that was not prefetched gets the fail mode.
    #[test]
    fn resolve_without_prefetch_fails_closed_without_io() {
        let policy = KeyResolutionPolicy::builder()
            .with_fetcher(Arc::new(JwksFetcher::new()))
            .build();
        let issuer: Url = "https://idp.example.com".parse().unwrap();
        match policy.resolve(&issuer).unwrap_err() {
            ResolveError::NetworkError(msg) => assert!(msg.contains("prefetch"), "{msg}"),
            other => panic!("expected NetworkError, got {other:?}"),
        }
    }

    /// A failed network prefetch is negative-cached and reported by the
    /// synchronous `resolve`.
    #[tokio::test]
    async fn failed_prefetch_is_reported_by_resolve() {
        let policy = KeyResolutionPolicy::builder()
            .with_fetcher(Arc::new(JwksFetcher::new()))
            .build();
        // A plain-http issuer is refused by the fetcher before any I/O.
        let issuer: Url = "http://idp.example.com".parse().unwrap();
        policy.prefetch(&issuer).await;
        assert!(policy.cached_failure(&issuer).is_some());
        match policy.resolve(&issuer).unwrap_err() {
            ResolveError::NetworkError(msg) => assert!(msg.contains("negative-cached"), "{msg}"),
            other => panic!("expected NetworkError, got {other:?}"),
        }
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
