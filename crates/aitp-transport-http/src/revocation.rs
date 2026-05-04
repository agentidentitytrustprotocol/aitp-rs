//! Revocation policy + per-issuer revocation cache (RFC-AITP-0008).
//!
//! Composes a [`RevocationProvider`] (typically the HTTP fetcher in
//! [`crate::client::RevocationFetcher`]) with a per-issuer cache, applies
//! a configurable [`RevocationFailMode`] when the network source is
//! unreachable, and exposes a `is_revoked(jti, issuer)` decision for
//! handshake / TCT verifiers.

use aitp_core::{Aid, Timestamp};
use aitp_tct::{
    verify_revocation_list, RevocationListEnvelope, TctError, VerifyRevocationListContext,
};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;
use uuid::Uuid;

/// Source of revocation snapshots — typically backed by an HTTP fetch.
///
/// Implementations are sync. The concrete HTTP fetcher in this crate
/// bridges into a tokio runtime to call its async client.
pub trait RevocationProvider: Send + Sync {
    /// Fetch the latest signed snapshot for `issuer`.
    fn fetch(&self, issuer: &Aid) -> Result<RevocationListEnvelope, RevocationError>;
}

/// Errors raised when fetching or applying a revocation snapshot.
#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    /// Underlying network/transport error.
    #[error("network error: {0}")]
    Network(String),
    /// Snapshot signature did not verify.
    #[error("snapshot signature invalid: {0}")]
    SignatureInvalid(TctError),
    /// Snapshot's `expires_at` predates `now`.
    #[error("snapshot is expired")]
    Expired,
    /// Snapshot violated [`RevocationPolicy::max_staleness_secs`] from
    /// the verifier's clock relative to `published_at`.
    #[error("snapshot is stale (published {published_at:?}, max_staleness={max_staleness_secs}s)")]
    Stale {
        /// `published_at` of the offending snapshot.
        published_at: Timestamp,
        /// Configured maximum staleness, seconds.
        max_staleness_secs: u64,
    },
    /// No snapshot available and policy refuses to fail open.
    #[error("revocation provider returned no snapshot and policy is fail-closed")]
    NoSnapshotFailClosed,
}

/// What to do when revocation cannot be checked freshly (network down,
/// no provider configured, snapshot stale, …).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationFailMode {
    /// Reject the underlying TCT — safest choice for high-value flows.
    /// Default.
    FailClosed,
    /// Accept the underlying TCT — appropriate for low-value flows where
    /// availability dominates.
    FailOpen,
    /// Same wire behavior as `FailOpen`; reserved for callers that want
    /// to wire their own logging/telemetry. Kept distinct so the policy
    /// surface mirrors `KeyResolutionFailMode`.
    SoftFail,
}

impl Default for RevocationFailMode {
    fn default() -> Self {
        Self::FailClosed
    }
}

/// Per-issuer revocation policy.
#[derive(Clone, Copy, Debug)]
pub struct RevocationPolicy {
    /// What to do when a fresh snapshot cannot be obtained.
    pub fail_mode: RevocationFailMode,
    /// Maximum age of a snapshot's `published_at` relative to the
    /// verifier's `now`. Snapshots older than this are treated as
    /// no-snapshot and the fail mode applies. Default 86400s (24 h).
    pub max_staleness_secs: u64,
    /// In-memory cache TTL for an already-verified snapshot. Default
    /// 60s — keeps verification cheap for back-to-back handshakes
    /// without hiding a fresh issuer push for too long.
    pub cache_ttl_secs: u64,
}

impl Default for RevocationPolicy {
    fn default() -> Self {
        Self {
            fail_mode: RevocationFailMode::default(),
            max_staleness_secs: 86_400,
            cache_ttl_secs: 60,
        }
    }
}

/// Cached snapshot.
struct CachedSnapshot {
    envelope: RevocationListEnvelope,
    cached_at: Timestamp,
}

/// Configurable revocation cache + checker.
pub struct RevocationCache<P: RevocationProvider> {
    provider: Option<P>,
    policy: RevocationPolicy,
    inner: RwLock<HashMap<Aid, CachedSnapshot>>,
}

impl<P: RevocationProvider> RevocationCache<P> {
    /// Construct with no provider (offline / pinned-only deployments).
    /// `is_revoked` falls through to the configured fail mode.
    pub fn offline(policy: RevocationPolicy) -> Self {
        Self {
            provider: None,
            policy,
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Construct with a network/file provider.
    pub fn new(provider: P, policy: RevocationPolicy) -> Self {
        Self {
            provider: Some(provider),
            policy,
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Return whether `jti` has been revoked by `issuer`. Network /
    /// signature / staleness failures translate via the configured
    /// fail mode:
    ///
    /// - `FailClosed` → `Err(RevocationError::*)` (caller treats as
    ///   "TCT rejected").
    /// - `FailOpen` / `SoftFail` → `Ok(false)` (caller proceeds).
    pub fn is_revoked(
        &self,
        jti: &Uuid,
        issuer: &Aid,
        now: Timestamp,
    ) -> Result<bool, RevocationError> {
        match self.snapshot_for(issuer, now) {
            Ok(env) => Ok(env.revocation_list.entries.iter().any(|e| &e.jti == jti)),
            Err(e) => match self.policy.fail_mode {
                RevocationFailMode::FailClosed => Err(e),
                RevocationFailMode::FailOpen | RevocationFailMode::SoftFail => Ok(false),
            },
        }
    }

    fn snapshot_for(
        &self,
        issuer: &Aid,
        now: Timestamp,
    ) -> Result<RevocationListEnvelope, RevocationError> {
        if let Some(env) = self.cached_fresh(issuer, now) {
            return Ok(env);
        }
        let provider = self
            .provider
            .as_ref()
            .ok_or(RevocationError::NoSnapshotFailClosed)?;
        let env = provider.fetch(issuer)?;
        // Verify signature + expiry.
        verify_revocation_list(
            &env,
            &VerifyRevocationListContext {
                expected_issuer: issuer,
                now,
            },
        )
        .map_err(|e| match e {
            TctError::Expired => RevocationError::Expired,
            other => RevocationError::SignatureInvalid(other),
        })?;
        // Apply max-staleness.
        let age = now.0.saturating_sub(env.revocation_list.published_at.0);
        if age > self.policy.max_staleness_secs as i64 {
            return Err(RevocationError::Stale {
                published_at: env.revocation_list.published_at,
                max_staleness_secs: self.policy.max_staleness_secs,
            });
        }
        self.store(issuer.clone(), env.clone(), now);
        Ok(env)
    }

    fn cached_fresh(&self, issuer: &Aid, now: Timestamp) -> Option<RevocationListEnvelope> {
        let cache = self.inner.read().ok()?;
        let entry = cache.get(issuer)?;
        let cache_age = now.0.saturating_sub(entry.cached_at.0);
        if cache_age <= self.policy.cache_ttl_secs as i64
            && !entry
                .envelope
                .revocation_list
                .expires_at
                .is_in_the_past(now)
        {
            Some(entry.envelope.clone())
        } else {
            None
        }
    }

    fn store(&self, issuer: Aid, envelope: RevocationListEnvelope, now: Timestamp) {
        if let Ok(mut cache) = self.inner.write() {
            cache.insert(
                issuer,
                CachedSnapshot {
                    envelope,
                    cached_at: now,
                },
            );
        }
    }
}

/// Manifest extension key (RFC-AITP-0012 namespace) carrying the
/// revocation list URL when an issuer publishes one. Wire format:
///
/// ```json
/// "extensions": {
///   "rfc-aitp-0008.revocation_list_uri": "https://issuer.example/.well-known/aitp-revocation-list"
/// }
/// ```
pub const REVOCATION_LIST_URI_EXT: &str = "rfc-aitp-0008.revocation_list_uri";

/// Helper: pull a revocation list URI out of a Manifest's
/// `extensions` map, if any. Returns `None` when the extension is
/// missing or not a string.
pub fn revocation_list_uri_from_manifest(manifest: &aitp_manifest::Manifest) -> Option<url::Url> {
    manifest
        .extensions
        .get(REVOCATION_LIST_URI_EXT)
        .and_then(|v| v.as_str())
        .and_then(|s| url::Url::parse(s).ok())
        .filter(|u| u.scheme() == "https")
}

/// Default duration after which the cache TTL falls back if the
/// provided [`RevocationPolicy::cache_ttl_secs`] is zero.
pub const DEFAULT_REVOCATION_CACHE_TTL: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;
    use aitp_crypto::AitpSigningKey;
    use aitp_tct::{sign_revocation_list, RevocationEntry, RevocationList};

    fn make_envelope(
        jti: Uuid,
        issuer_key: &AitpSigningKey,
        published_at: Timestamp,
        expires_at: Timestamp,
    ) -> RevocationListEnvelope {
        sign_revocation_list(
            RevocationList {
                version: "aitp/0.1".into(),
                issuer: issuer_key.aid().clone(),
                published_at,
                expires_at,
                entries: vec![RevocationEntry {
                    jti,
                    revoked_at: published_at,
                    reason: None,
                }],
            },
            issuer_key,
        )
        .unwrap()
    }

    struct FakeProvider {
        envelope: RevocationListEnvelope,
    }
    impl RevocationProvider for FakeProvider {
        fn fetch(&self, _issuer: &Aid) -> Result<RevocationListEnvelope, RevocationError> {
            Ok(self.envelope.clone())
        }
    }

    struct ErrProvider;
    impl RevocationProvider for ErrProvider {
        fn fetch(&self, _issuer: &Aid) -> Result<RevocationListEnvelope, RevocationError> {
            Err(RevocationError::Network("offline".into()))
        }
    }

    #[test]
    fn revoked_jti_is_rejected() {
        let key = AitpSigningKey::from_seed(&[1u8; 32]);
        let jti = Uuid::new_v4();
        let env = make_envelope(
            jti,
            &key,
            Timestamp::now(),
            Timestamp(Timestamp::now().0 + 3600),
        );
        let cache =
            RevocationCache::new(FakeProvider { envelope: env }, RevocationPolicy::default());
        let revoked = cache.is_revoked(&jti, key.aid(), Timestamp::now()).unwrap();
        assert!(revoked, "jti listed in snapshot must read as revoked");
    }

    #[test]
    fn unrevoked_jti_passes() {
        let key = AitpSigningKey::from_seed(&[2u8; 32]);
        let env = make_envelope(
            Uuid::new_v4(),
            &key,
            Timestamp::now(),
            Timestamp(Timestamp::now().0 + 3600),
        );
        let cache =
            RevocationCache::new(FakeProvider { envelope: env }, RevocationPolicy::default());
        let revoked = cache
            .is_revoked(&Uuid::new_v4(), key.aid(), Timestamp::now())
            .unwrap();
        assert!(!revoked);
    }

    #[test]
    fn expired_snapshot_not_used_fail_closed() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let now = Timestamp::now();
        let env = make_envelope(
            Uuid::new_v4(),
            &key,
            Timestamp(now.0 - 7200),
            Timestamp(now.0 - 3600),
        );
        let cache =
            RevocationCache::new(FakeProvider { envelope: env }, RevocationPolicy::default());
        let err = cache
            .is_revoked(&Uuid::new_v4(), key.aid(), now)
            .unwrap_err();
        assert!(matches!(err, RevocationError::Expired), "got {err:?}");
    }

    #[test]
    fn stale_snapshot_rejected_fail_closed() {
        let key = AitpSigningKey::from_seed(&[4u8; 32]);
        let now = Timestamp::now();
        // Snapshot published two days ago, still in its expires_at
        // window — but exceeds 24h staleness.
        let env = make_envelope(
            Uuid::new_v4(),
            &key,
            Timestamp(now.0 - 172_800),
            Timestamp(now.0 + 3600),
        );
        let cache =
            RevocationCache::new(FakeProvider { envelope: env }, RevocationPolicy::default());
        let err = cache
            .is_revoked(&Uuid::new_v4(), key.aid(), now)
            .unwrap_err();
        assert!(matches!(err, RevocationError::Stale { .. }), "got {err:?}");
    }

    #[test]
    fn invalid_signature_rejected_fail_closed() {
        let key = AitpSigningKey::from_seed(&[5u8; 32]);
        let now = Timestamp::now();
        let mut env = make_envelope(Uuid::new_v4(), &key, now, Timestamp(now.0 + 3600));
        // Corrupt signature.
        env.signature = "A".repeat(86);
        let cache =
            RevocationCache::new(FakeProvider { envelope: env }, RevocationPolicy::default());
        let err = cache
            .is_revoked(&Uuid::new_v4(), key.aid(), now)
            .unwrap_err();
        assert!(
            matches!(err, RevocationError::SignatureInvalid(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn fail_open_returns_not_revoked() {
        let key = AitpSigningKey::from_seed(&[6u8; 32]);
        let cache = RevocationCache::new(
            ErrProvider,
            RevocationPolicy {
                fail_mode: RevocationFailMode::FailOpen,
                ..Default::default()
            },
        );
        // Network error → fail-open → not revoked.
        let revoked = cache
            .is_revoked(&Uuid::new_v4(), key.aid(), Timestamp::now())
            .unwrap();
        assert!(!revoked);
    }

    #[test]
    fn soft_fail_returns_not_revoked() {
        let key = AitpSigningKey::from_seed(&[7u8; 32]);
        let cache = RevocationCache::new(
            ErrProvider,
            RevocationPolicy {
                fail_mode: RevocationFailMode::SoftFail,
                ..Default::default()
            },
        );
        let revoked = cache
            .is_revoked(&Uuid::new_v4(), key.aid(), Timestamp::now())
            .unwrap();
        assert!(!revoked);
    }

    #[test]
    fn fail_closed_no_provider_errors() {
        let key = AitpSigningKey::from_seed(&[8u8; 32]);
        let cache = RevocationCache::<FakeProvider>::offline(RevocationPolicy::default());
        let err = cache
            .is_revoked(&Uuid::new_v4(), key.aid(), Timestamp::now())
            .unwrap_err();
        assert!(matches!(err, RevocationError::NoSnapshotFailClosed));
    }
}
