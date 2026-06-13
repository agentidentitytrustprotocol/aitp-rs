//! Revocation policy + per-issuer revocation cache (RFC-AITP-0008).
//!
//! Composes a [`RevocationProvider`] (typically backed by the HTTP
//! client in [`crate::client`]) with a per-issuer cache, applies a
//! configurable [`RevocationFailMode`] when the network source is
//! unreachable, and exposes a `is_revoked(jti, issuer)` decision for
//! handshake / TCT verifiers.

use aitp_core::{Aid, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_tct::{
    sign_revocation_list, verify_revocation_list, RevocationList, RevocationListEnvelope, TctError,
    VerifyRevocationListContext,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::Duration;
use tracing::debug;
use uuid::Uuid;

/// Source of revocation snapshots — typically backed by an HTTP fetch.
///
/// Implementations are sync. The concrete HTTP fetcher in this crate
/// bridges into a tokio runtime to call its async client.
pub trait RevocationProvider: Send + Sync {
    /// Fetch the latest signed snapshot for `issuer`.
    fn fetch(&self, issuer: &Aid) -> Result<RevocationListEnvelope, RevocationError>;
}

/// A [`RevocationProvider`] that always returns a freshly-signed, **empty**
/// revocation list for its configured issuer — i.e. "this issuer has revoked
/// nothing."
///
/// Intended for tests and local/dev wiring that need a working provider
/// without standing up an HTTP revocation source (the previous alternative
/// was hand-rolling a signed empty envelope in every test). Because a
/// snapshot must be signed by the issuer (RFC-AITP-0008), the provider is
/// built from that issuer's signing key and only speaks for `key.aid()`: a
/// `fetch` produces a list signed by this key, which the verifier checks
/// against the *requested* issuer, so using it for a different issuer fails
/// closed (correct — the provider cannot vouch for an issuer whose key it
/// does not hold).
///
/// This is NOT a "skip revocation" switch — for that, configure
/// [`RevocationPolicy`] with no provider plus [`RevocationFailMode::FailOpen`].
pub struct EmptyRevocationProvider {
    issuer_key: AitpSigningKey,
    ttl_secs: i64,
}

impl EmptyRevocationProvider {
    /// New provider that signs empty lists as `issuer_key`'s AID, each valid
    /// for one hour from issuance.
    pub fn new(issuer_key: AitpSigningKey) -> Self {
        Self {
            issuer_key,
            ttl_secs: 3600,
        }
    }

    /// Override the validity window (seconds) of the signed empty lists.
    pub fn with_ttl_secs(mut self, ttl_secs: i64) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }
}

impl RevocationProvider for EmptyRevocationProvider {
    fn fetch(&self, _issuer: &Aid) -> Result<RevocationListEnvelope, RevocationError> {
        let now = Timestamp::now();
        sign_revocation_list(
            RevocationList {
                version: "aitp/0.2".into(),
                issuer: self.issuer_key.aid().clone(),
                published_at: now,
                expires_at: Timestamp(now.0 + self.ttl_secs),
                entries: vec![],
            },
            &self.issuer_key,
        )
        .map_err(RevocationError::SignatureInvalid)
    }
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevocationFailMode {
    /// Reject the underlying TCT — safest choice for high-value flows.
    /// Default.
    FailClosed,
    /// Accept the underlying TCT — appropriate for low-value flows where
    /// availability dominates.
    FailOpen,
    /// Reduce the issued grant set to a configured safe subset
    /// (RFC-AITP-0008). Callers consuming a [`RevocationOutcome`]
    /// receive the safe subset and MUST intersect it with the
    /// peer's requested grants before issuing a TCT — an empty
    /// intersection MUST surface as `POLICY_VIOLATION` per
    /// RFC-AITP-0008 §X.
    ///
    /// `SoftFail { safe_grants: vec![] }` is identical in effect to
    /// `FailClosed` (RFC requirement: SoftFail without a non-empty
    /// safe-grant list MUST fail closed).
    SoftFail {
        /// The grants that may still be issued when the revocation
        /// source is unavailable. Typically a small, low-risk subset
        /// of the issuer's offered capabilities (e.g. read-only
        /// surfaces).
        safe_grants: Vec<String>,
    },
}

impl Default for RevocationFailMode {
    fn default() -> Self {
        Self::FailClosed
    }
}

/// Result of a `RevocationCache::check` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevocationOutcome {
    /// The TCT's JTI is not on the issuer's revocation list. The
    /// caller may issue/accept the TCT with the full grant set.
    Clear,
    /// The TCT's JTI is on the issuer's revocation list. Reject.
    Revoked,
    /// The revocation source was unavailable and the configured
    /// `RevocationFailMode::SoftFail` applies. The caller MUST
    /// intersect outgoing grants with `safe_grants` before issuing a
    /// TCT (RFC-AITP-0008 §X). Empty intersection ⇒ `POLICY_VIOLATION`.
    SoftFailSafeSubset {
        /// The configured safe grant subset; non-empty by construction
        /// (an empty `safe_grants` configuration degenerates to
        /// `FailClosed` and surfaces as a `RevocationError` instead).
        safe_grants: Vec<String>,
    },
}

/// Intersect the peer's requested grants with the configured safe
/// subset under [`RevocationFailMode::SoftFail`]. Returns the grants
/// that may be issued under the degraded policy.
///
/// Empty result is the caller's signal to surface `POLICY_VIOLATION`.
pub fn apply_safe_subset(requested: &[String], safe_grants: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter(|g| safe_grants.iter().any(|s| s == *g))
        .cloned()
        .collect()
}

/// Per-issuer revocation policy.
#[derive(Clone, Debug)]
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

    /// Decide what to do for `(jti, issuer)`. Snapshot fetch /
    /// signature / staleness failures translate via the configured
    /// fail mode (RFC-AITP-0008):
    ///
    /// - `FailClosed` → `Err(RevocationError::*)` (caller rejects TCT).
    /// - `FailOpen` → `Ok(Clear)` (caller proceeds with full grants).
    /// - `SoftFail { safe_grants: non-empty }` → `Ok(SoftFailSafeSubset
    ///   { safe_grants })`. Caller MUST intersect outgoing grants with
    ///   the subset; empty intersection is `POLICY_VIOLATION`.
    /// - `SoftFail { safe_grants: empty }` → degenerates to `FailClosed`
    ///   (RFC: SoftFail without a non-empty safe list MUST fail closed).
    pub fn check(
        &self,
        jti: &Uuid,
        issuer: &Aid,
        now: Timestamp,
    ) -> Result<RevocationOutcome, RevocationError> {
        let outcome = match self.snapshot_for(issuer, now) {
            Ok(env) => {
                if env.revocation_list.entries.iter().any(|e| &e.jti == jti) {
                    Ok(RevocationOutcome::Revoked)
                } else {
                    Ok(RevocationOutcome::Clear)
                }
            }
            Err(e) => match &self.policy.fail_mode {
                RevocationFailMode::FailClosed => Err(e),
                RevocationFailMode::FailOpen => Ok(RevocationOutcome::Clear),
                RevocationFailMode::SoftFail { safe_grants } if safe_grants.is_empty() => Err(e),
                RevocationFailMode::SoftFail { safe_grants } => {
                    Ok(RevocationOutcome::SoftFailSafeSubset {
                        safe_grants: safe_grants.clone(),
                    })
                }
            },
        };
        match &outcome {
            Ok(RevocationOutcome::Clear) => {
                debug!(%jti, %issuer, outcome = "clear", "revocation check");
            }
            Ok(RevocationOutcome::Revoked) => {
                debug!(%jti, %issuer, outcome = "revoked", "revocation check");
            }
            Ok(RevocationOutcome::SoftFailSafeSubset { safe_grants }) => {
                debug!(
                    %jti,
                    %issuer,
                    outcome = "soft_fail_safe_subset",
                    safe_grant_count = safe_grants.len(),
                    "revocation check"
                );
            }
            Err(e) => {
                debug!(%jti, %issuer, error = %e, "revocation check failed closed");
            }
        }
        outcome
    }

    /// Bool-flavored revocation check kept for handshake hooks that
    /// only need to answer "is this TCT on the revocation list?".
    /// Maps `RevocationOutcome::Clear` and `SoftFailSafeSubset` to
    /// `Ok(false)` (TCT may proceed; if the caller is the *issuer*
    /// it should call [`Self::check`] instead and apply the safe
    /// subset). `Revoked` maps to `Ok(true)`.
    pub fn is_revoked(
        &self,
        jti: &Uuid,
        issuer: &Aid,
        now: Timestamp,
    ) -> Result<bool, RevocationError> {
        match self.check(jti, issuer, now)? {
            RevocationOutcome::Revoked => Ok(true),
            RevocationOutcome::Clear | RevocationOutcome::SoftFailSafeSubset { .. } => Ok(false),
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
        let cache = self.inner.read();
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
        let mut cache = self.inner.write();
        cache.insert(
            issuer,
            CachedSnapshot {
                envelope,
                cached_at: now,
            },
        );
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
    // `super::*` already brings `AitpSigningKey`, `sign_revocation_list`,
    // and `RevocationList` (top-level imports); only `RevocationEntry` is
    // additionally needed here.
    use super::*;
    use aitp_tct::RevocationEntry;

    fn make_envelope(
        jti: Uuid,
        issuer_key: &AitpSigningKey,
        published_at: Timestamp,
        expires_at: Timestamp,
    ) -> RevocationListEnvelope {
        sign_revocation_list(
            RevocationList {
                version: "aitp/0.2".into(),
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
    fn empty_provider_reads_everything_as_unrevoked() {
        let key = AitpSigningKey::from_seed(&[9u8; 32]);
        let issuer = key.aid().clone();
        let cache = RevocationCache::new(
            EmptyRevocationProvider::new(key),
            RevocationPolicy::default(),
        );
        // Any jti is unrevoked because the issuer's signed snapshot is empty.
        let revoked = cache
            .is_revoked(&Uuid::new_v4(), &issuer, Timestamp::now())
            .unwrap();
        assert!(!revoked, "empty signed snapshot ⇒ nothing is revoked");
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
    fn soft_fail_with_safe_grants_returns_subset() {
        let key = AitpSigningKey::from_seed(&[7u8; 32]);
        let cache = RevocationCache::new(
            ErrProvider,
            RevocationPolicy {
                fail_mode: RevocationFailMode::SoftFail {
                    safe_grants: vec!["read_data".into()],
                },
                ..Default::default()
            },
        );
        let outcome = cache
            .check(&Uuid::new_v4(), key.aid(), Timestamp::now())
            .unwrap();
        assert!(matches!(
            outcome,
            RevocationOutcome::SoftFailSafeSubset { ref safe_grants } if safe_grants == &["read_data".to_string()]
        ));

        // The safe-subset helper drops grants outside the configured
        // list and keeps the rest.
        let issued = apply_safe_subset(
            &["read_data".to_string(), "write_data".to_string()],
            &["read_data".to_string()],
        );
        assert_eq!(issued, vec!["read_data".to_string()]);

        // Empty intersection → caller's signal to fail with
        // POLICY_VIOLATION.
        let issued = apply_safe_subset(&["write_data".to_string()], &["read_data".to_string()]);
        assert!(issued.is_empty());

        // is_revoked() for a SoftFail outcome reports "not revoked" —
        // it's the issuer's responsibility to apply the safe subset.
        let not_revoked = cache
            .is_revoked(&Uuid::new_v4(), key.aid(), Timestamp::now())
            .unwrap();
        assert!(!not_revoked);
    }

    #[test]
    fn soft_fail_with_empty_safe_grants_degrades_to_fail_closed() {
        // RFC-AITP-0008: SoftFail without a non-empty safe-grant list
        // MUST behave as FailClosed.
        let key = AitpSigningKey::from_seed(&[7u8; 32]);
        let cache = RevocationCache::new(
            ErrProvider,
            RevocationPolicy {
                fail_mode: RevocationFailMode::SoftFail {
                    safe_grants: vec![],
                },
                ..Default::default()
            },
        );
        let err = cache
            .check(&Uuid::new_v4(), key.aid(), Timestamp::now())
            .unwrap_err();
        assert!(matches!(err, RevocationError::Network(_)));
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
