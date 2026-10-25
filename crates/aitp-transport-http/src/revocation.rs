//! Revocation policy + per-issuer revocation cache (RFC-AITP-0008).
//!
//! Composes a [`RevocationProvider`] (typically backed by the HTTP
//! client in [`crate::client`]) with a per-issuer cache, applies a
//! configurable [`RevocationFailMode`] when the network source is
//! unreachable, and exposes a `is_revoked(jti, issuer)` decision for
//! handshake / TCT verifiers.

use aitp_core::{Aid, Timestamp};
use aitp_crypto::AitpSigner;
use aitp_tct::{
    sign_revocation_list, verify_revocation_list, RevocationList, RevocationListEnvelope, TctError,
    VerifyRevocationListContext,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;
use uuid::Uuid;

/// Source of revocation snapshots — typically backed by an HTTP fetch.
///
/// Implementations are sync. The concrete HTTP fetcher in this crate
/// bridges into a tokio runtime to call its async client.
pub trait RevocationProvider: Send + Sync {
    /// Fetch the latest signed snapshot for `issuer`.
    ///
    /// An implementation that decodes untrusted bytes off the wire (an
    /// HTTP response body, a file, …) MUST apply RFC-AITP-0001 §7's
    /// member-set check before returning — via
    /// [`aitp_tct::parse_revocation_snapshot_wire`] on the raw
    /// [`serde_json::Value`], not a bare `serde_json::from_value` /
    /// `from_slice` into [`RevocationListEnvelope`], which would only
    /// surface an unknown member as an opaque `serde_json::Error` for the
    /// caller to (mis)classify. Map the resulting
    /// `Err(aitp_tct::TctError::UnknownField(_))` to
    /// [`RevocationError::UnknownField`], and
    /// `Err(aitp_tct::TctError::ClaimsMalformed(_))` (a missing/mistyped
    /// known member — the member set itself was intact) to
    /// [`RevocationError::Malformed`] — **never** either one to
    /// [`RevocationError::SignatureInvalid`], which would misreport a
    /// structural rejection (the signature is never reached) as a
    /// cryptographic one, exactly the miscategorization
    /// [`RevocationCache`]'s own signature/expiry check
    /// (see its `snapshot_for` internals) is careful to avoid for errors
    /// that originate *after* this call.
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
    issuer_key: Arc<dyn AitpSigner>,
    ttl_secs: i64,
}

impl EmptyRevocationProvider {
    /// New provider that signs empty lists as `issuer_key`'s AID, each valid
    /// for one hour from issuance.
    ///
    /// Accepts any [`AitpSigner`] (in-process key, KMS, HSM); a backend
    /// failure makes `fetch` return [`RevocationError::Signer`].
    pub fn new<S: AitpSigner + 'static>(issuer_key: S) -> Self {
        Self {
            issuer_key: Arc::new(issuer_key),
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
                version: aitp_core::PROTOCOL_VERSION.into(),
                issuer: self.issuer_key.aid().clone(),
                published_at: now,
                expires_at: Timestamp(now.0 + self.ttl_secs),
                entries: vec![],
                extensions: None,
            },
            &*self.issuer_key,
        )
        .map_err(|e| match e {
            TctError::Crypto(aitp_crypto::CryptoError::Signer(s)) => RevocationError::Signer(s),
            other => RevocationError::SignatureInvalid(other),
        })
    }
}

/// Errors raised when fetching or applying a revocation snapshot.
///
/// Marked `#[non_exhaustive]` so a future structural-rejection category
/// (mirroring [`aitp_manifest::ManifestError`], which carries the same
/// attribute) doesn't force a breaking change on every downstream match —
/// this variant set is still expected to grow as RFC-AITP-0008 §1.5's
/// structural-rejection table does.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
    /// The fetched snapshot carried a JSON member outside its
    /// schema-declared member set (RFC-AITP-0001 §7), at either the
    /// envelope or the inner `revocation_list` body. Distinct from
    /// [`RevocationError::SignatureInvalid`]: a structural member-set
    /// violation means the signature was never reached, so reporting it
    /// as a signature failure would be a miscategorization — exactly the
    /// spec's new structural-rejection table (RFC-AITP-0008 §1.5) exists
    /// to prevent.
    #[error("revocation snapshot has unknown field: {0}")]
    UnknownField(String),
    /// The fetched snapshot's member set was intact (nothing extra, see
    /// [`RevocationError::UnknownField`]) but a required member was
    /// missing or a known member had the wrong shape —
    /// [`aitp_tct::TctError::ClaimsMalformed`] from
    /// [`aitp_tct::parse_revocation_snapshot_wire`]. Also never the
    /// signature check's fault: the signature was never reached. This is
    /// the `REVOCATION_SNAPSHOT_INVALID` case, the revocation-snapshot
    /// sibling of `ManifestError::Malformed` (RFC-AITP-0008 §1.5).
    ///
    /// [`RevocationCache`] also reports an unknown
    /// `revocation_list.version` as this variant (issue #265): spec
    /// VERSIONING.md makes `REVOCATION_SNAPSHOT_INVALID` a snapshot's
    /// unknown-version code. It was previously
    /// `SignatureInvalid(TctError::VersionUnknown)`.
    #[error("revocation snapshot is malformed: {0}")]
    Malformed(String),
    /// Our own signing backend (in-process key, KMS, HSM) failed while
    /// [`EmptyRevocationProvider`] signed a snapshot. A local fault, not
    /// a bad snapshot: [`aitp_crypto::SignerError::is_transient`] tells
    /// whether a retry may help.
    #[error("signing backend failed: {0}")]
    Signer(#[from] aitp_crypto::SignerError),
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
    /// Accept the TCT only when its issuer's verified Manifest
    /// advertises no `ListRevoked` URL at all, and log each acceptance
    /// at `info`. An advertised list that cannot be fetched, verified or
    /// kept fresh still fails closed, so a list that exists is never
    /// ignored.
    ///
    /// **Only for TCTs the deployment never uses to authorise anything.**
    /// A TCT accepted this way has had no revocation check, so it must
    /// gate no action, grant or data. The example is the interop peer
    /// (`aitp serve --interop`): its initiators (a CLI, a CI job) publish
    /// no list, and it discards the TCT they issue it. A service that
    /// acts on received TCTs keeps the default, [`Self::FailClosed`].
    ///
    /// Only [`crate::RevocationFetcher`], which sees the
    /// Manifest, can tell the two cases apart; [`RevocationCache`] treats
    /// this mode as [`Self::FailClosed`].
    FailOpenIfUnadvertised,
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

    /// Construct for the issuer whose (already verified) Manifest is
    /// `manifest`, polling the `ListRevoked` URL it advertises under
    /// [`REVOCATION_LIST_URI_EXT`] (RFC-AITP-0008 §1.4). `make_provider`
    /// builds the provider for that URL.
    ///
    /// A Manifest without the key (or with a non-HTTPS value) is not
    /// rejected: the result is [`Self::offline`], so every check reports
    /// revocation as unavailable and `policy.fail_mode` decides
    /// (RFC-AITP-0008 §3).
    pub fn for_issuer_manifest(
        manifest: &aitp_manifest::Manifest,
        policy: RevocationPolicy,
        make_provider: impl FnOnce(url::Url) -> P,
    ) -> Self {
        match revocation_list_uri_from_manifest(manifest) {
            Some(url) => Self::new(make_provider(url), policy),
            None => {
                debug!(
                    issuer = %manifest.aid,
                    "issuer Manifest advertises no revocation_list_uri; revocation unavailable"
                );
                Self::offline(policy)
            }
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
                // No Manifest here, so "unadvertised" cannot be shown.
                RevocationFailMode::FailClosed | RevocationFailMode::FailOpenIfUnadvertised => {
                    Err(e)
                }
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
            crate::obs::revocation_cache("hit");
            return Ok(env);
        }
        crate::obs::revocation_cache("miss");
        let provider = self
            .provider
            .as_ref()
            .ok_or(RevocationError::NoSnapshotFailClosed)?;
        let env = provider.fetch(issuer)?;
        verify_snapshot(&env, issuer, now, self.policy.max_staleness_secs)?;
        crate::obs::revocation_cache("refresh");
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

/// Verify a fetched snapshot for `issuer` at `now`: signature, expiry and
/// structure (RFC-AITP-0008 §1.5), then `max_staleness_secs` (§3.2).
/// Shared by [`RevocationCache`] and the async
/// [`crate::revocation_fetch::RevocationFetcher`].
pub(crate) fn verify_snapshot(
    env: &RevocationListEnvelope,
    issuer: &Aid,
    now: Timestamp,
    max_staleness_secs: u64,
) -> Result<(), RevocationError> {
    // Verify signature + expiry. `TctError::UnknownField` and
    // `TctError::ClaimsMalformed` each get their own arm rather than
    // falling into the `other` catch-all below: a provider that parses
    // the raw wire form via `aitp_tct::parse_revocation_snapshot_wire`
    // (as it MUST, to honor RFC-AITP-0001 §7's member-set check on a
    // live fetch) surfaces a structurally-rejected snapshot as one of
    // these two errors, and collapsing either into `SignatureInvalid`
    // here would misreport a structural rejection — whose signature was
    // never reached — as a cryptographic one.
    verify_revocation_list(env, &VerifyRevocationListContext::new(issuer, now)).map_err(
        |e| match e {
            TctError::Expired => RevocationError::Expired,
            TctError::UnknownField(field) => RevocationError::UnknownField(field),
            TctError::ClaimsMalformed(msg) => RevocationError::Malformed(msg),
            // #265: an unknown `version` is the snapshot's schema
            // failure (REVOCATION_SNAPSHOT_INVALID, spec VERSIONING.md),
            // checked before the signature. Never a signature failure.
            TctError::VersionUnknown => RevocationError::Malformed(format!(
                "unknown revocation snapshot version {:?}",
                env.revocation_list.version
            )),
            other => RevocationError::SignatureInvalid(other),
        },
    )?;
    // Apply max-staleness.
    let age = now.0.saturating_sub(env.revocation_list.published_at.0);
    if age > max_staleness_secs as i64 {
        crate::obs::revocation_cache("stale");
        return Err(RevocationError::Stale {
            published_at: env.revocation_list.published_at,
            max_staleness_secs,
        });
    }
    Ok(())
}

/// Manifest extension key (RFC-AITP-0012 namespace) carrying the
/// issuer's `ListRevoked` URL. Every TCT issuer MUST advertise it
/// (RFC-AITP-0005 §11, RFC-AITP-0008 §1.4); issuers set it with
/// [`aitp_manifest::ManifestBuilder::revocation_list_uri`]. Wire format:
///
/// ```json
/// "extensions": {
///   "rfc-aitp-0008.revocation_list_uri": "https://issuer.example/.well-known/aitp-revocation-list"
/// }
/// ```
pub const REVOCATION_LIST_URI_EXT: &str = aitp_manifest::REVOCATION_LIST_URI_EXT;

/// Helper: pull a revocation list URI out of a Manifest's
/// `extensions` map, if any. Returns `None` when the extension is
/// missing, not a string, or not an HTTPS URL.
///
/// `None` is never a reason to reject the Manifest (RFC-AITP-0008
/// §1.4): the issuer's revocation status is unavailable and the
/// configured [`RevocationFailMode`] applies, exactly as for an
/// unreachable endpoint. [`RevocationCache::for_issuer_manifest`] wires
/// that up.
pub fn revocation_list_uri_from_manifest(manifest: &aitp_manifest::Manifest) -> Option<url::Url> {
    manifest
        .extensions
        .as_ref()?
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
    // `super::*` already brings `sign_revocation_list` and
    // `RevocationList` (top-level imports); `AitpSigningKey` and
    // `RevocationEntry` are additionally needed here.
    use super::*;
    use aitp_crypto::AitpSigningKey;
    use aitp_tct::RevocationEntry;

    /// Re-enter an in-memory `Value` through `CheckedJson`'s text-only
    /// constructor (a `Value` has no duplicate key, so this cannot fail).
    fn checked(v: &serde_json::Value) -> aitp_core::CheckedJson {
        v.to_string().parse().expect("valid JSON")
    }

    fn make_envelope(
        jti: Uuid,
        issuer_key: &AitpSigningKey,
        published_at: Timestamp,
        expires_at: Timestamp,
    ) -> RevocationListEnvelope {
        sign_revocation_list(
            RevocationList {
                version: "aitp/0.3".into(),
                issuer: issuer_key.aid().clone(),
                published_at,
                expires_at,
                entries: vec![RevocationEntry {
                    jti,
                    revoked_at: published_at,
                    reason: None,
                }],
                extensions: None,
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
    fn empty_provider_accepts_a_kms_backend() {
        use aitp_crypto::testing::{MockKmsSigner, MockOutput};
        let kms = MockKmsSigner::new(AitpSigningKey::from_p256_seed(&[9u8; 32]).unwrap())
            .output(MockOutput::DerHighS);
        let issuer = kms.aid().clone();
        let cache = RevocationCache::new(
            EmptyRevocationProvider::new(kms),
            RevocationPolicy::default(),
        );
        let revoked = cache
            .is_revoked(&Uuid::new_v4(), &issuer, Timestamp::now())
            .unwrap();
        assert!(!revoked, "KMS-signed empty snapshot verifies");
    }

    #[test]
    fn empty_provider_surfaces_backend_failure_as_signer_error() {
        use aitp_crypto::testing::MockKmsSigner;
        let kms = MockKmsSigner::new(AitpSigningKey::from_p256_seed(&[9u8; 32]).unwrap())
            .sign_with(AitpSigningKey::from_p256_seed(&[8u8; 32]).unwrap());
        let issuer = kms.aid().clone();
        let err = EmptyRevocationProvider::new(kms)
            .fetch(&issuer)
            .expect_err("wrong-key backend must fail");
        assert!(
            matches!(
                err,
                RevocationError::Signer(aitp_crypto::SignerError::VerificationFailed)
            ),
            "{err:?}"
        );
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

    /// rev-010-version-unknown shape (#265): sign validly, then change
    /// only `version`, so the signature is invalid too. The version is
    /// checked first and reported as the REVOCATION_SNAPSHOT_INVALID case
    /// (`Malformed`), never as `SignatureInvalid`.
    #[test]
    fn unknown_version_is_malformed_not_signature_invalid() {
        let key = AitpSigningKey::from_seed(&[0x5A; 32]);
        let now = Timestamp::now();
        let mut env = make_envelope(Uuid::new_v4(), &key, now, Timestamp(now.0 + 3600));
        env.revocation_list.version = "aitp/9.9".into();
        let cache =
            RevocationCache::new(FakeProvider { envelope: env }, RevocationPolicy::default());
        let err = cache
            .is_revoked(&Uuid::new_v4(), key.aid(), now)
            .unwrap_err();
        assert!(
            matches!(err, RevocationError::Malformed(ref m) if m.contains("aitp/9.9")),
            "got {err:?}"
        );
    }

    /// Third collapse site (issue #140 hazard 4 addendum): a provider
    /// whose `fetch` decodes untrusted wire bytes via
    /// `aitp_tct::parse_revocation_snapshot_wire` — the documented
    /// contract on [`RevocationProvider::fetch`] — and maps an
    /// unknown-member rejection to [`RevocationError::UnknownField`] must
    /// have that classification survive through [`RevocationCache`]
    /// unchanged. Before this phase, `RevocationError` had no variant
    /// other than `SignatureInvalid` a provider could plausibly map a
    /// `TctError` onto, so a live snapshot fetch that rejected on a
    /// member-set violation could only be reported as a signature
    /// failure — even though the signature was never reached.
    struct WireParsingProvider {
        raw: serde_json::Value,
    }
    impl RevocationProvider for WireParsingProvider {
        fn fetch(&self, _issuer: &Aid) -> Result<RevocationListEnvelope, RevocationError> {
            aitp_tct::parse_revocation_snapshot_wire(&checked(&self.raw)).map_err(|e| match e {
                TctError::UnknownField(field) => RevocationError::UnknownField(field),
                TctError::ClaimsMalformed(msg) => RevocationError::Malformed(msg),
                other => RevocationError::SignatureInvalid(other),
            })
        }
    }

    #[test]
    fn unknown_member_snapshot_is_not_reported_as_signature_invalid() {
        let key = AitpSigningKey::from_seed(&[7u8; 32]);
        let now = Timestamp::now();
        let env = make_envelope(Uuid::new_v4(), &key, now, Timestamp(now.0 + 3600));
        let mut raw = serde_json::to_value(&env).unwrap();
        raw["revocation_list"]
            .as_object_mut()
            .unwrap()
            .insert("list_owner".into(), serde_json::json!("team-trust"));

        let cache = RevocationCache::new(WireParsingProvider { raw }, RevocationPolicy::default());
        let err = cache
            .is_revoked(&Uuid::new_v4(), key.aid(), now)
            .unwrap_err();
        assert!(
            matches!(err, RevocationError::UnknownField(ref f) if f == "list_owner"),
            "an unknown-member snapshot must report UnknownField, not a signature \
             failure — the signature was never reached: got {err:?}"
        );
        assert!(
            !matches!(err, RevocationError::SignatureInvalid(_)),
            "must not collapse a structural rejection into SignatureInvalid: got {err:?}"
        );
    }

    /// issue #144 regression, sibling of the unknown-member test above: a
    /// snapshot whose member set is intact but is missing a required member
    /// (`published_at`) must report `RevocationError::Malformed`, not
    /// `SignatureInvalid` — the signature was never reached, and it isn't
    /// an *unknown* field either (nothing extra is present). Before this
    /// fix, `RevocationError` had no variant other than `SignatureInvalid`
    /// a provider could map `TctError::ClaimsMalformed` onto, reproducing
    /// — for revocation snapshots — the exact manifest/signature
    /// conflation bug `MANIFEST_INVALID` was introduced to fix.
    #[test]
    fn claims_malformed_snapshot_is_not_reported_as_signature_invalid() {
        let key = AitpSigningKey::from_seed(&[7u8; 32]);
        let now = Timestamp::now();
        let env = make_envelope(Uuid::new_v4(), &key, now, Timestamp(now.0 + 3600));
        let mut raw = serde_json::to_value(&env).unwrap();
        raw["revocation_list"]
            .as_object_mut()
            .unwrap()
            .remove("published_at");

        let cache = RevocationCache::new(WireParsingProvider { raw }, RevocationPolicy::default());
        let err = cache
            .is_revoked(&Uuid::new_v4(), key.aid(), now)
            .unwrap_err();
        assert!(
            matches!(err, RevocationError::Malformed(_)),
            "a snapshot missing a required field must report Malformed, not {err:?}"
        );
        assert!(
            !matches!(err, RevocationError::SignatureInvalid(_)),
            "must not collapse a structural rejection into SignatureInvalid: got {err:?}"
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

    fn issuer_manifest(
        key: &AitpSigningKey,
        revocation_uri: Option<&str>,
    ) -> aitp_manifest::Manifest {
        let mut b = aitp_manifest::ManifestBuilder::new(key)
            .handshake_endpoint("https://issuer.example/aitp/handshake".parse().unwrap())
            .identity_hint(aitp_manifest::IdentityHint {
                kind: aitp_manifest::IdentityHintKind::Oidc,
                subject: "issuer".into(),
                issuer: Some("https://idp.example.com".parse().unwrap()),
                public_key: None,
            })
            .accept_trust_anchor("https://idp.example.com".parse().unwrap())
            .offer("demo.echo");
        if let Some(uri) = revocation_uri {
            b = b.revocation_list_uri(uri.parse().unwrap());
        }
        b.build().unwrap()
    }

    /// RFC-AITP-0008 §1.4 / §3: an issuer Manifest without
    /// `rfc-aitp-0008.revocation_list_uri` still verifies and is not
    /// rejected; revocation is unavailable and the fail mode decides —
    /// the provider factory is never invoked.
    #[test]
    fn manifest_without_revocation_uri_applies_fail_mode() {
        let key = AitpSigningKey::from_seed(&[10u8; 32]);
        let manifest = issuer_manifest(&key, None);
        aitp_manifest::verify_manifest(&manifest, &aitp_manifest::VerifyManifestContext::now())
            .expect("a Manifest lacking the key MUST NOT be rejected");
        assert!(revocation_list_uri_from_manifest(&manifest).is_none());
        let now = Timestamp::now();
        let jti = Uuid::new_v4();
        let never = |_: url::Url| -> FakeProvider { panic!("no URL is advertised") };

        let closed =
            RevocationCache::for_issuer_manifest(&manifest, RevocationPolicy::default(), never);
        assert!(matches!(
            closed.check(&jti, key.aid(), now),
            Err(RevocationError::NoSnapshotFailClosed)
        ));

        let open = RevocationCache::for_issuer_manifest(
            &manifest,
            RevocationPolicy {
                fail_mode: RevocationFailMode::FailOpen,
                ..Default::default()
            },
            never,
        );
        assert_eq!(
            open.check(&jti, key.aid(), now).unwrap(),
            RevocationOutcome::Clear
        );

        let soft = RevocationCache::for_issuer_manifest(
            &manifest,
            RevocationPolicy {
                fail_mode: RevocationFailMode::SoftFail {
                    safe_grants: vec!["read_data".into()],
                },
                ..Default::default()
            },
            never,
        );
        assert_eq!(
            soft.check(&jti, key.aid(), now).unwrap(),
            RevocationOutcome::SoftFailSafeSubset {
                safe_grants: vec!["read_data".into()]
            }
        );
    }

    /// With the key advertised, the provider is built for exactly that URL
    /// and its snapshot is consulted.
    #[test]
    fn manifest_with_revocation_uri_polls_the_advertised_url() {
        let key = AitpSigningKey::from_seed(&[11u8; 32]);
        let uri = "https://issuer.example/.well-known/aitp-revocation-list";
        let manifest = issuer_manifest(&key, Some(uri));
        let now = Timestamp::now();
        let jti = Uuid::new_v4();
        let env = make_envelope(jti, &key, now, Timestamp(now.0 + 3600));
        let cache =
            RevocationCache::for_issuer_manifest(&manifest, RevocationPolicy::default(), |url| {
                assert_eq!(url.as_str(), uri);
                FakeProvider { envelope: env }
            });
        assert!(cache.is_revoked(&jti, key.aid(), now).unwrap());
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
