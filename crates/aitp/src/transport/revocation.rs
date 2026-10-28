//! Revocation policy and snapshot sources (RFC-AITP-0008).
//!
//! [`RevocationPolicy`] and [`RevocationFailMode`] say what a verifier
//! does when an issuer's revocation status cannot be obtained. A
//! [`RevocationProvider`] is a non-HTTP snapshot source for
//! [`crate::transport::RevocationFetcher::with_provider`]; the fetcher
//! caches, verifies and decides.

use crate::core::{Aid, BoxFuture, Timestamp};
use crate::crypto::AitpSigner;
use crate::tct::{
    sign_revocation_list, verify_revocation_list, RevocationList, RevocationListEnvelope, TctError,
    VerifyRevocationListContext,
};
use std::sync::Arc;

/// Source of an issuer's signed revocation snapshots, for
/// [`crate::transport::RevocationFetcher::with_provider`]. The fetcher
/// verifies each snapshot (signature, expiry, staleness) and caches it.
pub trait RevocationProvider: Send + Sync {
    /// Fetch the latest signed snapshot for `issuer`.
    ///
    /// An implementation that decodes untrusted bytes off the wire (an
    /// HTTP response body, a file, …) MUST apply RFC-AITP-0001 §7's
    /// member-set check before returning — via
    /// [`crate::tct::parse_revocation_snapshot_wire`] on the raw
    /// [`serde_json::Value`], not a bare `serde_json::from_value` /
    /// `from_slice` into [`RevocationListEnvelope`], which would only
    /// surface an unknown member as an opaque `serde_json::Error` for the
    /// caller to (mis)classify. Map the resulting
    /// `Err(crate::tct::TctError::UnknownField(_))` to
    /// [`RevocationError::UnknownField`], and
    /// `Err(crate::tct::TctError::ClaimsMalformed(_))` (a missing/mistyped
    /// known member — the member set itself was intact) to
    /// [`RevocationError::Malformed`] — **never** either one to
    /// [`RevocationError::SignatureInvalid`], which would misreport a
    /// structural rejection (the signature is never reached) as a
    /// cryptographic one, the miscategorization the fetcher's own
    /// signature/expiry check avoids for errors that originate *after*
    /// this call.
    fn fetch<'a>(
        &'a self,
        issuer: &'a Aid,
    ) -> BoxFuture<'a, Result<RevocationListEnvelope, RevocationError>>;
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
/// This is NOT a "skip revocation" switch — for that, use
/// [`crate::tct::RevocationSource::FailOpen`] or
/// [`RevocationFailMode::FailOpen`].
pub struct EmptyRevocationProvider {
    issuer_key: Arc<dyn AitpSigner>,
    ttl_secs: i64,
}

impl std::fmt::Debug for EmptyRevocationProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmptyRevocationProvider")
            .field("issuer", self.issuer_key.aid())
            .field("ttl_secs", &self.ttl_secs)
            .finish_non_exhaustive()
    }
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

impl EmptyRevocationProvider {
    /// Sign an empty list valid from now. `extensions` stays absent.
    pub(crate) fn sign_empty(&self) -> Result<RevocationListEnvelope, RevocationError> {
        let now = Timestamp::now();
        sign_revocation_list(
            RevocationList {
                version: crate::core::PROTOCOL_VERSION.into(),
                issuer: self.issuer_key.aid().clone(),
                published_at: now,
                expires_at: Timestamp(now.0 + self.ttl_secs),
                entries: vec![],
                extensions: None,
            },
            &*self.issuer_key,
        )
        .map_err(|e| match e {
            TctError::Crypto(crate::crypto::CryptoError::Signer(s)) => RevocationError::Signer(s),
            other => RevocationError::SignatureInvalid(other),
        })
    }
}

impl RevocationProvider for EmptyRevocationProvider {
    fn fetch<'a>(
        &'a self,
        _issuer: &'a Aid,
    ) -> BoxFuture<'a, Result<RevocationListEnvelope, RevocationError>> {
        Box::pin(std::future::ready(self.sign_empty()))
    }
}

/// Errors raised when fetching or applying a revocation snapshot.
///
/// Marked `#[non_exhaustive]` so a future structural-rejection category
/// (mirroring [`crate::manifest::ManifestError`], which carries the same
/// attribute) doesn't force a breaking change on every downstream match —
/// this variant set is still expected to grow as RFC-AITP-0008 §1.5's
/// structural-rejection table does.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RevocationError {
    /// Underlying network/transport error.
    #[error("network error: {0}")]
    Network(#[source] crate::core::BoxError),
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
    /// [`crate::tct::TctError::ClaimsMalformed`] from
    /// [`crate::tct::parse_revocation_snapshot_wire`]. Also never the
    /// signature check's fault: the signature was never reached. This is
    /// the `REVOCATION_SNAPSHOT_INVALID` case, the revocation-snapshot
    /// sibling of `ManifestError::Malformed` (RFC-AITP-0008 §1.5).
    ///
    /// An unknown `revocation_list.version` is also this variant
    /// (issue #265): spec
    /// VERSIONING.md makes `REVOCATION_SNAPSHOT_INVALID` a snapshot's
    /// unknown-version code. It was previously
    /// `SignatureInvalid(TctError::VersionUnknown)`.
    #[error("revocation snapshot is malformed: {0}")]
    Malformed(String),
    /// Our own signing backend (in-process key, KMS, HSM) failed while
    /// [`EmptyRevocationProvider`] signed a snapshot. A local fault, not
    /// a bad snapshot: [`crate::crypto::SignerError::is_transient`] tells
    /// whether a retry may help.
    #[error("signing backend failed: {0}")]
    Signer(#[from] crate::crypto::SignerError),
}

/// What to do when revocation cannot be checked freshly (network down,
/// no provider configured, snapshot stale, …).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevocationFailMode {
    /// Reject the underlying TCT — safest choice for high-value flows.
    /// Default.
    FailClosed,
    /// Accept the underlying TCT — appropriate for low-value flows where
    /// availability dominates.
    FailOpen,
    /// Accept with the artifact's grants narrowed to a configured safe
    /// subset (RFC-AITP-0008 §3.1): the decision is
    /// [`crate::tct::RevocationStatus::SoftFailSafeSubset`], and an empty
    /// intersection fails with `POLICY_VIOLATION`.
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
    /// [`crate::transport::RevocationFetcher::prepare`] is told whether
    /// the Manifest advertises a URL, so it can tell the two cases apart.
    FailOpenIfUnadvertised,
}

impl Default for RevocationFailMode {
    fn default() -> Self {
        Self::FailClosed
    }
}

/// Per-issuer revocation policy.
#[derive(Clone, Debug)]
#[non_exhaustive]
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

impl RevocationPolicy {
    /// Set `fail_mode`.
    pub fn with_fail_mode(mut self, fail_mode: RevocationFailMode) -> Self {
        self.fail_mode = fail_mode;
        self
    }

    /// Set `max_staleness_secs`.
    pub fn with_max_staleness_secs(mut self, secs: u64) -> Self {
        self.max_staleness_secs = secs;
        self
    }

    /// Set `cache_ttl_secs`.
    pub fn with_cache_ttl_secs(mut self, secs: u64) -> Self {
        self.cache_ttl_secs = secs;
        self
    }
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

/// Verify a fetched snapshot for `issuer` at `now`: signature, expiry and
/// structure (RFC-AITP-0008 §1.5), then `max_staleness_secs` (§3.2).
/// Used by [`crate::transport::revocation_fetch::RevocationFetcher`].
pub(crate) fn verify_snapshot(
    env: &RevocationListEnvelope,
    issuer: &Aid,
    now: Timestamp,
    max_staleness_secs: u64,
) -> Result<(), RevocationError> {
    // Verify signature + expiry. `TctError::UnknownField` and
    // `TctError::ClaimsMalformed` each get their own arm rather than
    // falling into the `other` catch-all below: a provider that parses
    // the raw wire form via `crate::tct::parse_revocation_snapshot_wire`
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
        crate::transport::obs::revocation_cache("stale");
        return Err(RevocationError::Stale {
            published_at: env.revocation_list.published_at,
            max_staleness_secs,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AitpSigningKey;

    #[tokio::test]
    async fn empty_provider_signs_an_empty_list_without_extensions() {
        let key = AitpSigningKey::from_ed25519_seed(&[9u8; 32]);
        let issuer = key.aid().clone();
        let env = EmptyRevocationProvider::new(key)
            .fetch(&issuer)
            .await
            .unwrap();
        assert!(env.revocation_list.entries.is_empty());
        assert!(env.revocation_list.extensions.is_none());
        verify_snapshot(&env, &issuer, Timestamp::now(), 60).unwrap();
    }

    #[tokio::test]
    async fn empty_provider_surfaces_backend_failure_as_signer_error() {
        use crate::crypto::testing::MockKmsSigner;
        let kms = MockKmsSigner::new(AitpSigningKey::from_p256_seed(&[9u8; 32]).unwrap())
            .sign_with(AitpSigningKey::from_p256_seed(&[8u8; 32]).unwrap());
        let issuer = kms.aid().clone();
        let err = EmptyRevocationProvider::new(kms)
            .fetch(&issuer)
            .await
            .expect_err("wrong-key backend must fail");
        assert!(
            matches!(
                err,
                RevocationError::Signer(crate::crypto::SignerError::VerificationFailed)
            ),
            "{err:?}"
        );
    }
}
