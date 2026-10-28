//! Async, Manifest-discovered revocation lookups for the handshake
//! (RFC-AITP-0008).
//!
//! The handshake state machine is sync, so the network fetch happens
//! here, before the sync call: [`RevocationFetcher::prepare`] fetches
//! (or reuses a cached) signed snapshot from the peer's advertised
//! `ListRevoked` URL, or from a [`RevocationProvider`] set with
//! [`RevocationFetcher::with_provider`], and returns a
//! [`PreparedRevocation`], a plain value whose
//! [`PreparedRevocation::decide`] is a [`crate::tct::RevocationCheckFn`]:
//!
//! ```no_run
//! # async fn demo(
//! #     fetcher: &aitp::transport::RevocationFetcher,
//! #     initiator: &aitp::handshake::Initiator,
//! # ) {
//! use aitp::tct::{RevocationQuery, RevocationSource};
//!
//! let prepared = fetcher
//!     .prepare(
//!         initiator.peer_aid().expect("after on_hello_ack"),
//!         initiator.peer_revocation_list_uri(),
//!         aitp::core::Timestamp::now(),
//!     )
//!     .await;
//! let check = move |q: &RevocationQuery<'_>| prepared.decide(q);
//! let source = RevocationSource::Check(&check);
//! # let _ = source;
//! # }
//! ```
//!
//! **Ordering (RFC-AITP-0008 §3.3).** The lookup key is the peer AID and
//! URL from a Manifest the handshake has already bound to the peer's
//! key at HELLO / HELLO_ACK, never a claim of the not-yet-verified TCT,
//! so an off-path attacker cannot steer the fetch. `decide` itself does
//! no I/O.
//!
//! **Fail mode.** When no snapshot can be obtained (no advertised URL,
//! non-HTTPS URL, unreachable, discarded per §1.5, stale per §3.2) the
//! [`RevocationPolicy::fail_mode`] decides: `FailClosed` (the default)
//! answers [`RevocationUnavailable`], which a TCT verifier reports as
//! [`TctError::RevocationUnavailable`],
//! `TCT_REVOKED` on the wire but names the reason; `FailOpen` accepts
//! and logs a warning; `SoftFail` narrows the grants;
//! `FailOpenIfUnadvertised` accepts only when the Manifest advertises no
//! URL, and otherwise fails closed.

use crate::core::{Aid, CheckedJson, Timestamp};
use crate::tct::{RevocationQuery, RevocationStatus, RevocationUnavailable, TctError};
use crate::transport::net_guard::HostGuard;
use crate::transport::revocation::{
    verify_snapshot, RevocationError, RevocationFailMode, RevocationPolicy, RevocationProvider,
};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};
use url::Url;
use uuid::Uuid;

/// Default per-fetch timeout. The fetch sits on the handshake's
/// critical path, so it is short.
pub const DEFAULT_REVOCATION_FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum `ListRevoked` response body, bytes.
pub const DEFAULT_MAX_REVOCATION_LIST_BYTES: usize = 1024 * 1024;

/// A verified snapshot, reduced to what a decision needs.
#[derive(Clone)]
struct Snapshot {
    revoked: Arc<HashSet<Uuid>>,
    /// The snapshot's own `expires_at`; never reused past it.
    expires_at: Timestamp,
    /// When this process verified it, for the cache TTL.
    cached_at: Timestamp,
}

/// Per-issuer slot. The async mutex makes concurrent `prepare` calls for
/// one issuer share a single fetch (single flight).
type Slot = Arc<tokio::sync::Mutex<Option<Snapshot>>>;

/// Fetches and caches issuers' signed revocation snapshots from the
/// `ListRevoked` URL their Manifests advertise
/// ([`crate::manifest::REVOCATION_LIST_URI_EXT`]), or from a
/// [`RevocationProvider`] ([`Self::with_provider`]). Each snapshot is
/// verified (signature, expiry, staleness) before it is cached for
/// [`RevocationPolicy::cache_ttl`]. See the [module docs](self).
///
/// Hardened like [`crate::transport::ManifestFetcher`]: HTTPS only, no redirects,
/// [`HostGuard`] address checks with the vetted addresses pinned into
/// the connection, a body cap, and a short timeout
/// ([`DEFAULT_REVOCATION_FETCH_TIMEOUT`]).
pub struct RevocationFetcher {
    policy: RevocationPolicy,
    timeout: Duration,
    max_bytes: usize,
    host_guard: HostGuard,
    insecure_localhost: bool,
    provider: Option<Arc<dyn RevocationProvider>>,
    slots: Mutex<HashMap<Aid, Slot>>,
}

impl std::fmt::Debug for RevocationFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationFetcher")
            .field("policy", &self.policy)
            .field("timeout", &self.timeout)
            .field("max_bytes", &self.max_bytes)
            .field("host_guard", &self.host_guard)
            .field("insecure_localhost", &self.insecure_localhost)
            .field("provider", &self.provider.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for RevocationFetcher {
    fn default() -> Self {
        Self::new(RevocationPolicy::default())
    }
}

impl RevocationFetcher {
    /// A fetcher applying `policy`. [`RevocationPolicy::default`] is
    /// `fail_closed`.
    pub fn new(policy: RevocationPolicy) -> Self {
        Self {
            policy,
            timeout: DEFAULT_REVOCATION_FETCH_TIMEOUT,
            max_bytes: DEFAULT_MAX_REVOCATION_LIST_BYTES,
            host_guard: HostGuard::default(),
            insecure_localhost: false,
            provider: None,
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// The policy this fetcher applies.
    pub fn policy(&self) -> &RevocationPolicy {
        &self.policy
    }

    /// Override the per-fetch timeout (default
    /// [`DEFAULT_REVOCATION_FETCH_TIMEOUT`]).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the SSRF [`HostGuard`] (default
    /// [`crate::transport::GuardMode::DenyPrivate`]).
    pub fn with_host_guard(mut self, guard: HostGuard) -> Self {
        self.host_guard = guard;
        self
    }

    /// Tolerate `http://localhost` / `http://127.0.0.1` list URLs and
    /// admit loopback addresses (`127.0.0.0/8`, `::1`) through the host
    /// guard, as [`HostGuard::allow_loopback_dangerous`] does. For local
    /// dev and tests.
    pub fn with_insecure_localhost_dangerous(mut self) -> Self {
        self.insecure_localhost = true;
        self
    }

    /// Take snapshots from `provider` instead of the advertised URL (a
    /// file, a database, a test fixture). The list URL passed to
    /// [`Self::prepare`] then only tells
    /// [`RevocationFailMode::FailOpenIfUnadvertised`] whether one is
    /// advertised.
    pub fn with_provider(mut self, provider: Arc<dyn RevocationProvider>) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Obtain revocation status for `issuer`, whose verified Manifest
    /// advertises `list_uri` (`None` when it advertises none), and
    /// return the decision value for the sync handshake step.
    ///
    /// Never fails: an unobtainable snapshot is recorded in the result
    /// and the fail mode applies when [`PreparedRevocation::decide`]
    /// runs.
    pub async fn prepare(
        &self,
        issuer: &Aid,
        list_uri: Option<&str>,
        now: Timestamp,
    ) -> PreparedRevocation {
        let status = match (&self.provider, list_uri) {
            (None, None) => Err(format!(
                "issuer {issuer} advertises no {}",
                crate::manifest::REVOCATION_LIST_URI_EXT
            )),
            (_, uri) => self
                .snapshot(issuer, uri, now)
                .await
                .map_err(|e| format!("revocation list for issuer {issuer}: {e}")),
        };
        if let Err(reason) = &status {
            debug!(%issuer, %reason, "revocation status unavailable");
        }
        PreparedRevocation {
            issuer: issuer.clone(),
            status,
            advertised: list_uri.is_some(),
            fail_mode: self.policy.fail_mode.clone(),
        }
    }

    /// The issuer's verified, cached revocation set. Reads from the
    /// provider when one is set, else from `uri` (`Some` then).
    async fn snapshot(
        &self,
        issuer: &Aid,
        uri: Option<&str>,
        now: Timestamp,
    ) -> Result<Arc<HashSet<Uuid>>, RevocationError> {
        let slot = Arc::clone(self.slots.lock().entry(issuer.clone()).or_default());
        let mut cached = slot.lock().await;
        if let Some(snap) = cached.as_ref() {
            let age = now.0.saturating_sub(snap.cached_at.0);
            if age <= crate::core::time::duration_secs(self.policy.cache_ttl)
                && !snap.expires_at.is_in_the_past(now)
            {
                crate::transport::obs::revocation_cache("hit");
                return Ok(Arc::clone(&snap.revoked));
            }
        }
        crate::transport::obs::revocation_cache("miss");
        let env = match (&self.provider, uri) {
            (Some(provider), _) => provider.fetch(issuer).await?,
            (None, Some(uri)) => self.fetch(uri).await?,
            (None, None) => return Err(RevocationError::NoSnapshotFailClosed),
        };
        verify_snapshot(&env, issuer, now, self.policy.max_staleness)?;
        crate::transport::obs::revocation_cache("refresh");
        let revoked: Arc<HashSet<Uuid>> =
            Arc::new(env.revocation_list.entries.iter().map(|e| e.jti).collect());
        *cached = Some(Snapshot {
            revoked: Arc::clone(&revoked),
            expires_at: env.revocation_list.expires_at,
            cached_at: now,
        });
        Ok(revoked)
    }

    async fn fetch(
        &self,
        uri: &str,
    ) -> Result<crate::tct::RevocationListEnvelope, RevocationError> {
        let url = Url::parse(uri)
            .map_err(|e| RevocationError::Network(format!("invalid list URL: {e}").into()))?;
        let localhost_http = url.scheme() == "http"
            && matches!(url.host_str(), Some("localhost") | Some("127.0.0.1"));
        if url.scheme() != "https" && !(localhost_http && self.insecure_localhost) {
            return Err(RevocationError::Network(
                "list URL is not https (RFC-AITP-0008 §1.4)".into(),
            ));
        }
        let mut builder = reqwest::Client::builder()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::none());
        if !localhost_http {
            let addrs = self
                .host_guard
                .resolve_checked_with(&url, self.insecure_localhost)
                .await
                .map_err(|e| RevocationError::Network(e.into()))?;
            if let Some(url::Host::Domain(domain)) = url.host() {
                builder = builder.resolve_to_addrs(domain, &addrs);
            }
        }
        let client = builder
            .build()
            .map_err(|e| RevocationError::Network(e.into()))?;
        let mut resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| RevocationError::Network(e.into()))?;
        if !resp.status().is_success() {
            return Err(RevocationError::Network(
                format!("upstream status {}", resp.status().as_u16()).into(),
            ));
        }
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| RevocationError::Network(e.into()))?
        {
            if body.len() + chunk.len() > self.max_bytes {
                return Err(RevocationError::Network(
                    format!("response exceeds {} bytes", self.max_bytes).into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        // RFC-AITP-0001 §5.4.5 / §7: duplicate keys and unknown members
        // are rejected on the raw wire form, before the signature check.
        let value = CheckedJson::from_slice(&body)
            .map_err(|e| RevocationError::Malformed(e.to_string()))?;
        crate::tct::parse_revocation_snapshot_wire(&value).map_err(|e| match e {
            TctError::UnknownField(field) => RevocationError::UnknownField(field),
            other => RevocationError::Malformed(other.to_string()),
        })
    }
}

/// Revocation status for one issuer, obtained by
/// [`RevocationFetcher::prepare`]; decides synchronously. See the
/// [module docs](self).
#[derive(Clone, Debug)]
pub struct PreparedRevocation {
    issuer: Aid,
    /// The issuer's revoked `jti`s, or why they are unknown.
    status: Result<Arc<HashSet<Uuid>>, String>,
    /// Whether the issuer's Manifest advertised a list URL.
    advertised: bool,
    fail_mode: RevocationFailMode,
}

impl PreparedRevocation {
    /// Whether a snapshot was obtained.
    pub fn is_available(&self) -> bool {
        self.status.is_ok()
    }

    /// The status of `query.jti` under `query.issuer`, so a closure over
    /// this is a [`crate::tct::RevocationCheckFn`]. An issuer other than
    /// the prepared one has no snapshot and takes the fail mode. Does no
    /// I/O.
    pub fn decide(
        &self,
        query: &RevocationQuery<'_>,
    ) -> Result<RevocationStatus, RevocationUnavailable> {
        let (iss, jti) = (query.issuer, query.jti);
        let reason = match &self.status {
            Ok(revoked) if iss == &self.issuer => {
                let (status, outcome) = if revoked.contains(jti) {
                    (RevocationStatus::Revoked, "revoked")
                } else {
                    (RevocationStatus::Clear, "clear")
                };
                debug!(%iss, %jti, outcome, "revocation check");
                return Ok(status);
            }
            Ok(_) => format!("no snapshot prepared for issuer {iss}"),
            Err(reason) => reason.clone(),
        };
        match &self.fail_mode {
            RevocationFailMode::FailOpen => {
                warn!(%iss, %jti, %reason, "revocation unavailable; accepting under fail_open");
                Ok(RevocationStatus::Clear)
            }
            RevocationFailMode::FailOpenIfUnadvertised if !self.advertised => {
                info!(%iss, %jti, "issuer advertises no revocation list; accepting under fail_open_if_unadvertised");
                Ok(RevocationStatus::Clear)
            }
            RevocationFailMode::SoftFail { safe_grants } if !safe_grants.is_empty() => {
                warn!(%iss, %jti, %reason, "revocation unavailable; restricting grants under soft_fail");
                debug!(%iss, %jti, outcome = "soft_fail_safe_subset", "revocation check");
                Ok(RevocationStatus::SoftFailSafeSubset {
                    safe_grants: safe_grants.clone(),
                })
            }
            // FailClosed, SoftFail with no safe subset (RFC-AITP-0008
            // §3.1: that degenerates to fail_closed), and
            // FailOpenIfUnadvertised for an advertised list.
            _ => Err(RevocationUnavailable::new(reason)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::BoxFuture;
    use crate::crypto::AitpSigningKey;
    use crate::tct::{
        sign_revocation_list, RevocationEntry, RevocationList, RevocationListEnvelope,
    };
    use crate::transport::revocation::EmptyRevocationProvider;

    fn aid(seed: u8) -> Aid {
        AitpSigningKey::from_ed25519_seed(&[seed; 32]).aid().clone()
    }

    fn query<'a>(issuer: &'a Aid, jti: &'a Uuid) -> RevocationQuery<'a> {
        RevocationQuery::new(issuer, jti, Timestamp::now())
    }

    fn prepared(
        status: Result<Vec<Uuid>, &str>,
        fail_mode: RevocationFailMode,
    ) -> PreparedRevocation {
        PreparedRevocation {
            issuer: aid(1),
            status: status
                .map(|v| Arc::new(v.into_iter().collect()))
                .map_err(str::to_owned),
            advertised: true,
            fail_mode,
        }
    }

    fn make_envelope(
        jti: Uuid,
        issuer_key: &AitpSigningKey,
        published_at: Timestamp,
        expires_at: Timestamp,
    ) -> RevocationListEnvelope {
        sign_revocation_list(
            RevocationList::new(
                issuer_key.aid().clone(),
                published_at,
                expires_at,
                vec![RevocationEntry::new(jti, published_at)],
            ),
            issuer_key,
        )
        .unwrap()
    }

    /// A provider returning a fixed envelope, or a network error.
    struct FixedProvider(Option<RevocationListEnvelope>);
    impl RevocationProvider for FixedProvider {
        fn fetch<'a>(
            &'a self,
            _issuer: &'a Aid,
        ) -> BoxFuture<'a, Result<RevocationListEnvelope, RevocationError>> {
            let out = self
                .0
                .clone()
                .ok_or_else(|| RevocationError::Network("offline".into()));
            Box::pin(std::future::ready(out))
        }
    }

    /// A provider that decodes raw wire JSON, as the trait contract asks.
    struct WireParsingProvider(serde_json::Value);
    impl RevocationProvider for WireParsingProvider {
        fn fetch<'a>(
            &'a self,
            _issuer: &'a Aid,
        ) -> BoxFuture<'a, Result<RevocationListEnvelope, RevocationError>> {
            let checked: CheckedJson = self.0.to_string().parse().expect("valid JSON");
            let out = crate::tct::parse_revocation_snapshot_wire(&checked).map_err(|e| match e {
                TctError::UnknownField(field) => RevocationError::UnknownField(field),
                TctError::ClaimsMalformed(msg) => RevocationError::Malformed(msg),
                other => RevocationError::SignatureInvalid(other),
            });
            Box::pin(std::future::ready(out))
        }
    }

    async fn prepare_with(
        provider: impl RevocationProvider + 'static,
        policy: RevocationPolicy,
        issuer: &Aid,
        now: Timestamp,
    ) -> PreparedRevocation {
        RevocationFetcher::new(policy)
            .with_provider(Arc::new(provider))
            .prepare(issuer, None, now)
            .await
    }

    #[test]
    fn listed_jti_is_revoked_and_others_clear() {
        let jti = Uuid::new_v4();
        let p = prepared(Ok(vec![jti]), RevocationFailMode::FailClosed);
        assert_eq!(
            p.decide(&query(&aid(1), &jti)).unwrap(),
            RevocationStatus::Revoked
        );
        assert_eq!(
            p.decide(&query(&aid(1), &Uuid::new_v4())).unwrap(),
            RevocationStatus::Clear
        );
    }

    #[test]
    fn unavailable_fails_closed_by_default_with_distinct_detail() {
        let p = prepared(Err("unreachable"), RevocationPolicy::default().fail_mode);
        let err = p.decide(&query(&aid(1), &Uuid::new_v4())).unwrap_err();
        assert_eq!(
            err.to_string(),
            "revocation source unavailable: unreachable"
        );
    }

    #[test]
    fn unavailable_fail_open_accepts() {
        let p = prepared(Err("unreachable"), RevocationFailMode::FailOpen);
        assert_eq!(
            p.decide(&query(&aid(1), &Uuid::new_v4())).unwrap(),
            RevocationStatus::Clear
        );
    }

    #[test]
    fn soft_fail_narrows_and_empty_subset_fails_closed() {
        let safe = vec!["read".to_string()];
        let p = prepared(
            Err("unreachable"),
            RevocationFailMode::SoftFail {
                safe_grants: safe.clone(),
            },
        );
        assert_eq!(
            p.decide(&query(&aid(1), &Uuid::new_v4())).unwrap(),
            RevocationStatus::SoftFailSafeSubset { safe_grants: safe }
        );
        let p = prepared(
            Err("unreachable"),
            RevocationFailMode::SoftFail {
                safe_grants: vec![],
            },
        );
        assert!(p.decide(&query(&aid(1), &Uuid::new_v4())).is_err());
    }

    #[test]
    fn other_issuer_takes_the_fail_mode() {
        let p = prepared(Ok(vec![]), RevocationFailMode::FailClosed);
        assert!(p.decide(&query(&aid(2), &Uuid::new_v4())).is_err());
    }

    #[test]
    fn fail_open_if_unadvertised_still_honours_a_revoked_jti() {
        let jti = Uuid::new_v4();
        let p = prepared(Ok(vec![jti]), RevocationFailMode::FailOpenIfUnadvertised);
        assert_eq!(
            p.decide(&query(&aid(1), &jti)).unwrap(),
            RevocationStatus::Revoked
        );
    }

    #[tokio::test]
    async fn no_advertised_uri_is_unavailable() {
        let p = RevocationFetcher::default()
            .prepare(&aid(1), None, Timestamp::now())
            .await;
        assert!(!p.is_available());
    }

    #[tokio::test]
    async fn fail_open_if_unadvertised_accepts_only_without_a_list_uri() {
        let fetcher = RevocationFetcher::new(RevocationPolicy {
            fail_mode: RevocationFailMode::FailOpenIfUnadvertised,
            ..Default::default()
        });
        let p = fetcher.prepare(&aid(1), None, Timestamp::now()).await;
        assert_eq!(
            p.decide(&query(&aid(1), &Uuid::new_v4())).unwrap(),
            RevocationStatus::Clear
        );
        // An advertised list that cannot be obtained is not ignored.
        let p = fetcher
            .prepare(
                &aid(1),
                Some("http://issuer.example/list"),
                Timestamp::now(),
            )
            .await;
        assert!(p.decide(&query(&aid(1), &Uuid::new_v4())).is_err());
    }

    #[tokio::test]
    async fn non_https_uri_is_unavailable() {
        let p = RevocationFetcher::default()
            .prepare(
                &aid(1),
                Some("http://issuer.example/list"),
                Timestamp::now(),
            )
            .await;
        assert!(!p.is_available());
    }

    #[tokio::test]
    async fn provider_snapshot_decides_revoked_and_clear() {
        let key = AitpSigningKey::from_ed25519_seed(&[1u8; 32]);
        let now = Timestamp::now();
        let jti = Uuid::new_v4();
        let env = make_envelope(jti, &key, now, Timestamp(now.0 + 3600));
        let p = prepare_with(
            FixedProvider(Some(env)),
            RevocationPolicy::default(),
            key.aid(),
            now,
        )
        .await;
        assert!(p.is_available());
        assert_eq!(
            p.decide(&query(key.aid(), &jti)).unwrap(),
            RevocationStatus::Revoked
        );
        assert_eq!(
            p.decide(&query(key.aid(), &Uuid::new_v4())).unwrap(),
            RevocationStatus::Clear
        );
    }

    #[tokio::test]
    async fn empty_provider_reads_everything_as_unrevoked() {
        let key = AitpSigningKey::from_ed25519_seed(&[9u8; 32]);
        let issuer = key.aid().clone();
        let p = prepare_with(
            EmptyRevocationProvider::new(key),
            RevocationPolicy::default(),
            &issuer,
            Timestamp::now(),
        )
        .await;
        assert_eq!(
            p.decide(&query(&issuer, &Uuid::new_v4())).unwrap(),
            RevocationStatus::Clear
        );
    }

    #[tokio::test]
    async fn empty_provider_accepts_a_kms_backend() {
        use crate::crypto::testing::{MockKmsSigner, MockOutput};
        let kms = MockKmsSigner::new(AitpSigningKey::from_p256_seed(&[9u8; 32]).unwrap())
            .output(MockOutput::DerHighS);
        let issuer = crate::crypto::AitpSigner::aid(&kms).clone();
        let p = prepare_with(
            EmptyRevocationProvider::new(kms),
            RevocationPolicy::default(),
            &issuer,
            Timestamp::now(),
        )
        .await;
        assert!(p.is_available(), "KMS-signed empty snapshot verifies");
    }

    /// Snapshots the fetcher must discard: the fail mode then decides,
    /// and the reason names the defect.
    async fn discarded_reason(env: RevocationListEnvelope, issuer: &Aid, now: Timestamp) -> String {
        let p = prepare_with(
            FixedProvider(Some(env)),
            RevocationPolicy::default(),
            issuer,
            now,
        )
        .await;
        assert!(!p.is_available());
        p.decide(&query(issuer, &Uuid::new_v4()))
            .unwrap_err()
            .to_string()
    }

    #[tokio::test]
    async fn expired_snapshot_is_discarded() {
        let key = AitpSigningKey::from_ed25519_seed(&[3u8; 32]);
        let now = Timestamp::now();
        let env = make_envelope(
            Uuid::new_v4(),
            &key,
            Timestamp(now.0 - 7200),
            Timestamp(now.0 - 3600),
        );
        let reason = discarded_reason(env, key.aid(), now).await;
        assert!(reason.contains("expired"), "{reason}");
    }

    #[tokio::test]
    async fn stale_snapshot_is_discarded() {
        let key = AitpSigningKey::from_ed25519_seed(&[4u8; 32]);
        let now = Timestamp::now();
        // Published two days ago, still inside expires_at, but past the
        // 24h staleness bound.
        let env = make_envelope(
            Uuid::new_v4(),
            &key,
            Timestamp(now.0 - 172_800),
            Timestamp(now.0 + 3600),
        );
        let reason = discarded_reason(env, key.aid(), now).await;
        assert!(reason.contains("stale"), "{reason}");
    }

    #[tokio::test]
    async fn invalid_signature_is_discarded() {
        let key = AitpSigningKey::from_ed25519_seed(&[5u8; 32]);
        let now = Timestamp::now();
        let mut env = make_envelope(Uuid::new_v4(), &key, now, Timestamp(now.0 + 3600));
        env.signature = "A".repeat(86);
        let reason = discarded_reason(env, key.aid(), now).await;
        assert!(reason.contains("signature invalid"), "{reason}");
    }

    /// rev-010 shape (#265): an unknown `version` is reported as a
    /// malformed snapshot, never as a signature failure.
    #[tokio::test]
    async fn unknown_version_is_malformed_not_signature_invalid() {
        let key = AitpSigningKey::from_ed25519_seed(&[0x5A; 32]);
        let now = Timestamp::now();
        let mut env = make_envelope(Uuid::new_v4(), &key, now, Timestamp(now.0 + 3600));
        env.revocation_list.version = "aitp/9.9".into();
        let reason = discarded_reason(env, key.aid(), now).await;
        assert!(
            reason.contains("malformed") && reason.contains("aitp/9.9"),
            "{reason}"
        );
    }

    /// A provider's member-set rejection (issue #140) keeps its
    /// classification: unknown member, not signature failure.
    #[tokio::test]
    async fn unknown_member_snapshot_is_not_reported_as_signature_invalid() {
        let key = AitpSigningKey::from_ed25519_seed(&[7u8; 32]);
        let now = Timestamp::now();
        let env = make_envelope(Uuid::new_v4(), &key, now, Timestamp(now.0 + 3600));
        let mut raw = serde_json::to_value(&env).unwrap();
        raw["revocation_list"]
            .as_object_mut()
            .unwrap()
            .insert("list_owner".into(), serde_json::json!("team-trust"));
        let p = prepare_with(
            WireParsingProvider(raw),
            RevocationPolicy::default(),
            key.aid(),
            now,
        )
        .await;
        let reason = p
            .decide(&query(key.aid(), &Uuid::new_v4()))
            .unwrap_err()
            .to_string();
        assert!(reason.contains("unknown field: list_owner"), "{reason}");
        assert!(!reason.contains("signature"), "{reason}");
    }

    /// issue #144: a missing required member is a malformed snapshot.
    #[tokio::test]
    async fn claims_malformed_snapshot_is_not_reported_as_signature_invalid() {
        let key = AitpSigningKey::from_ed25519_seed(&[7u8; 32]);
        let now = Timestamp::now();
        let env = make_envelope(Uuid::new_v4(), &key, now, Timestamp(now.0 + 3600));
        let mut raw = serde_json::to_value(&env).unwrap();
        raw["revocation_list"]
            .as_object_mut()
            .unwrap()
            .remove("published_at");
        let p = prepare_with(
            WireParsingProvider(raw),
            RevocationPolicy::default(),
            key.aid(),
            now,
        )
        .await;
        let reason = p
            .decide(&query(key.aid(), &Uuid::new_v4()))
            .unwrap_err()
            .to_string();
        assert!(reason.contains("malformed"), "{reason}");
        assert!(!reason.contains("signature"), "{reason}");
    }

    #[tokio::test]
    async fn unreachable_provider_takes_the_fail_mode() {
        let issuer = aid(6);
        let now = Timestamp::now();
        let open = prepare_with(
            FixedProvider(None),
            RevocationPolicy::default().with_fail_mode(RevocationFailMode::FailOpen),
            &issuer,
            now,
        )
        .await;
        assert_eq!(
            open.decide(&query(&issuer, &Uuid::new_v4())).unwrap(),
            RevocationStatus::Clear
        );
        let soft = prepare_with(
            FixedProvider(None),
            RevocationPolicy::default().with_fail_mode(RevocationFailMode::SoftFail {
                safe_grants: vec!["read_data".into()],
            }),
            &issuer,
            now,
        )
        .await;
        assert_eq!(
            soft.decide(&query(&issuer, &Uuid::new_v4())).unwrap(),
            RevocationStatus::SoftFailSafeSubset {
                safe_grants: vec!["read_data".into()]
            }
        );
        // SoftFail with no safe subset degenerates to fail_closed.
        let empty = prepare_with(
            FixedProvider(None),
            RevocationPolicy::default().with_fail_mode(RevocationFailMode::SoftFail {
                safe_grants: vec![],
            }),
            &issuer,
            now,
        )
        .await;
        assert!(empty.decide(&query(&issuer, &Uuid::new_v4())).is_err());
    }

    /// A verified snapshot is reused within the cache TTL.
    #[tokio::test]
    async fn verified_snapshot_is_cached() {
        struct Counting(std::sync::atomic::AtomicUsize, EmptyRevocationProvider);
        impl RevocationProvider for Counting {
            fn fetch<'a>(
                &'a self,
                issuer: &'a Aid,
            ) -> BoxFuture<'a, Result<RevocationListEnvelope, RevocationError>> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.1.fetch(issuer)
            }
        }
        let key = AitpSigningKey::from_ed25519_seed(&[12u8; 32]);
        let issuer = key.aid().clone();
        let provider = Arc::new(Counting(
            std::sync::atomic::AtomicUsize::new(0),
            EmptyRevocationProvider::new(key),
        ));
        let fetcher = RevocationFetcher::default()
            .with_provider(Arc::clone(&provider) as Arc<dyn RevocationProvider>);
        let now = Timestamp::now();
        assert!(fetcher.prepare(&issuer, None, now).await.is_available());
        assert!(fetcher.prepare(&issuer, None, now).await.is_available());
        assert_eq!(provider.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}
