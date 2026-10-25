//! Async, Manifest-discovered revocation lookups for the handshake
//! (RFC-AITP-0008).
//!
//! The handshake state machine is sync, so the network fetch happens
//! here, before the sync call: [`RevocationFetcher::prepare`] fetches
//! (or reuses a cached) signed snapshot from the peer's advertised
//! `ListRevoked` URL and returns a [`PreparedRevocation`], a plain value
//! whose [`PreparedRevocation::decide`] backs
//! [`aitp_handshake::RevocationSource::Check`]:
//!
//! ```no_run
//! # async fn demo(
//! #     fetcher: &aitp_transport_http::RevocationFetcher,
//! #     initiator: &aitp_handshake::Initiator,
//! # ) {
//! use aitp_handshake::RevocationSource;
//!
//! let prepared = fetcher
//!     .prepare(
//!         initiator.peer_aid().expect("after on_hello_ack"),
//!         initiator.peer_revocation_list_uri(),
//!         aitp_core::Timestamp::now(),
//!     )
//!     .await;
//! let check = move |iss: &_, jti: &_| prepared.decide(iss, jti);
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
//! rejects with [`TctError::RevocationUnavailable`], which is
//! `TCT_REVOKED` on the wire but names the reason; `FailOpen` accepts
//! and logs a warning; `SoftFail` narrows the grants.

use crate::net_guard::HostGuard;
use crate::revocation::{verify_snapshot, RevocationError, RevocationFailMode, RevocationPolicy};
use aitp_core::{Aid, CheckedJson, Timestamp};
use aitp_handshake::{HandshakeError, HandshakeRevocationDecision};
use aitp_tct::TctError;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};
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
/// ([`crate::REVOCATION_LIST_URI_EXT`]). See the [module docs](self).
///
/// Hardened like [`crate::ManifestFetcher`]: HTTPS only, no redirects,
/// [`HostGuard`] address checks with the vetted addresses pinned into
/// the connection, a body cap, and a short timeout
/// ([`DEFAULT_REVOCATION_FETCH_TIMEOUT`]).
pub struct RevocationFetcher {
    policy: RevocationPolicy,
    timeout: Duration,
    max_bytes: usize,
    host_guard: HostGuard,
    allow_insecure_localhost: bool,
    slots: Mutex<HashMap<Aid, Slot>>,
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
            allow_insecure_localhost: false,
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
    /// [`crate::GuardMode::WarnPrivate`]).
    pub fn with_host_guard(mut self, guard: HostGuard) -> Self {
        self.host_guard = guard;
        self
    }

    /// Tolerate `http://localhost` / `http://127.0.0.1` list URLs (local
    /// dev and tests). Default `false`.
    pub fn with_insecure_localhost(mut self, allow: bool) -> Self {
        self.allow_insecure_localhost = allow;
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
        let status = match list_uri {
            None => Err(format!(
                "issuer {issuer} advertises no {}",
                crate::REVOCATION_LIST_URI_EXT
            )),
            Some(uri) => self
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
            fail_mode: self.policy.fail_mode.clone(),
        }
    }

    async fn snapshot(
        &self,
        issuer: &Aid,
        uri: &str,
        now: Timestamp,
    ) -> Result<Arc<HashSet<Uuid>>, RevocationError> {
        let slot = Arc::clone(self.slots.lock().entry(issuer.clone()).or_default());
        let mut cached = slot.lock().await;
        if let Some(snap) = cached.as_ref() {
            let age = now.0.saturating_sub(snap.cached_at.0);
            if age <= self.policy.cache_ttl_secs as i64 && !snap.expires_at.is_in_the_past(now) {
                crate::obs::revocation_cache("hit");
                return Ok(Arc::clone(&snap.revoked));
            }
        }
        crate::obs::revocation_cache("miss");
        let env = self.fetch(uri).await?;
        verify_snapshot(&env, issuer, now, self.policy.max_staleness_secs)?;
        crate::obs::revocation_cache("refresh");
        let revoked: Arc<HashSet<Uuid>> =
            Arc::new(env.revocation_list.entries.iter().map(|e| e.jti).collect());
        *cached = Some(Snapshot {
            revoked: Arc::clone(&revoked),
            expires_at: env.revocation_list.expires_at,
            cached_at: now,
        });
        Ok(revoked)
    }

    async fn fetch(&self, uri: &str) -> Result<aitp_tct::RevocationListEnvelope, RevocationError> {
        let url = Url::parse(uri)
            .map_err(|e| RevocationError::Network(format!("invalid list URL: {e}")))?;
        let localhost_http = url.scheme() == "http"
            && matches!(url.host_str(), Some("localhost") | Some("127.0.0.1"));
        if url.scheme() != "https" && !(localhost_http && self.allow_insecure_localhost) {
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
                .resolve_checked(&url)
                .await
                .map_err(|e| RevocationError::Network(e.to_string()))?;
            if let Some(url::Host::Domain(domain)) = url.host() {
                builder = builder.resolve_to_addrs(domain, &addrs);
            }
        }
        let client = builder
            .build()
            .map_err(|e| RevocationError::Network(e.to_string()))?;
        let mut resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| RevocationError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(RevocationError::Network(format!(
                "upstream status {}",
                resp.status().as_u16()
            )));
        }
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| RevocationError::Network(e.to_string()))?
        {
            if body.len() + chunk.len() > self.max_bytes {
                return Err(RevocationError::Network(format!(
                    "response exceeds {} bytes",
                    self.max_bytes
                )));
            }
            body.extend_from_slice(&chunk);
        }
        // RFC-AITP-0001 §5.4.5 / §7: duplicate keys and unknown members
        // are rejected on the raw wire form, before the signature check.
        let value = CheckedJson::from_slice(&body)
            .map_err(|e| RevocationError::Malformed(e.to_string()))?;
        aitp_tct::parse_revocation_snapshot_wire(&value).map_err(|e| match e {
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
    fail_mode: RevocationFailMode,
}

impl PreparedRevocation {
    /// Whether a snapshot was obtained.
    pub fn is_available(&self) -> bool {
        self.status.is_ok()
    }

    /// The decision for the TCT `(iss, jti)`, in the shape
    /// [`aitp_handshake::RevocationCheckFn`] returns. An `iss` other than
    /// the prepared issuer has no snapshot and takes the fail mode.
    pub fn decide(
        &self,
        iss: &Aid,
        jti: &Uuid,
    ) -> Result<HandshakeRevocationDecision, HandshakeError> {
        let reason = match &self.status {
            Ok(revoked) if iss == &self.issuer => {
                return Ok(if revoked.contains(jti) {
                    HandshakeRevocationDecision::Revoked
                } else {
                    HandshakeRevocationDecision::Clear
                });
            }
            Ok(_) => format!("no snapshot prepared for issuer {iss}"),
            Err(reason) => reason.clone(),
        };
        match &self.fail_mode {
            RevocationFailMode::FailOpen => {
                warn!(%iss, %jti, %reason, "revocation unavailable; accepting under fail_open");
                Ok(HandshakeRevocationDecision::Clear)
            }
            RevocationFailMode::SoftFail { safe_grants } if !safe_grants.is_empty() => {
                warn!(%iss, %jti, %reason, "revocation unavailable; restricting grants under soft_fail");
                Ok(HandshakeRevocationDecision::SoftFailSafeSubset {
                    safe_grants: safe_grants.clone(),
                })
            }
            // FailClosed, and SoftFail with no safe subset (RFC-AITP-0008
            // §3.1: that degenerates to fail_closed).
            _ => Err(HandshakeError::Tct(TctError::RevocationUnavailable(reason))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitp_crypto::AitpSigningKey;

    fn aid(seed: u8) -> Aid {
        AitpSigningKey::from_seed(&[seed; 32]).aid().clone()
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
            fail_mode,
        }
    }

    #[test]
    fn listed_jti_is_revoked_and_others_clear() {
        let jti = Uuid::new_v4();
        let p = prepared(Ok(vec![jti]), RevocationFailMode::FailClosed);
        assert_eq!(
            p.decide(&aid(1), &jti).unwrap(),
            HandshakeRevocationDecision::Revoked
        );
        assert_eq!(
            p.decide(&aid(1), &Uuid::new_v4()).unwrap(),
            HandshakeRevocationDecision::Clear
        );
    }

    #[test]
    fn unavailable_fails_closed_by_default_with_distinct_detail() {
        let p = prepared(Err("unreachable"), RevocationPolicy::default().fail_mode);
        let err = p.decide(&aid(1), &Uuid::new_v4()).unwrap_err();
        assert!(matches!(
            &err,
            HandshakeError::Tct(TctError::RevocationUnavailable(r)) if r == "unreachable"
        ));
    }

    #[test]
    fn unavailable_fail_open_accepts() {
        let p = prepared(Err("unreachable"), RevocationFailMode::FailOpen);
        assert_eq!(
            p.decide(&aid(1), &Uuid::new_v4()).unwrap(),
            HandshakeRevocationDecision::Clear
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
            p.decide(&aid(1), &Uuid::new_v4()).unwrap(),
            HandshakeRevocationDecision::SoftFailSafeSubset { safe_grants: safe }
        );
        let p = prepared(
            Err("unreachable"),
            RevocationFailMode::SoftFail {
                safe_grants: vec![],
            },
        );
        assert!(p.decide(&aid(1), &Uuid::new_v4()).is_err());
    }

    #[test]
    fn other_issuer_takes_the_fail_mode() {
        let p = prepared(Ok(vec![]), RevocationFailMode::FailClosed);
        assert!(matches!(
            p.decide(&aid(2), &Uuid::new_v4()),
            Err(HandshakeError::Tct(TctError::RevocationUnavailable(_)))
        ));
    }

    #[tokio::test]
    async fn no_advertised_uri_is_unavailable() {
        let p = RevocationFetcher::default()
            .prepare(&aid(1), None, Timestamp::now())
            .await;
        assert!(!p.is_available());
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
}
