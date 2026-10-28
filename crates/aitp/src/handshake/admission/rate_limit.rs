//! Per-source challenge rate limiting (proposal agentidentitytrustprotocol#72
//! Item 5; the MUST and its defaults are RFC-AITP-0009 §3.1).
//!
//! Challenges are issued before the requester is authenticated, so the
//! source key MUST include a transport identifier (client IP or TLS
//! client-certificate fingerprint). A self-asserted AID is never the only
//! key: [`ChallengeSource`] cannot be built without a transport identity,
//! and its optional label only adds a second, independent limit.

use super::nonce_store::lock;
use crate::core::base64url;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The transport-level identity of a challenge requester.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportId {
    /// The peer address as the verifier's edge sees it. Behind a proxy,
    /// pass the address from a trusted forwarding header, not the
    /// proxy's.
    Ip(IpAddr),
    /// SHA-256 fingerprint of the mTLS client certificate.
    TlsClientCertSha256([u8; 32]),
}

/// Who is asking for a challenge: a transport identity plus an optional
/// self-asserted label (a claimed AID, a tenant id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeSource {
    transport: TransportId,
    transport_key: String,
    label: Option<String>,
}

impl ChallengeSource {
    /// A source identified by its network address. IPv6 addresses are
    /// keyed by their /64, the usual single-subscriber allocation, so a
    /// host cannot rotate through its prefix to reset its budget. An
    /// IPv4-mapped IPv6 address is keyed as the IPv4 address.
    pub fn ip(addr: IpAddr) -> Self {
        let addr = match addr {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(addr),
            v4 => v4,
        };
        let transport_key = match addr {
            IpAddr::V4(v4) => format!("ip4:{v4}"),
            IpAddr::V6(v6) => {
                let s = v6.segments();
                format!("ip6:{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        };
        Self {
            transport: TransportId::Ip(addr),
            transport_key,
            label: None,
        }
    }

    /// A source identified by its mTLS client certificate's SHA-256
    /// fingerprint.
    pub fn tls_client_cert_sha256(sha256_fingerprint: [u8; 32]) -> Self {
        Self {
            transport: TransportId::TlsClientCertSha256(sha256_fingerprint),
            transport_key: format!("cert:{}", base64url::encode(&sha256_fingerprint)),
            label: None,
        }
    }

    /// Attach a self-asserted label, typically the AID the requester
    /// claims. It is limited separately and never replaces the transport
    /// key.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// The transport identity.
    pub fn transport(&self) -> &TransportId {
        &self.transport
    }

    /// The canonical rate-limit key of the transport identity
    /// (`ip4:…`, `ip6:…::/64`, `cert:…`).
    pub fn transport_key(&self) -> &str {
        &self.transport_key
    }

    /// The self-asserted label, if any. Unauthenticated.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
}

impl std::fmt::Display for ChallengeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.transport_key)?;
        if let Some(l) = &self.label {
            write!(f, " label={l:?}")?;
        }
        Ok(())
    }
}

/// Decides whether `source` may receive another challenge.
///
/// `Err(retry_after)` refuses. Implementations are free to share state
/// across replicas (Redis `INCR` + `EXPIRE`, an API gateway…); the
/// library only calls this before minting a nonce. An implementation
/// MUST key on [`ChallengeSource::transport_key`]; it MAY add limits on
/// [`ChallengeSource::label`].
pub trait ChallengeRateLimiter: Send + Sync {
    /// Charge one challenge to `source`.
    fn check(&self, source: &ChallengeSource) -> Result<(), Duration>;
}

impl<T: ChallengeRateLimiter + ?Sized> ChallengeRateLimiter for std::sync::Arc<T> {
    fn check(&self, source: &ChallengeSource) -> Result<(), Duration> {
        (**self).check(source)
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// A token bucket per key: `burst` challenges at once, refilling at
/// `per_second`. As a [`ChallengeRateLimiter`] it keys on
/// [`ChallengeSource::transport_key`] only. Tracks at most `max_sources` sources; at that bound it
/// forgets sources whose bucket has refilled (state-free by definition)
/// and, failing that, refuses unknown sources rather than reset anyone's
/// bucket.
pub struct TokenBucketLimiter {
    burst: f64,
    per_second: f64,
    max_sources: usize,
    buckets: Mutex<Buckets>,
}

impl std::fmt::Debug for TokenBucketLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenBucketLimiter")
            .field("burst", &self.burst)
            .field("per_second", &self.per_second)
            .field("max_sources", &self.max_sources)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct Buckets {
    map: HashMap<String, Bucket>,
    /// Last full-table prune; at most one per [`PRUNE_INTERVAL`].
    last_prune: Option<Instant>,
}

/// A full table is pruned at most this often, so a flood of new sources
/// costs O(1) each rather than a scan each.
const PRUNE_INTERVAL: Duration = Duration::from_secs(1);

impl TokenBucketLimiter {
    /// Default bound on tracked sources.
    pub const DEFAULT_MAX_SOURCES: usize = 100_000;

    /// `burst` challenges at once, `per_second` sustained, per source.
    ///
    /// Out-of-range values are clamped, never rejected: a `burst` of 0
    /// is 1, and a `per_second` that is 0, negative or NaN is the
    /// smallest positive rate, so a spent bucket effectively never
    /// refills and its refusals carry a retry-after of
    /// [`Duration::MAX`]. An infinite `per_second` never refuses.
    pub fn new(burst: u32, per_second: f64) -> Self {
        Self {
            burst: f64::from(burst.max(1)),
            per_second: per_second.max(f64::MIN_POSITIVE),
            max_sources: Self::DEFAULT_MAX_SOURCES,
            buckets: Mutex::default(),
        }
    }

    /// Change the bound on tracked sources.
    pub fn max_sources(mut self, max: usize) -> Self {
        self.max_sources = max.max(1);
        self
    }

    /// Charge one challenge to an arbitrary `key`. For composing custom
    /// limiters.
    pub fn check_key(&self, key: &str) -> Result<(), Duration> {
        self.check_key_at(key, Instant::now())
    }

    /// As [`Self::check_key`] on an explicit monotonic clock, for
    /// deterministic tests and for callers that already read the clock.
    /// Calls with an earlier `now` than the key last saw refill nothing.
    ///
    /// At `max_sources`, an unknown key triggers a prune of refilled
    /// buckets at most once per second of `now`; between prunes it is
    /// refused.
    pub fn check_key_at(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let mut guard = lock(&self.buckets);
        let st = &mut *guard;
        if !st.map.contains_key(key) && st.map.len() >= self.max_sources {
            let due = st
                .last_prune
                .is_none_or(|t| now.saturating_duration_since(t) >= PRUNE_INTERVAL);
            if due {
                st.last_prune = Some(now);
                let (burst, rate) = (self.burst, self.per_second);
                st.map.retain(|_, b| refill(b, now, burst, rate) < burst);
            }
            if st.map.len() >= self.max_sources {
                return Err(wait(1.0 / self.per_second).max(PRUNE_INTERVAL));
            }
        }
        let b = st.map.entry(key.to_owned()).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        let tokens = refill(b, now, self.burst, self.per_second);
        if tokens >= 1.0 {
            b.tokens = tokens - 1.0;
            Ok(())
        } else {
            Err(wait((1.0 - tokens) / self.per_second))
        }
    }
}

/// `secs` as a retry-after, saturating at [`Duration::MAX`]: a rate near
/// zero gives a wait too long for a `Duration`.
fn wait(secs: f64) -> Duration {
    Duration::try_from_secs_f64(secs).unwrap_or(Duration::MAX)
}

/// Refill `b` up to `now` and return its token count.
fn refill(b: &mut Bucket, now: Instant, burst: f64, rate: f64) -> f64 {
    let dt = now.saturating_duration_since(b.last).as_secs_f64();
    b.tokens = (b.tokens + dt * rate).min(burst);
    b.last = now;
    b.tokens
}

impl ChallengeRateLimiter for TokenBucketLimiter {
    fn check(&self, source: &ChallengeSource) -> Result<(), Duration> {
        self.check_key(source.transport_key())
    }
}

/// The default limiter: a token bucket per transport source and, when the
/// source carries a label, a second one per label. Both must admit.
///
/// [`Default`] uses RFC-AITP-0009 §3.1's RECOMMENDED rates: 30 per minute
/// per source address, 10 per minute per claimed AID, each with a burst
/// equal to the minute's budget.
#[derive(Debug)]
pub struct RecommendedLimiter {
    transport: TokenBucketLimiter,
    label: Option<TokenBucketLimiter>,
}

impl RecommendedLimiter {
    /// RFC-AITP-0009 §3.1: requests per source IP per 60 s.
    pub const PER_TRANSPORT_PER_MINUTE: u32 = 30;
    /// RFC-AITP-0009 §3.1: requests per initiator AID per 60 s.
    pub const PER_LABEL_PER_MINUTE: u32 = 10;

    /// `burst`/`per_second` per transport source, and optionally
    /// `(burst, per_second)` per label. `None` leaves labels unlimited
    /// (the transport limit still applies).
    pub fn new(burst: u32, per_second: f64, per_label: Option<(u32, f64)>) -> Self {
        Self {
            transport: TokenBucketLimiter::new(burst, per_second),
            label: per_label.map(|(b, r)| TokenBucketLimiter::new(b, r)),
        }
    }
}

impl Default for RecommendedLimiter {
    fn default() -> Self {
        let per_min = |n: u32| (n, f64::from(n) / 60.0);
        let (tb, tr) = per_min(Self::PER_TRANSPORT_PER_MINUTE);
        Self::new(tb, tr, Some(per_min(Self::PER_LABEL_PER_MINUTE)))
    }
}

impl ChallengeRateLimiter for RecommendedLimiter {
    fn check(&self, source: &ChallengeSource) -> Result<(), Duration> {
        self.check_at(source, Instant::now())
    }
}

impl RecommendedLimiter {
    /// As [`ChallengeRateLimiter::check`] on an explicit monotonic clock
    /// (see [`TokenBucketLimiter::check_key_at`]).
    pub fn check_at(&self, source: &ChallengeSource, now: Instant) -> Result<(), Duration> {
        self.transport.check_key_at(source.transport_key(), now)?;
        match (&self.label, source.label()) {
            (Some(l), Some(label)) => l.check_key_at(label, now),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refuse_then_refill() {
        let l = TokenBucketLimiter::new(2, 1.0);
        let t0 = Instant::now();
        assert!(l.check_key_at("a", t0).is_ok());
        assert!(l.check_key_at("a", t0).is_ok());
        let wait = l.check_key_at("a", t0).unwrap_err();
        assert!(wait <= Duration::from_secs(1) && wait > Duration::ZERO);
        // Other sources are unaffected.
        assert!(l.check_key_at("b", t0).is_ok());
        assert!(l.check_key_at("a", t0 + Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn source_bound_refuses_new_sources_instead_of_resetting() {
        let l = TokenBucketLimiter::new(1, 0.001).max_sources(2);
        let t0 = Instant::now();
        l.check_key_at("a", t0).unwrap();
        l.check_key_at("b", t0).unwrap();
        assert!(
            l.check_key_at("c", t0).is_err(),
            "full table refuses newcomers"
        );
        // `a` is still throttled: it was not evicted and re-created.
        assert!(l.check_key_at("a", t0).is_err());
        // Once a bucket has refilled it is forgettable.
        let later = t0 + Duration::from_secs(2000);
        assert!(l.check_key_at("c", later).is_ok());
    }

    /// A flood of new sources at a full table prunes once per second,
    /// not once per request.
    #[test]
    fn full_table_prune_is_throttled() {
        let l = TokenBucketLimiter::new(1, 2.0).max_sources(2);
        let t0 = Instant::now();
        l.check_key_at("a", t0).unwrap();
        l.check_key_at("b", t0).unwrap();
        // Prunes (nothing refilled yet) and refuses.
        let wait = l.check_key_at("c", t0).unwrap_err();
        assert!(wait >= PRUNE_INTERVAL);
        // a and b have refilled, but the last prune was <1s ago.
        let t1 = t0 + Duration::from_millis(600);
        assert!(l.check_key_at("c", t1).is_err());
        assert!(l.check_key_at("c", t0 + Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn a_degenerate_rate_never_panics() {
        let t0 = Instant::now();
        for rate in [0.0, -1.0, f64::NAN, f64::NEG_INFINITY] {
            let l = TokenBucketLimiter::new(1, rate);
            l.check_key_at("a", t0).unwrap();
            // A spent bucket waits "forever", not a panic.
            assert_eq!(l.check_key_at("a", t0), Err(Duration::MAX), "rate {rate}");
            let later = t0 + Duration::from_secs(3_600);
            assert_eq!(
                l.check_key_at("a", later),
                Err(Duration::MAX),
                "rate {rate}"
            );
            // The full-table path computes its wait from the rate too.
            let l = TokenBucketLimiter::new(1, rate).max_sources(1);
            l.check_key_at("a", t0).unwrap();
            assert_eq!(l.check_key_at("b", t0), Err(Duration::MAX), "rate {rate}");
        }
    }

    #[test]
    fn an_infinite_rate_never_refuses() {
        let l = TokenBucketLimiter::new(1, f64::INFINITY);
        let t0 = Instant::now();
        for _ in 0..100 {
            l.check_key_at("a", t0).unwrap();
        }
        let l = TokenBucketLimiter::new(1, f64::INFINITY).max_sources(1);
        l.check_key_at("a", t0).unwrap();
        l.check_key_at("b", t0 + Duration::from_millis(1)).unwrap();
    }

    #[test]
    fn a_zero_burst_admits_one() {
        let l = TokenBucketLimiter::new(0, 1.0);
        let t0 = Instant::now();
        l.check_key_at("a", t0).unwrap();
        assert!(l.check_key_at("a", t0).is_err());
    }

    #[test]
    fn recommended_limiter_on_injected_clock() {
        use std::net::{IpAddr, Ipv4Addr};
        let l = RecommendedLimiter::default();
        let src = ChallengeSource::ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let t0 = Instant::now();
        for _ in 0..RecommendedLimiter::PER_TRANSPORT_PER_MINUTE {
            l.check_at(&src, t0).unwrap();
        }
        assert!(l.check_at(&src, t0).is_err());
        assert!(l.check_at(&src, t0 + Duration::from_secs(2)).is_ok());
    }
}
