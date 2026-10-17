//! Per-source challenge rate limiting (proposal agentidentitytrustprotocol#72
//! Item 5; the MUST and its defaults are RFC-AITP-0009 §3.1).
//!
//! Challenges are issued before the requester is authenticated, so the
//! source key MUST include a transport identifier (client IP or TLS
//! client-certificate fingerprint). A self-asserted AID is never the only
//! key: [`ChallengeSource`] cannot be built without a transport identity,
//! and its optional label only adds a second, independent limit.

use super::nonce_store::lock;
use aitp_core::base64url;
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
    TlsClientCert([u8; 32]),
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
    pub fn tls_client_cert(sha256_fingerprint: [u8; 32]) -> Self {
        Self {
            transport: TransportId::TlsClientCert(sha256_fingerprint),
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
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl TokenBucketLimiter {
    /// Default bound on tracked sources.
    pub const DEFAULT_MAX_SOURCES: usize = 100_000;

    /// `burst` challenges at once, `per_second` sustained, per source.
    pub fn new(burst: u32, per_second: f64) -> Self {
        Self {
            burst: f64::from(burst.max(1)),
            per_second: per_second.max(f64::MIN_POSITIVE),
            max_sources: Self::DEFAULT_MAX_SOURCES,
            buckets: Mutex::new(HashMap::new()),
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
        self.check_at(key, Instant::now())
    }

    fn check_at(&self, source: &str, now: Instant) -> Result<(), Duration> {
        let mut map = lock(&self.buckets);
        if !map.contains_key(source) && map.len() >= self.max_sources {
            let (burst, rate) = (self.burst, self.per_second);
            map.retain(|_, b| refill(b, now, burst, rate) < burst);
            if map.len() >= self.max_sources {
                return Err(Duration::from_secs_f64(1.0 / rate));
            }
        }
        let b = map.entry(source.to_owned()).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        let tokens = refill(b, now, self.burst, self.per_second);
        if tokens >= 1.0 {
            b.tokens = tokens - 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - tokens) / self.per_second))
        }
    }
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
        self.transport.check_key(source.transport_key())?;
        match (&self.label, source.label()) {
            (Some(l), Some(label)) => l.check_key(label),
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
        assert!(l.check_at("a", t0).is_ok());
        assert!(l.check_at("a", t0).is_ok());
        let wait = l.check_at("a", t0).unwrap_err();
        assert!(wait <= Duration::from_secs(1) && wait > Duration::ZERO);
        // Other sources are unaffected.
        assert!(l.check_at("b", t0).is_ok());
        assert!(l.check_at("a", t0 + Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn source_bound_refuses_new_sources_instead_of_resetting() {
        let l = TokenBucketLimiter::new(1, 0.001).max_sources(2);
        let t0 = Instant::now();
        l.check_at("a", t0).unwrap();
        l.check_at("b", t0).unwrap();
        assert!(l.check_at("c", t0).is_err(), "full table refuses newcomers");
        // `a` is still throttled: it was not evicted and re-created.
        assert!(l.check_at("a", t0).is_err());
        // Once a bucket has refilled it is forgettable.
        let later = t0 + Duration::from_secs(2000);
        assert!(l.check_at("c", later).is_ok());
    }
}
