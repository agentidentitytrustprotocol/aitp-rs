//! Per-source challenge rate limiting (proposal Item 5: "per-source rate
//! limit").

use super::nonce_store::lock;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Decides whether `source` may receive another challenge.
///
/// `Err(retry_after)` refuses. Implementations are free to share state
/// across replicas (Redis `INCR` + `EXPIRE`, an API gateway…); the
/// library only calls this before minting a nonce.
pub trait ChallengeRateLimiter: Send + Sync {
    /// Charge one challenge to `source`.
    fn check(&self, source: &str) -> Result<(), Duration>;
}

impl<T: ChallengeRateLimiter + ?Sized> ChallengeRateLimiter for std::sync::Arc<T> {
    fn check(&self, source: &str) -> Result<(), Duration> {
        (**self).check(source)
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// A token bucket per source: `burst` challenges at once, refilling at
/// `per_second`. Tracks at most `max_sources` sources; at that bound it
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
    fn check(&self, source: &str) -> Result<(), Duration> {
        self.check_at(source, Instant::now())
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
