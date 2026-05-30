//! Retry policy for outbound HTTP fetches (Phase 2).
//!
//! AITP fetchers must tolerate transient network conditions: TCP RSTs,
//! DNS hiccups, gateway 502/503/504s, and slow upstreams under load.
//! Without retry the surrounding handshake fails for any one-off network
//! glitch — which in practice is the dominant cause of inter-peer
//! failures, not protocol bugs.
//!
//! `RetryPolicy` is opt-in. Default-construction yields one attempt with
//! no backoff (matching the rc.1 behavior); callers wire a non-trivial
//! policy via the fetchers' `with_retry_policy(...)` builder methods.
//!
//! # Idempotency
//!
//! Only idempotent reads are retried (Manifest fetch, JWKS fetch, OIDC
//! discovery). The handshake POSTs are NOT retried at this layer — a
//! retried POST could double-publish a `MUTUAL_HELLO_ACK` and is the
//! caller's decision.

use rand::Rng;
use std::time::Duration;

/// Exponential-backoff retry policy.
///
/// Computed delay before attempt `n` (1-indexed) is
/// `min(max_delay, base_delay * multiplier^(n-1))`, optionally
/// perturbed by full or partial jitter (see [`Self::with_jitter_ratio`]).
///
/// # Why jitter
///
/// Without jitter, every retrying caller wakes at exactly the same
/// instants (100ms, 200ms, 400ms…). Under a fleet-wide upstream
/// outage, all callers retry in lockstep, hammering the recovering
/// service and prolonging the incident. Adding even a small jitter
/// ratio (e.g. 0.1 for ±10 %) spreads retries across a window and
/// significantly reduces thundering-herd amplification — see AWS's
/// "Exponential Backoff and Jitter" guidance.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    max_attempts: u32,
    base_delay: Duration,
    max_delay: Duration,
    multiplier: f64,
    /// Symmetric jitter as a fraction of the base delay. `0.0` ==
    /// deterministic (back-compat with rc.1 behavior). `0.1` means
    /// the actual delay is sampled uniformly from
    /// `[delay * 0.9, delay * 1.1]`. Clamped to `[0.0, 1.0]` at
    /// construction.
    jitter_ratio: f64,
}

impl RetryPolicy {
    /// No retry — single attempt. Equivalent to rc.1 behavior.
    pub const fn none() -> Self {
        Self {
            max_attempts: 1,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
            multiplier: 1.0,
            jitter_ratio: 0.0,
        }
    }

    /// Conservative default: 3 attempts total, 100ms base, 2× multiplier,
    /// capped at 1s. Total worst-case delay ≈ 100 + 200 = 300ms.
    pub const fn conservative() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(1),
            multiplier: 2.0,
            jitter_ratio: 0.0,
        }
    }

    /// Aggressive: 5 attempts, 200ms base, 2× multiplier, capped at 5s.
    /// Total worst-case ≈ 200 + 400 + 800 + 1600 = 3000ms.
    pub const fn aggressive() -> Self {
        Self {
            max_attempts: 5,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(5),
            multiplier: 2.0,
            jitter_ratio: 0.0,
        }
    }

    /// Custom policy.
    pub fn custom(
        max_attempts: u32,
        base_delay: Duration,
        max_delay: Duration,
        multiplier: f64,
    ) -> Self {
        assert!(max_attempts >= 1, "max_attempts must be >= 1");
        assert!(multiplier >= 1.0, "multiplier must be >= 1.0");
        Self {
            max_attempts,
            base_delay,
            max_delay,
            multiplier,
            jitter_ratio: 0.0,
        }
    }

    /// Configure symmetric jitter. `ratio` is the fraction of the
    /// scheduled delay by which the actual delay may vary, in
    /// `[0.0, 1.0]`. For example, `ratio = 0.1` produces an actual
    /// delay in `[delay * 0.9, delay * 1.1]`; `ratio = 1.0` produces
    /// `[0, delay * 2.0]` ("full jitter"). Values outside the range
    /// are clamped.
    ///
    /// Recommended starting point: `0.1` for general use, `0.2` for
    /// high-fanout systems where retry storms have been observed.
    /// `0.0` disables jitter (the default, for backwards-compat with
    /// rc.1 behavior).
    pub fn with_jitter_ratio(mut self, ratio: f64) -> Self {
        self.jitter_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Current jitter ratio.
    pub fn jitter_ratio(&self) -> f64 {
        self.jitter_ratio
    }

    /// Maximum number of attempts (including the first).
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Deterministic delay before attempt number `attempt`
    /// (1-indexed). Returns `Duration::ZERO` for `attempt == 1`.
    /// Before attempt 2, the delay is `base_delay` exactly;
    /// subsequent attempts scale by `multiplier`, capped at
    /// `max_delay`.
    ///
    /// This is the *un-jittered* base value. If a non-zero jitter
    /// ratio is configured, callers should perturb the returned
    /// value via [`Self::apply_jitter`] (or call
    /// [`Self::jittered_delay_before`] which does both).
    pub fn delay_before(&self, attempt: u32) -> Duration {
        if attempt <= 1 {
            return Duration::ZERO;
        }
        let exp = (attempt - 2) as i32;
        let factor = self.multiplier.powi(exp);
        let nanos = (self.base_delay.as_nanos() as f64 * factor) as u128;
        let max_nanos = self.max_delay.as_nanos();
        let clamped = nanos.min(max_nanos);
        Duration::from_nanos(clamped.try_into().unwrap_or(u64::MAX))
    }

    /// Sample a jittered delay around the deterministic value.
    /// `delay` is typically the result of [`Self::delay_before`].
    /// Returns `delay` unchanged when `jitter_ratio == 0.0`.
    pub fn apply_jitter(&self, delay: Duration) -> Duration {
        if self.jitter_ratio <= f64::EPSILON {
            return delay;
        }
        if delay.is_zero() {
            return delay;
        }
        let nanos = delay.as_nanos() as f64;
        let low = nanos * (1.0 - self.jitter_ratio);
        let high = nanos * (1.0 + self.jitter_ratio);
        // Defensive lower bound — `low` can be 0.0 when ratio == 1.0.
        let low = low.max(0.0);
        let mut rng = rand::thread_rng();
        let sampled = rng.gen_range(low..=high);
        Duration::from_nanos(sampled as u64)
    }

    /// Compute the jittered delay scheduled before `attempt`. Useful
    /// for callers that want a single call rather than chaining
    /// [`Self::delay_before`] + [`Self::apply_jitter`].
    pub fn jittered_delay_before(&self, attempt: u32) -> Duration {
        self.apply_jitter(self.delay_before(attempt))
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_is_single_attempt() {
        let p = RetryPolicy::none();
        assert_eq!(p.max_attempts(), 1);
        assert_eq!(p.delay_before(1), Duration::ZERO);
    }

    #[test]
    fn conservative_grows_then_caps() {
        let p = RetryPolicy::conservative();
        assert_eq!(p.delay_before(1), Duration::ZERO);
        assert_eq!(p.delay_before(2), Duration::from_millis(100));
        assert_eq!(p.delay_before(3), Duration::from_millis(200));
        // capped at max_delay = 1s
        let p2 = RetryPolicy::custom(10, Duration::from_millis(500), Duration::from_secs(1), 2.0);
        assert_eq!(p2.delay_before(2), Duration::from_millis(500));
        assert_eq!(p2.delay_before(3), Duration::from_secs(1)); // capped
        assert_eq!(p2.delay_before(10), Duration::from_secs(1)); // still capped
    }

    #[test]
    fn aggressive_progression() {
        let p = RetryPolicy::aggressive();
        assert_eq!(p.delay_before(2), Duration::from_millis(200));
        assert_eq!(p.delay_before(3), Duration::from_millis(400));
        assert_eq!(p.delay_before(4), Duration::from_millis(800));
        assert_eq!(p.delay_before(5), Duration::from_millis(1600));
    }

    #[test]
    fn jitter_zero_is_deterministic() {
        let p = RetryPolicy::conservative();
        assert_eq!(p.jitter_ratio(), 0.0);
        for _ in 0..10 {
            assert_eq!(
                p.jittered_delay_before(2),
                Duration::from_millis(100),
                "with no jitter the value must be exact"
            );
        }
    }

    #[test]
    fn jitter_ratio_clamps_to_unit_interval() {
        let p = RetryPolicy::conservative().with_jitter_ratio(5.0);
        assert!((p.jitter_ratio() - 1.0).abs() < f64::EPSILON);
        let p2 = RetryPolicy::conservative().with_jitter_ratio(-0.5);
        assert_eq!(p2.jitter_ratio(), 0.0);
    }

    #[test]
    fn jitter_keeps_delay_within_symmetric_bounds() {
        let p = RetryPolicy::conservative().with_jitter_ratio(0.1);
        let base = Duration::from_millis(100);
        let low = Duration::from_millis(90);
        let high = Duration::from_millis(110);
        for _ in 0..200 {
            let sampled = p.apply_jitter(base);
            assert!(
                sampled >= low && sampled <= high,
                "sampled {sampled:?} outside [{low:?}, {high:?}]"
            );
        }
    }

    #[test]
    fn jitter_preserves_zero_delay() {
        let p = RetryPolicy::conservative().with_jitter_ratio(0.5);
        assert_eq!(p.apply_jitter(Duration::ZERO), Duration::ZERO);
        assert_eq!(
            p.jittered_delay_before(1),
            Duration::ZERO,
            "attempt 1 must never incur backoff regardless of jitter"
        );
    }
}
