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

use std::time::Duration;

/// Exponential-backoff retry policy.
///
/// Computed delay before attempt `n` (1-indexed) is
/// `min(max_delay, base_delay * multiplier^(n-1))`.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    max_attempts: u32,
    base_delay: Duration,
    max_delay: Duration,
    multiplier: f64,
}

impl RetryPolicy {
    /// No retry — single attempt. Equivalent to rc.1 behavior.
    pub const fn none() -> Self {
        Self {
            max_attempts: 1,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
            multiplier: 1.0,
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
        }
    }

    /// Maximum number of attempts (including the first).
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Delay before attempt number `attempt` (1-indexed). Returns
    /// `Duration::ZERO` for `attempt == 1`. Before attempt 2, the delay
    /// is `base_delay` exactly; subsequent attempts scale by
    /// `multiplier`, capped at `max_delay`.
    pub fn delay_before(&self, attempt: u32) -> Duration {
        if attempt <= 1 {
            return Duration::ZERO;
        }
        // attempt=2 → exp=0 → factor=1.0 → delay = base_delay.
        let exp = (attempt - 2) as i32;
        let factor = self.multiplier.powi(exp);
        let nanos = (self.base_delay.as_nanos() as f64 * factor) as u128;
        let max_nanos = self.max_delay.as_nanos();
        let clamped = nanos.min(max_nanos);
        Duration::from_nanos(clamped.try_into().unwrap_or(u64::MAX))
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
}
