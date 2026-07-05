//! Pluggable replay-detection store for one-time identifiers.
//!
//! Two AITP mechanisms reject replays by remembering a one-time value
//! for the length of a freshness window: envelope `message_id`s
//! (RFC-AITP-0001 §5.5) and DPoP `jti`s (RFC 9449). "Remembering" is the
//! only stateful thing the server layer does that carries a *security*
//! guarantee — so it is the one piece worth making the caller's to own.
//!
//! # Clustering
//!
//! The default [`InMemoryReplayGuard`] is **per-process**. A clustered
//! deployment — several verifier instances behind a load balancer —
//! MUST either use sticky routing or supply a **shared** implementation
//! (e.g. Redis `SET key val NX EX <ttl>`). Otherwise a value replayed to
//! a second instance is accepted, because the first instance holds the
//! record. `aitp-rs` never persists this itself: the trait is the seam,
//! the storage decision (in-memory, Redis, a database) belongs to the
//! embedding framework.
//!
//! The trait is deliberately synchronous and keyed by `&str` with a
//! [`Duration`] TTL: that preserves the in-memory implementation's exact
//! behavior and maps one-to-one onto the `SET NX EX` primitive of every
//! mainstream key-value store, so a backend implementation is a few
//! lines. A backend that performs network I/O runs it on whatever
//! bridge the caller's runtime provides — that is the caller's tradeoff
//! to make, not one this library imposes.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// A store that detects replayed one-time identifiers.
///
/// See the [module docs](self) for the clustering contract.
pub trait ReplayGuard: Send + Sync {
    /// Atomically record `key` for `ttl` **iff** it has not been seen
    /// within its window. Returns `true` if the key is **fresh** (and is
    /// now recorded), `false` if it is a **replay**.
    ///
    /// Implementations MUST be atomic per key: two concurrent
    /// presentations of the same key must not both observe `true`.
    fn check_and_record(&self, key: &str, ttl: Duration) -> bool;
}

/// In-memory [`ReplayGuard`] — the default. Bounded by the traffic in
/// the active window; expired entries are swept on every check. Uses a
/// monotonic clock internally, so it is immune to wall-clock jumps but
/// is not shareable across processes (see the [module docs](self)).
#[derive(Default)]
pub struct InMemoryReplayGuard {
    /// key → expiry instant (insertion time + that call's `ttl`).
    seen: Mutex<HashMap<String, Instant>>,
}

impl InMemoryReplayGuard {
    /// Construct an empty guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of unexpired entries currently held. Test/introspection
    /// only.
    #[doc(hidden)]
    pub fn len(&self) -> usize {
        let now = Instant::now();
        self.seen.lock().values().filter(|exp| **exp > now).count()
    }

    /// Whether no unexpired entries are held. Test/introspection only.
    #[doc(hidden)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ReplayGuard for InMemoryReplayGuard {
    fn check_and_record(&self, key: &str, ttl: Duration) -> bool {
        let now = Instant::now();
        // Store an absolute expiry per entry so mixed TTLs are handled
        // correctly; saturate rather than panic on an absurd `ttl`.
        let expiry = now.checked_add(ttl).unwrap_or(now);
        let mut seen = self.seen.lock();
        // Drop expired entries first so the map stays bounded by recent
        // traffic and a long-gone key is treated as fresh again.
        seen.retain(|_, exp| *exp > now);
        if seen.contains_key(key) {
            return false; // seen and still within its window → replay
        }
        seen.insert(key.to_string(), expiry);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_then_replay() {
        let guard = InMemoryReplayGuard::new();
        let ttl = Duration::from_secs(300);
        assert!(
            guard.check_and_record("abc", ttl),
            "first sighting is fresh"
        );
        assert!(
            !guard.check_and_record("abc", ttl),
            "second sighting is a replay"
        );
        assert!(
            guard.check_and_record("def", ttl),
            "a different key is fresh"
        );
        assert_eq!(guard.len(), 2);
    }

    #[test]
    fn expired_entry_is_fresh_again_and_swept() {
        let guard = InMemoryReplayGuard::new();
        // 0ns TTL: the entry expires immediately, so the same key is
        // fresh on the next check and the map does not grow.
        assert!(guard.check_and_record("k", Duration::from_nanos(0)));
        assert!(
            guard.check_and_record("k", Duration::from_secs(300)),
            "an expired key is fresh again"
        );
        assert_eq!(guard.len(), 1, "expired entries are swept");
    }

    #[test]
    fn works_through_trait_object() {
        let guard: std::sync::Arc<dyn ReplayGuard> =
            std::sync::Arc::new(InMemoryReplayGuard::new());
        let ttl = Duration::from_secs(60);
        assert!(guard.check_and_record("x", ttl));
        assert!(!guard.check_and_record("x", ttl));
    }
}
