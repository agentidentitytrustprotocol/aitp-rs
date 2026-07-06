//! Operational metrics facade (feature `metrics`).
//!
//! `aitp-rs` libraries emit `tracing` events for logs/traces; this module
//! adds first-class **metrics** at the operational trust-decision points a
//! server operator alarms on — handshake outcomes, replay rejections,
//! revocation- and JWKS-cache effectiveness, session pressure.
//!
//! Everything here is behind the `metrics` Cargo feature and routes through
//! the [`metrics`](https://docs.rs/metrics) facade crate: when no recorder
//! is installed the calls are a cheap atomic load, and when the feature is
//! off they compile to nothing. Install a recorder (e.g.
//! `metrics-exporter-prometheus`) in your binary to collect — see
//! `examples/observability/`.
//!
//! Metric names use the `aitp_` prefix and stable, low-cardinality label
//! values (bounded enums like `outcome`/`result`), never per-request
//! identifiers (AIDs, session ids) — those belong in trace fields.
//!
//! Not every emit point is reachable in every feature combination — the
//! handshake/session counters are server-only, the cache counters are
//! client-only — so unused-in-this-build helpers are expected. Allow
//! dead code module-wide rather than cfg-gating each wrapper by the
//! feature(s) that happen to call it.
#![allow(dead_code)]

// Metric names — kept as constants so producers and the docs/dashboard
// agree on exact strings.

/// Counter: envelope `message_id` replay rejections (RFC-AITP-0001 §5.5).
pub(crate) const REPLAY_REJECTED: &str = "aitp_replay_rejected_total";
/// Counter: handshake message outcomes. Labels: `stage` (hello|commit),
/// `result` (ok|rejected).
pub(crate) const HANDSHAKE_TOTAL: &str = "aitp_handshake_total";
/// Counter: in-flight sessions evicted to enforce the max-sessions cap.
pub(crate) const SESSIONS_EVICTED: &str = "aitp_sessions_evicted_total";
/// Counter: revocation-cache lookups. Label: `outcome`
/// (hit|miss|stale|refresh).
pub(crate) const REVOCATION_CACHE: &str = "aitp_revocation_cache_total";
/// Counter: JWKS/key-resolution cache lookups. Label: `outcome`
/// (hit|miss|negative_hit).
pub(crate) const JWKS_CACHE: &str = "aitp_jwks_cache_total";

#[cfg(feature = "metrics")]
mod imp {
    /// Increment a label-free counter by one.
    #[inline]
    pub(crate) fn counter(name: &'static str) {
        metrics::counter!(name).increment(1);
    }

    /// Increment a counter carrying a single static label by `n`.
    #[inline]
    pub(crate) fn counter_by(name: &'static str, n: u64) {
        metrics::counter!(name).increment(n);
    }

    /// Increment a counter carrying a single static label by one.
    #[inline]
    pub(crate) fn counter_labeled(name: &'static str, key: &'static str, val: &'static str) {
        metrics::counter!(name, key => val).increment(1);
    }

    /// Increment a counter carrying two static labels by one.
    #[inline]
    pub(crate) fn counter_labeled2(
        name: &'static str,
        k1: &'static str,
        v1: &'static str,
        k2: &'static str,
        v2: &'static str,
    ) {
        metrics::counter!(name, k1 => v1, k2 => v2).increment(1);
    }
}

#[cfg(not(feature = "metrics"))]
mod imp {
    #[inline]
    pub(crate) fn counter(_name: &'static str) {}
    #[inline]
    pub(crate) fn counter_by(_name: &'static str, _n: u64) {}
    #[inline]
    pub(crate) fn counter_labeled(_name: &'static str, _key: &'static str, _val: &'static str) {}
    #[inline]
    pub(crate) fn counter_labeled2(
        _name: &'static str,
        _k1: &'static str,
        _v1: &'static str,
        _k2: &'static str,
        _v2: &'static str,
    ) {
    }
}

pub(crate) use imp::*;

// Convenience wrappers naming the actual events, so call sites read as
// intent (`obs::replay_rejected()`), not plumbing.

/// A replayed envelope `message_id` was rejected.
#[inline]
pub(crate) fn replay_rejected() {
    counter(REPLAY_REJECTED);
}

/// A handshake message reached a terminal outcome.
/// `stage` ∈ {`hello`, `commit`}; `result` ∈ {`ok`, `rejected`}.
#[inline]
pub(crate) fn handshake(stage: &'static str, result: &'static str) {
    counter_labeled2(HANDSHAKE_TOTAL, "stage", stage, "result", result);
}

/// `n` in-flight sessions were evicted to hold the max-sessions cap.
#[inline]
pub(crate) fn sessions_evicted(n: u64) {
    counter_by(SESSIONS_EVICTED, n);
}

/// A revocation-cache lookup resolved with `outcome`
/// (`hit`|`miss`|`stale`|`refresh`).
#[inline]
pub(crate) fn revocation_cache(outcome: &'static str) {
    counter_labeled(REVOCATION_CACHE, "outcome", outcome);
}

/// A JWKS/key-resolution cache lookup resolved with `outcome`
/// (`hit`|`miss`|`negative_hit`).
#[inline]
pub(crate) fn jwks_cache(outcome: &'static str) {
    counter_labeled(JWKS_CACHE, "outcome", outcome);
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use metrics_util::debugging::DebuggingRecorder;

    #[test]
    fn helpers_emit_expected_metrics() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        // Scope the recorder to this thread so parallel tests don't fight
        // over the global one.
        metrics::with_local_recorder(&recorder, || {
            super::replay_rejected();
            super::handshake("hello", "ok");
            super::sessions_evicted(3);
            super::revocation_cache("hit");
            super::jwks_cache("miss");
        });
        let names: Vec<String> = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(key, _, _, _)| key.key().name().to_string())
            .collect();
        for expected in [
            super::REPLAY_REJECTED,
            super::HANDSHAKE_TOTAL,
            super::SESSIONS_EVICTED,
            super::REVOCATION_CACHE,
            super::JWKS_CACHE,
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "expected metric `{expected}` to be emitted; got {names:?}"
            );
        }
    }
}
