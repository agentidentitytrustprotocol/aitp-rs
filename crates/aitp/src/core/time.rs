//! Unix-second timestamps with freshness checks.

use crate::core::DEFAULT_TIMESTAMP_TOLERANCE;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A Unix timestamp in seconds.
///
/// AITP timestamps are integers — never floats. This newtype enforces that at
/// the type level: it serializes and deserializes as a JSON integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// The current time as a [`Timestamp`].
    pub fn now() -> Self {
        let secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            Err(e) => i64::try_from(e.duration().as_secs()).map_or(i64::MIN, |s| -s),
        };
        Self(secs)
    }

    /// `self` plus the whole seconds of `d` (a fraction of a second is
    /// dropped), saturating on overflow.
    pub fn saturating_add(self, d: Duration) -> Self {
        Self(self.0.saturating_add(duration_secs(d)))
    }

    /// `self` minus the whole seconds of `d` (a fraction of a second is
    /// dropped), saturating on overflow.
    pub fn saturating_sub(self, d: Duration) -> Self {
        Self(self.0.saturating_sub(duration_secs(d)))
    }

    /// True if `self` is within `±tolerance` of `reference`, counting
    /// the whole seconds of `tolerance`.
    ///
    /// `self.0` is deserialized verbatim from the wire, so the difference
    /// is computed with `checked_sub` + `unsigned_abs` to avoid an `i64`
    /// overflow (e.g. `i64::MIN - reference`, or `i64::MIN.abs()`) on
    /// attacker-controlled extremes — a debug panic / release wraparound.
    pub fn is_within_tolerance_of(self, reference: Timestamp, tolerance: Duration) -> bool {
        let tolerance = tolerance.as_secs();
        match self.0.checked_sub(reference.0) {
            Some(diff) => diff.unsigned_abs() <= tolerance,
            // Difference doesn't fit in i64 → far outside any tolerance.
            None => false,
        }
    }

    /// True if `self` is within the default ±300s window of `reference`.
    pub fn is_fresh(self, reference: Timestamp) -> bool {
        self.is_within_tolerance_of(reference, DEFAULT_TIMESTAMP_TOLERANCE)
    }

    /// True if `self` is in the past (relative to `reference`).
    pub fn is_in_the_past(self, reference: Timestamp) -> bool {
        self.0 < reference.0
    }

    /// True if `self` is in the future (relative to `reference`).
    pub fn is_in_the_future(self, reference: Timestamp) -> bool {
        self.0 > reference.0
    }
}

/// The whole seconds of `d` as an `i64`, saturating at `i64::MAX`.
pub(crate) fn duration_secs(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

impl From<i64> for Timestamp {
    fn from(secs: i64) -> Self {
        Self(secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freshness_within_tolerance() {
        let now = Timestamp(1_700_000_000);
        assert!(Timestamp(1_700_000_100).is_fresh(now));
        assert!(Timestamp(1_699_999_900).is_fresh(now));
        assert!(!Timestamp(1_700_000_400).is_fresh(now));
    }

    #[test]
    fn tolerance_does_not_overflow_on_extremes() {
        let now = Timestamp(1_700_000_000);
        // These would panic in debug / wrap in release with naive
        // `(a - b).abs()`. Must simply be "not fresh".
        let tol = Duration::from_secs(300);
        assert!(!Timestamp(i64::MIN).is_within_tolerance_of(now, tol));
        assert!(!Timestamp(i64::MAX).is_within_tolerance_of(now, tol));
        assert!(!Timestamp(i64::MIN).is_within_tolerance_of(Timestamp(i64::MAX), tol));
        // A zero tolerance admits only the same second.
        assert!(!Timestamp(1_700_000_001).is_within_tolerance_of(now, Duration::ZERO));
        assert!(now.is_within_tolerance_of(now, Duration::ZERO));
        // A fraction of a second is dropped.
        assert!(!Timestamp(1_700_000_001).is_within_tolerance_of(now, Duration::from_millis(999)));
    }

    #[test]
    fn saturating_arithmetic() {
        let t = Timestamp(100);
        assert_eq!(t.saturating_add(Duration::from_secs(5)), Timestamp(105));
        assert_eq!(t.saturating_sub(Duration::from_secs(5)), Timestamp(95));
        assert_eq!(
            t.saturating_add(Duration::from_millis(1_999)),
            Timestamp(101)
        );
        assert_eq!(
            Timestamp(i64::MAX).saturating_add(Duration::MAX),
            Timestamp(i64::MAX)
        );
        assert_eq!(
            Timestamp(i64::MIN).saturating_sub(Duration::MAX),
            Timestamp(i64::MIN)
        );
    }

    #[test]
    fn ordering_works_as_expected() {
        assert!(Timestamp(100) < Timestamp(200));
    }

    #[test]
    fn now_is_close_to_system_time() {
        let a = Timestamp::now().0;
        let b = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!((a - b).abs() <= 5, "Timestamp::now() drift: {} vs {}", a, b);
    }

    #[test]
    fn serializes_as_json_integer_not_string() {
        let s = serde_json::to_string(&Timestamp(1_700_000_000)).unwrap();
        assert_eq!(s, "1700000000");
        let back: Timestamp = serde_json::from_str(&s).unwrap();
        assert_eq!(back, Timestamp(1_700_000_000));
    }
}
