//! Unix-second timestamps with freshness checks.

use crate::DEFAULT_TIMESTAMP_TOLERANCE_SECS;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
        Self(Utc::now().timestamp())
    }

    /// Add seconds, saturating on overflow.
    pub fn plus_secs(self, secs: i64) -> Self {
        Self(self.0.saturating_add(secs))
    }

    /// True if `self` is within `±tolerance` seconds of `reference`.
    pub fn is_within_tolerance_of(self, reference: Timestamp, tolerance_secs: i64) -> bool {
        (self.0 - reference.0).abs() <= tolerance_secs
    }

    /// True if `self` is within the default ±300s window of `reference`.
    pub fn is_fresh(self, reference: Timestamp) -> bool {
        self.is_within_tolerance_of(reference, DEFAULT_TIMESTAMP_TOLERANCE_SECS)
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

impl From<DateTime<Utc>> for Timestamp {
    fn from(dt: DateTime<Utc>) -> Self {
        Self(dt.timestamp())
    }
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
    fn ordering_works_as_expected() {
        assert!(Timestamp(100) < Timestamp(200));
    }

    #[test]
    fn now_is_close_to_chrono_now() {
        let a = Timestamp::now().0;
        let b = chrono::Utc::now().timestamp();
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
