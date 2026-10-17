//! Admission metric names (aitp-rs#205 A-4). Emitted through the
//! `metrics` facade when the `metrics` feature is on; the names are
//! always available so dashboards and alerts can reference them.
//!
//! Label values are a fixed set, so cardinality is bounded no matter
//! what peers send.

#[cfg(feature = "metrics")]
use super::RefusalCause;
use super::{AdmissionChallenge, AdmissionError, Admitted};

/// Counter. One per [`challenge`](super::PinnedAdmission::challenge)
/// call. Label `result`: `issued`, `rate_limited`, `at_capacity` or
/// `error` (store backend or CSPRNG failure).
pub const CHALLENGE_TOTAL: &str = "aitp_admission_challenge_total";

/// Counter. One per [`admit`](super::PinnedAdmission::admit) call.
/// Label `result`: `admitted`, the lowercased wire code
/// (`replay_detected`, `identity_failed`, `invalid_signature`, …),
/// `rate_limited` (HTTP 429), or `local_error` for a failure that is not
/// the peer's fault.
pub const ADMIT_TOTAL: &str = "aitp_admission_admit_total";

/// Gauge. Records held by an
/// [`InMemoryNonceStore`](super::InMemoryNonceStore), including expired
/// ones not yet reclaimed. Several stores in one process share it.
pub const NONCES_OUTSTANDING: &str = "aitp_admission_nonces_outstanding";

#[cfg(feature = "metrics")]
pub(super) fn challenge_result(r: &Result<AdmissionChallenge, AdmissionError>) -> &'static str {
    match r {
        Ok(_) => "issued",
        Err(AdmissionError::ChallengeRefused {
            cause: RefusalCause::RateLimited,
            ..
        }) => "rate_limited",
        Err(AdmissionError::ChallengeRefused {
            cause: RefusalCause::AtCapacity,
            ..
        }) => "at_capacity",
        Err(_) => "error",
    }
}

#[cfg(feature = "metrics")]
pub(super) fn admit_result(r: &Result<Admitted, AdmissionError>) -> &'static str {
    match r {
        Ok(_) => "admitted",
        Err(AdmissionError::RateLimited { .. }) => "rate_limited",
        Err(e) => match e.code() {
            Some("REPLAY_DETECTED") => "replay_detected",
            Some("INVALID_ENVELOPE") => "invalid_envelope",
            Some("UNKNOWN_FIELD") => "unknown_field",
            Some("UNKNOWN_VERSION") => "unknown_version",
            Some("TIMESTAMP_EXPIRED") => "timestamp_expired",
            Some("IDENTITY_FAILED") => "identity_failed",
            Some("INVALID_SIGNATURE") => "invalid_signature",
            Some(_) => "other",
            None => "local_error",
        },
    }
}

#[cfg(feature = "metrics")]
pub(super) fn record_challenge(r: &Result<AdmissionChallenge, AdmissionError>) {
    metrics::counter!(CHALLENGE_TOTAL, "result" => challenge_result(r)).increment(1);
}

#[cfg(not(feature = "metrics"))]
pub(super) fn record_challenge(_r: &Result<AdmissionChallenge, AdmissionError>) {}

#[cfg(feature = "metrics")]
pub(super) fn record_admit(r: &Result<Admitted, AdmissionError>) {
    metrics::counter!(ADMIT_TOTAL, "result" => admit_result(r)).increment(1);
}

#[cfg(not(feature = "metrics"))]
pub(super) fn record_admit(_r: &Result<Admitted, AdmissionError>) {}
