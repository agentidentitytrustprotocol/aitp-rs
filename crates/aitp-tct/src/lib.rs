//! Trust Context Token (TCT) — the canonical output of AITP.
//!
//! A TCT is a signed, audience-bound, capability-scoped grant. Each peer
//! holds the TCT issued by its counterpart in a Mutual Handshake.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod builder;
pub mod error;
pub mod pop;
/// In-band TCT renewal (RFC-AITP-0004 §8.1, post-v0.1). Gated behind
/// the `experimental-renewal` Cargo feature — v0.1 deployments MUST
/// re-run the Mutual Handshake instead.
#[cfg(feature = "experimental-renewal")]
pub mod renewal;
pub mod revocation;
pub mod types;
pub mod verifier;

pub use builder::TctBuilder;
pub use error::TctError;
pub use pop::{sign_pop_response, verify_pop_response, PopChallenge, PopResponse};
#[cfg(feature = "experimental-renewal")]
pub use renewal::{build_renewal_request, process_renewal_request};
pub use revocation::{
    sign_revocation_list, verify_revocation_list, RevocationEntry, RevocationList,
    RevocationListEnvelope, VerifyRevocationListContext,
};
pub use types::{Tct, TctBinding, TctEnvelope};
#[cfg(feature = "experimental-renewal")]
pub use types::TctRenewalPayload;
pub use verifier::{verify_tct, TctVerifyContext};

/// Recommended TCT TTL (1 hour).
pub const DEFAULT_TCT_TTL_SECS: i64 = 3600;
