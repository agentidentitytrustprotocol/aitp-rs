//! Trust Context Token (TCT) — the canonical output of AITP.
//!
//! A TCT is a signed, audience-bound, capability-scoped grant. Each peer
//! holds the TCT issued by its counterpart in a Mutual Handshake.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod builder;
pub mod error;
pub mod pop;
pub mod revocation;
pub mod types;
pub mod verifier;

pub use builder::TctBuilder;
pub use error::TctError;
pub use pop::{sign_pop_response, verify_pop_response, PopChallenge, PopResponse};
pub use revocation::{
    sign_revocation_list, verify_revocation_list, RevocationEntry, RevocationList,
    RevocationListEnvelope, VerifyRevocationListContext,
};
pub use types::{Tct, TctBinding, TctEnvelope};
pub use verifier::{verify_tct, TctVerifyContext};

/// Recommended TCT TTL (1 hour).
pub const DEFAULT_TCT_TTL_SECS: i64 = 3600;
