//! Trust Context Token (TCT) — the canonical output of AITP.
//!
//! A TCT is a signed, audience-bound, capability-scoped grant. Each peer
//! holds the TCT issued by its counterpart in a Mutual Handshake.
//!
//! In `aitp/0.2` the TCT and its companion grant voucher are **compact
//! JWS strings** (RFC-AITP-0001 §5.4.5): signatures cover the exact
//! transmitted bytes, so any off-the-shelf JOSE library can verify them
//! given only the issuer public key. The revocation snapshot
//! (RFC-AITP-0008) is protocol-internal and stays JCS-signed.

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
#[cfg(feature = "experimental-renewal")]
pub use types::TctRenewalPayload;
pub use types::{Cnf, GrantVoucherClaims, IssuedTct, TctClaims, VerifiedTct};
pub use verifier::{
    verify_tct, verify_voucher, TctVerifyContext, TctVerifyContextBuilder, TctVerifyContextError,
};

/// Recommended TCT TTL (1 hour).
pub const DEFAULT_TCT_TTL_SECS: i64 = 3600;
