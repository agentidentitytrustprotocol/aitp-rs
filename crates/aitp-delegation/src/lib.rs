//! Single-hop delegation tokens (RFC-AITP-0006).
//!
//! Multi-hop delegation is reserved for v0.2 (RFC-AITP-0011).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod builder;
pub mod error;
pub mod types;
pub mod verifier;

pub use builder::{DelegationBuilder, DEFAULT_DELEGATION_TTL_SECS};
pub use error::DelegationError;
pub use types::{DelegationEnvelope, DelegationToken, GrantProof};
pub use verifier::{verify_delegation, VerifyDelegationContext};
