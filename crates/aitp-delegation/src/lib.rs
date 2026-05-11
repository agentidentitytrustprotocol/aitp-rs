//! Delegation tokens.
//!
//! Single-hop (RFC-AITP-0006) is the v0.1 default. Multi-hop chains
//! (RFC-AITP-0011) are carried in optional `chain` and `chain_hash`
//! fields on [`DelegationToken`]. Verifiers configure the maximum
//! permitted chain length via [`VerifyDelegationContext::max_hops`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod builder;
pub mod error;
pub mod types;
pub mod verifier;

pub use builder::{DelegationBuilder, DEFAULT_DELEGATION_TTL_SECS};
pub use error::DelegationError;
pub use types::{DelegationEnvelope, DelegationStep, DelegationToken, GrantProof};
pub use verifier::{
    compute_chain_hash, verify_delegation, VerifyDelegationContext, DEFAULT_MAX_HOPS,
    V0_1_STRICT_MAX_HOPS,
};
