//! Multi-hop delegation (RFC-AITP-0011, Draft).
//!
//! A multi-hop token is a delegation compact JWS (RFC-AITP-0006 §2)
//! whose claims also carry the prior hops verbatim in `chain`, a
//! digest-array `chain_hash` and a per-hop `jti`. Authority bottoms out
//! in `chain[0]`'s grant voucher. Every signature is verified over the
//! bytes exactly as transmitted.
//!
//! [`verify_chained_delegation`] verifies both single-hop tokens (with an
//! optional `jti`) and chains, up to
//! [`VerifyChainContext::max_delegation_hops`] total hops. The stable
//! single-hop verifier is [`aitp::delegation::verify_delegation`], which
//! rejects every chain-bearing token with `DELEGATION_MULTIHOP_NOT_SUPPORTED`.

mod builder;
mod error;
mod types;
mod verifier;

pub use builder::{compute_chain_hash, ChainedDelegationBuilder};
pub use error::ChainedDelegationError;
pub use types::{ChainedDelegationClaims, VerifiedChainedDelegation};
pub use verifier::{
    verify_chained_delegation, HopRevocationCheck, VerifyChainContext, DEFAULT_MAX_DELEGATION_HOPS,
};
