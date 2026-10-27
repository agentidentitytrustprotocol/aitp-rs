//! Delegation tokens (compact JWS, `typ: aitp-delegation+jwt`).
//!
//! **No stability promise.** This crate is published so the AITP bindings
//! and tools can build on it; its API can change in any release. Depend
//! on the [`aitp`](https://docs.rs/aitp) facade crate instead.
//!
//! Single-hop (RFC-AITP-0006) is the v0.2 default: B delegates against
//! the grant voucher A minted alongside B's TCT, embedded verbatim in
//! the token. Multi-hop chains (RFC-AITP-0011) are carried in optional
//! `chain` / `chain_hash` claims; verifiers opt in via
//! [`VerifyDelegationContext::max_delegation_hops`] and otherwise reject any
//! chain-bearing token structurally. No verification step ever
//! reconstructs a byte sequence — every signature covers transmitted
//! bytes.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod builder;
pub mod error;
pub mod types;
pub mod verifier;

pub use builder::{compute_chain_hash, DelegationBuilder, DEFAULT_DELEGATION_TTL_SECS};
pub use error::DelegationError;
pub use types::{DelegationClaims, VerifiedDelegation, DELEGATION_CLAIMS_MEMBERS};
pub use verifier::{
    verify_delegation, DelegationRevocation, HopRevocationCheck, SourceRevocationCheck,
    VerifyDelegationContext, DEFAULT_MAX_DELEGATION_HOPS,
};
