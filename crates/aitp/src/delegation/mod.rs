//! Delegation tokens (compact JWS, `typ: aitp-delegation+jwt`).
//!
//! B delegates against the grant voucher A minted alongside B's TCT,
//! embedded verbatim in the token (RFC-AITP-0006). A token carrying a
//! multi-hop `chain` claim (RFC-AITP-0011) is rejected structurally;
//! multi-hop delegation is in `aitp_experimental::delegation`. No
//! verification step reconstructs a byte sequence: every signature covers
//! transmitted bytes.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub(crate) mod builder;
pub(crate) mod error;
pub(crate) mod types;
pub(crate) mod verifier;

pub use builder::{DelegationBuilder, DEFAULT_DELEGATION_TTL};
pub use error::DelegationError;
pub use types::{
    DelegationClaims, IssuedDelegation, IssuedDelegationParts, VerifiedDelegation,
    VerifiedDelegationParts, DELEGATION_CLAIMS_MEMBERS,
};
pub use verifier::{verify_delegation, DelegationVerifyContext};
