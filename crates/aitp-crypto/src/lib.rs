//! Ed25519 signing keys, verifying keys, and JWK thumbprint computation.
//!
//! AITP v0.1 uses Ed25519 only. Crypto agility is reserved for a future
//! major version.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod keys;
pub mod thumbprint;

pub use error::CryptoError;
pub use keys::{AitpSigningKey, AitpVerifyingKey, Signature};
pub use thumbprint::compute_jwk_thumbprint;
