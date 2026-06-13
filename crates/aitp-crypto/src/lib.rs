//! Ed25519 / P-256 signing keys, verifying keys, JWK thumbprints, and
//! the compact-JWS profile for portable trust artifacts
//! (RFC-AITP-0001 §5.4.5).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod jws;
pub mod keys;
pub mod thumbprint;

pub use error::CryptoError;
pub use keys::{AitpSigningKey, AitpVerifyingKey, Signature, SignatureAlgorithm};
pub use thumbprint::{compute_jwk_thumbprint, compute_jwk_thumbprint_p256};
