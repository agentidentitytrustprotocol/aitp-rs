//! Ed25519 / P-256 signing keys, verifying keys, JWK thumbprints, and
//! the compact-JWS profile for portable trust artifacts
//! (RFC-AITP-0001 §5.4.5).
//!
//! **No stability promise.** This crate is published so the AITP bindings
//! and tools can build on it; its API can change in any release. Depend
//! on the [`aitp`](https://docs.rs/aitp) facade crate instead.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub(crate) mod digest;
pub(crate) mod error;
pub mod jws;
pub(crate) mod keys;
pub(crate) mod signer;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;
pub(crate) mod thumbprint;

pub use digest::Digest32;
pub use error::CryptoError;
pub use keys::{AitpSigningKey, AitpVerifyingKey, Signature, SignatureAlgorithm};
pub use signer::{
    check_public_key, check_public_key_async, sign_jcs, sign_jcs_async, sign_raw, sign_raw_async,
    AitpSigner, AsyncAitpSigner, BackendSignature, BlockingSigner, DynAsyncAitpSigner, SignRequest,
    SignerError,
};
pub use thumbprint::{compute_jwk_thumbprint_ed25519_sha256, compute_jwk_thumbprint_p256_sha256};
