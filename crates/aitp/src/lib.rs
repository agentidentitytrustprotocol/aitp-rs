//! Agent Identity & Trust Protocol (AITP) — facade crate.
//!
//! This crate re-exports the AITP protocol crates so most users can depend
//! on a single crate:
//!
//! ```toml
//! [dependencies]
//! aitp = "0.1"
//! ```
//!
//! Consumers that need only TCT verification (e.g. integrating into an
//! existing service) should depend on `aitp-tct` and `aitp-crypto`
//! directly to avoid pulling in the handshake state machine and HTTP
//! transport.
//!
//! # Example: issue and verify a TCT
//!
//! ```
//! use aitp::core::Timestamp;
//! use aitp::prelude::*;
//! use aitp::tct::{verify_tct, TctBuilder, TctVerifyContext};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let alice = AitpSigningKey::from_seed(&[0x11; 32]);
//! let bob = AitpSigningKey::from_seed(&[0x22; 32]);
//! let now = Timestamp(1_700_000_000);
//!
//! let tct = TctBuilder::new(&alice)
//!     .subject(bob.aid().clone())
//!     .audience(bob.aid().clone())  // v0.1: audience == subject
//!     .grants(["demo.echo"])
//!     .ttl_secs(3600)
//!     .subject_pubkey(bob.verifying_key())
//!     .issued_at(now)
//!     .build()?;
//!
//! let alice_pubkey = AitpVerifyingKey::from_aid(alice.aid())?;
//! let ctx = TctVerifyContext {
//!     expected_audience: bob.aid(),
//!     issuer_pubkey: &alice_pubkey,
//!     now,
//!     issuer_manifest_expires_at: None,
//!     revocation_check: None,
//! };
//! verify_tct(&tct, &ctx)?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

pub use aitp_core as core;
pub use aitp_crypto as crypto;
pub use aitp_delegation as delegation;
pub use aitp_handshake as handshake;
pub use aitp_manifest as manifest;
pub use aitp_tct as tct;

#[cfg(feature = "http-client")]
pub use aitp_transport_http as transport;

#[cfg(feature = "http-client")]
pub mod facade;

/// Convenience re-exports of the most common types.
pub mod prelude {
    pub use crate::core::{Aid, AitpEnvelope, Timestamp};
    pub use crate::crypto::{AitpSigningKey, AitpVerifyingKey};
    pub use crate::manifest::Manifest;
    pub use crate::tct::{Tct, TctBuilder};
}
