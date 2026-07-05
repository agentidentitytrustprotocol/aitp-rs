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
//! # Example: issue and verify a TCT (compact JWS)
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
//! // `issued.token` is the opaque compact JWS that goes on the wire;
//! // `issued.voucher` is the companion grant voucher bob can later
//! // delegate with.
//! let issued = TctBuilder::new(&alice)
//!     .subject(bob.aid().clone())
//!     .audience(bob.aid().clone())  // v0.2: audience == subject
//!     .grants(["demo.echo"])
//!     .ttl_secs(3600)
//!     .subject_pubkey(bob.verifying_key())
//!     .issued_at(now)
//!     .build()?;
//!
//! // The strict builder forces an explicit decision on the two
//! // silent-accept surfaces (revocation source, issuer-Manifest expiry
//! // cap). Here — a self-issued holder receipt with no Manifest
//! // resolved — both are deliberately waived; production verifiers
//! // supply `.revocation_check(..)` and `.issuer_manifest_expires_at(..)`.
//! let ctx = TctVerifyContext::builder(bob.aid(), alice.aid(), now)
//!     .accept_unchecked_revocation_dangerous()
//!     .skip_manifest_expiry_cap_dangerous()
//!     .build()?;
//! let verified = verify_tct(&issued.token, &ctx)?;
//! assert_eq!(verified.claims.grants, vec!["demo.echo".to_string()]);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

pub use aitp_core as core;
pub use aitp_crypto as crypto;
pub use aitp_delegation as delegation;
pub use aitp_handshake as handshake;
pub use aitp_manifest as manifest;
#[cfg(feature = "experimental-session-bundle")]
pub use aitp_session_bundle as session_bundle;
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
    pub use crate::tct::{IssuedTct, TctBuilder, TctClaims, VerifiedTct};
}
