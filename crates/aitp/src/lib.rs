//! Agent Identity & Trust Protocol (AITP).
//!
//! ```toml
//! [dependencies]
//! aitp = "0.24"
//! ```
//!
//! # Modules
//!
//! - [`core`]: AIDs, envelopes, timestamps, error codes, JCS, nonce stores
//!   (RFC-AITP-0001).
//! - [`crypto`]: signing keys, the signer traits, digests, compact JWS.
//! - [`envelope`]: building and signing envelopes.
//! - [`manifest`]: Manifest building, resolution and verification
//!   (RFC-AITP-0003).
//! - [`handshake`]: the mutual handshake state machine, `PeerConfig` and
//!   identity verification (RFC-AITP-0004, RFC-AITP-0002).
//!   `handshake::admission` needs feature `pinned-admission`.
//! - [`tct`]: TCT issuance and verification, grant vouchers, revocation
//!   lists (RFC-AITP-0005, RFC-AITP-0008).
//! - [`delegation`]: delegation tokens (RFC-AITP-0006).
//! - [`transport`]: HTTP fetchers (feature `http-client`), `HandshakeServer`
//!   (feature `http-server`), revocation sources (RFC-AITP-0007,
//!   RFC-AITP-0009).
//! - `facade` (feature `http-client`): `run_initiator_handshake`,
//!   `TctStore`.
//!
//! Each public item has one path, normally its module root
//! (`aitp::tct::TctBuilder`, `aitp::transport::HostGuard`); STABILITY.md,
//! "Public paths", lists the namespace submodules.
//!
//! The stable surface (STABILITY.md) is frozen, with signatures, in
//! `crates/aitp/public-api.stable.txt` and checked in CI. Features named
//! `experimental-*` carry no promise, nor does the `aitp-experimental`
//! crate (Session Trust Bundles).
//!
//! # Example: issue and verify a TCT (compact JWS)
//!
//! ```
//! use aitp::core::Timestamp;
//! use aitp::crypto::AitpSigningKey;
//! use aitp::tct::{verify_tct, RevocationSource, TctBuilder, TctVerifyContext};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let alice = AitpSigningKey::from_ed25519_seed(&[0x11; 32]);
//! let bob = AitpSigningKey::from_ed25519_seed(&[0x22; 32]);
//! let now = Timestamp(1_700_000_000);
//!
//! // `issued.token` is the opaque compact JWS that goes on the wire;
//! // `issued.voucher` is the companion grant voucher bob can later
//! // delegate with.
//! let issued = TctBuilder::new(&alice)
//!     .subject(bob.aid().clone())
//!     .audience(bob.aid().clone())  // v0.2: audience == subject
//!     .grants(["demo.echo"])
//!     .ttl(std::time::Duration::from_secs(3600))
//!     .subject_pubkey(bob.verifying_key())
//!     .issued_at(now)
//!     .build()?;
//!
//! // The strict builder forces an explicit decision on the two
//! // silent-accept surfaces (revocation source, issuer-Manifest expiry
//! // cap). Here — a self-issued holder receipt with no Manifest
//! // resolved — both are deliberately waived; production verifiers
//! // supply `.revocation(RevocationSource::Check(..))` and
//! // `.issuer_manifest_expires_at(..)`.
//! let ctx = TctVerifyContext::builder(bob.aid(), alice.aid(), now)
//!     .revocation(RevocationSource::FailOpen)
//!     .skip_manifest_expiry_cap_dangerous()
//!     .build()?;
//! let verified = verify_tct(&issued.token, &ctx)?;
//! assert_eq!(verified.claims().grants, vec!["demo.echo".to_string()]);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod core;
pub mod crypto;
pub mod delegation;
pub mod envelope;
pub mod handshake;
pub mod manifest;
pub mod tct;
pub mod transport;

/// High-level client helpers: run a handshake, cache TCTs.
#[cfg(feature = "http-client")]
pub mod facade;

#[doc(hidden)]
pub mod __private;
