//! Agent Identity & Trust Protocol (AITP): the experimental surface.
//!
//! **No stability promise.** Everything here tracks Draft spec text and
//! can change or disappear in any release (STABILITY.md). The stable API
//! is the [`aitp`] crate.
//!
//! - [`delegation`]: multi-hop delegation (RFC-AITP-0011, Draft).
//! - [`session_bundle`]: Session Trust Bundles (RFC-AITP-0010, Draft).
//!   `SessionBundleServer`, the HTTP endpoint, needs feature `http-server`.
//! - [`renewal`]: TCT renewal (RFC-AITP-0013, Draft). `RenewalServer`
//!   needs feature `http-server`; `renew_tct` needs feature `http-client`.
//! - [`spiffe`]: SPIFFE identity verification (RFC-AITP-0002 §6, registry
//!   status Proposed), plugged into the handshake as an
//!   [`aitp::handshake::IdentityVerifier`]. Needs feature
//!   `spiffe-identity`.
//! - [`a2a`]: the A2A Agent Card binding's client verification
//!   (RFC-AITP-0014, Draft). Pure, no I/O. Needs feature `a2a-agent-card`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "a2a-agent-card")]
pub mod a2a;
pub mod delegation;
pub mod renewal;
pub mod session_bundle;
#[cfg(feature = "spiffe-identity")]
pub mod spiffe;
