//! Agent Identity & Trust Protocol (AITP): the experimental surface.
//!
//! **No stability promise.** Everything here tracks Draft spec text and
//! can change or disappear in any release (STABILITY.md). The stable API
//! is the [`aitp`] crate.
//!
//! - [`delegation`]: multi-hop delegation (RFC-AITP-0011, Draft).
//! - [`session_bundle`]: Session Trust Bundles (RFC-AITP-0010, Draft).
//!   `SessionBundleServer`, the HTTP endpoint, needs feature `http-server`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod delegation;
pub mod session_bundle;
