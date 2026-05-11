//! Core types and primitives for the Agent Identity & Trust Protocol (AITP).
//!
//! This crate is pure — no I/O, no crypto, no transport. It defines:
//!
//! - The [`Aid`] newtype: a validated AITP Agent Identifier.
//! - The [`AitpEnvelope`] message wrapper.
//! - JSON canonicalization per RFC 8785 ([`jcs`]).
//! - Strict unpadded base64url codec ([`base64url`]).
//! - The [`Timestamp`] newtype for Unix-second timestamps.
//! - The [`ExtensionsMap`] type for forward-compatible extensions.
//! - The [`AitpError`] and [`ErrorCode`] taxonomy from RFC-AITP-0001.
//!
//! Higher-level protocol crates (`aitp-manifest`, `aitp-tct`, `aitp-handshake`,
//! `aitp-delegation`) build on these primitives.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod aid;
pub mod base64url;
pub mod envelope;
pub mod error;
pub mod extensions;
pub mod jcs;
pub mod raw_url;
pub mod time;

pub use aid::{Aid, AidAlgorithm, AidParseError};
pub use envelope::{
    envelope_signing_digest, envelope_signing_input, AitpEnvelope, MessageType, Sender,
};
pub use error::{AitpError, ErrorCode};
pub use extensions::ExtensionsMap;
pub use raw_url::RawUrl;
pub use time::Timestamp;

/// Protocol version this crate implements.
pub const PROTOCOL_VERSION: &str = "aitp/0.1";

/// Default timestamp tolerance for replay protection (300 seconds, ±).
pub const DEFAULT_TIMESTAMP_TOLERANCE_SECS: i64 = 300;

/// Length of an AID identifier component when method = `pubkey`
/// (Ed25519 raw public key encoded as unpadded base64url).
pub const AID_PUBKEY_IDENTIFIER_LEN: usize = 43;

/// Length of an Ed25519 signature encoded as unpadded base64url.
pub const ED25519_SIGNATURE_BASE64URL_LEN: usize = 86;
