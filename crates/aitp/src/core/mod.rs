//! Core types and primitives for the Agent Identity & Trust Protocol (AITP).
//!
//! **No stability promise.** This crate is published so the AITP bindings
//! and tools can build on it; its API can change in any release. Depend
//! on the [`aitp`](https://docs.rs/aitp) facade crate instead.
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
//! - The [`UnknownField`] member-set checker for RFC-AITP-0001 §7, and
//!   [`CheckedJson`], the duplicate-key-checked input every `parse_*_wire`
//!   function takes (RFC-AITP-0001 §5.4.5).
//! - The [`nonce_store::NonceStore`] single-use nonce store trait and its
//!   in-memory implementation (pinned-key admission, TCT renewal).
//!
//! Higher-level protocol modules (`aitp::manifest`, `aitp::tct`, `aitp::handshake`,
//! `aitp::delegation`) build on these primitives.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod aid;
pub mod base64url;
pub mod envelope;
pub mod error;
pub mod extensions;
pub mod ids;
pub mod jcs;
pub mod nonce_store;
pub mod raw_url;
pub mod time;
pub mod unknown_field;

pub use aid::{Aid, AidAlgorithm, AidParseError};
pub use envelope::{
    check_envelope_structure, check_unsigned_envelope_structure, envelope_signing_digest,
    envelope_signing_input, parse_envelope_wire, AitpEnvelope, EnvelopeParseError, MessageType,
    Sender, AITP_ENVELOPE_MEMBERS, ENVELOPE_SIGNING_DOMAIN_TAG,
};
pub use error::{AitpError, ErrorCode};
pub use extensions::ExtensionsMap;
pub use nonce_store::{InMemoryNonceStore, NonceStore};
pub use raw_url::RawUrl;
pub use time::Timestamp;
pub use unknown_field::{
    check_members, from_serde_error, reject_duplicate_keys, CheckedJson, CheckedJsonError,
    UnknownField,
};

/// Protocol version this crate implements. Carried as the `version`
/// field on JCS-profile artifacts and as the `ver` private claim on
/// compact-JWS portable trust artifacts (RFC-AITP-0001 §5.4.5).
pub const PROTOCOL_VERSION: &str = "aitp/0.3";

/// Default timestamp tolerance for replay protection (300 seconds, ±).
pub const DEFAULT_TIMESTAMP_TOLERANCE_SECS: i64 = 300;

/// Length of an AID identifier component when method = `pubkey`
/// (Ed25519 raw public key encoded as unpadded base64url).
pub const AID_PUBKEY_IDENTIFIER_LEN: usize = 43;

/// Length of an Ed25519 signature encoded as unpadded base64url.
pub const ED25519_SIGNATURE_BASE64URL_LEN: usize = 86;
