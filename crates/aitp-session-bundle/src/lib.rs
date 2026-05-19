//! Session Trust Bundle (RFC-AITP-0010).
//!
//! In a multi-agent session of N participants, requiring O(N²) bilateral
//! Mutual Handshakes is unscalable. The Session Trust Bundle is a signed
//! artifact a coordinator constructs from N coordinator↔participant
//! Mutual Handshakes (each producing a peer-issued TCT) and distributes
//! to all participants, so that every agent-to-agent pair within the
//! session has a verifiable trust artifact without a full mesh of
//! handshakes.
//!
//! # Trust model
//!
//! A bundle provides **coordinator-attested membership**, not
//! peer-to-peer identity binding. If A and B both appear in the same
//! bundle, they know:
//! 1. The coordinator authenticated each of them directly via a
//!    bilateral handshake (the coordinator holds a peer-issued TCT for
//!    each participant).
//! 2. The coordinator signed both of those TCTs into the same bundle.
//!
//! Pairs that need direct peer-to-peer identity binding (rather than
//! coordinator-attested membership) MUST run a separate bilateral
//! Mutual Handshake.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod builder;
pub mod error;
pub mod types;
pub mod verifier;

pub use builder::{SessionBundleBuilder, DEFAULT_BUNDLE_VERSION};
pub use error::SessionBundleError;
pub use types::{ParticipantEntry, SessionBundleEnvelope, SessionTrustBundle};
pub use verifier::{verify_session_bundle, BundleOutcome, VerifySessionBundleContext};

/// Manifest `extensions` key under which a coordinator advertises the
/// concrete HTTPS URL of its session-bundle endpoint (RFC-AITP-0010
/// §4.3.1; registered in the spec's `registries/extension-keys.md`).
///
/// The §4.3.1 paths (`/aitp/session/bundle` and
/// `/aitp/session/bundle/{session_id}`) are RECOMMENDED, not reserved:
/// participants MUST discover the actual endpoint via this extension
/// key and MUST NOT probe the default paths when the key is absent.
pub const RFC_AITP_0010_BUNDLE_URI: &str = "rfc-aitp-0010.bundle_uri";
