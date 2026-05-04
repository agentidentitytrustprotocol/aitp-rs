//! Agent Manifest — the discovery primitive for A2A peers.
//!
//! A Manifest is a signed self-description published at
//! `/.well-known/aitp-manifest`. It carries the agent's AID, a static
//! `identity_hint` (NOT a fresh JWT — fresh proofs are exchanged in the
//! Mutual Handshake), the handshake endpoint, accepted trust anchors and
//! identity types, offered capabilities, and a proof-of-possession that
//! ties the Manifest to the AID's signing key.
//!
//! See RFC-AITP-0003.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod builder;
pub mod error;
pub mod types;
pub mod verifier;

pub use builder::{ManifestBuilder, DEFAULT_MANIFEST_TTL_SECS};
pub use error::ManifestError;
pub use types::{IdentityHint, IdentityHintKind, Manifest, ManifestEnvelope, ManifestPop};
pub use verifier::{verify_manifest, VerifyManifestContext};
