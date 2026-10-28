//! Agent Manifest — the discovery primitive for A2A peers.
//!
//! **No stability promise.** This crate is published so the AITP bindings
//! and tools can build on it; its API can change in any release. Depend
//! on the [`aitp`](https://docs.rs/aitp) facade crate instead.
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

pub(crate) mod builder;
pub(crate) mod error;
pub(crate) mod resolver;
pub(crate) mod types;
pub(crate) mod verifier;

pub use builder::{ManifestBuilder, DEFAULT_MANIFEST_TTL, REVOCATION_LIST_URI_EXT};
pub use error::ManifestError;
pub use resolver::{resolve_verified_manifest, ManifestResolver};
pub use types::{
    IdentityHint, IdentityHintKind, Manifest, ManifestEnvelope, ManifestPop, MANIFEST_MEMBERS,
};
pub use verifier::{
    check_identity_type_compatibility, parse_manifest_wire, verify_manifest, ManifestVerifyContext,
    VerifiedManifest,
};
