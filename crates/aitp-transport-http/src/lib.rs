//! HTTP client and server bindings for AITP.
//!
//! Feature-gated. Enable `client` for outbound Manifest fetches and JWKS
//! resolution; enable `server` for serving Manifests and accepting
//! incoming handshakes.
//!
//! Other crates in the workspace must NOT depend on this crate. The
//! protocol crates (`aitp-handshake`, `aitp-tct`, etc.) operate on parsed
//! types; this crate is the layer that gets bytes off the wire and into
//! those types.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(any(feature = "client", feature = "server"))]
pub mod common;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "client")]
pub mod key_resolution;

#[cfg(any(feature = "client", feature = "server"))]
pub mod revocation;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub use client::{FetchError, JwksFetcher, JwksFetcherError, ManifestFetcher};

#[cfg(feature = "client")]
pub use key_resolution::{
    KeyResolutionFailMode, KeyResolutionPolicy, KeyResolutionPolicyBuilder, PinnedIssuerKeyStore,
    StaticPinnedIssuerKeyStore,
};

#[cfg(feature = "server")]
pub use server::{HandshakeServer, ManifestServer, RevocationListProducer, DEFAULT_SESSION_TTL};

#[cfg(any(feature = "client", feature = "server"))]
pub use common::{sign_envelope, sign_envelope_with, verify_envelope_signature};

#[cfg(any(feature = "client", feature = "server"))]
pub use revocation::{
    apply_safe_subset, revocation_list_uri_from_manifest, RevocationCache, RevocationError,
    RevocationFailMode, RevocationOutcome, RevocationPolicy, RevocationProvider,
    REVOCATION_LIST_URI_EXT,
};
