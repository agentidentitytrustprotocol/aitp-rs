//! HTTP client and server bindings for AITP.
//!
//! **No stability promise.** This crate is published so the AITP bindings
//! and tools can build on it; its API can change in any release. Depend
//! on the [`aitp`](https://docs.rs/aitp) facade crate instead.
//!
//! Feature-gated. Enable `client` for outbound Manifest fetches and JWKS
//! resolution; enable `server` for serving Manifests and accepting
//! incoming handshakes.
//!
//! Other crates in the workspace must NOT depend on this crate. The
//! protocol modules (`aitp::handshake`, `aitp::tct`, etc.) operate on parsed
//! types; this crate is the layer that gets bytes off the wire and into
//! those types.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(any(feature = "http-client", feature = "http-server"))]
pub mod common;

#[cfg(feature = "http-client")]
pub mod client;

#[cfg(feature = "http-client")]
pub mod retry;

#[cfg(feature = "http-client")]
pub mod client_config;

#[cfg(feature = "client-spki-pinning")]
pub mod tls_pinning;

#[cfg(feature = "http-client")]
pub mod key_resolution;

#[cfg(feature = "http-client")]
pub mod net_guard;

#[cfg(any(feature = "http-client", feature = "http-server"))]
mod obs;

#[cfg(any(feature = "http-client", feature = "http-server"))]
pub mod replay_store;

#[cfg(any(feature = "http-client", feature = "http-server"))]
pub mod revocation;

#[cfg(feature = "http-client")]
pub mod revocation_fetch;

#[cfg(feature = "http-server")]
pub mod server;

#[cfg(feature = "source-ip")]
pub mod source_ip;

#[cfg(feature = "http-server")]
pub mod server_limits;

#[cfg(feature = "http-client")]
pub use client::{FetchError, JwksFetcher, JwksFetcherError, ManifestFetcher};

#[cfg(feature = "http-client")]
pub use net_guard::{GuardMode, HostGuard, HostGuardError};

#[cfg(feature = "http-client")]
pub use retry::RetryPolicy;

#[cfg(feature = "http-client")]
pub use client_config::ClientConfig;

#[cfg(feature = "client-spki-pinning")]
pub use tls_pinning::{build_pinning_client_config, compute_spki_hash, SpkiHash, SpkiPinVerifier};

#[cfg(feature = "http-client")]
pub use key_resolution::{
    AsyncJwksResolver, KeyResolutionFailMode, KeyResolutionOutcome, KeyResolutionPolicy,
    KeyResolutionPolicyBuilder, PinnedIssuerKeyStore, StaticPinnedIssuerKeyStore,
};

#[cfg(feature = "http-server")]
pub use server::{
    HandshakeServer, ManifestServer, RateLimitConfig, RateLimitOutcome, RevocationListProducer,
    ServeConfig, DEFAULT_SESSION_TTL, REVOCATION_LIST_PATH,
};

#[cfg(feature = "source-ip")]
pub use source_ip::{resolve_source_ip, TrustedProxy, TrustedProxyParseError};

#[cfg(feature = "experimental-axum")]
pub use server_limits::{with_request_body_limit, with_request_body_limit_default};
#[cfg(feature = "http-server")]
pub use server_limits::{DEFAULT_REQUEST_BODY_LIMIT, RECOMMENDED_MAX_HEADER_BYTES};

#[cfg(any(feature = "http-client", feature = "http-server"))]
pub use common::{
    sign_envelope, sign_envelope_async, sign_envelope_with, sign_envelope_with_async,
    verify_envelope_signature,
};

#[cfg(any(feature = "http-client", feature = "http-server"))]
pub use replay_store::{InMemoryReplayGuard, ReplayGuard};

#[cfg(any(feature = "http-client", feature = "http-server"))]
pub use revocation::{
    apply_safe_subset, revocation_list_uri_from_manifest, RevocationCache, RevocationError,
    RevocationFailMode, RevocationOutcome, RevocationPolicy, RevocationProvider,
    REVOCATION_LIST_URI_EXT,
};

#[cfg(feature = "http-client")]
pub use revocation_fetch::{
    PreparedRevocation, RevocationFetcher, DEFAULT_MAX_REVOCATION_LIST_BYTES,
    DEFAULT_REVOCATION_FETCH_TIMEOUT,
};
