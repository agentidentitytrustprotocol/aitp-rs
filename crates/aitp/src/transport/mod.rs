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

#[cfg(feature = "http-client")]
mod rsa_floor;

#[cfg(feature = "http-client")]
pub(crate) mod client;

#[cfg(feature = "http-client")]
pub(crate) mod retry;

#[cfg(feature = "http-client")]
pub(crate) mod client_config;

#[cfg(feature = "client-spki-pinning")]
pub(crate) mod tls_pinning;

#[cfg(feature = "http-client")]
pub(crate) mod key_resolution;

#[cfg(feature = "http-client")]
pub(crate) mod net_guard;

#[cfg(any(feature = "http-client", feature = "http-server"))]
mod obs;

#[cfg(any(feature = "http-client", feature = "http-server"))]
pub(crate) mod replay_store;

#[cfg(any(feature = "http-client", feature = "http-server"))]
pub(crate) mod revocation;

#[cfg(feature = "http-client")]
pub(crate) mod revocation_fetch;

#[cfg(feature = "http-server")]
pub(crate) mod server;

#[cfg(feature = "source-ip")]
pub(crate) mod source_ip;

#[cfg(feature = "http-server")]
pub(crate) mod server_limits;

#[cfg(feature = "http-client")]
pub use client::{
    FetchError, JwksFetcher, JwksFetcherError, ManifestFetcher, DEFAULT_MAX_JWKS_BYTES,
    DEFAULT_MAX_MANIFEST_BYTES, DEFAULT_OIDC_DISCOVERY_TTL,
};

#[cfg(feature = "http-client")]
pub use net_guard::{GuardMode, HostGuard, HostGuardError};

#[cfg(feature = "http-client")]
pub use retry::{RetryPolicy, RetryPolicyBuilder};

#[cfg(feature = "http-client")]
pub use client_config::ClientConfig;

#[cfg(feature = "client-spki-pinning")]
pub use tls_pinning::{build_pinning_client_config, compute_spki_hash, SpkiHash, SpkiPinVerifier};

#[cfg(feature = "http-client")]
pub use key_resolution::{
    KeyResolutionFailMode, KeyResolutionOutcome, KeyResolutionPolicy, KeyResolutionPolicyBuilder,
    PinnedIssuerKeyStore, StaticPinnedIssuerKeyStore, DEFAULT_NEGATIVE_CACHE_TTL,
};

#[cfg(feature = "http-server")]
pub use server::{
    HandshakeServer, ManifestServer, RateLimitConfig, RevocationListProducer, ServeConfig,
    DEFAULT_BODY_READ_TIMEOUT, DEFAULT_MAX_SESSIONS, DEFAULT_REPLAY_WINDOW,
    DEFAULT_SESSION_SWEEP_INTERVAL, DEFAULT_SESSION_TTL, REVOCATION_LIST_PATH,
};

#[cfg(feature = "source-ip")]
pub use source_ip::{resolve_source_ip, TrustedProxy, TrustedProxyParseError};

#[cfg(feature = "experimental-axum")]
pub use server_limits::{with_request_body_limit, with_request_body_limit_default};
#[cfg(feature = "http-server")]
pub use server_limits::{
    DEFAULT_REQUEST_BODY_LIMIT, RECOMMENDED_MAX_HEADER_BYTES, REVOCATION_LIST_BODY_LIMIT,
};

#[cfg(any(feature = "http-client", feature = "http-server"))]
pub use replay_store::{InMemoryReplayGuard, ReplayGuard};

#[cfg(any(feature = "http-client", feature = "http-server"))]
pub use revocation::{
    EmptyRevocationProvider, RevocationError, RevocationFailMode, RevocationPolicy,
    RevocationProvider,
};

#[cfg(feature = "http-client")]
pub use revocation_fetch::{
    PreparedRevocation, RevocationFetcher, DEFAULT_MAX_REVOCATION_LIST_BYTES,
    DEFAULT_REVOCATION_FETCH_TIMEOUT,
};
