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
pub mod retry;

#[cfg(feature = "client")]
pub mod client_config;

#[cfg(feature = "client")]
pub mod token_exchange;

#[cfg(feature = "client-spki-pinning")]
pub mod tls_pinning;

#[cfg(any(feature = "client", feature = "server"))]
pub mod dpop;

#[cfg(feature = "client")]
pub mod key_resolution;

#[cfg(any(feature = "client", feature = "server"))]
pub mod revocation;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "server")]
pub mod server_limits;

#[cfg(feature = "client")]
pub use client::{FetchError, JwksFetcher, JwksFetcherError, ManifestFetcher};

#[cfg(feature = "client")]
pub use retry::RetryPolicy;

#[cfg(feature = "client")]
pub use client_config::ClientConfig;

#[cfg(feature = "client")]
pub use token_exchange::{
    exchange_token, SubjectCredential, TokenExchangeError, TokenExchangeRequest,
    TokenExchangeResponse, REQUESTED_TYPE_ACCESS_TOKEN, SUBJECT_TYPE_ID_TOKEN, SUBJECT_TYPE_JWT,
    SUBJECT_TYPE_SAML2, TOKEN_EXCHANGE_GRANT_TYPE,
};

#[cfg(feature = "client-spki-pinning")]
pub use tls_pinning::{build_pinning_client_config, compute_spki_hash, SpkiHash, SpkiPinVerifier};

#[cfg(any(feature = "client", feature = "server"))]
pub use dpop::{
    verify_dpop_proof, verify_dpop_proof_full, DpopError, DpopHeader, DpopProof, DpopReplayCache,
    DpopVerifyContext,
};

#[cfg(feature = "client")]
pub use key_resolution::{
    KeyResolutionFailMode, KeyResolutionPolicy, KeyResolutionPolicyBuilder, PinnedIssuerKeyStore,
    StaticPinnedIssuerKeyStore,
};

#[cfg(feature = "server")]
pub use server::{HandshakeServer, ManifestServer, RevocationListProducer, DEFAULT_SESSION_TTL};

#[cfg(feature = "server")]
pub use server_limits::{
    recommended_max_header_bytes, with_request_body_limit, with_request_body_limit_default,
    DEFAULT_REQUEST_BODY_LIMIT, RECOMMENDED_MAX_HEADER_BYTES,
};

#[cfg(any(feature = "client", feature = "server"))]
pub use common::{sign_envelope, sign_envelope_with, verify_envelope_signature};

#[cfg(any(feature = "client", feature = "server"))]
pub use revocation::{
    apply_safe_subset, revocation_list_uri_from_manifest, RevocationCache, RevocationError,
    RevocationFailMode, RevocationOutcome, RevocationPolicy, RevocationProvider,
    REVOCATION_LIST_URI_EXT,
};
