//! Shared helpers: JWKS resolvers and `PeerConfig` construction.
//!
//! A pinned-key-only handshake uses [`NoOpJwksResolver`], which fails
//! every JWKS resolution so an unexpected OIDC peer is rejected rather
//! than silently trusted. OIDC-mode sessions supply a real resolver via
//! [`crate::oidc::PyJwksProvider`] threaded through `make_peer_config`.

use aitp_core::{RawUrl, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_handshake::{JwkPublicKey, JwksResolver, PeerConfig, ResolveError};
use aitp_manifest::Manifest;
use url::Url;

/// A JWKS resolver that always fails. Used for pinned-key-only sessions.
pub struct NoOpJwksResolver;

impl JwksResolver for NoOpJwksResolver {
    fn resolve(&self, _issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Err(ResolveError::NetworkError(
            "no JWKS resolver configured for this session (pinned-key only)".into(),
        ))
    }
}

/// Build a [`PeerConfig`] with the supplied resolver and trust anchors.
///
/// SDK sessions pass `&NoOpJwksResolver` for pinned-key mode and a real
/// resolver (e.g. `JwksProvider`) for OIDC mode. `pinned_key_store`,
/// `grant_policy`, and `revocation_check` remain `None` for the binding
/// surface; production deployments that need them should use the Rust
/// crates directly.
pub fn make_peer_config<'a>(
    key: &'a AitpSigningKey,
    manifest: &'a Manifest,
    jwks: &'a (dyn JwksResolver + 'a),
    trust_anchors: &'a [RawUrl],
) -> PeerConfig<'a> {
    PeerConfig {
        signing_key: key,
        manifest,
        trust_anchors,
        jwks_resolver: jwks,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: Timestamp::now(),
    }
}
