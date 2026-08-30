//! Shared helpers: JWKS resolvers and `PeerConfig` construction.

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
