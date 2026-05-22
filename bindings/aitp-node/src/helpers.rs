//! Shared helpers: a no-op JWKS resolver and `PeerConfig` construction.
//!
//! SDK v1 supports pinned-key identities only. OIDC identity proofs
//! require a JWKS resolver; until one is wired in, [`NoOpJwksResolver`]
//! fails every resolution so an OIDC peer is rejected rather than
//! silently trusted.

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_handshake::{JwkPublicKey, JwksResolver, PeerConfig, ResolveError};
use aitp_manifest::Manifest;
use url::Url;

/// A JWKS resolver that always fails. SDK v1 is pinned-key only.
pub struct NoOpJwksResolver;

impl JwksResolver for NoOpJwksResolver {
    fn resolve(&self, _issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Err(ResolveError::NetworkError(
            "no JWKS resolver configured in this SDK build (pinned-key only)".into(),
        ))
    }
}

/// Build a [`PeerConfig`] for pinned-key handshakes.
///
/// SDK v1 uses key-possession-only pinned-key identity (`pinned_key_store:
/// None`), no grant policy, and no revocation check.
pub fn make_peer_config<'a>(
    key: &'a AitpSigningKey,
    manifest: &'a Manifest,
    jwks: &'a NoOpJwksResolver,
) -> PeerConfig<'a> {
    PeerConfig {
        signing_key: key,
        manifest,
        trust_anchors: &[],
        jwks_resolver: jwks,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: Timestamp::now(),
    }
}
