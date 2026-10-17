//! Shared helpers: JWKS resolvers and `PeerConfig` construction.

use aitp_core::{RawUrl, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_handshake::{JwkPublicKey, JwksResolver, PeerConfig, PinnedKeyStore, ResolveError};
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

/// Build a [`PeerConfig`] with the supplied resolver, trust anchors and
/// pinned-key trust store.
///
/// `pinned_keys` is the session's local pinned-key trust store
/// (RFC-AITP-0002 §3.2): a `pinned_key` peer is accepted only if its key
/// is in it, and the store is consulted before the proof is verified. It
/// is REQUIRED; an empty store rejects every pinned-key peer.
/// `grant_policy` and `revocation_check` remain `None` for the binding
/// surface; production deployments that need them should use the Rust
/// crates directly.
pub fn make_peer_config<'a>(
    key: &'a AitpSigningKey,
    manifest: &'a Manifest,
    jwks: &'a (dyn JwksResolver + 'a),
    trust_anchors: &'a [RawUrl],
    pinned_keys: &'a dyn PinnedKeyStore,
) -> PeerConfig<'a> {
    PeerConfig {
        signing_key: key,
        manifest,
        trust_anchors,
        jwks_resolver: jwks,
        pinned_key_store: pinned_keys,
        grant_policy: None,
        revocation_check: None,
        now: Timestamp::now(),
    }
}
