//! Shared helpers: JWKS resolvers and `PeerConfig` construction.
//!
//! A pinned-key-only handshake uses [`NoOpJwksResolver`], which fails
//! every JWKS resolution so an unexpected OIDC peer is rejected rather
//! than silently trusted. OIDC-mode sessions supply a real resolver via
//! [`crate::oidc::PyJwksProvider`] threaded through `make_peer_config`.

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
/// SDK sessions pass `&NoOpJwksResolver` for pinned-key mode and a real
/// resolver (e.g. `JwksProvider`) for OIDC mode. `pinned_keys` is the
/// session's local pinned-key trust store (RFC-AITP-0002 §3.2): a
/// `pinned_key` peer is accepted only if its key is in it, and the store
/// is consulted before the proof is verified. It is REQUIRED; an empty
/// store rejects every pinned-key peer. `grant_policy` and
/// `revocation_check` remain `None` for the binding surface; production
/// deployments that need them should use the Rust crates directly.
pub fn make_peer_config<'a>(
    key: &'a AitpSigningKey,
    manifest: &'a Manifest,
    jwks: &'a (dyn JwksResolver + 'a),
    trust_anchors: &'a [RawUrl],
    pinned_keys: &'a dyn PinnedKeyStore,
) -> PeerConfig<'a> {
    PeerConfig::new(key, manifest, jwks, pinned_keys, Timestamp::now())
        .with_trust_anchors(trust_anchors)
}

/// Parse a wire-bound UUID v4 strictly (RFC-AITP-0001 §5.2): lowercase
/// hyphenated, version 4, RFC 9562 variant, via
/// [`aitp_core::ids::parse_v4`]. Uppercase, braced, `urn:uuid:`,
/// unhyphenated and non-v4 forms are refused: the value is signed or sent
/// as given, so it must already be in wire form. The error names `field`.
pub fn parse_strict_v4(field: &str, s: &str) -> Result<uuid::Uuid, String> {
    aitp_core::ids::parse_v4(s)
        .map_err(|e| format!("{field} is not a lowercase UUID v4: {s} ({e})"))
}

/// Parse a revoked-`jti` deny list into a lookup set.
///
/// The set is a lookup key only, never signed or sent, so it is lenient:
/// an entry may be in any RFC 9562 text form (uppercase, braced,
/// `urn:uuid:`, unhyphenated) and is normalized before matching. A non-v4
/// entry is accepted but can never match, since every verified `jti` is
/// v4. An entry that is not a UUID at all is refused rather than dropped,
/// so a malformed list fails closed.
pub fn parse_revoked_jtis<'a, I>(jtis: I) -> Result<std::collections::HashSet<uuid::Uuid>, String>
where
    I: IntoIterator<Item = &'a str>,
{
    jtis.into_iter()
        .map(|s| {
            uuid::Uuid::parse_str(s)
                .map_err(|e| format!("revoked_jtis entry is not a UUID: {s} ({e})"))
        })
        .collect()
}
