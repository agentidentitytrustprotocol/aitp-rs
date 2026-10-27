//! Peer Manifest resolution by AID (RFC-AITP-0007 §1).
//!
//! Every peer-signed artifact whose signer is not the verifier itself —
//! a delegation hop (RFC-AITP-0006 §4 step 1, RFC-AITP-0011 §3 step 1),
//! a peer-issued TCT, a session-bundle coordinator's signature — is
//! verified against "the issuer's public key, resolved from that
//! issuer's Manifest". [`ManifestResolver`] is the source of those
//! Manifests; [`resolve_verified_manifest`] turns a source lookup into a
//! Manifest that has passed RFC-AITP-0003 §5 and designates the
//! requested AID, so artifact verifiers never use an unverified one.

use crate::core::Aid;
use crate::manifest::verifier::{verify_manifest, VerifyManifestContext};
use crate::manifest::{Manifest, ManifestError};
use std::collections::HashMap;

/// A source of peer Manifests keyed by AID: a cache, the Manifests
/// received inline during the Mutual Handshake, a well-known fetcher, or
/// any combination (RFC-AITP-0007 §1 lists the sources; precedence among
/// them is the implementation's).
///
/// Synchronous by design, matching the artifact verifiers that consume
/// it; a networked implementation prefetches (or serves from its cache)
/// rather than blocking inside verification.
///
/// Implementations return what they hold — they need not verify it.
/// Consumers MUST go through [`resolve_verified_manifest`] (or call
/// [`verify_manifest`] themselves) before trusting the returned value.
pub trait ManifestResolver: Send + Sync {
    /// The current Manifest published by `aid`, or `None` when none can
    /// be obtained (RFC-AITP-0003 §10 `MANIFEST_NOT_FOUND`).
    fn resolve_manifest(&self, aid: &Aid) -> Option<Manifest>;
}

/// `true` when `manifest_aid` names the same key as `aid`. The legacy
/// untagged form and `aid:pubkey:ed25519:` are trust-equivalent
/// (RFC-AITP-0001 §5.3), so the comparison is on algorithm + identifier
/// rather than the raw string.
fn designates(manifest_aid: &Aid, aid: &Aid) -> bool {
    manifest_aid.algorithm() == aid.algorithm() && manifest_aid.identifier() == aid.identifier()
}

/// A fixed set of Manifests. When several designate the same AID the most
/// recently published wins (RFC-AITP-0007 §1: a newer `published_at`
/// overrides an older copy).
impl ManifestResolver for [Manifest] {
    fn resolve_manifest(&self, aid: &Aid) -> Option<Manifest> {
        self.iter()
            .filter(|m| designates(&m.aid, aid))
            .max_by_key(|m| m.published_at.0)
            .cloned()
    }
}

impl ManifestResolver for Vec<Manifest> {
    fn resolve_manifest(&self, aid: &Aid) -> Option<Manifest> {
        self.as_slice().resolve_manifest(aid)
    }
}

/// Exact-key lookup: the map is keyed by the AID string as published.
impl ManifestResolver for HashMap<Aid, Manifest> {
    fn resolve_manifest(&self, aid: &Aid) -> Option<Manifest> {
        self.get(aid).cloned()
    }
}

/// Resolve `aid`'s Manifest from `resolver` and verify it before use.
///
/// 1. No Manifest from the source ⇒ [`ManifestError::NotFound`].
/// 2. The full RFC-AITP-0003 §5 check ([`verify_manifest`]: version,
///    expiry, signature, proof-of-possession, identity-hint shape) — its
///    error is returned unchanged.
/// 3. The verified Manifest MUST designate `aid` — a Manifest published
///    under a different (e.g. rotated, RFC-AITP-0003 §8.1) key is not
///    `aid`'s Manifest ⇒ [`ManifestError::AidMismatch`].
///
/// Callers verifying a peer-signed artifact then use the returned
/// Manifest's `aid` as the verification key and roll any error up to
/// `KEY_RESOLUTION_FAILED` (RFC-AITP-0007 §1).
pub fn resolve_verified_manifest(
    resolver: &dyn ManifestResolver,
    aid: &Aid,
    ctx: &VerifyManifestContext,
) -> Result<Manifest, ManifestError> {
    let manifest = resolver
        .resolve_manifest(aid)
        .ok_or(ManifestError::NotFound)?;
    verify_manifest(&manifest, ctx)?;
    if !designates(&manifest.aid, aid) {
        return Err(ManifestError::AidMismatch);
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Timestamp;
    use crate::crypto::AitpSigningKey;
    use crate::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};

    const NOW: Timestamp = Timestamp(1_700_000_000);

    fn manifest(key: &AitpSigningKey, published_at: Timestamp, ttl_secs: i64) -> Manifest {
        ManifestBuilder::new(key)
            .handshake_endpoint("https://agent.example.com/handshake".parse().unwrap())
            .identity_hint(IdentityHint {
                kind: IdentityHintKind::Oidc,
                subject: "agent".into(),
                issuer: Some("https://idp.example.com".parse().unwrap()),
                public_key: None,
            })
            .accept_trust_anchor("https://idp.example.com".parse().unwrap())
            .published_at(published_at)
            .ttl_secs(ttl_secs)
            .build()
            .unwrap()
    }

    fn ctx() -> VerifyManifestContext {
        VerifyManifestContext { now: NOW }
    }

    #[test]
    fn verified_manifest_resolves() {
        let key = AitpSigningKey::from_seed(&[1; 32]);
        let source = vec![manifest(&key, NOW, 3600)];
        let got = resolve_verified_manifest(&source, key.aid(), &ctx()).unwrap();
        assert_eq!(&got.aid, key.aid());
    }

    #[test]
    fn missing_manifest_is_not_found() {
        let key = AitpSigningKey::from_seed(&[1; 32]);
        let other = AitpSigningKey::from_seed(&[2; 32]);
        let source = vec![manifest(&other, NOW, 3600)];
        assert!(matches!(
            resolve_verified_manifest(&source, key.aid(), &ctx()),
            Err(ManifestError::NotFound)
        ));
    }

    #[test]
    fn manifest_for_another_key_is_aid_mismatch() {
        // A map entry under `aid` whose Manifest was published by a
        // different key does not designate `aid`.
        let key = AitpSigningKey::from_seed(&[1; 32]);
        let rotated = AitpSigningKey::from_seed(&[2; 32]);
        let source = HashMap::from([(key.aid().clone(), manifest(&rotated, NOW, 3600))]);
        assert!(matches!(
            resolve_verified_manifest(&source, key.aid(), &ctx()),
            Err(ManifestError::AidMismatch)
        ));
    }

    #[test]
    fn unverifiable_manifest_error_is_returned() {
        let key = AitpSigningKey::from_seed(&[1; 32]);
        let expired = vec![manifest(&key, Timestamp(NOW.0 - 120), 60)];
        assert!(matches!(
            resolve_verified_manifest(&expired, key.aid(), &ctx()),
            Err(ManifestError::Expired)
        ));
    }

    #[test]
    fn newest_published_manifest_wins() {
        let key = AitpSigningKey::from_seed(&[1; 32]);
        // The older copy has expired; the newer one is current.
        let source = vec![
            manifest(&key, Timestamp(NOW.0 - 120), 60),
            manifest(&key, Timestamp(NOW.0 - 10), 3600),
        ];
        let got = resolve_verified_manifest(&source, key.aid(), &ctx()).unwrap();
        assert_eq!(got.published_at, Timestamp(NOW.0 - 10));
    }
}
