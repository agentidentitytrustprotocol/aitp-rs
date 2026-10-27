//! Shared test support: a delegation issuer's published Manifest.
//!
//! Every delegation JWS verifies under the key its issuer's verified
//! Manifest designates (RFC-AITP-0006 §4 step 1; RFC-AITP-0011 §3
//! step 1), so each verifying test supplies one through
//! `VerifyDelegationContext::with_issuer_manifests`.

use aitp::core::{Aid, Timestamp};
use aitp::crypto::AitpSigner;
use aitp::delegation::{DelegationRevocation, VerifyDelegationContext};
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder, ManifestResolver};

/// `key`'s published Manifest: published at `published_at`, valid for
/// one day.
pub fn manifest_for(key: &dyn AitpSigner, published_at: Timestamp) -> Manifest {
    ManifestBuilder::new(key)
        .handshake_endpoint("https://agent.example.com/aitp/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityHintKind::Oidc, "agent")
                .with_issuer("https://idp.example.com".parse().unwrap()),
        )
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .published_at(published_at)
        .ttl_secs(86_400)
        .build()
        .unwrap()
}

/// A context bound to `manifests` as its issuer Manifest source.
#[allow(dead_code)] // not every test binary uses every helper
pub fn verify_ctx<'a>(
    verifier: &'a Aid,
    now: Timestamp,
    manifests: &'a dyn ManifestResolver,
) -> VerifyDelegationContext<'a> {
    VerifyDelegationContext::new(verifier, now, DelegationRevocation::FailOpen)
        .with_issuer_manifests(manifests)
}
