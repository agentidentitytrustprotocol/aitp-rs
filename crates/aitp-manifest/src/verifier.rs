//! Manifest verification per RFC-AITP-0003 §5.

use crate::builder::ManifestSigningView;
use crate::types::{IdentityHintKind, Manifest};
use crate::ManifestError;
use aitp_core::{jcs, Timestamp};
use aitp_crypto::{AitpVerifyingKey, Signature};
use sha2::{Digest, Sha256};

/// Inputs for verifying a Manifest.
pub struct VerifyManifestContext {
    /// Current time, used for expiry check. Pass `Timestamp::now()` in
    /// production; pass a pinned value in tests.
    pub now: Timestamp,
}

impl VerifyManifestContext {
    /// Build a context using the system clock.
    pub fn now() -> Self {
        Self {
            now: Timestamp::now(),
        }
    }
}

/// Verify a Manifest per RFC-AITP-0003 §5.
///
/// Verification order:
///
/// 1. **Version** — `manifest.version == "aitp/0.1"`. Else
///    [`ManifestError::VersionUnknown`].
/// 2. **Expiry** — `manifest.expires_at` is in the future relative to
///    `ctx.now`. Else [`ManifestError::Expired`].
/// 3. **PoP** — verify `proof_of_possession.signature` covers
///    `sha256(challenge)` using the public key encoded in `manifest.aid`.
///    Else [`ManifestError::PopFailed`].
/// 4. **Outer signature** — re-canonicalize the Manifest minus signature
///    via JCS, hash with SHA-256, verify with the same key. Else
///    [`ManifestError::SignatureInvalid`].
/// 5. **Identity-hint shape** — type/subject/issuer/public_key
///    consistency. Else [`ManifestError::IdentityHintMalformed`].
///
/// Identity-proof verification (the actual JWT or pinned-key signature
/// check) does NOT happen here. That's done in the Mutual Handshake using
/// the fresh `payload.identity` field.
pub fn verify_manifest(
    manifest: &Manifest,
    ctx: &VerifyManifestContext,
) -> Result<(), ManifestError> {
    // 1. Version check.
    if manifest.version != "aitp/0.1" {
        return Err(ManifestError::VersionUnknown);
    }

    // 2. Expiry check.
    if manifest.expires_at.is_in_the_past(ctx.now) {
        return Err(ManifestError::Expired);
    }

    // 3. PoP signature check.
    let issuer_pubkey = AitpVerifyingKey::from_aid(&manifest.aid)?;
    let pop_input = Sha256::digest(manifest.proof_of_possession.challenge.as_bytes());
    let pop_sig = Signature::parse(&manifest.proof_of_possession.signature)
        .map_err(|_| ManifestError::PopFailed)?;
    issuer_pubkey
        .verify(&pop_input, &pop_sig)
        .map_err(|_| ManifestError::PopFailed)?;

    // 4. Outer signature check.
    let view = ManifestSigningView {
        version: &manifest.version,
        aid: &manifest.aid,
        display_name: manifest.display_name.as_deref(),
        identity_hint: &manifest.identity_hint,
        handshake_endpoint: &manifest.handshake_endpoint,
        accepted_trust_anchors: &manifest.accepted_trust_anchors,
        accepted_identity_types: &manifest.accepted_identity_types,
        offered_capabilities: &manifest.offered_capabilities,
        required_peer_capabilities: &manifest.required_peer_capabilities,
        proof_of_possession: &manifest.proof_of_possession,
        published_at: &manifest.published_at,
        expires_at: &manifest.expires_at,
        extensions: &manifest.extensions,
    };
    let canonical = jcs::canonicalize_serializable(&view)
        .map_err(|e| ManifestError::Canonicalization(e.to_string()))?;
    let digest = Sha256::digest(&canonical);
    let outer_sig =
        Signature::parse(&manifest.signature).map_err(|_| ManifestError::SignatureInvalid)?;
    issuer_pubkey
        .verify(&digest, &outer_sig)
        .map_err(|_| ManifestError::SignatureInvalid)?;

    // 5. Identity-hint shape check.
    match manifest.identity_hint.kind {
        IdentityHintKind::Oidc => {
            if manifest.identity_hint.issuer.is_none() {
                return Err(ManifestError::IdentityHintMalformed(
                    "oidc requires `issuer`",
                ));
            }
            if manifest.identity_hint.public_key.is_some() {
                return Err(ManifestError::IdentityHintMalformed(
                    "oidc must not include `public_key`",
                ));
            }
        }
        IdentityHintKind::PinnedKey => {
            if manifest.identity_hint.public_key.is_none() {
                return Err(ManifestError::IdentityHintMalformed(
                    "pinned_key requires `public_key`",
                ));
            }
        }
    }

    Ok(())
}
