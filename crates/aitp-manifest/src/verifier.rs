//! Manifest verification per RFC-AITP-0003 §5.

use crate::builder::ManifestSigningView;
use crate::types::{IdentityHintKind, Manifest};
use crate::ManifestError;
use aitp_core::{base64url, jcs, Timestamp};
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
///    `sha256(base64url_decode(challenge))` using the public key encoded
///    in `manifest.aid` (RFC-AITP-0001 §5.4.2 unified signing-input
///    convention; RFC-AITP-0003 §3, §5). The hash input is the raw
///    decoded challenge bytes, NOT the ASCII bytes of the base64url
///    string. Else [`ManifestError::PopFailed`].
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

    // 3. PoP signature check. RFC-AITP-0001 §5.4.2: the signing input
    //    for every PoP construction is `sha256(base64url_decode(x))` —
    //    decode the challenge to its raw bytes before hashing.
    let issuer_pubkey = AitpVerifyingKey::from_aid(&manifest.aid)?;
    let challenge_bytes = base64url::decode_strict(&manifest.proof_of_possession.challenge)
        .map_err(|_| ManifestError::PopFailed)?;
    let pop_input = Sha256::digest(&challenge_bytes);
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

/// Check that `peer_manifest.accepted_identity_types` includes
/// `our_identity_type` (RFC-AITP-0003 §3.2 / §5 step 5).
///
/// Initiators MUST call this after fetching a peer's Manifest and
/// before initiating the Mutual Handshake. Without this check, a
/// pinned-key peer might attempt to present pinned-key identity to a
/// peer that only accepts OIDC, only to be rejected after several
/// round trips (RFC-AITP-0003 §5 step 5 makes the responder reject
/// the HELLO at that point — pre-checking saves the round trips and
/// produces a cleaner error code).
///
/// Field semantics (RFC-AITP-0003 §3.2):
/// - **Absent / not present**: defaults to `["oidc"]` per the
///   spec's backward-compatibility rule.
/// - **Empty array**: explicit "accept nothing" — rejects every
///   peer regardless of presented type.
/// - **Non-empty array**: peer must present a type from the list.
///
/// `our_identity_type` is `"pinned_key"` or `"oidc"` (RFC-AITP-0002
/// §2 vocabulary).
pub fn check_identity_type_compatibility(
    peer_manifest: &crate::Manifest,
    our_identity_type: &'static str,
) -> Result<(), ManifestError> {
    // Per RFC-AITP-0003 §3.2: present-but-empty is a different state
    // from absent. The on-the-wire JSON distinguishes the two; here
    // the type system collapses absent into "Vec::new()". The
    // builder/parser must preserve the distinction (Manifest stores
    // an empty Vec for both states currently). We treat any caller
    // that builds a Manifest with an explicitly empty Vec the same
    // way the wire-format empty array is treated: reject. Callers
    // wanting the absent-default behavior should leave the field at
    // its default of `["oidc"]`.
    if peer_manifest.accepted_identity_types.is_empty() {
        return Err(ManifestError::IncompatibleIdentityType(our_identity_type));
    }
    if !peer_manifest
        .accepted_identity_types
        .iter()
        .any(|t| t == our_identity_type)
    {
        return Err(ManifestError::IncompatibleIdentityType(our_identity_type));
    }
    Ok(())
}
