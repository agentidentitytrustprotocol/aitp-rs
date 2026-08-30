//! Manifest verification per RFC-AITP-0003 §5.

use crate::builder::ManifestSigningView;
use crate::types::{IdentityHintKind, Manifest, MANIFEST_MEMBERS};
use crate::ManifestError;
use aitp_core::{base64url, check_members, from_serde_error, jcs, Timestamp};
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
/// 1. **Version** — `manifest.version == "aitp/0.2"`. Else
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
    if manifest.version != "aitp/0.2" {
        return Err(ManifestError::VersionUnknown);
    }

    // 2. Expiry check.
    if manifest.expires_at.is_in_the_past(ctx.now) {
        return Err(ManifestError::Expired);
    }

    // Resolve the issuer pubkey early — both the PoP and outer
    // signature verify against it, and the AID parse can fail
    // before either check.
    let issuer_pubkey = AitpVerifyingKey::from_aid(&manifest.aid)?;

    // 3. Outer signature check. Order matters: the spec
    //    conformance fixture `mh-002` corrupts the outer signature
    //    on a manifest whose PoP is also from a non-pinned key,
    //    and expects `MANIFEST_SIGNATURE_INVALID` rather than
    //    `MANIFEST_POP_FAILED` when both checks would fail. Doing
    //    the outer-sig check first surfaces the higher-level error
    //    that matches spec semantics — the manifest body itself
    //    isn't trustworthy, so PoP details are moot.
    let view = ManifestSigningView {
        version: &manifest.version,
        aid: &manifest.aid,
        display_name: manifest.display_name.as_deref(),
        identity_hint: &manifest.identity_hint,
        handshake_endpoint: &manifest.handshake_endpoint,
        accepted_trust_anchors: &manifest.accepted_trust_anchors,
        accepted_identity_types: manifest.accepted_identity_types.as_deref(),
        accepted_signature_algorithms: manifest.accepted_signature_algorithms.as_deref(),
        offered_capabilities: &manifest.offered_capabilities,
        required_peer_capabilities: manifest.required_peer_capabilities.as_deref(),
        proof_of_possession: &manifest.proof_of_possession,
        published_at: &manifest.published_at,
        expires_at: &manifest.expires_at,
        extensions: manifest.extensions.as_ref(),
    };
    let canonical = jcs::canonicalize_serializable(&view)
        .map_err(|e| ManifestError::Canonicalization(e.to_string()))?;
    let digest = Sha256::digest(&canonical);
    let outer_sig =
        Signature::parse(&manifest.signature).map_err(|_| ManifestError::SignatureInvalid)?;
    issuer_pubkey
        .verify(&digest, &outer_sig)
        .map_err(|_| ManifestError::SignatureInvalid)?;

    // 4. PoP signature check. RFC-AITP-0001 §5.4.2: the signing input
    //    for every PoP construction is `sha256(base64url_decode(x))` —
    //    decode the challenge to its raw bytes before hashing.
    let challenge_bytes = base64url::decode_strict(&manifest.proof_of_possession.challenge)
        .map_err(|_| ManifestError::PopFailed)?;
    let pop_input = Sha256::digest(&challenge_bytes);
    let pop_sig = Signature::parse(&manifest.proof_of_possession.signature)
        .map_err(|_| ManifestError::PopFailed)?;
    issuer_pubkey
        .verify(&pop_input, &pop_sig)
        .map_err(|_| ManifestError::PopFailed)?;

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

/// Parse a raw wire-form JSON value into a [`Manifest`], enforcing
/// RFC-AITP-0001 §7's member-set check before typed deserialization.
///
/// RFC-AITP-0003 §5 makes the member-set check **step 2**, ahead of expiry
/// (step 3), PoP (step 4), and signature (step 5). Calling this before
/// [`verify_manifest`] makes that ordering structural: an unknown top-level
/// member is rejected before the manifest is ever deserialized, let alone
/// cryptographically checked.
///
/// `value` may be either shape:
/// - the bare inner Manifest body (what the conformance fixtures and the
///   adapter's `verify_manifest` op supply), or
/// - the `{"manifest": {...}}` HTTP transport wrapper (RFC-AITP-0003 §6.1,
///   [`crate::ManifestEnvelope`]) — detected structurally: no valid Manifest
///   body has a top-level `manifest` key (it is not in [`MANIFEST_MEMBERS`]),
///   so an object with that key is unambiguously the wrapper shape. When
///   present, the wrapper's own member set (`["manifest"]`) is checked
///   first, then the inner body's.
///
/// Order of operations:
/// 1. If wrapped, [`check_members`] the wrapper against `["manifest"]`.
/// 2. [`check_members`] the (unwrapped) body against [`MANIFEST_MEMBERS`] —
///    rejects any top-level member the schema does not declare.
/// 3. `serde_json::from_value` into [`Manifest`].
/// 4. On a residual serde error (which, now that the top-level check has
///    already passed, can only come from a nested closed object —
///    `identity_hint` or `proof_of_possession`), [`from_serde_error`]
///    recovers the offending field name so the caller still gets
///    [`ManifestError::UnknownField`] rather than a generic parse failure.
pub fn parse_manifest_wire(value: &serde_json::Value) -> Result<Manifest, ManifestError> {
    const WRAPPER_MEMBERS: &[&str] = &["manifest"];

    let body = match value.as_object() {
        Some(obj) if obj.contains_key("manifest") => {
            check_members("ManifestEnvelope", value, WRAPPER_MEMBERS)
                .map_err(|e| ManifestError::UnknownField(e.field))?;
            obj.get("manifest").expect("checked contains_key above")
        }
        _ => value,
    };

    check_members("Manifest", body, MANIFEST_MEMBERS)
        .map_err(|e| ManifestError::UnknownField(e.field))?;

    serde_json::from_value(body.clone()).map_err(|e| {
        if let Some(field) = from_serde_error(&e) {
            ManifestError::UnknownField(field)
        } else {
            ManifestError::Malformed(e.to_string())
        }
    })
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
/// - **Absent / not present** (`None`): defaults to `["oidc"]`
///   per the spec's backward-compatibility rule.
/// - **Empty array** (`Some(vec![])`): explicit "accept nothing"
///   — rejects every peer regardless of presented type.
/// - **Non-empty array** (`Some(non_empty)`): peer must present
///   a type from the list.
///
/// `our_identity_type` is `"pinned_key"` or `"oidc"` (RFC-AITP-0002
/// §2 vocabulary).
pub fn check_identity_type_compatibility(
    peer_manifest: &crate::Manifest,
    our_identity_type: &'static str,
) -> Result<(), ManifestError> {
    let allowed: &[String] = match peer_manifest.accepted_identity_types.as_deref() {
        // Absent → spec default ["oidc"].
        None => {
            // Inline a static slice so we don't allocate per call.
            const DEFAULT: [&str; 1] = ["oidc"];
            return if our_identity_type == DEFAULT[0] {
                Ok(())
            } else {
                Err(ManifestError::IncompatibleIdentityType(our_identity_type))
            };
        }
        // Explicit empty → reject every peer.
        Some([]) => {
            return Err(ManifestError::IncompatibleIdentityType(our_identity_type));
        }
        Some(v) => v,
    };
    if !allowed.iter().any(|t| t == our_identity_type) {
        return Err(ManifestError::IncompatibleIdentityType(our_identity_type));
    }
    Ok(())
}
