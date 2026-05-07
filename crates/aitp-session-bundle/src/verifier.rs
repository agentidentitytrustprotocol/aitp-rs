//! Session Trust Bundle verification (RFC-AITP-0010 §5-§6).

use crate::builder::{BundleSigningView, DEFAULT_BUNDLE_VERSION};
use crate::error::SessionBundleError;
use crate::types::SessionTrustBundle;
use aitp_core::{jcs, Aid, Timestamp};
use aitp_crypto::{AitpVerifyingKey, Signature};
use aitp_tct::{verify_tct, TctVerifyContext};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Inputs for [`verify_session_bundle`].
pub struct VerifySessionBundleContext<'a> {
    /// Verifier's own AID. The bundle MUST list this AID in
    /// `participants[]`; otherwise verification returns
    /// [`SessionBundleError::NotMember`].
    pub verifier_aid: &'a Aid,
    /// Current time, for expiry checks.
    pub now: Timestamp,
    /// Optional revocation lookup against the verifier's deny list.
    /// Returns `true` if the JTI is revoked. Per-pair degradation
    /// (RFC-AITP-0010 §6): a revoked participant is dropped from the
    /// active set, but the bundle as a whole remains usable so long
    /// as the verifier's own TCT is still valid.
    pub revocation_check: Option<&'a dyn Fn(&Uuid) -> bool>,
}

/// Outcome of verifying a Session Trust Bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleOutcome {
    /// Every participant TCT verified clean. The full membership set
    /// is usable for coordinator-attested trust.
    Clear {
        /// All AIDs in the bundle.
        active_aids: Vec<Aid>,
    },
    /// At least one participant's TCT was revoked. Their AID is
    /// removed from `active_aids`. The verifier's own AID is still in
    /// the active set (otherwise the bundle is useless to this
    /// verifier and we'd return [`SessionBundleError::NotMember`]
    /// equivalent — but keep this strictly informational; callers
    /// decide policy).
    DegradedSubset {
        /// AIDs whose TCTs verified.
        active_aids: Vec<Aid>,
        /// AIDs whose TCTs were revoked.
        dropped_aids: Vec<Aid>,
    },
}

/// Verify a session bundle.
///
/// Order of checks:
/// 1. `version == "aitp/0.1"`.
/// 2. `expires_at` not in the past.
/// 3. `expires_at == min(participants[*].tct.expires_at)` invariant.
/// 4. Verifier's AID is present in `participants[]`.
/// 5. Outer bundle signature against `coordinator`'s key.
/// 6. Each participant TCT: issuer == coordinator, audience == entry.aid,
///    [`verify_tct`] passes.
/// 7. Per-pair revocation degradation: if any TCT JTI is in the deny
///    list, that participant is dropped from `active_aids`.
pub fn verify_session_bundle(
    bundle: &SessionTrustBundle,
    ctx: &VerifySessionBundleContext<'_>,
) -> Result<BundleOutcome, SessionBundleError> {
    // 1.
    if bundle.version != DEFAULT_BUNDLE_VERSION {
        return Err(SessionBundleError::VersionMismatch);
    }

    // 2.
    if bundle.expires_at.is_in_the_past(ctx.now) {
        return Err(SessionBundleError::Expired);
    }

    if bundle.participants.is_empty() {
        return Err(SessionBundleError::EmptyParticipants);
    }

    // 3.
    let computed_min = bundle
        .participants
        .iter()
        .map(|p| p.tct.expires_at)
        .min_by_key(|t| t.0)
        .ok_or(SessionBundleError::EmptyParticipants)?;
    if computed_min.0 != bundle.expires_at.0 {
        return Err(SessionBundleError::ExpiryWindowInvariant);
    }

    // 4.
    let verifier_present = bundle
        .participants
        .iter()
        .any(|p| &p.aid == ctx.verifier_aid);
    if !verifier_present {
        return Err(SessionBundleError::NotMember);
    }

    // 5. Outer signature.
    let coord_key = AitpVerifyingKey::from_aid(&bundle.coordinator)?;
    let view = BundleSigningView {
        version: &bundle.version,
        session_id: &bundle.session_id,
        coordinator: &bundle.coordinator,
        issued_at: &bundle.issued_at,
        expires_at: &bundle.expires_at,
        participants: &bundle.participants,
    };
    let canonical = jcs::canonicalize_serializable(&view)
        .map_err(|e| SessionBundleError::Canonicalization(e.to_string()))?;
    let digest = Sha256::digest(&canonical);
    let outer_sig =
        Signature::parse(&bundle.signature).map_err(|_| SessionBundleError::InvalidSignature)?;
    coord_key
        .verify(&digest, &outer_sig)
        .map_err(|_| SessionBundleError::InvalidSignature)?;

    // 6. Per-participant TCT verification. The coordinator's pubkey
    // is the issuer's pubkey for every embedded TCT (§3 invariant).
    let mut active = Vec::with_capacity(bundle.participants.len());
    let mut dropped = Vec::new();

    for entry in &bundle.participants {
        // Coordinator is the issuer of every embedded TCT.
        if entry.tct.issuer != bundle.coordinator {
            return Err(SessionBundleError::CoordinatorIssuerMismatch);
        }
        // The bundle redistributes each participant's OWN TCT — so
        // audience MUST be the entry's AID.
        if entry.tct.audience != entry.aid {
            return Err(SessionBundleError::AudienceMismatch);
        }
        // Full TCT verification (issuer signature, expiry, binding).
        let tct_ctx = TctVerifyContext {
            expected_audience: &entry.aid,
            issuer_pubkey: &coord_key,
            now: ctx.now,
            issuer_manifest_expires_at: None,
            revocation_check: None, // applied separately below for §7
        };
        verify_tct(&entry.tct, &tct_ctx).map_err(SessionBundleError::TctVerification)?;

        // 7. Per-pair revocation: drop revoked participants but don't
        // fail the whole bundle.
        let is_revoked = ctx
            .revocation_check
            .map(|check| check(&entry.tct.jti))
            .unwrap_or(false);
        if is_revoked {
            dropped.push(entry.aid.clone());
        } else {
            active.push(entry.aid.clone());
        }
    }

    if dropped.is_empty() {
        Ok(BundleOutcome::Clear {
            active_aids: active,
        })
    } else {
        Ok(BundleOutcome::DegradedSubset {
            active_aids: active,
            dropped_aids: dropped,
        })
    }
}
