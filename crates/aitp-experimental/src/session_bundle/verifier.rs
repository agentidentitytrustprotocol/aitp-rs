//! Session Trust Bundle verification (RFC-AITP-0010 §5-§6).

use crate::session_bundle::builder::{peek_tct_claims, DEFAULT_BUNDLE_VERSION};
use crate::session_bundle::error::SessionBundleError;
use crate::session_bundle::types::SessionTrustBundle;
use aitp::core::{Aid, Timestamp};
use aitp::crypto::{AitpVerifyingKey, Signature};
use aitp::manifest::{verify_manifest, Manifest, ManifestVerifyContext};
use aitp::tct::{verify_tct, TctError, TctVerifyContext};
use uuid::Uuid;

/// How [`verify_session_bundle`] resolves the coordinator's public key
/// (RFC-AITP-0010 §5 step 5).
#[derive(Clone, Copy)]
pub enum CoordinatorKeySource<'a> {
    /// The coordinator's Manifest, as fetched by the caller (for example
    /// with `aitp::transport::ManifestFetcher::fetch`). The verifier
    /// re-runs [`aitp::manifest::verify_manifest`] on it (RFC-AITP-0003 §5),
    /// requires `manifest.aid == bundle.coordinator`, and resolves the key
    /// from `manifest.aid`. The Manifest's `expires_at` also caps every
    /// embedded TCT's `exp` (RFC-AITP-0005 §10.4), since the coordinator
    /// is their issuer.
    Manifest(&'a Manifest),
    /// Skip the Manifest step and derive the key from the
    /// `bundle.coordinator` AID alone. **Not RFC-AITP-0010 §5 step 5
    /// conformant**: nothing establishes that the coordinator publishes a
    /// valid, unexpired Manifest. Only for callers that pin the
    /// coordinator out of band and have no Manifest to hand (offline
    /// verification, tests). The conformance adapter and the language
    /// bindings never use it: they require the coordinator's Manifest.
    UnverifiedAidDangerous,
}

/// Inputs for [`verify_session_bundle`].
pub struct SessionBundleVerifyContext<'a> {
    /// Verifier's own AID. The bundle MUST list this AID in
    /// `participants[]`; otherwise verification returns
    /// [`SessionBundleError::NotMember`].
    pub verifier_aid: &'a Aid,
    /// Current time, for expiry checks.
    pub now: Timestamp,
    /// Optional revocation lookup against the verifier's deny list.
    /// Returns `true` if the JTI is revoked. Per-pair degradation
    /// (RFC-AITP-0010 §7): a revoked participant is dropped from the
    /// active set, but the bundle as a whole remains usable so long
    /// as the verifier's own TCT is still valid.
    pub revocation_check: Option<&'a dyn Fn(&Uuid) -> bool>,
    /// Where the coordinator's key comes from (§5 step 5).
    pub coordinator_key: CoordinatorKeySource<'a>,
    /// Accept a coordinator Manifest whose `handshake_endpoint` is plain
    /// `http://localhost` or `http://127.0.0.1`, for local development.
    /// Off in production.
    pub insecure_localhost_dangerous: bool,
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

/// Verify a session bundle, in RFC-AITP-0010 §5 order:
///
/// 0. Member-set check — done by the wire parser
///    ([`crate::session_bundle::parse_session_bundle_wire`]) before this runs.
/// 1. `version == "aitp/0.3"`.
/// 2. `expires_at` not in the past.
/// 3. `expires_at == min(participants[*].tct.exp)` invariant. Vacuous on
///    an empty `participants` array (there is no minimum to exceed), so
///    an empty bundle is reported by step 4.
/// 4. `participants` non-empty.
/// 5. Coordinator key resolution per [`CoordinatorKeySource`]: verify
///    the coordinator's Manifest (RFC-AITP-0003 §5) and resolve the key
///    from `manifest.aid`.
/// 6. Outer bundle signature against that key.
/// 7. Each participant TCT: issuer == coordinator, audience == entry.aid,
///    [`verify_tct`] passes. Per-pair revocation (§7): a revoked TCT's
///    participant is dropped from `active_aids`, not an error.
/// 8. Verifier's AID is present in `participants[]` (its TCT's `aud`
///    was pinned to that AID in step 7).
pub fn verify_session_bundle(
    bundle: &SessionTrustBundle,
    ctx: &SessionBundleVerifyContext<'_>,
) -> Result<BundleOutcome, SessionBundleError> {
    // 1.
    if bundle.version != DEFAULT_BUNDLE_VERSION {
        return Err(SessionBundleError::VersionMismatch);
    }

    // 2.
    if bundle.expires_at.is_in_the_past(ctx.now) {
        return Err(SessionBundleError::Expired);
    }

    // 3. Expiry-window invariant against the (still-unverified) claim
    // peeks — the embedded token strings become coordinator-attested
    // once the outer signature verifies in step 6, and each is then
    // fully verified in step 7.
    let mut computed_min: Option<Timestamp> = None;
    for p in &bundle.participants {
        let exp = peek_tct_claims(&p.tct)?.exp;
        computed_min = Some(match computed_min {
            Some(m) if m.0 <= exp.0 => m,
            _ => exp,
        });
    }
    if let Some(computed_min) = computed_min {
        if computed_min.0 != bundle.expires_at.0 {
            return Err(SessionBundleError::ExpiryWindowInvariant);
        }
    }

    // 4.
    if bundle.participants.is_empty() {
        return Err(SessionBundleError::EmptyParticipants);
    }

    // 5. Coordinator key resolution.
    let (coord_key, coordinator_manifest_expires_at) = match ctx.coordinator_key {
        CoordinatorKeySource::Manifest(manifest) => {
            let mut manifest_ctx = ManifestVerifyContext::at(ctx.now);
            if ctx.insecure_localhost_dangerous {
                manifest_ctx = manifest_ctx.with_insecure_localhost_dangerous();
            }
            verify_manifest(manifest, &manifest_ctx)
                .map_err(SessionBundleError::CoordinatorManifest)?;
            if manifest.aid != bundle.coordinator {
                return Err(SessionBundleError::CoordinatorManifestMismatch);
            }
            (
                AitpVerifyingKey::from_aid(&manifest.aid)?,
                Some(manifest.expires_at),
            )
        }
        CoordinatorKeySource::UnverifiedAidDangerous => {
            (AitpVerifyingKey::from_aid(&bundle.coordinator)?, None)
        }
    };

    // 6. Outer signature.
    let canonical = crate::session_bundle::builder::bundle_signing_bytes(
        &crate::session_bundle::builder::BundleSigningBody {
            version: &bundle.version,
            session_id: &bundle.session_id,
            coordinator: &bundle.coordinator,
            issued_at: &bundle.issued_at,
            expires_at: &bundle.expires_at,
            participants: &bundle.participants,
            extensions: bundle.extensions.as_ref(),
        },
    )?;
    let digest = aitp::crypto::Digest32::sha256(&canonical);
    let outer_sig =
        Signature::parse(&bundle.signature).map_err(|_| SessionBundleError::InvalidSignature)?;
    coord_key
        .verify_jcs(&digest, &outer_sig)
        .map_err(|_| SessionBundleError::InvalidSignature)?;

    // 7. Per-participant TCT verification. The coordinator's pubkey
    // is the issuer's pubkey for every embedded TCT (§3 invariant).
    let mut active = Vec::with_capacity(bundle.participants.len());
    let mut dropped = Vec::new();

    for entry in &bundle.participants {
        // Full TCT verification (typ, alg pin, signature, claims).
        // `verify_tct` pins the issuer to the coordinator's AID and
        // the audience to the entry's AID — the §3 invariants surface
        // as the bundle-specific error codes below.
        let tct_ctx = TctVerifyContext::builder().expected_audience(&entry.aid).issuer(&bundle.coordinator).now(ctx.now)
            // §7 per-pair revocation is applied separately below, after
            // signature verification (RFC-AITP-0008 §3.3 ordering).
            .revocation(aitp::tct::RevocationSource::FailOpen);
        // The coordinator issued every embedded TCT, so its verified
        // Manifest's `expires_at` is the issuer-Manifest cap. Without a
        // Manifest (`UnverifiedAidDangerous`) the cap cannot apply; the
        // bundle's own expiry-window invariant still bounds lifetimes.
        let tct_ctx = match coordinator_manifest_expires_at {
            Some(expires_at) => tct_ctx.issuer_manifest_expires_at(expires_at),
            None => tct_ctx.skip_manifest_expiry_cap_dangerous(),
        }
        .build()
        .expect("both verify decisions are made above");
        let verified = match verify_tct(&entry.tct, &tct_ctx) {
            Ok(v) => v,
            Err(TctError::IssuerMismatch) => {
                return Err(SessionBundleError::CoordinatorIssuerMismatch)
            }
            Err(TctError::AudienceMismatch) => return Err(SessionBundleError::AudienceMismatch),
            Err(e) => return Err(SessionBundleError::TctVerification(e)),
        };

        // Per-pair revocation (§7): drop revoked participants but don't
        // fail the whole bundle.
        let is_revoked = ctx
            .revocation_check
            .map(|check| check(&verified.claims().jti))
            .unwrap_or(false);
        if is_revoked {
            dropped.push(entry.aid.clone());
        } else {
            active.push(entry.aid.clone());
        }
    }

    // 8. Self-membership, last: every embedded TCT has verified, and
    // step 7 pinned each one's `aud` to its entry's AID.
    let verifier_present = bundle
        .participants
        .iter()
        .any(|p| &p.aid == ctx.verifier_aid);
    if !verifier_present {
        return Err(SessionBundleError::NotMember);
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
