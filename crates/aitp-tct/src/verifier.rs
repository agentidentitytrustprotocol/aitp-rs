//! TCT verification (RFC-AITP-0005 §9).

use crate::builder::TctSigningView;
use crate::types::Tct;
use crate::TctError;
use aitp_core::{base64url, jcs, Aid, Timestamp};
use aitp_crypto::{AitpVerifyingKey, Signature};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Inputs for verifying a TCT.
///
/// The caller resolves the issuer's public key (typically from the
/// issuer's Manifest) and provides it here. Revocation is pluggable via a
/// callback; pass `None` to skip revocation checking.
pub struct TctVerifyContext<'a> {
    /// The verifier's own AID. `tct.audience` MUST equal this.
    pub expected_audience: &'a Aid,
    /// The issuer's verifying key.
    pub issuer_pubkey: &'a AitpVerifyingKey,
    /// Current time, for expiry / freshness checks.
    pub now: Timestamp,
    /// Optional revocation lookup. Returns `true` if `jti` is revoked.
    pub revocation_check: Option<&'a dyn Fn(&Uuid) -> bool>,
}

impl<'a> TctVerifyContext<'a> {
    /// Build a context with no revocation list and the system clock.
    pub fn now(expected_audience: &'a Aid, issuer_pubkey: &'a AitpVerifyingKey) -> Self {
        Self {
            expected_audience,
            issuer_pubkey,
            now: Timestamp::now(),
            revocation_check: None,
        }
    }
}

/// Verify a TCT.
///
/// Verification order (RFC-AITP-0005 §9):
///
/// 1. `version == "aitp/0.1"` — else [`TctError::VersionUnknown`].
/// 2. `audience == ctx.expected_audience` — else [`TctError::AudienceMismatch`].
/// 3. v0.1 invariant: `audience == subject` — else [`TctError::AudienceMismatch`].
/// 4. `expires_at` in the future and `issued_at` not in the future —
///    else [`TctError::Expired`].
/// 5. `grants` non-empty — else [`TctError::EmptyGrants`].
/// 6. `binding.cnf` is 43-char base64url decoding to 32 bytes — else
///    [`TctError::CnfMalformed`].
/// 7. JCS-canonicalize the TCT minus signature. SHA-256. Verify with
///    `ctx.issuer_pubkey`. Else [`TctError::SignatureInvalid`].
/// 8. If `ctx.revocation_check` is `Some`, call it with `tct.jti`. If
///    true, [`TctError::Revoked`].
///
/// On success returns a reference to the verified TCT.
pub fn verify_tct<'a>(tct: &'a Tct, ctx: &TctVerifyContext<'_>) -> Result<&'a Tct, TctError> {
    if tct.version != "aitp/0.1" {
        return Err(TctError::VersionUnknown);
    }
    if &tct.audience != ctx.expected_audience {
        return Err(TctError::AudienceMismatch);
    }
    if tct.audience != tct.subject {
        return Err(TctError::AudienceMismatch);
    }
    if tct.expires_at.is_in_the_past(ctx.now) {
        return Err(TctError::Expired);
    }
    if tct.issued_at.is_in_the_future(ctx.now) {
        return Err(TctError::Expired);
    }
    if tct.grants.is_empty() {
        return Err(TctError::EmptyGrants);
    }

    let cnf_bytes =
        base64url::decode_strict(&tct.binding.cnf).map_err(|_| TctError::CnfMalformed)?;
    if cnf_bytes.len() != 32 {
        return Err(TctError::CnfMalformed);
    }

    let view = TctSigningView {
        version: &tct.version,
        jti: &tct.jti,
        issuer: &tct.issuer,
        subject: &tct.subject,
        audience: &tct.audience,
        issued_at: &tct.issued_at,
        expires_at: &tct.expires_at,
        grants: &tct.grants,
        binding: &tct.binding,
    };
    let canonical = jcs::canonicalize_serializable(&view)
        .map_err(|e| TctError::Canonicalization(e.to_string()))?;
    let digest = Sha256::digest(&canonical);
    let sig = Signature::parse(&tct.signature).map_err(|_| TctError::SignatureInvalid)?;
    ctx.issuer_pubkey
        .verify(&digest, &sig)
        .map_err(|_| TctError::SignatureInvalid)?;

    if let Some(check) = ctx.revocation_check {
        if check(&tct.jti) {
            return Err(TctError::Revoked);
        }
    }

    Ok(tct)
}
