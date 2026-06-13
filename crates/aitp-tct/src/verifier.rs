//! TCT and grant-voucher verification (RFC-AITP-0005 §7.2 / §8).

use crate::types::{GrantVoucherClaims, TctClaims, VerifiedTct};
use crate::TctError;
use aitp_core::{Aid, Timestamp, PROTOCOL_VERSION};
use aitp_crypto::{jws, AitpVerifyingKey};
use uuid::Uuid;

/// Inputs for verifying a TCT.
///
/// The caller names the expected issuer AID (typically taken from the
/// issuer's verified Manifest); the verifying key and the sole
/// acceptable JWS `alg` are both derived from it, so an unsigned or
/// confused token can neither steer key resolution nor pick its own
/// algorithm. Revocation is pluggable via a callback; pass `None` to
/// skip revocation checking.
pub struct TctVerifyContext<'a> {
    /// The verifier's own AID. The `aud` claim MUST equal this.
    pub expected_audience: &'a Aid,
    /// The issuer's AID. Pins the verifying key, the JWS `alg`, and the
    /// `iss` claim.
    pub issuer: &'a Aid,
    /// Current time, for expiry / freshness checks.
    pub now: Timestamp,
    /// If provided, the TCT's `exp` MUST NOT exceed this value (the
    /// issuer Manifest's `expires_at`). Callers that have resolved the
    /// issuer's Manifest SHOULD supply it; when absent, the verifier
    /// skips this check (RFC-AITP-0005 §10.4: MAY skip when the issuer
    /// Manifest is unavailable).
    pub issuer_manifest_expires_at: Option<Timestamp>,
    /// Optional revocation lookup. Returns `true` if `jti` is revoked.
    pub revocation_check: Option<&'a dyn Fn(&Uuid) -> bool>,
}

impl<'a> TctVerifyContext<'a> {
    /// Build a context with no revocation list and the system clock.
    pub fn now(expected_audience: &'a Aid, issuer: &'a Aid) -> Self {
        Self {
            expected_audience,
            issuer,
            now: Timestamp::now(),
            issuer_manifest_expires_at: None,
            revocation_check: None,
        }
    }
}

/// Verify a TCT compact JWS.
///
/// Verification order (RFC-AITP-0005 §7.2):
///
/// 1. **Strict parse + `typ` + `alg` pin + signature** — delegated to
///    [`jws::verify_compact`]: exactly three non-empty base64url
///    segments, header exactly `{alg, typ}`, `typ` ==
///    `aitp-tct+jwt`, `alg` derived solely from `ctx.issuer`, signature
///    over the exact transmitted bytes. Failures surface as
///    [`TctError::Crypto`] with the specific
///    [`aitp_crypto::CryptoError`] variant
///    (`TypMismatch`/`AlgMismatch`/`JwsMalformed`/`SignatureInvalid`).
/// 2. **Typed claims** — `deny_unknown_fields` deserialization rejects
///    unknown and duplicate claims (`ext` excepted) —
///    [`TctError::ClaimsMalformed`].
/// 3. `ver == "aitp/0.2"` — else [`TctError::VersionUnknown`].
/// 4. `iss == ctx.issuer` — else [`TctError::IssuerMismatch`].
/// 5. `aud == ctx.expected_audience` and `aud == sub` — else
///    [`TctError::AudienceMismatch`].
/// 6. `exp` in the future, `iat` not in the future — else
///    [`TctError::Expired`]; if `ctx.issuer_manifest_expires_at` is
///    `Some`, `exp` MUST NOT exceed it — else
///    [`TctError::ExpiresAfterManifest`].
/// 7. `grants` non-empty — else [`TctError::EmptyGrants`].
/// 8. `cnf.jkt` equals the RFC 7638 thumbprint of the key the `sub` AID
///    encodes — else [`TctError::CnfMalformed`].
/// 9. If `ctx.revocation_check` is `Some`, call it with `jti` — only
///    after every signature check (RFC-AITP-0008 §3.3). If true,
///    [`TctError::Revoked`].
///
/// On success returns the [`VerifiedTct`] (verbatim token + trusted
/// claims).
pub fn verify_tct(token: &str, ctx: &TctVerifyContext<'_>) -> Result<VerifiedTct, TctError> {
    let payload = jws::verify_compact(ctx.issuer, jws::TYP_TCT, token).map_err(TctError::Crypto)?;
    let claims: TctClaims =
        serde_json::from_slice(&payload).map_err(|e| TctError::ClaimsMalformed(e.to_string()))?;

    if claims.ver != PROTOCOL_VERSION {
        return Err(TctError::VersionUnknown);
    }
    if &claims.iss != ctx.issuer {
        return Err(TctError::IssuerMismatch);
    }
    if &claims.aud != ctx.expected_audience {
        return Err(TctError::AudienceMismatch);
    }
    if claims.aud != claims.sub {
        return Err(TctError::AudienceMismatch);
    }
    if claims.exp.is_in_the_past(ctx.now) {
        return Err(TctError::Expired);
    }
    if claims.iat.is_in_the_future(ctx.now) {
        return Err(TctError::Expired);
    }
    if let Some(manifest_expires_at) = ctx.issuer_manifest_expires_at {
        if claims.exp.0 > manifest_expires_at.0 {
            return Err(TctError::ExpiresAfterManifest);
        }
    }
    if claims.grants.is_empty() {
        return Err(TctError::EmptyGrants);
    }

    // §3: the sub AID is authoritative for the bound key; cnf.jkt is
    // its (deliberately redundant) thumbprint. A mismatch means the
    // issuer bound a different key — reject.
    let subject_key = AitpVerifyingKey::from_aid(&claims.sub).map_err(TctError::Crypto)?;
    let expected_jkt = subject_key.to_jwk_thumbprint().map_err(TctError::Crypto)?;
    if claims.cnf.jkt != expected_jkt {
        return Err(TctError::CnfMalformed);
    }

    if let Some(check) = ctx.revocation_check {
        if check(&claims.jti) {
            return Err(TctError::Revoked);
        }
    }

    Ok(VerifiedTct {
        token: token.to_string(),
        claims,
    })
}

/// Verify a grant voucher compact JWS under the voucher issuer's AID.
///
/// Used by the issuer itself during delegation verification
/// (RFC-AITP-0006 §4 step 3 — "A is verifying its own past signature")
/// and by subjects sanity-checking a voucher received in a commit
/// payload. Checks: strict parse / `typ aitp-grant+jwt` / `alg` pin /
/// signature (via [`jws::verify_compact`]), typed claims, `ver`, and
/// `iss == issuer`. Expiry and grant semantics are contextual
/// (delegation verification owns them) and are NOT checked here.
pub fn verify_voucher(token: &str, issuer: &Aid) -> Result<GrantVoucherClaims, TctError> {
    let payload =
        jws::verify_compact(issuer, jws::TYP_GRANT_VOUCHER, token).map_err(TctError::Crypto)?;
    let claims: GrantVoucherClaims =
        serde_json::from_slice(&payload).map_err(|e| TctError::ClaimsMalformed(e.to_string()))?;
    if claims.ver != PROTOCOL_VERSION {
        return Err(TctError::VersionUnknown);
    }
    if &claims.iss != issuer {
        return Err(TctError::IssuerMismatch);
    }
    if claims.grants.is_empty() {
        return Err(TctError::EmptyGrants);
    }
    Ok(claims)
}
