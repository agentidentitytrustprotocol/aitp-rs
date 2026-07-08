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
#[non_exhaustive]
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
    /// Symmetric clock-skew tolerance, in seconds, applied to the `exp`
    /// and `iat` freshness checks. `0` (the default) is strict: a TCT
    /// one second past `exp`, or with `iat` one second in the future, is
    /// rejected. A small positive value (e.g. 5–30s) absorbs benign
    /// clock drift between issuer and verifier without materially
    /// widening the acceptance window. Set via
    /// [`TctVerifyContextBuilder::clock_skew_secs`].
    pub clock_skew_secs: i64,
}

/// Error returned by [`TctVerifyContextBuilder::build`] when a security-
/// relevant check was neither supplied nor explicitly waived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TctVerifyContextError {
    /// Neither a revocation source nor an explicit
    /// [`TctVerifyContextBuilder::accept_unchecked_revocation_dangerous`]
    /// waiver was provided. A verifier with no revocation source
    /// silently accepts revoked-but-unexpired TCTs, so the decision is
    /// mandatory.
    #[error(
        "revocation decision required: call .revocation_check(..) or \
         .accept_unchecked_revocation_dangerous()"
    )]
    RevocationDecisionRequired,
    /// Neither an issuer-Manifest expiry cap nor an explicit
    /// [`TctVerifyContextBuilder::skip_manifest_expiry_cap_dangerous`]
    /// waiver was provided. Without the cap a verifier accepts
    /// arbitrarily long-lived TCTs.
    #[error(
        "manifest-expiry decision required: call .issuer_manifest_expires_at(..) or \
         .skip_manifest_expiry_cap_dangerous()"
    )]
    ManifestCapDecisionRequired,
}

impl<'a> TctVerifyContext<'a> {
    /// Build a context with no revocation list and the system clock.
    ///
    /// This is the **permissive** shortcut: both the revocation check
    /// and the issuer-Manifest expiry cap are skipped. It is convenient
    /// for tests and offline/dev use, but production verifiers SHOULD
    /// use [`Self::builder`] so the two silent-accept surfaces
    /// (revocation, Manifest cap) are explicit decisions rather than
    /// accidental omissions. See RFC-AITP-0005 §10.4 and RFC-AITP-0008.
    pub fn now(expected_audience: &'a Aid, issuer: &'a Aid) -> Self {
        Self {
            expected_audience,
            issuer,
            now: Timestamp::now(),
            issuer_manifest_expires_at: None,
            revocation_check: None,
            clock_skew_secs: 0,
        }
    }

    /// Permissive context with an explicit clock: both the revocation
    /// check and the issuer-Manifest expiry cap are skipped. Convenient
    /// for tests and offline/dev use where the clock is pinned. Production
    /// verifiers SHOULD use [`Self::builder`] so those two silent-accept
    /// surfaces are explicit decisions.
    pub fn permissive_at(expected_audience: &'a Aid, issuer: &'a Aid, now: Timestamp) -> Self {
        Self {
            expected_audience,
            issuer,
            now,
            issuer_manifest_expires_at: None,
            revocation_check: None,
            clock_skew_secs: 0,
        }
    }

    /// Start a strict-by-construction builder. Unlike [`Self::now`], the
    /// resulting [`TctVerifyContextBuilder::build`] refuses to produce a
    /// context until both the revocation source and the issuer-Manifest
    /// expiry cap have been either supplied or explicitly waived with a
    /// `*_dangerous` method — closing the two silent-accept surfaces a
    /// misconfigured verifier would otherwise expose.
    ///
    /// ```
    /// use aitp_tct::TctVerifyContext;
    /// use aitp_core::Timestamp;
    /// use aitp_crypto::AitpSigningKey;
    ///
    /// let audience = AitpSigningKey::from_seed(&[1; 32]).aid().clone();
    /// let issuer = AitpSigningKey::from_seed(&[2; 32]).aid().clone();
    ///
    /// // build() fails until BOTH silent-accept surfaces are decided...
    /// assert!(TctVerifyContext::builder(&audience, &issuer, Timestamp(1_700_000_000))
    ///     .build()
    ///     .is_err());
    ///
    /// // ...here we explicitly waive both (only sound for tests/offline).
    /// let ctx = TctVerifyContext::builder(&audience, &issuer, Timestamp(1_700_000_000))
    ///     .accept_unchecked_revocation_dangerous()
    ///     .skip_manifest_expiry_cap_dangerous()
    ///     .build()
    ///     .expect("both decisions made");
    /// let _ = ctx;
    /// ```
    pub fn builder(
        expected_audience: &'a Aid,
        issuer: &'a Aid,
        now: Timestamp,
    ) -> TctVerifyContextBuilder<'a> {
        TctVerifyContextBuilder {
            expected_audience,
            issuer,
            now,
            issuer_manifest_expires_at: None,
            revocation_check: None,
            clock_skew_secs: 0,
            manifest_cap_decided: false,
            revocation_decided: false,
        }
    }
}

/// Strict builder for [`TctVerifyContext`]. See [`TctVerifyContext::builder`].
pub struct TctVerifyContextBuilder<'a> {
    expected_audience: &'a Aid,
    issuer: &'a Aid,
    now: Timestamp,
    issuer_manifest_expires_at: Option<Timestamp>,
    revocation_check: Option<&'a dyn Fn(&Uuid) -> bool>,
    clock_skew_secs: i64,
    manifest_cap_decided: bool,
    revocation_decided: bool,
}

impl<'a> TctVerifyContextBuilder<'a> {
    /// Supply the issuer Manifest's `expires_at`; the TCT's `exp` must
    /// not exceed it. Satisfies the manifest-cap decision.
    pub fn issuer_manifest_expires_at(mut self, expires_at: Timestamp) -> Self {
        self.issuer_manifest_expires_at = Some(expires_at);
        self.manifest_cap_decided = true;
        self
    }

    /// Explicitly waive the issuer-Manifest expiry cap (e.g. offline
    /// verification where the Manifest is genuinely unavailable,
    /// RFC-AITP-0005 §10.4). Satisfies the manifest-cap decision without
    /// enforcing the bound — **the TCT may then outlive its issuer's
    /// Manifest.**
    pub fn skip_manifest_expiry_cap_dangerous(mut self) -> Self {
        self.issuer_manifest_expires_at = None;
        self.manifest_cap_decided = true;
        self
    }

    /// Supply a revocation lookup (returns `true` if a `jti` is
    /// revoked). Satisfies the revocation decision.
    pub fn revocation_check(mut self, check: &'a dyn Fn(&Uuid) -> bool) -> Self {
        self.revocation_check = Some(check);
        self.revocation_decided = true;
        self
    }

    /// Explicitly accept TCTs without consulting any revocation source.
    /// Satisfies the revocation decision **but a revoked-yet-unexpired
    /// TCT will be accepted.** Only appropriate for dev/offline use.
    pub fn accept_unchecked_revocation_dangerous(mut self) -> Self {
        self.revocation_check = None;
        self.revocation_decided = true;
        self
    }

    /// Set the symmetric clock-skew tolerance (seconds) for the `exp` /
    /// `iat` freshness checks. Defaults to `0` (strict). Negative values
    /// are clamped to `0`.
    pub fn clock_skew_secs(mut self, secs: i64) -> Self {
        self.clock_skew_secs = secs.max(0);
        self
    }

    /// Finalize the context, or error if a required decision is missing.
    pub fn build(self) -> Result<TctVerifyContext<'a>, TctVerifyContextError> {
        if !self.revocation_decided {
            return Err(TctVerifyContextError::RevocationDecisionRequired);
        }
        if !self.manifest_cap_decided {
            return Err(TctVerifyContextError::ManifestCapDecisionRequired);
        }
        Ok(TctVerifyContext {
            expected_audience: self.expected_audience,
            issuer: self.issuer,
            now: self.now,
            issuer_manifest_expires_at: self.issuer_manifest_expires_at,
            revocation_check: self.revocation_check,
            clock_skew_secs: self.clock_skew_secs,
        })
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
    // Freshness checks with symmetric skew tolerance (default 0). A TCT
    // is "expired" only once `now` is past `exp + skew`, and "not yet
    // valid" only once `iat` is beyond `now + skew`.
    let skew = ctx.clock_skew_secs;
    if claims.exp.0 < ctx.now.0.saturating_sub(skew) {
        return Err(TctError::Expired);
    }
    if claims.iat.0 > ctx.now.0.saturating_add(skew) {
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

#[cfg(test)]
mod builder_tests {
    use super::*;
    use aitp_crypto::AitpSigningKey;

    fn aids() -> (aitp_core::Aid, aitp_core::Aid) {
        let a = AitpSigningKey::from_seed(&[0x10; 32]).aid().clone();
        let b = AitpSigningKey::from_seed(&[0x20; 32]).aid().clone();
        (a, b)
    }

    #[test]
    fn build_requires_revocation_decision() {
        let (aud, iss) = aids();
        // `TctVerifyContext` has no `Debug` (fn-pointer field), so match
        // rather than `unwrap_err()`.
        let result = TctVerifyContext::builder(&aud, &iss, Timestamp(1))
            .skip_manifest_expiry_cap_dangerous()
            .build();
        assert!(matches!(
            result,
            Err(TctVerifyContextError::RevocationDecisionRequired)
        ));
    }

    #[test]
    fn build_requires_manifest_cap_decision() {
        let (aud, iss) = aids();
        let result = TctVerifyContext::builder(&aud, &iss, Timestamp(1))
            .accept_unchecked_revocation_dangerous()
            .build();
        assert!(matches!(
            result,
            Err(TctVerifyContextError::ManifestCapDecisionRequired)
        ));
    }

    #[test]
    fn build_succeeds_when_both_decided() {
        let (aud, iss) = aids();
        let ctx = TctVerifyContext::builder(&aud, &iss, Timestamp(42))
            .accept_unchecked_revocation_dangerous()
            .issuer_manifest_expires_at(Timestamp(100))
            .build()
            .expect("both decisions made");
        assert_eq!(ctx.now, Timestamp(42));
        assert_eq!(ctx.issuer_manifest_expires_at, Some(Timestamp(100)));
        assert!(ctx.revocation_check.is_none());
    }

    #[test]
    fn revocation_check_is_threaded_through() {
        let (aud, iss) = aids();
        let deny = |_: &uuid::Uuid| true;
        let ctx = TctVerifyContext::builder(&aud, &iss, Timestamp(1))
            .revocation_check(&deny)
            .skip_manifest_expiry_cap_dangerous()
            .build()
            .unwrap();
        assert!(ctx.revocation_check.is_some());
    }

    #[test]
    fn clock_skew_defaults_to_zero_and_clamps_negatives() {
        let (aud, iss) = aids();
        let strict = TctVerifyContext::permissive_at(&aud, &iss, Timestamp(1));
        assert_eq!(strict.clock_skew_secs, 0);

        let ctx = TctVerifyContext::builder(&aud, &iss, Timestamp(1))
            .accept_unchecked_revocation_dangerous()
            .skip_manifest_expiry_cap_dangerous()
            .clock_skew_secs(-5)
            .build()
            .unwrap();
        assert_eq!(ctx.clock_skew_secs, 0, "negative skew clamps to 0");

        let ctx = TctVerifyContext::builder(&aud, &iss, Timestamp(1))
            .accept_unchecked_revocation_dangerous()
            .skip_manifest_expiry_cap_dangerous()
            .clock_skew_secs(30)
            .build()
            .unwrap();
        assert_eq!(ctx.clock_skew_secs, 30);
    }
}
