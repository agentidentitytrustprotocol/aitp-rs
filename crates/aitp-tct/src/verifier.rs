//! TCT and grant-voucher verification (RFC-AITP-0005 §7.2 / §8).

use crate::types::{
    GrantVoucherClaims, TctClaims, VerifiedTct, GRANT_VOUCHER_CLAIMS_MEMBERS, TCT_CLAIMS_MEMBERS,
};
use crate::TctError;
use aitp_core::{
    check_members, from_serde_error, reject_duplicate_keys, Aid, Timestamp, PROTOCOL_VERSION,
};
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

/// Best-effort, **unverified** peek at a compact JWS's header `typ`
/// member — no signature, no `alg` check, not even confirmation the
/// header is a well-formed two-member object.
///
/// The sole purpose is to gate the pre-signature claim-set check in
/// [`verify_tct`] / [`verify_voucher`] so that a type-confused token
/// (RFC-AITP-0005 §7.2 step 2 — e.g. tct-010's grant voucher presented
/// as a TCT) is diagnosed by the authoritative, fully-checked `typ`
/// enforcement inside [`jws::verify_compact`] as `TypMismatch`, rather
/// than by this crate's claim-set check misreporting an unrelated
/// artifact's differently-shaped claims as an unknown field. Returns
/// `None` on any decode/parse failure or a missing/non-string `typ` —
/// callers must treat `None` the same as a mismatch (skip the peek-gated
/// check) and let the full, verified path make the final call either
/// way; this function's opinion is never trusted for anything but that
/// gate.
pub(crate) fn peek_header_typ(token: &str) -> Option<String> {
    jws::peek_typ(token)
}

/// Verify a TCT compact JWS.
///
/// Verification order (RFC-AITP-0005 §7.2):
///
/// 1. **`typ` (unverified peek)** — RFC-AITP-0005 §7.2 step 2 enforces
///    header `typ` == `aitp-tct+jwt` ahead of claims checks (tct-010: a
///    valid grant voucher, `typ aitp-grant+jwt`, presented as a TCT MUST
///    report `TOKEN_TYP_MISMATCH`, not an unrelated claims defect, even
///    though voucher claims carry `src_jti`, which is not a member of
///    [`TCT_CLAIMS_MEMBERS`]). `peek_header_typ` reads the header
///    unverified purely to gate step 2 below; a mismatch (or a peek that
///    fails to parse at all) skips step 2 and defers straight to
///    [`jws::verify_compact`], which performs the authoritative,
///    exactly-once `typ` check.
/// 2. **Claim-set check (unverified peek), gated on step 1** — once the
///    peeked `typ` matches, the decoded JWS payload's top-level JSON
///    members are checked against [`TCT_CLAIMS_MEMBERS`] (RFC-AITP-0001
///    §7) via [`jws::decode_payload_unverified`], still **before** AID-
///    pinned `alg` checking or signature verification. A reject decision
///    drawn from unverified bytes is sound — no trust is ever extended
///    on the strength of it — and it makes the ordering structural: an
///    unknown claim outranks even a corrupt signature (once past the
///    `typ` gate). Failures surface as [`TctError::UnknownField`]. A
///    payload that isn't valid JSON at this stage is left for step 3 to
///    diagnose.
/// 3. **Strict parse + `typ` + `alg` pin + signature** — delegated to
///    [`jws::verify_compact`]: exactly three non-empty base64url
///    segments, header exactly `{alg, typ}`, `typ` ==
///    `aitp-tct+jwt`, `alg` derived solely from `ctx.issuer`, signature
///    over the exact transmitted bytes. Failures surface as
///    [`TctError::Crypto`] with the specific
///    [`aitp_crypto::CryptoError`] variant
///    (`TypMismatch`/`AlgMismatch`/`JwsMalformed`/`SignatureInvalid`).
/// 4. **Typed claims** — `deny_unknown_fields` deserialization rejects
///    unknown and duplicate claims (`ext` excepted) —
///    [`TctError::ClaimsMalformed`], or [`TctError::UnknownField`] if the
///    residual serde error is a nested closed object's (`cnf`) unknown
///    member, recovered via [`from_serde_error`].
/// 5. `ver == "aitp/0.2"` — else [`TctError::VersionUnknown`].
/// 6. `iss == ctx.issuer` — else [`TctError::IssuerMismatch`].
/// 7. `aud == ctx.expected_audience` and `aud == sub` — else
///    [`TctError::AudienceMismatch`].
/// 8. `exp` in the future, `iat` not in the future — else
///    [`TctError::Expired`]; if `ctx.issuer_manifest_expires_at` is
///    `Some`, `exp` MUST NOT exceed it — else
///    [`TctError::ExpiresAfterManifest`].
/// 9. `grants` non-empty — else [`TctError::EmptyGrants`].
/// 10. `cnf.jkt` equals the RFC 7638 thumbprint of the key the `sub` AID
///     encodes — else [`TctError::CnfMalformed`].
/// 11. If `ctx.revocation_check` is `Some`, call it with `jti` — only
///     after every signature check (RFC-AITP-0008 §3.3). If true,
///     [`TctError::Revoked`].
///
/// On success returns the [`VerifiedTct`] (verbatim token + trusted
/// claims).
pub fn verify_tct(token: &str, ctx: &TctVerifyContext<'_>) -> Result<VerifiedTct, TctError> {
    // Steps 1-2: claim-set check on the unverified peek, gated on the
    // peeked typ matching — structurally ahead of alg/signature, but
    // never ahead of the typ check itself (tct-010; RFC-AITP-0005 §7.2).
    // A payload that fails to parse as JSON here is not this check's
    // problem; `verify_compact` below still rejects it, just under its
    // own crypto/parse error.
    if peek_header_typ(token).as_deref() == Some(jws::TYP_TCT) {
        let peek = jws::decode_payload_unverified(token).map_err(TctError::Crypto)?;
        // RFC-AITP-0001 §5.4.5 / issue #140: this peek's own `Value` step
        // is last-write-wins on a duplicate key, so the raw-bytes check
        // must run first, against `peek` itself.
        reject_duplicate_keys(&peek).map_err(TctError::ClaimsMalformed)?;
        if let Ok(peek_value) = serde_json::from_slice::<serde_json::Value>(&peek) {
            check_members("TctClaims", &peek_value, TCT_CLAIMS_MEMBERS)
                .map_err(|e| TctError::UnknownField(e.field))?;
        }
    }

    let payload = jws::verify_compact(ctx.issuer, jws::TYP_TCT, token).map_err(TctError::Crypto)?;
    let claims: TctClaims = serde_json::from_slice(&payload).map_err(|e| {
        if let Some(field) = from_serde_error(&e) {
            TctError::UnknownField(field)
        } else {
            TctError::ClaimsMalformed(e.to_string())
        }
    })?;

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
/// payload. Checks (RFC-AITP-0005 §7.2): a claim-set check against
/// [`GRANT_VOUCHER_CLAIMS_MEMBERS`] on the unverified payload peek,
/// structurally ahead of `typ`/`alg`/signature (same ordering rationale
/// as [`verify_tct`]); strict parse / `typ aitp-grant+jwt` / `alg` pin /
/// signature (via [`jws::verify_compact`]); typed claims; `ver`; and
/// `iss == issuer`. Expiry and grant semantics are contextual
/// (delegation verification owns them) and are NOT checked here.
pub fn verify_voucher(token: &str, issuer: &Aid) -> Result<GrantVoucherClaims, TctError> {
    // Same typ-gated ordering as `verify_tct` (RFC-AITP-0005 §7.2 step 2
    // ahead of the claim-set check): a TCT (or any other artifact whose
    // claims aren't voucher-shaped) presented where a voucher is expected
    // must be diagnosed by the authoritative `typ` check below, not
    // misreported as an unrelated unknown claim.
    if peek_header_typ(token).as_deref() == Some(jws::TYP_GRANT_VOUCHER) {
        let peek = jws::decode_payload_unverified(token).map_err(TctError::Crypto)?;
        // RFC-AITP-0001 §5.4.5 / issue #140: same raw-bytes-first
        // rationale as `verify_tct`'s peek above.
        reject_duplicate_keys(&peek).map_err(TctError::ClaimsMalformed)?;
        if let Ok(peek_value) = serde_json::from_slice::<serde_json::Value>(&peek) {
            check_members(
                "GrantVoucherClaims",
                &peek_value,
                GRANT_VOUCHER_CLAIMS_MEMBERS,
            )
            .map_err(|e| TctError::UnknownField(e.field))?;
        }
    }

    let payload =
        jws::verify_compact(issuer, jws::TYP_GRANT_VOUCHER, token).map_err(TctError::Crypto)?;
    let claims: GrantVoucherClaims = serde_json::from_slice(&payload).map_err(|e| {
        if let Some(field) = from_serde_error(&e) {
            TctError::UnknownField(field)
        } else {
            TctError::ClaimsMalformed(e.to_string())
        }
    })?;
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

/// Claim-set check tests (RFC-AITP-0001 §7 / RFC-AITP-0005 §7.2, issue
/// #140 Phase 6a). Builds claims manually with [`jws::sign_compact`]
/// (rather than [`crate::TctBuilder`], which hardcodes `ext: None` with
/// no setter — a producer-side gap orthogonal to this verifier work) so
/// tests can inject an unknown top-level claim, a junk key inside `ext`,
/// or a corrupted signature.
#[cfg(test)]
mod claim_set_tests {
    use super::*;
    use aitp_crypto::AitpSigningKey;
    use serde_json::json;

    fn issuer_subject() -> (AitpSigningKey, AitpSigningKey) {
        (
            AitpSigningKey::from_seed(&[0x50; 32]),
            AitpSigningKey::from_seed(&[0x51; 32]),
        )
    }

    fn base_tct_claims(issuer: &AitpSigningKey, subject: &AitpSigningKey) -> serde_json::Value {
        let jkt = subject.verifying_key().to_jwk_thumbprint().unwrap();
        json!({
            "ver": "aitp/0.2",
            "jti": "550e8400-e29b-41d4-a716-446655440000",
            "iss": issuer.aid().as_str(),
            "sub": subject.aid().as_str(),
            "aud": subject.aid().as_str(),
            "iat": 1_700_000_000,
            "exp": 1_700_003_600,
            "grants": ["demo.echo"],
            "cnf": { "jkt": jkt },
        })
    }

    fn base_voucher_claims(issuer: &AitpSigningKey, subject: &AitpSigningKey) -> serde_json::Value {
        json!({
            "ver": "aitp/0.2",
            "iss": issuer.aid().as_str(),
            "sub": subject.aid().as_str(),
            "grants": ["demo.echo"],
            "iat": 1_700_000_000,
            "exp": 1_700_003_600,
            "src_jti": "550e8400-e29b-41d4-a716-446655440000",
        })
    }

    fn permissive_ctx<'a>(
        issuer: &'a aitp_core::Aid,
        subject: &'a aitp_core::Aid,
    ) -> TctVerifyContext<'a> {
        TctVerifyContext::permissive_at(subject, issuer, Timestamp(1_700_000_100))
    }

    /// Flip the first character of the signature segment — invalidates
    /// the signature while keeping the compact-JWS shape intact.
    fn corrupt_signature(token: &str) -> String {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "expected a 3-segment compact JWS");
        let mut sig_chars: Vec<char> = parts[2].chars().collect();
        sig_chars[0] = if sig_chars[0] == 'A' { 'B' } else { 'A' };
        let corrupted: String = sig_chars.into_iter().collect();
        format!("{}.{}.{}", parts[0], parts[1], corrupted)
    }

    // ---- AC3: unknown claim rejected before signature verification ----

    #[test]
    fn tct_unknown_claim_rejected_even_with_corrupted_signature() {
        let (issuer, subject) = issuer_subject();
        let mut claims = base_tct_claims(&issuer, &subject);
        claims
            .as_object_mut()
            .unwrap()
            .insert("rogue".into(), json!("nope"));
        let token = jws::sign_compact(&issuer, jws::TYP_TCT, &claims).unwrap();
        let bad_sig_token = corrupt_signature(&token);

        let ctx = permissive_ctx(issuer.aid(), subject.aid());
        let err = verify_tct(&bad_sig_token, &ctx).unwrap_err();
        assert!(
            matches!(&err, TctError::UnknownField(f) if f == "rogue"),
            "expected UnknownField(\"rogue\") ahead of the corrupted signature, got {err:?}"
        );
    }

    #[test]
    fn voucher_unknown_claim_rejected_even_with_corrupted_signature() {
        let (issuer, subject) = issuer_subject();
        let mut claims = base_voucher_claims(&issuer, &subject);
        claims
            .as_object_mut()
            .unwrap()
            .insert("rogue".into(), json!(1));
        let token = jws::sign_compact(&issuer, jws::TYP_GRANT_VOUCHER, &claims).unwrap();
        let bad_sig_token = corrupt_signature(&token);

        let err = verify_voucher(&bad_sig_token, issuer.aid()).unwrap_err();
        assert!(
            matches!(&err, TctError::UnknownField(f) if f == "rogue"),
            "expected UnknownField(\"rogue\") ahead of the corrupted signature, got {err:?}"
        );
    }

    // ---- issue #140: duplicate claim rejected before signature verification ----

    /// Inject a raw-text duplicate of `key` right after the payload's
    /// opening `{` — a defect no `serde_json::Value` can even represent,
    /// which is exactly the point. The signature is left untouched, so it
    /// no longer matches the (now different) payload bytes; that must
    /// not matter, since the duplicate-key guard runs on the unverified
    /// peek, ahead of signature verification.
    fn inject_duplicate_key_into_payload(
        token: &str,
        key: &str,
        value: &serde_json::Value,
    ) -> String {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "expected a 3-segment compact JWS");
        let payload_bytes = aitp_core::base64url::decode_strict(parts[1]).unwrap();
        let payload_str = std::str::from_utf8(&payload_bytes).unwrap();
        assert!(
            payload_str.starts_with('{'),
            "expected a JSON object payload"
        );
        let dup = format!(
            "\"{key}\":{},",
            serde_json::to_string(value).expect("serializable")
        );
        let tampered_payload = format!("{{{dup}{}", &payload_str[1..]);
        let tampered_payload_b64 = aitp_core::base64url::encode(tampered_payload.as_bytes());
        format!("{}.{}.{}", parts[0], tampered_payload_b64, parts[2])
    }

    #[test]
    fn tct_duplicate_claim_rejected_even_with_now_invalid_signature() {
        let (issuer, subject) = issuer_subject();
        let claims = base_tct_claims(&issuer, &subject);
        let token = jws::sign_compact(&issuer, jws::TYP_TCT, &claims).unwrap();
        let dup_token = inject_duplicate_key_into_payload(&token, "ver", &claims["ver"]);

        let ctx = permissive_ctx(issuer.aid(), subject.aid());
        let err = verify_tct(&dup_token, &ctx).unwrap_err();
        assert!(
            matches!(&err, TctError::ClaimsMalformed(m) if m.contains("duplicate field `ver`")),
            "expected ClaimsMalformed(duplicate field `ver`) ahead of the now-invalid \
             signature, got {err:?}"
        );
    }

    #[test]
    fn voucher_duplicate_claim_rejected_even_with_now_invalid_signature() {
        let (issuer, subject) = issuer_subject();
        let claims = base_voucher_claims(&issuer, &subject);
        let token = jws::sign_compact(&issuer, jws::TYP_GRANT_VOUCHER, &claims).unwrap();
        let dup_token = inject_duplicate_key_into_payload(&token, "ver", &claims["ver"]);

        let err = verify_voucher(&dup_token, issuer.aid()).unwrap_err();
        assert!(
            matches!(&err, TctError::ClaimsMalformed(m) if m.contains("duplicate field `ver`")),
            "expected ClaimsMalformed(duplicate field `ver`) ahead of the now-invalid \
             signature, got {err:?}"
        );
    }

    // ---- AC4: junk key inside `ext` is accepted ----

    #[test]
    fn tct_junk_key_inside_ext_is_accepted() {
        let (issuer, subject) = issuer_subject();
        let mut claims = base_tct_claims(&issuer, &subject);
        claims
            .as_object_mut()
            .unwrap()
            .insert("ext".into(), json!({"x-junk": {"anything": true}}));
        let token = jws::sign_compact(&issuer, jws::TYP_TCT, &claims).unwrap();

        let ctx = permissive_ctx(issuer.aid(), subject.aid());
        let verified = verify_tct(&token, &ctx).expect("junk key inside ext must be accepted");
        assert!(verified
            .claims
            .ext
            .expect("ext must round-trip")
            .contains_key("x-junk"));
    }

    #[test]
    fn voucher_junk_key_inside_ext_is_accepted() {
        let (issuer, subject) = issuer_subject();
        let mut claims = base_voucher_claims(&issuer, &subject);
        claims
            .as_object_mut()
            .unwrap()
            .insert("ext".into(), json!({"x-junk": 1}));
        let token = jws::sign_compact(&issuer, jws::TYP_GRANT_VOUCHER, &claims).unwrap();

        let claims_out =
            verify_voucher(&token, issuer.aid()).expect("junk key inside ext must be accepted");
        assert!(claims_out
            .ext
            .expect("ext must round-trip")
            .contains_key("x-junk"));
    }

    // ---- AC7: protected-header failures are unchanged, never UNKNOWN_FIELD ----

    #[test]
    fn tct_header_unknown_member_keeps_crypto_code_not_unknown_field() {
        let (issuer, subject) = issuer_subject();
        let claims = base_tct_claims(&issuer, &subject);
        let token = jws::sign_compact(&issuer, jws::TYP_TCT, &claims).unwrap();
        let (_, rest) = token.split_once('.').unwrap();
        let evil_header =
            aitp_core::base64url::encode(br#"{"alg":"EdDSA","typ":"aitp-tct+jwt","kid":"x"}"#);
        let evil_token = format!("{evil_header}.{rest}");

        let ctx = permissive_ctx(issuer.aid(), subject.aid());
        let err = verify_tct(&evil_token, &ctx).unwrap_err();
        assert!(
            matches!(
                &err,
                TctError::Crypto(aitp_crypto::CryptoError::JwsMalformed(_))
            ),
            "an unknown protected-header member must keep its existing crypto/parse code, \
             never UNKNOWN_FIELD; got {err:?}"
        );
    }

    // ---- typ-confusion outranks the claim-set check (tct-010) ----

    /// A grant voucher's claims carry `src_jti`, which is not a member of
    /// [`TCT_CLAIMS_MEMBERS`] — but presenting a valid voucher where a TCT
    /// is expected must be diagnosed as `TypMismatch` (RFC-AITP-0005 §7.2
    /// step 2), never misreported as `UnknownField("src_jti")`. This is
    /// exactly the conformance corpus's tct-010 shape, pinned here at the
    /// library level too.
    #[test]
    fn voucher_typ_presented_as_tct_reports_typ_mismatch_not_unknown_field() {
        let (issuer, subject) = issuer_subject();
        let voucher_claims = base_voucher_claims(&issuer, &subject);
        let voucher_token = jws::sign_compact(&issuer, jws::TYP_GRANT_VOUCHER, &voucher_claims)
            .expect("sign voucher");

        let ctx = permissive_ctx(issuer.aid(), subject.aid());
        let err = verify_tct(&voucher_token, &ctx).unwrap_err();
        assert!(
            matches!(
                err,
                TctError::Crypto(aitp_crypto::CryptoError::TypMismatch { .. })
            ),
            "got {err:?}"
        );
    }
}
