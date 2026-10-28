//! Issuer side of TCT renewal (RFC-AITP-0013 §4, §6).

use crate::renewal::peek::{decode_renewal_nonce, peek_claims};
use crate::renewal::{
    renewal_pop_input, RenewalError, RenewalErrorPayload, RenewalResponsePayload, TctRenewalPayload,
};
use aitp::__private::reject_duplicate_keys;
use aitp::core::nonce_store::{IssuedNonce, NonceStore, NonceStoreError};
use aitp::core::{Aid, AitpEnvelope, ErrorCode, MessageType, Timestamp};
use aitp::crypto::{AitpSigner, AitpVerifyingKey, Digest32, Signature};
use aitp::envelope::sign_envelope_with;
use aitp::tct::{
    verify_tct, IssuedTct, RevocationSource, TctBuilder, TctError, TctVerifyContext,
    DEFAULT_TCT_TTL,
};
use uuid::Uuid;

/// Parse a renewal request body (RFC-AITP-0013 §4 step 1): a JSON object
/// with exactly `current_tct`, `pop_nonce` and `pop_signature`, each a
/// string, and no repeated key. Anything else is
/// [`RenewalError::RequestMalformed`] (`POP_RESPONSE_INVALID`).
pub fn parse_renewal_request(body: &[u8]) -> Result<TctRenewalPayload, RenewalError> {
    reject_duplicate_keys(body).map_err(RenewalError::RequestMalformed)?;
    serde_json::from_slice(body).map_err(|e| RenewalError::RequestMalformed(e.to_string()))
}

/// Issuer grant-policy hook re-run at renewal: given the holder AID and
/// the grants that survive the Manifest re-intersection, return the
/// grants to issue. Keyed by AID because a renewal request carries no
/// identity descriptor. A grant it returns outside its input is dropped:
/// renewal never widens grants (RFC-AITP-0013 §4 step 6).
pub type RenewalGrantPolicyFn = dyn Fn(&Aid, &[String]) -> Vec<String> + Send + Sync;

/// The issuer's current state, re-evaluated on every renewal
/// (RFC-AITP-0013 §4).
///
/// Every input that decides whether a renewal is safe is a required
/// argument of [`RenewalContext::new`]; there is no permissive default.
#[non_exhaustive]
pub struct RenewalContext<'a> {
    /// `expires_at` of the issuer's current Manifest. Caps both the
    /// presented TCT (§4 step 2) and the renewed one (§4 step 7).
    pub manifest_expires_at: Timestamp,
    /// The issuer Manifest's current `offered_capabilities`. The renewed
    /// grants are the presented TCT's grants intersected with these.
    pub offered_grants: &'a [String],
    /// Revocation source over the issuer's own deny list, queried with
    /// the presented TCT's `iss` and `jti`. A revoked TCT is refused with
    /// [`TctError::Revoked`]; under a soft-fail safe subset the renewed
    /// grants are limited to that subset.
    pub revocation: RevocationSource<'a>,
    /// Replay guard: every accepted `pop_nonce` is recorded here until
    /// the presented TCT's `exp`, and a nonce already present is refused
    /// with [`RenewalError::Replayed`]. Share one store across
    /// replicas, or the guard holds per replica only.
    pub nonce_store: &'a dyn NonceStore,
    /// Optional grant-policy hook, applied after the Manifest
    /// intersection. `None` keeps the intersection.
    pub grant_policy: Option<&'a RenewalGrantPolicyFn>,
    /// Requested lifetime of the renewed TCT, capped by
    /// [`Self::manifest_expires_at`]. Default [`DEFAULT_TCT_TTL`]. Counted in whole seconds.
    pub ttl: std::time::Duration,
    /// Whether to mint a companion grant voucher (§4 step 8). Default
    /// `true`.
    pub mint_voucher: bool,
    /// Verification clock.
    pub now: Timestamp,
}

impl<'a> RenewalContext<'a> {
    /// A context with every safety decision supplied, the default TTL,
    /// no extra grant policy, and voucher minting on.
    pub fn new(
        manifest_expires_at: Timestamp,
        offered_grants: &'a [String],
        revocation: RevocationSource<'a>,
        nonce_store: &'a dyn NonceStore,
        now: Timestamp,
    ) -> Self {
        Self {
            manifest_expires_at,
            offered_grants,
            revocation,
            nonce_store,
            grant_policy: None,
            ttl: DEFAULT_TCT_TTL,
            mint_voucher: true,
            now,
        }
    }

    /// Set the requested TTL (still capped by the Manifest window).
    pub fn ttl(mut self, ttl: std::time::Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Install a grant-policy hook.
    pub fn grant_policy(mut self, policy: &'a RenewalGrantPolicyFn) -> Self {
        self.grant_policy = Some(policy);
        self
    }

    /// Do not mint the companion grant voucher.
    pub fn without_voucher(mut self) -> Self {
        self.mint_voucher = false;
        self
    }
}

/// Issuer side: verify a parsed renewal request and mint the renewed
/// TCT (RFC-AITP-0013 §4 steps 1 to 8), stopping at the first failure:
///
/// 1. `pop_nonce` is 22 unpadded base64url characters decoding to 16
///    bytes → else [`RenewalError::NonceMalformed`].
/// 2. `current_tct` verifies as issued by this issuer (RFC-AITP-0005
///    §7.2: typ, alg, signature under the issuer's own key, claims,
///    `exp > now` ([`TctError::Expired`]) and the Manifest cap
///    ([`TctError::ExpiresAfterManifest`])), and its `aud` equals its
///    `sub` → else [`TctError::AudienceMismatch`].
/// 3. `pop_signature` verifies under the `sub` key over
///    [`renewal_pop_input`], rebuilt from the verified `iss` and `jti`
///    → else [`TctError::PopFailed`].
/// 4. The `jti` is not in the issuer's deny list → else
///    [`TctError::Revoked`].
/// 5. `pop_nonce` is recorded in [`RenewalContext::nonce_store`] until
///    the presented TCT's `exp`; a nonce already recorded →
///    [`RenewalError::Replayed`]. A store failure is
///    [`RenewalError::NonceStore`].
/// 6. Grants are the presented grants ∩ the Manifest's
///    `offered_capabilities`, narrowed by the grant policy. None left →
///    [`RenewalError::GrantsWithdrawn`].
/// 7. The renewed TCT keeps `iss`, `sub`, `aud` and `cnf`, has a new
///    `jti`, `iat = now` and `exp = min(now + ttl, Manifest expires_at)`.
/// 8. A companion grant voucher, unless [`RenewalContext::without_voucher`].
///
/// [`RenewalError::error_code`] gives each failure's registered code.
///
/// Accepts any [`AitpSigner`] (in-process key, KMS, HSM); a backend
/// failure returns `RenewalError::Tct(TctError::Crypto(CryptoError::Signer(_)))`.
pub async fn process_renewal_request(
    request: &TctRenewalPayload,
    issuer_key: &dyn AitpSigner,
    ctx: &RenewalContext<'_>,
) -> Result<IssuedTct, RenewalError> {
    let now = ctx.now;
    let nonce = decode_renewal_nonce(&request.pop_nonce)?;
    let issuer_aid = issuer_key.aid();

    // Step 2. The unverified claims name the audience to verify against;
    // `verify_tct` re-checks every field. Revocation is step 4, after the
    // PoP, so it is not consulted here.
    let claims = {
        let peek = peek_claims(&request.current_tct)?;
        let verify_ctx = TctVerifyContext::builder(&peek.aud, issuer_aid, now)
            .revocation(aitp::tct::RevocationSource::FailOpen)
            .issuer_manifest_expires_at(ctx.manifest_expires_at)
            .build()
            .expect("both decisions are made");
        verify_tct(&request.current_tct, &verify_ctx)?
            .into_parts()
            .claims
    };
    if claims.aud != claims.sub {
        return Err(TctError::AudienceMismatch.into());
    }

    // Step 3: the holder key is the one the sub AID encodes (verify_tct
    // already cross-checked cnf.jkt against it).
    let holder_pk = AitpVerifyingKey::from_aid(&claims.sub).map_err(TctError::Crypto)?;
    let input = renewal_pop_input(claims.iss.as_str(), &claims.jti.to_string(), &nonce);
    let digest = Digest32::sha256(&input);
    let sig = Signature::parse(&request.pop_signature).map_err(|_| TctError::PopFailed)?;
    holder_pk
        .verify_jcs(&digest, &sig)
        .map_err(|_| TctError::PopFailed)?;

    // Step 4.
    let effective_grants = aitp::__private::tct_revocation(&ctx.revocation, &claims, now)?;

    // Step 5. The record lives until the presented TCT expires: after
    // that the TCT cannot be renewed anyway, so the nonce can go.
    let record = IssuedNonce::new(
        nonce,
        issuer_aid.clone(),
        claims.sub.as_str(),
        now,
        claims.exp,
    );
    match ctx.nonce_store.issue(&record).await {
        Ok(()) => {}
        Err(NonceStoreError::Duplicate) => return Err(RenewalError::Replayed),
        Err(e) => return Err(RenewalError::NonceStore(e)),
    }

    // Step 6.
    let mut grants: Vec<String> = effective_grants
        .iter()
        .filter(|g| ctx.offered_grants.contains(g))
        .cloned()
        .collect();
    if let Some(policy) = ctx.grant_policy {
        let narrowed = policy(&claims.sub, &grants);
        grants.retain(|g| narrowed.contains(g));
    }
    if grants.is_empty() {
        return Err(RenewalError::GrantsWithdrawn);
    }

    // Steps 7 and 8. Step 2 bounds `claims.exp` by the Manifest and puts
    // it after `now`, so the capped lifetime is positive.
    let window = u64::try_from(ctx.manifest_expires_at.0.saturating_sub(now.0)).unwrap_or(0);
    let ttl = ctx.ttl.min(std::time::Duration::from_secs(window));
    let mut builder = TctBuilder::new(issuer_key)
        .subject(claims.sub.clone())
        .audience(claims.aud.clone())
        .grants(grants)
        .ttl(ttl)
        .subject_pubkey(holder_pk)
        .issued_at(now)
        .jti(Uuid::new_v4());
    if !ctx.mint_voucher {
        builder = builder.without_voucher();
    }
    Ok(builder.build()?)
}

/// The issuer's `tct` response envelope for a renewal (RFC-AITP-0013 §6):
/// signed by `issuer_key`, which issued the current TCT, and echoing the
/// request's `pop_nonce`.
pub fn renewal_response_envelope(
    issuer_key: &dyn AitpSigner,
    renewed: &IssuedTct,
    pop_nonce: &str,
    message_id: Uuid,
    now: Timestamp,
) -> Result<AitpEnvelope, RenewalError> {
    let payload = RenewalResponsePayload {
        tct: renewed.token.clone(),
        grant_voucher: renewed.voucher.clone(),
        pop_nonce_echo: pop_nonce.to_string(),
    };
    sign_payload(issuer_key, MessageType::Tct, &payload, message_id, now)
}

/// The issuer's `error` envelope refusing a renewal (RFC-AITP-0013 §6,
/// RFC-AITP-0001 §5.6).
pub fn renewal_error_envelope(
    issuer_key: &dyn AitpSigner,
    code: ErrorCode,
    reason: &str,
    retryable: bool,
    message_id: Uuid,
    now: Timestamp,
) -> Result<AitpEnvelope, RenewalError> {
    let payload = RenewalErrorPayload {
        code,
        reason: reason.to_string(),
        retryable,
    };
    sign_payload(issuer_key, MessageType::Error, &payload, message_id, now)
}

fn sign_payload(
    issuer_key: &dyn AitpSigner,
    message_type: MessageType,
    payload: &impl serde::Serialize,
    message_id: Uuid,
    now: Timestamp,
) -> Result<AitpEnvelope, RenewalError> {
    let payload =
        serde_json::to_value(payload).map_err(|e| TctError::Canonicalization(e.into()))?;
    Ok(sign_envelope_with(
        issuer_key,
        message_type,
        payload,
        message_id,
        now,
    )?)
}
