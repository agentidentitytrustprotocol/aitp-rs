//! TCT renewal (RFC-AITP-0013, Draft).
//!
//! A holder asks the issuer for a new TCT in place of the one it holds.
//! Renewal does not replay the Mutual Handshake: it carries forward the
//! identity binding in the current TCT's `sub` and `cnf`, and the holder
//! proves possession of the subject key over the renewal PoP input
//! ([`renewal_pop_input`], §3.1).
//!
//! The request (§3) is the unenveloped JSON body of a `POST` to the
//! issuer's `renew_uri`:
//!
//! ```json
//! {
//!   "current_tct":   "<compact JWS, typ aitp-tct+jwt>",
//!   "pop_nonce":     "<22-char base64url, fresh>",
//!   "pop_signature": "<sign(holder_key, sha256(renewal_pop_input))>"
//! }
//! ```
//!
//! The issuer runs [`parse_renewal_request`] and
//! [`process_renewal_request`] (§4) and answers with a signed `tct`
//! envelope built by [`renewal_response_envelope`] (§6), or an `error`
//! envelope built by [`renewal_error_envelope`] carrying
//! [`renewal_error_code`]. The holder checks the answer with
//! [`verify_renewal_response`] (§6.1) before it uses the renewed TCT.

use crate::core::nonce_store::{IssuedNonce, Nonce, NonceStore, NonceStoreError, NONCE_LEN};
use crate::core::{
    base64url, check_members, from_serde_error, reject_duplicate_keys, Aid, AitpEnvelope,
    ErrorCode, MessageType, Timestamp,
};
use crate::crypto::{AitpSigner, AitpVerifyingKey, CryptoError, Signature};
use crate::tct::types::{IssuedTct, TctClaims, TctRenewalPayload, VerifiedTct, TCT_CLAIMS_MEMBERS};
use crate::tct::{verify_tct, TctBuilder, TctError, TctVerifyContext};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The domain tag that starts the renewal PoP input (RFC-AITP-0013
/// §3.1): the 19 ASCII bytes `aitp-renewal-pop-v1` and one `0x00` byte.
pub const RENEWAL_POP_DOMAIN_TAG: &[u8; 20] = b"aitp-renewal-pop-v1\0";

/// The renewal PoP input of RFC-AITP-0013 §3.1:
/// `"aitp-renewal-pop-v1\0" || iss || "\0" || jti || "\0" || nonce`.
///
/// `iss` and `jti` are the current TCT's claims exactly as written in
/// the token; `pop_nonce` is the decoded nonce, not its base64url form.
/// The signature covers `sha256` of this input, hashed once.
pub fn renewal_pop_input(iss: &str, jti: &str, pop_nonce: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        RENEWAL_POP_DOMAIN_TAG.len() + iss.len() + 1 + jti.len() + 1 + pop_nonce.len(),
    );
    input.extend_from_slice(RENEWAL_POP_DOMAIN_TAG);
    input.extend_from_slice(iss.as_bytes());
    input.push(0);
    input.extend_from_slice(jti.as_bytes());
    input.push(0);
    input.extend_from_slice(pop_nonce);
    input
}

/// Build a [`TctRenewalPayload`] on the holder side (RFC-AITP-0013 §3).
///
/// `pop_nonce` is a fresh 22-character base64url nonce. The holder signs
/// `sha256(`[`renewal_pop_input`]`)` over the current TCT's `iss` and
/// `jti`, read from `current_tct`.
///
/// Accepts any [`AitpSigner`] (in-process key, KMS, HSM); a backend
/// failure returns `TctError::Crypto(CryptoError::Signer(_))`.
pub fn build_renewal_request(
    holder_key: &dyn AitpSigner,
    current_tct: String,
    pop_nonce: String,
) -> Result<TctRenewalPayload, TctError> {
    let nonce_bytes = base64url::decode_strict(&pop_nonce)
        .map_err(|e| TctError::RenewalNonceMalformed(e.to_string()))?;
    let current = peek_claims(&current_tct)?;
    let input = renewal_pop_input(current.iss.as_str(), &current.jti.to_string(), &nonce_bytes);
    let digest = crate::crypto::Digest32::sha256(&input);
    let pop_signature = crate::crypto::sign_jcs(holder_key, &digest)
        .map_err(CryptoError::Signer)?
        .into_string();
    Ok(TctRenewalPayload {
        current_tct,
        pop_nonce,
        pop_signature,
    })
}

/// Parse a renewal request body (RFC-AITP-0013 §4 step 1): a JSON object
/// with exactly `current_tct`, `pop_nonce` and `pop_signature`, each a
/// string, and no repeated key. Anything else is
/// [`TctError::RenewalRequestMalformed`] (`POP_RESPONSE_INVALID`).
pub fn parse_renewal_request(body: &[u8]) -> Result<TctRenewalPayload, TctError> {
    reject_duplicate_keys(body).map_err(TctError::RenewalRequestMalformed)?;
    serde_json::from_slice(body).map_err(|e| TctError::RenewalRequestMalformed(e.to_string()))
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
    /// grants are the presented TCT's grants intersected with these, so
    /// a capability the issuer has withdrawn does not carry over.
    pub offered_grants: &'a [String],
    /// Revocation lookup over the issuer's own deny list (`Ok(true)`
    /// means revoked, see [`crate::tct::RevocationCheckFn`]). A revoked TCT
    /// is refused with [`TctError::Revoked`].
    pub revocation_check: &'a (dyn Fn(&Uuid) -> Result<bool, TctError> + Send + Sync),
    /// Replay guard: every accepted `pop_nonce` is recorded here until
    /// the presented TCT's `exp`, and a nonce already present is refused
    /// with [`TctError::RenewalReplayed`]. Share one store across
    /// replicas, or the guard holds per replica only.
    pub nonce_store: &'a dyn NonceStore,
    /// Optional grant-policy hook, applied after the Manifest
    /// intersection. `None` keeps the intersection.
    pub grant_policy: Option<&'a RenewalGrantPolicyFn>,
    /// Requested lifetime of the renewed TCT, capped by
    /// [`Self::manifest_expires_at`]. Default
    /// [`crate::tct::DEFAULT_TCT_TTL_SECS`].
    pub ttl_secs: i64,
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
        revocation_check: &'a (dyn Fn(&Uuid) -> Result<bool, TctError> + Send + Sync),
        nonce_store: &'a dyn NonceStore,
        now: Timestamp,
    ) -> Self {
        Self {
            manifest_expires_at,
            offered_grants,
            revocation_check,
            nonce_store,
            grant_policy: None,
            ttl_secs: crate::tct::DEFAULT_TCT_TTL_SECS,
            mint_voucher: true,
            now,
        }
    }

    /// Set the requested TTL (still capped by the Manifest window).
    pub fn ttl_secs(mut self, ttl_secs: i64) -> Self {
        self.ttl_secs = ttl_secs;
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
///    bytes → else [`TctError::RenewalNonceMalformed`].
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
///    [`TctError::RenewalReplayed`]. A store failure is
///    [`TctError::RenewalNonceStore`].
/// 6. Grants are the presented grants ∩ the Manifest's
///    `offered_capabilities`, narrowed by the grant policy. None left →
///    [`TctError::RenewalGrantsWithdrawn`].
/// 7. The renewed TCT keeps `iss`, `sub`, `aud` and `cnf`, has a new
///    `jti`, `iat = now` and `exp = min(now + ttl, Manifest expires_at)`.
/// 8. A companion grant voucher, unless [`RenewalContext::without_voucher`].
///
/// [`renewal_error_code`] gives each failure's registered code.
///
/// Accepts any [`AitpSigner`] (in-process key, KMS, HSM); a backend
/// failure returns `TctError::Crypto(CryptoError::Signer(_))`.
pub async fn process_renewal_request(
    request: &TctRenewalPayload,
    issuer_key: &dyn AitpSigner,
    ctx: &RenewalContext<'_>,
) -> Result<IssuedTct, TctError> {
    let now = ctx.now;
    let nonce = decode_renewal_nonce(&request.pop_nonce)?;
    let issuer_aid = issuer_key.aid();

    // Step 2. The unverified claims name the audience to verify against;
    // `verify_tct` re-checks every field. Revocation is step 4, after the
    // PoP, so it is not consulted here.
    let claims = {
        let peek = peek_claims(&request.current_tct)?;
        let verify_ctx = TctVerifyContext::builder(&peek.aud, issuer_aid, now)
            .accept_unchecked_revocation_dangerous()
            .issuer_manifest_expires_at(ctx.manifest_expires_at)
            .build()
            .expect("both decisions are made");
        verify_tct(&request.current_tct, &verify_ctx)?.claims
    };
    if claims.aud != claims.sub {
        return Err(TctError::AudienceMismatch);
    }

    // Step 3: the holder key is the one the sub AID encodes (verify_tct
    // already cross-checked cnf.jkt against it).
    let holder_pk = AitpVerifyingKey::from_aid(&claims.sub).map_err(TctError::Crypto)?;
    let input = renewal_pop_input(claims.iss.as_str(), &claims.jti.to_string(), &nonce);
    let digest = crate::crypto::Digest32::sha256(&input);
    let sig = Signature::parse(&request.pop_signature).map_err(|_| TctError::PopFailed)?;
    holder_pk
        .verify_jcs(&digest, &sig)
        .map_err(|_| TctError::PopFailed)?;

    // Step 4.
    if (ctx.revocation_check)(&claims.jti)? {
        return Err(TctError::Revoked);
    }

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
        Err(NonceStoreError::Duplicate) => return Err(TctError::RenewalReplayed),
        Err(e) => return Err(TctError::RenewalNonceStore(e)),
    }

    // Step 6.
    let mut grants: Vec<String> = claims
        .grants
        .iter()
        .filter(|g| ctx.offered_grants.contains(g))
        .cloned()
        .collect();
    if let Some(policy) = ctx.grant_policy {
        let narrowed = policy(&claims.sub, &grants);
        grants.retain(|g| narrowed.contains(g));
    }
    if grants.is_empty() {
        return Err(TctError::RenewalGrantsWithdrawn);
    }

    // Steps 7 and 8. Step 2 bounds `claims.exp` by the Manifest and puts
    // it after `now`, so the capped lifetime is positive.
    let ttl = ctx.ttl_secs.min(ctx.manifest_expires_at.0 - now.0);
    let mut builder = TctBuilder::new(issuer_key)
        .subject(claims.sub.clone())
        .audience(claims.aud.clone())
        .grants(grants)
        .ttl_secs(ttl)
        .subject_pubkey(holder_pk)
        .issued_at(now)
        .jti(Uuid::new_v4());
    if !ctx.mint_voucher {
        builder = builder.without_voucher();
    }
    builder.build()
}

/// The registered code for an issuer-side renewal failure
/// (RFC-AITP-0013 §4, §8). The issuer's nonce store failing
/// ([`TctError::RenewalNonceStore`]) and its signer failing are local
/// faults: answer them with a retryable error, not this code.
pub fn renewal_error_code(err: &TctError) -> ErrorCode {
    use crate::crypto::CryptoError;
    match err {
        TctError::RenewalRequestMalformed(_)
        | TctError::RenewalNonceMalformed(_)
        | TctError::PopFailed => ErrorCode::PopResponseInvalid,
        TctError::Revoked | TctError::RevocationUnavailable(_) => ErrorCode::TctRevoked,
        TctError::RenewalReplayed => ErrorCode::ReplayDetected,
        TctError::RenewalGrantsWithdrawn => ErrorCode::PolicyViolation,
        TctError::Expired => ErrorCode::TctExpired,
        TctError::ExpiresAfterManifest => ErrorCode::TctExpiresAfterManifest,
        TctError::UnknownField(_) => ErrorCode::UnknownField,
        TctError::VersionUnknown => ErrorCode::UnknownVersion,
        TctError::ClaimsMalformed(_)
        | TctError::MissingField(_)
        | TctError::CnfMalformed
        | TctError::EmptyGrants
        | TctError::GrantWhitespace(_)
        | TctError::Crypto(CryptoError::JwsMalformed(_)) => ErrorCode::InvalidEnvelope,
        TctError::Crypto(CryptoError::AlgMismatch(_)) => ErrorCode::TokenAlgMismatch,
        TctError::Crypto(CryptoError::TypMismatch { .. }) => ErrorCode::TokenTypMismatch,
        // Signature, issuer pin (a TCT this issuer did not sign), `aud`
        // other than `sub`, `jti` layout, self-issued or attestation
        // marker: not a TCT this issuer issued (§4 step 2).
        _ => ErrorCode::TctSignatureInvalid,
    }
}

/// Payload of a `tct` renewal response envelope (RFC-AITP-0013 §6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RenewalResponsePayload {
    /// The renewed TCT, compact JWS.
    pub tct: String,
    /// The renewed TCT's companion grant voucher, when minted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_voucher: Option<String>,
    /// The request's `pop_nonce`, byte for byte.
    pub pop_nonce_echo: String,
}

/// Members of [`RenewalResponsePayload`].
pub const RENEWAL_RESPONSE_PAYLOAD_MEMBERS: &[&str] = &["tct", "grant_voucher", "pop_nonce_echo"];

/// Payload of an `error` envelope (RFC-AITP-0001 §5.6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct RenewalErrorPayload {
    /// The registered error code.
    pub code: ErrorCode,
    /// Informational text; never used for decisions.
    #[serde(default)]
    pub reason: String,
    /// Whether the holder may retry the same request later.
    #[serde(default)]
    pub retryable: bool,
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
) -> Result<AitpEnvelope, TctError> {
    let payload = RenewalResponsePayload {
        tct: renewed.token.clone(),
        grant_voucher: renewed.voucher.clone(),
        pop_nonce_echo: pop_nonce.to_string(),
    };
    let payload =
        serde_json::to_value(&payload).map_err(|e| TctError::Canonicalization(e.to_string()))?;
    crate::envelope::sign_envelope_with(issuer_key, MessageType::Tct, payload, message_id, now)
        .map_err(TctError::Canonicalization)
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
) -> Result<AitpEnvelope, TctError> {
    let payload = RenewalErrorPayload {
        code,
        reason: reason.to_string(),
        retryable,
    };
    let payload =
        serde_json::to_value(&payload).map_err(|e| TctError::Canonicalization(e.to_string()))?;
    crate::envelope::sign_envelope_with(issuer_key, MessageType::Error, payload, message_id, now)
        .map_err(TctError::Canonicalization)
}

/// What the holder checks a renewal response against (RFC-AITP-0013
/// §6.1).
#[non_exhaustive]
pub struct RenewalResponseContext<'a> {
    /// The holder's own AID: the current TCT's `sub` and `aud`.
    pub self_aid: &'a Aid,
    /// The TCT the holder presented, compact JWS.
    pub current_tct: &'a str,
    /// The `pop_nonce` the holder sent in this request.
    pub sent_pop_nonce: &'a str,
    /// Verification clock.
    pub now: Timestamp,
    /// `expires_at` of the issuer's Manifest, when the holder has it
    /// (RFC-AITP-0005 §10.4).
    pub issuer_manifest_expires_at: Option<Timestamp>,
}

impl<'a> RenewalResponseContext<'a> {
    /// A context for the response to the request that presented
    /// `current_tct` with `sent_pop_nonce`.
    pub fn new(
        self_aid: &'a Aid,
        current_tct: &'a str,
        sent_pop_nonce: &'a str,
        now: Timestamp,
    ) -> Self {
        Self {
            self_aid,
            current_tct,
            sent_pop_nonce,
            now,
            issuer_manifest_expires_at: None,
        }
    }

    /// Bound the renewed TCT by the issuer Manifest's `expires_at`.
    pub fn issuer_manifest_expires_at(mut self, expires_at: Timestamp) -> Self {
        self.issuer_manifest_expires_at = Some(expires_at);
        self
    }
}

/// A renewal response that passed [`verify_renewal_response`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RenewedTct {
    /// The renewed TCT.
    pub tct: VerifiedTct,
    /// Its companion grant voucher, verbatim, when the issuer sent one.
    pub grant_voucher: Option<String>,
}

/// Why the holder rejected a renewal response (RFC-AITP-0013 §6.1).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RenewalResponseError {
    /// Step 1: the envelope or its payload is malformed, or its
    /// `message_type` is neither `tct` nor `error`.
    #[error("invalid renewal response envelope: {0}")]
    InvalidEnvelope(String),
    /// Step 1: the payload carries a member outside its schema.
    #[error("unknown field: {0}")]
    UnknownField(String),
    /// Step 1: the envelope timestamp is outside the window.
    #[error("renewal response timestamp outside the window")]
    TimestampExpired,
    /// Step 1: the envelope signature does not verify under its sender.
    #[error("renewal response signature invalid")]
    InvalidSignature,
    /// Step 2: the sender is not the current TCT's issuer.
    #[error("renewal response sender is not the current TCT's issuer")]
    PeerMismatch,
    /// Step 3: `pop_nonce_echo` is not the nonce the holder sent.
    #[error("renewal response pop_nonce_echo does not match the request")]
    NonceMismatch,
    /// Step 4: the renewed TCT fails RFC-AITP-0005 §7.2, or the current
    /// TCT the holder supplied cannot be read.
    #[error("renewed TCT: {0}")]
    Tct(#[source] TctError),
    /// Step 5: the renewed TCT's `sub` or `cnf.jkt` is not the holder's.
    #[error("renewed TCT subject is not the holder")]
    AudienceMismatch,
    /// Step 6: the renewed TCT carries a grant the current one does not.
    #[error("renewed TCT carries a grant the current TCT does not")]
    GrantOverflow,
    /// The issuer refused the renewal with an `error` envelope that
    /// passed steps 1 and 2.
    #[error("issuer refused renewal: {code:?}: {reason}")]
    Refused {
        /// The code the issuer sent.
        code: ErrorCode,
        /// The issuer's informational text.
        reason: String,
        /// Whether the issuer marked the failure retryable.
        retryable: bool,
    },
}

impl RenewalResponseError {
    /// The registered code (RFC-AITP-0013 §8). For [`Self::Refused`],
    /// the issuer's code.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidEnvelope(_) => ErrorCode::InvalidEnvelope,
            Self::UnknownField(_) => ErrorCode::UnknownField,
            Self::TimestampExpired => ErrorCode::TimestampExpired,
            Self::InvalidSignature => ErrorCode::InvalidSignature,
            Self::PeerMismatch => ErrorCode::PeerMismatch,
            Self::NonceMismatch => ErrorCode::NonceMismatch,
            Self::Tct(TctError::AudienceMismatch) => ErrorCode::AudienceMismatch,
            Self::Tct(e) => renewal_error_code(e),
            Self::AudienceMismatch => ErrorCode::AudienceMismatch,
            Self::GrantOverflow => ErrorCode::GrantOverflow,
            Self::Refused { code, .. } => *code,
        }
    }
}

/// Holder side: check the issuer's answer to a renewal request
/// (RFC-AITP-0013 §6.1 steps 1 to 6), stopping at the first failure.
/// The envelope has already passed [`crate::core::parse_envelope_wire`]
/// (`version` and member set); `message_id` deduplication (RFC-AITP-0001
/// §5.5) is the caller's.
///
/// 1. The timestamp is within the default window, `message_type` is
///    `tct` or `error`, and the signature verifies under the sender.
/// 2. The sender is the current TCT's `iss`. An `error` envelope that
///    passes steps 1 and 2 is [`RenewalResponseError::Refused`].
/// 3. `pop_nonce_echo` is the nonce the holder sent.
/// 4. The renewed TCT verifies as addressed to the holder and issued by
///    the current TCT's `iss`.
/// 5. Its `sub` is the holder and its `cnf.jkt` the current TCT's.
/// 6. Its grants are a subset of the current TCT's.
pub fn verify_renewal_response(
    envelope: &AitpEnvelope,
    ctx: &RenewalResponseContext<'_>,
) -> Result<RenewedTct, RenewalResponseError> {
    let current = peek_claims(ctx.current_tct).map_err(RenewalResponseError::Tct)?;

    // Step 1.
    if !envelope.timestamp.is_fresh(ctx.now) {
        return Err(RenewalResponseError::TimestampExpired);
    }
    if !matches!(envelope.message_type, MessageType::Tct | MessageType::Error) {
        return Err(RenewalResponseError::InvalidEnvelope(format!(
            "message_type {} is neither tct nor error",
            envelope.message_type.as_wire_str()
        )));
    }
    let sender_pk = AitpVerifyingKey::from_aid(&envelope.sender.agent_id)
        .map_err(|_| RenewalResponseError::InvalidSignature)?;
    crate::envelope::verify_envelope_signature(envelope, &sender_pk)
        .map_err(|_| RenewalResponseError::InvalidSignature)?;

    // Step 2.
    if envelope.sender.agent_id.as_str() != current.iss.as_str() {
        return Err(RenewalResponseError::PeerMismatch);
    }
    if envelope.message_type == MessageType::Error {
        let refusal: RenewalErrorPayload = serde_json::from_value(envelope.payload.clone())
            .map_err(|e| RenewalResponseError::InvalidEnvelope(e.to_string()))?;
        return Err(RenewalResponseError::Refused {
            code: refusal.code,
            reason: refusal.reason,
            retryable: refusal.retryable,
        });
    }
    check_members(
        "RenewalResponsePayload",
        &envelope.payload,
        RENEWAL_RESPONSE_PAYLOAD_MEMBERS,
    )
    .map_err(|e| RenewalResponseError::UnknownField(e.field))?;
    let payload: RenewalResponsePayload = serde_json::from_value(envelope.payload.clone())
        .map_err(|e| RenewalResponseError::InvalidEnvelope(e.to_string()))?;

    // Step 3.
    if payload.pop_nonce_echo != ctx.sent_pop_nonce {
        return Err(RenewalResponseError::NonceMismatch);
    }

    // Step 4. The holder has just been issued this TCT, so it does not
    // consult the issuer's revocation list for it.
    let builder = TctVerifyContext::builder(ctx.self_aid, &current.iss, ctx.now)
        .accept_unchecked_revocation_dangerous();
    let builder = match ctx.issuer_manifest_expires_at {
        Some(exp) => builder.issuer_manifest_expires_at(exp),
        None => builder.skip_manifest_expiry_cap_dangerous(),
    };
    let verify_ctx = builder.build().expect("both decisions are made");
    let renewed = verify_tct(&payload.tct, &verify_ctx).map_err(RenewalResponseError::Tct)?;

    // Step 5.
    if &renewed.claims.sub != ctx.self_aid || renewed.claims.cnf.jkt != current.cnf.jkt {
        return Err(RenewalResponseError::AudienceMismatch);
    }

    // Step 6.
    if renewed
        .claims
        .grants
        .iter()
        .any(|g| !current.grants.contains(g))
    {
        return Err(RenewalResponseError::GrantOverflow);
    }

    Ok(RenewedTct {
        tct: renewed,
        grant_voucher: payload.grant_voucher,
    })
}

/// The claims of a TCT, decoded without verifying it. Strict as
/// [`verify_tct`]'s parse: a repeated key is
/// [`TctError::ClaimsMalformed`] and, when the header `typ` is the TCT
/// one, an unknown claim is [`TctError::UnknownField`] (tct-010: a `typ`
/// confusion is left to `verify_tct`'s own check).
fn peek_claims(token: &str) -> Result<TctClaims, TctError> {
    let peek = crate::crypto::jws::decode_payload_unverified(token).map_err(TctError::Crypto)?;
    // RFC-AITP-0001 §5.4.5 / issue #140: run the raw-bytes duplicate-key
    // guard before the `Value` conversion, which would collapse a
    // duplicate key to its last occurrence.
    reject_duplicate_keys(&peek).map_err(TctError::ClaimsMalformed)?;
    let value: serde_json::Value =
        serde_json::from_slice(&peek).map_err(|e| TctError::ClaimsMalformed(e.to_string()))?;
    if crate::tct::verifier::peek_header_typ(token).as_deref() == Some(crate::crypto::jws::TYP_TCT)
    {
        check_members("TctClaims", &value, TCT_CLAIMS_MEMBERS)
            .map_err(|e| TctError::UnknownField(e.field))?;
    }
    serde_json::from_value(value).map_err(|e| {
        if let Some(field) = from_serde_error(&e) {
            TctError::UnknownField(field)
        } else {
            TctError::ClaimsMalformed(e.to_string())
        }
    })
}

/// Strict `pop_nonce` decode: 22 unpadded base64url characters, 16 bytes.
fn decode_renewal_nonce(pop_nonce: &str) -> Result<Nonce, TctError> {
    let bytes = base64url::decode_strict(pop_nonce)
        .map_err(|e| TctError::RenewalNonceMalformed(e.to_string()))?;
    bytes.try_into().map_err(|b: Vec<u8>| {
        TctError::RenewalNonceMalformed(format!(
            "must decode to exactly {NONCE_LEN} bytes, got {}",
            b.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::nonce_store::InMemoryNonceStore;
    use crate::crypto::AitpSigningKey;

    const GRANTS: &[&str] = &["demo.echo", "demo.write"];

    fn offered() -> Vec<String> {
        GRANTS.iter().map(|s| s.to_string()).collect()
    }

    fn not_revoked(_: &Uuid) -> Result<bool, TctError> {
        Ok(false)
    }

    fn issue(
        issuer: &AitpSigningKey,
        holder: &AitpSigningKey,
        now: Timestamp,
        ttl: i64,
    ) -> IssuedTct {
        TctBuilder::new(issuer)
            .subject(holder.aid().clone())
            .audience(holder.aid().clone())
            .grants(GRANTS.iter().copied())
            .ttl_secs(ttl)
            .subject_pubkey(holder.verifying_key())
            .issued_at(now)
            .build()
            .unwrap()
    }

    /// Run `process_renewal_request` with a fresh store and the given
    /// Manifest expiry, no revocation, every grant still offered.
    async fn renew(
        request: &TctRenewalPayload,
        issuer: &AitpSigningKey,
        manifest_exp: Timestamp,
        now: Timestamp,
        ttl: i64,
    ) -> Result<IssuedTct, TctError> {
        let store = InMemoryNonceStore::new(16);
        let offered = offered();
        let ctx =
            RenewalContext::new(manifest_exp, &offered, &not_revoked, &store, now).ttl_secs(ttl);
        process_renewal_request(request, issuer, &ctx).await
    }

    #[tokio::test]
    async fn round_trip_renewal_succeeds() {
        let issuer = AitpSigningKey::from_seed(&[0x01; 32]);
        let holder = AitpSigningKey::from_seed(&[0x02; 32]);
        let now = Timestamp(1_700_000_000);
        let manifest_exp = Timestamp(now.0 + 86_400);

        let original = issue(&issuer, &holder, now, 60);
        let request = build_renewal_request(
            &holder,
            original.token.clone(),
            base64url::encode(&[0x33; 16]),
        )
        .unwrap();

        let renewed = renew(&request, &issuer, manifest_exp, now, 3600)
            .await
            .unwrap();
        assert_ne!(renewed.claims.jti, original.claims.jti);
        assert_eq!(renewed.claims.sub, original.claims.sub);
        assert_eq!(renewed.claims.grants, original.claims.grants);
        assert_eq!(renewed.claims.exp.0, now.0 + 3600);
        assert!(renewed.voucher.is_some(), "renewal mints a fresh voucher");
    }

    #[tokio::test]
    async fn renewal_with_wrong_holder_key_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x10; 32]);
        let holder = AitpSigningKey::from_seed(&[0x11; 32]);
        let attacker = AitpSigningKey::from_seed(&[0x12; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 60);
        let request = build_renewal_request(
            &attacker, // attacker signs with its own key
            original.token,
            base64url::encode(&[0x44; 16]),
        )
        .unwrap();
        let err = renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
            .await
            .unwrap_err();
        assert!(matches!(err, TctError::PopFailed), "got {err:?}");
    }

    #[tokio::test]
    async fn renewal_bounded_by_manifest_expiry() {
        let issuer = AitpSigningKey::from_seed(&[0x20; 32]);
        let holder = AitpSigningKey::from_seed(&[0x21; 32]);
        let now = Timestamp(1_700_000_000);
        let manifest_exp = Timestamp(now.0 + 600); // 10 min left
        let original = issue(&issuer, &holder, now, 60);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0x55; 16])).unwrap();
        // Caller asks for 1 hour TTL, manifest only allows 10 min.
        let renewed = renew(&request, &issuer, manifest_exp, now, 3600)
            .await
            .unwrap();
        assert_eq!(
            renewed.claims.exp.0, manifest_exp.0,
            "TTL must be capped by manifest expiry"
        );
    }

    #[tokio::test]
    async fn renewal_after_manifest_expired_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x30; 32]);
        let holder = AitpSigningKey::from_seed(&[0x31; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 60);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0x66; 16])).unwrap();
        // Manifest already expired: the presented TCT now outlives it.
        let err = renew(&request, &issuer, Timestamp(now.0 - 1), now, 3600)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TctError::ExpiresAfterManifest | TctError::Expired),
            "got {err:?}"
        );
    }

    /// RFC-AITP-0013: renewal is not a bypass for Manifest rotation.
    /// A TCT whose `exp` exceeds the issuer's current Manifest is refused,
    /// where the old `skip_manifest_expiry_cap_dangerous` waiver let it in.
    #[tokio::test]
    async fn renewal_of_tct_outliving_rotated_manifest_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x32; 32]);
        let holder = AitpSigningKey::from_seed(&[0x33; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 3600);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0x67; 16])).unwrap();
        let err = renew(&request, &issuer, Timestamp(now.0 + 600), now, 3600)
            .await
            .unwrap_err();
        assert!(matches!(err, TctError::ExpiresAfterManifest), "got {err:?}");
    }

    #[tokio::test]
    async fn renewal_of_expired_tct_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x34; 32]);
        let holder = AitpSigningKey::from_seed(&[0x35; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 60);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0x68; 16])).unwrap();
        let later = Timestamp(now.0 + 3600);
        let err = renew(&request, &issuer, Timestamp(now.0 + 86_400), later, 3600)
            .await
            .unwrap_err();
        assert!(matches!(err, TctError::Expired), "got {err:?}");
    }

    #[tokio::test]
    async fn renewal_of_foreign_issuer_token_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x40; 32]);
        let other_issuer = AitpSigningKey::from_seed(&[0x41; 32]);
        let holder = AitpSigningKey::from_seed(&[0x42; 32]);
        let now = Timestamp(1_700_000_000);
        let foreign = issue(&other_issuer, &holder, now, 60);
        let request =
            build_renewal_request(&holder, foreign.token, base64url::encode(&[0x77; 16])).unwrap();
        // `issuer` cannot renew a TCT signed by `other_issuer`.
        assert!(
            renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
                .await
                .is_err()
        );
    }

    /// RFC-AITP-0001 §5.4.5 / issue #140: a `current_tct` whose (unverified)
    /// payload carries a duplicate top-level key must be rejected with
    /// `ClaimsMalformed`, not silently accepted with the key's last
    /// occurrence winning. Deliberately raw-text tampering of an
    /// otherwise-validly-signed token's payload segment — a defect no
    /// `serde_json::Value` can even represent.
    #[tokio::test]
    async fn renewal_of_token_with_duplicate_claim_is_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x50; 32]);
        let holder = AitpSigningKey::from_seed(&[0x51; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 60);

        let parts: Vec<&str> = original.token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let payload_bytes = base64url::decode_strict(parts[1]).unwrap();
        let payload_str = std::str::from_utf8(&payload_bytes).unwrap();
        assert!(payload_str.starts_with('{'));
        let dup_payload = format!("{{\"ver\":\"aitp/0.3\",{}", &payload_str[1..]);
        let dup_token = format!(
            "{}.{}.{}",
            parts[0],
            base64url::encode(dup_payload.as_bytes()),
            parts[2]
        );

        // The holder's builder refuses it too; present it directly.
        assert!(matches!(
            build_renewal_request(&holder, dup_token.clone(), base64url::encode(&[0x88; 16])),
            Err(TctError::ClaimsMalformed(_))
        ));
        let request = TctRenewalPayload {
            current_tct: dup_token,
            pop_nonce: base64url::encode(&[0x88; 16]),
            pop_signature: "AA".into(),
        };
        let err = renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, TctError::ClaimsMalformed(m) if m.contains("duplicate field `ver`")),
            "got {err:?}"
        );
    }

    /// #196: the same signed request presented twice mints only once.
    #[tokio::test]
    async fn replayed_pop_nonce_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x60; 32]);
        let holder = AitpSigningKey::from_seed(&[0x61; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0x99; 16])).unwrap();
        let store = InMemoryNonceStore::new(16);
        let offered = offered();
        let ctx = RenewalContext::new(
            Timestamp(now.0 + 86_400),
            &offered,
            &not_revoked,
            &store,
            now,
        );
        process_renewal_request(&request, &issuer, &ctx)
            .await
            .expect("first presentation renews");
        let err = process_renewal_request(&request, &issuer, &ctx)
            .await
            .unwrap_err();
        assert!(matches!(err, TctError::RenewalReplayed), "got {err:?}");
        assert_eq!(store.len(), 1);
    }

    /// A request whose PoP fails never reaches the store, so it cannot
    /// burn the holder's nonce.
    #[tokio::test]
    async fn failed_pop_does_not_record_nonce() {
        let issuer = AitpSigningKey::from_seed(&[0x62; 32]);
        let holder = AitpSigningKey::from_seed(&[0x63; 32]);
        let attacker = AitpSigningKey::from_seed(&[0x64; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let nonce = base64url::encode(&[0x9a; 16]);
        let forged =
            build_renewal_request(&attacker, original.token.clone(), nonce.clone()).unwrap();
        let store = InMemoryNonceStore::new(16);
        let offered = offered();
        let ctx = RenewalContext::new(
            Timestamp(now.0 + 86_400),
            &offered,
            &not_revoked,
            &store,
            now,
        );
        let err = process_renewal_request(&forged, &issuer, &ctx)
            .await
            .unwrap_err();
        assert!(matches!(err, TctError::PopFailed), "got {err:?}");
        assert!(store.is_empty());
        let genuine = build_renewal_request(&holder, original.token, nonce).unwrap();
        process_renewal_request(&genuine, &issuer, &ctx)
            .await
            .expect("holder's nonce is still usable");
    }

    #[tokio::test]
    async fn pop_nonce_of_wrong_length_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x65; 32]);
        let holder = AitpSigningKey::from_seed(&[0x66; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        for len in [0usize, 8, 15, 17, 32] {
            let request = build_renewal_request(
                &holder,
                original.token.clone(),
                base64url::encode(&vec![1; len]),
            )
            .unwrap();
            let err = renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
                .await
                .unwrap_err();
            assert!(
                matches!(err, TctError::RenewalNonceMalformed(_)),
                "len {len}: got {err:?}"
            );
        }
        // Not base64url at all.
        let mut request =
            build_renewal_request(&holder, original.token, base64url::encode(&[1; 16])).unwrap();
        request.pop_nonce = "not base64url!".into();
        let err = renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TctError::RenewalNonceMalformed(_)),
            "got {err:?}"
        );
    }

    /// #196: the old `accept_unchecked_revocation_dangerous` waiver let a
    /// revoked-but-unexpired TCT renew. It must not.
    #[tokio::test]
    async fn renewal_of_revoked_tct_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x70; 32]);
        let holder = AitpSigningKey::from_seed(&[0x71; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let revoked_jti = original.claims.jti;
        let revoked = move |j: &Uuid| Ok(*j == revoked_jti);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0xaa; 16])).unwrap();
        let store = InMemoryNonceStore::new(16);
        let offered = offered();
        let ctx = RenewalContext::new(Timestamp(now.0 + 86_400), &offered, &revoked, &store, now);
        let err = process_renewal_request(&request, &issuer, &ctx)
            .await
            .unwrap_err();
        assert!(matches!(err, TctError::Revoked), "got {err:?}");
        assert!(store.is_empty(), "a refused request records no nonce");
    }

    /// A grant the issuer's Manifest no longer offers is dropped.
    #[tokio::test]
    async fn withdrawn_grant_is_dropped() {
        let issuer = AitpSigningKey::from_seed(&[0x72; 32]);
        let holder = AitpSigningKey::from_seed(&[0x73; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0xab; 16])).unwrap();
        let store = InMemoryNonceStore::new(16);
        let offered = vec!["demo.echo".to_string()];
        let ctx = RenewalContext::new(
            Timestamp(now.0 + 86_400),
            &offered,
            &not_revoked,
            &store,
            now,
        );
        let renewed = process_renewal_request(&request, &issuer, &ctx)
            .await
            .unwrap();
        assert_eq!(renewed.claims.grants, vec!["demo.echo".to_string()]);
    }

    /// Every grant withdrawn (by the Manifest or by policy): refused.
    #[tokio::test]
    async fn all_grants_withdrawn_refused() {
        let issuer = AitpSigningKey::from_seed(&[0x74; 32]);
        let holder = AitpSigningKey::from_seed(&[0x75; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let store = InMemoryNonceStore::new(16);
        let manifest_exp = Timestamp(now.0 + 86_400);

        let request = build_renewal_request(
            &holder,
            original.token.clone(),
            base64url::encode(&[0xac; 16]),
        )
        .unwrap();
        let none_offered: Vec<String> = vec!["other.cap".into()];
        let ctx = RenewalContext::new(manifest_exp, &none_offered, &not_revoked, &store, now);
        let err = process_renewal_request(&request, &issuer, &ctx)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TctError::RenewalGrantsWithdrawn),
            "got {err:?}"
        );

        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0xad; 16])).unwrap();
        let offered = offered();
        let deny_all = |_: &Aid, _: &[String]| Vec::new();
        let ctx = RenewalContext::new(manifest_exp, &offered, &not_revoked, &store, now)
            .grant_policy(&deny_all);
        let err = process_renewal_request(&request, &issuer, &ctx)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TctError::RenewalGrantsWithdrawn),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn grant_policy_narrows_and_voucher_is_optional() {
        let issuer = AitpSigningKey::from_seed(&[0x76; 32]);
        let holder = AitpSigningKey::from_seed(&[0x77; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0xae; 16])).unwrap();
        let store = InMemoryNonceStore::new(16);
        let offered = offered();
        let policy = |_: &Aid, g: &[String]| {
            g.iter()
                .filter(|c| c.as_str() == "demo.write")
                .cloned()
                .collect()
        };
        let ctx = RenewalContext::new(
            Timestamp(now.0 + 86_400),
            &offered,
            &not_revoked,
            &store,
            now,
        )
        .grant_policy(&policy)
        .without_voucher();
        let renewed = process_renewal_request(&request, &issuer, &ctx)
            .await
            .unwrap();
        assert_eq!(renewed.claims.grants, vec!["demo.write".to_string()]);
        assert!(renewed.voucher.is_none());
    }

    #[tokio::test]
    async fn nonce_store_at_capacity_is_a_local_error() {
        let issuer = AitpSigningKey::from_seed(&[0x78; 32]);
        let holder = AitpSigningKey::from_seed(&[0x79; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let store = InMemoryNonceStore::new(1);
        let offered = offered();
        let ctx = RenewalContext::new(
            Timestamp(now.0 + 86_400),
            &offered,
            &not_revoked,
            &store,
            now,
        );
        let first = build_renewal_request(
            &holder,
            original.token.clone(),
            base64url::encode(&[0xb0; 16]),
        )
        .unwrap();
        process_renewal_request(&first, &issuer, &ctx)
            .await
            .unwrap();
        let second =
            build_renewal_request(&holder, original.token, base64url::encode(&[0xb1; 16])).unwrap();
        let err = process_renewal_request(&second, &issuer, &ctx)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                TctError::RenewalNonceStore(NonceStoreError::AtCapacity { .. })
            ),
            "got {err:?}"
        );
    }

    /// The renewal future is `Send`, so a multi-threaded server can await it.
    #[test]
    fn renewal_future_is_send() {
        fn assert_send<T: Send>(_: &T) {}
        let issuer = AitpSigningKey::from_seed(&[0x7a; 32]);
        let store = InMemoryNonceStore::new(1);
        let offered = offered();
        let ctx = RenewalContext::new(Timestamp(1), &offered, &not_revoked, &store, Timestamp(0));
        let req = TctRenewalPayload {
            current_tct: String::new(),
            pop_nonce: String::new(),
            pop_signature: String::new(),
        };
        let fut = process_renewal_request(&req, &issuer, &ctx);
        assert_send(&fut);
    }

    fn kat_vector(id: &str) -> serde_json::Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/schemas/known-answer/jcs-sha256.json");
        let kat: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        kat["vectors"]
            .as_array()
            .expect("vectors array")
            .iter()
            .find(|v| v["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("vector {id} missing from jcs-sha256.json"))
            .clone()
    }

    /// kat-renewal-pop-001 and kat-renewal-pop-002-p256, read from the
    /// vendored spec file: the input bytes, its digest, and the
    /// signature verifying over it under the signer AID.
    #[test]
    fn renewal_pop_input_matches_kats() {
        for id in ["kat-renewal-pop-001", "kat-renewal-pop-002-p256"] {
            let v = kat_vector(id);
            let nonce = base64url::decode_strict(v["pop_nonce"].as_str().unwrap()).unwrap();
            let input = renewal_pop_input(
                v["issuer_aid"].as_str().unwrap(),
                v["current_tct_jti"].as_str().unwrap(),
                &nonce,
            );
            assert_eq!(
                hex::encode(&input),
                v["input_hex"].as_str().unwrap(),
                "{id}"
            );
            assert_eq!(input.len() as u64, v["input_len_bytes"].as_u64().unwrap());
            let digest = crate::crypto::Digest32::sha256(&input);
            assert_eq!(
                hex::encode(digest.as_bytes()),
                v["sha256_hex"].as_str().unwrap()
            );
            let signer = Aid::parse(v["signer_aid"].as_str().unwrap()).unwrap();
            let pk = AitpVerifyingKey::from_aid(&signer).unwrap();
            let sig = v["signature"]
                .as_str()
                .or(v["signature_b64url"].as_str())
                .unwrap();
            pk.verify_jcs(&digest, &Signature::parse(sig).unwrap())
                .unwrap_or_else(|e| panic!("{id}: {e}"));
            // The nonce enters as its decoded bytes, not its string.
            let wrong = renewal_pop_input(
                v["issuer_aid"].as_str().unwrap(),
                v["current_tct_jti"].as_str().unwrap(),
                v["pop_nonce"].as_str().unwrap().as_bytes(),
            );
            assert!(pk
                .verify_jcs(
                    &crate::crypto::Digest32::sha256(&wrong),
                    &Signature::parse(sig).unwrap()
                )
                .is_err());
            if let Some(double) = v["double_hash_signature_MUST_NOT_verify"].as_str() {
                assert!(pk
                    .verify_jcs(&digest, &Signature::parse(double).unwrap())
                    .is_err());
            }
        }
    }

    /// §4: the PoP is checked before revocation, so a revoked TCT with a
    /// bad PoP is refused for the PoP.
    #[tokio::test]
    async fn pop_is_checked_before_revocation() {
        let issuer = AitpSigningKey::from_seed(&[0x7b; 32]);
        let holder = AitpSigningKey::from_seed(&[0x7c; 32]);
        let other = AitpSigningKey::from_seed(&[0x7d; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let revoked = |_: &Uuid| Ok(true);
        let request =
            build_renewal_request(&other, original.token, base64url::encode(&[0xab; 16])).unwrap();
        let store = InMemoryNonceStore::new(16);
        let offered = offered();
        let ctx = RenewalContext::new(Timestamp(now.0 + 86_400), &offered, &revoked, &store, now);
        let err = process_renewal_request(&request, &issuer, &ctx)
            .await
            .unwrap_err();
        assert!(matches!(err, TctError::PopFailed), "got {err:?}");
        assert_eq!(renewal_error_code(&err), ErrorCode::PopResponseInvalid);
    }

    /// §4 step 6: a grant the policy returns outside its input is dropped.
    #[tokio::test]
    async fn grant_policy_cannot_widen() {
        let issuer = AitpSigningKey::from_seed(&[0x7e; 32]);
        let holder = AitpSigningKey::from_seed(&[0x7f; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0xac; 16])).unwrap();
        let store = InMemoryNonceStore::new(16);
        let offered = offered();
        let widen = |_: &Aid, _: &[String]| vec!["demo.echo".to_string(), "demo.admin".into()];
        let ctx = RenewalContext::new(
            Timestamp(now.0 + 86_400),
            &offered,
            &not_revoked,
            &store,
            now,
        )
        .grant_policy(&widen);
        let renewed = process_renewal_request(&request, &issuer, &ctx)
            .await
            .unwrap();
        assert_eq!(renewed.claims.grants, vec!["demo.echo".to_string()]);
    }

    /// §4 step 2: a TCT whose `aud` is not its `sub` is not one this
    /// issuer issued for renewal. (`TctBuilder` refuses to mint one.)
    #[test]
    fn audience_other_than_subject_is_tct_signature_invalid() {
        assert_eq!(
            renewal_error_code(&TctError::AudienceMismatch),
            ErrorCode::TctSignatureInvalid
        );
    }

    #[test]
    fn malformed_request_body_is_pop_response_invalid() {
        for body in [
            &b"not json"[..],
            br#"{"current_tct":"a","pop_nonce":"b"}"#,
            br#"{"current_tct":"a","pop_nonce":"b","pop_signature":"c","x":1}"#,
            br#"{"current_tct":"a","pop_nonce":"b","pop_signature":"c","pop_nonce":"d"}"#,
        ] {
            let err = parse_renewal_request(body).unwrap_err();
            assert_eq!(renewal_error_code(&err), ErrorCode::PopResponseInvalid);
        }
    }

    struct Exchange {
        issuer: AitpSigningKey,
        holder: AitpSigningKey,
        current: String,
        nonce: String,
        renewed: IssuedTct,
        now: Timestamp,
    }

    async fn exchange() -> Exchange {
        let issuer = AitpSigningKey::from_seed(&[0x83; 32]);
        let holder = AitpSigningKey::from_seed(&[0x84; 32]);
        let now = Timestamp(1_700_000_000);
        let current = issue(&issuer, &holder, now, 600).token;
        let nonce = base64url::encode(&[0xae; 16]);
        let request = build_renewal_request(&holder, current.clone(), nonce.clone()).unwrap();
        let renewed = renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 600)
            .await
            .unwrap();
        Exchange {
            issuer,
            holder,
            current,
            nonce,
            renewed,
            now,
        }
    }

    #[tokio::test]
    async fn holder_accepts_the_issuer_response() {
        let x = exchange().await;
        let env = renewal_response_envelope(&x.issuer, &x.renewed, &x.nonce, Uuid::new_v4(), x.now)
            .unwrap();
        let ctx = RenewalResponseContext::new(x.holder.aid(), &x.current, &x.nonce, x.now);
        let out = verify_renewal_response(&env, &ctx).unwrap();
        assert_eq!(out.tct.claims.jti, x.renewed.claims.jti);
        assert_eq!(out.grant_voucher, x.renewed.voucher);
    }

    #[tokio::test]
    async fn holder_rejects_a_bad_response() {
        let x = exchange().await;
        let ctx = RenewalResponseContext::new(x.holder.aid(), &x.current, &x.nonce, x.now);

        // Step 3: another nonce echoed.
        let other_nonce = base64url::encode(&[0xaf; 16]);
        let env =
            renewal_response_envelope(&x.issuer, &x.renewed, &other_nonce, Uuid::new_v4(), x.now)
                .unwrap();
        let err = verify_renewal_response(&env, &ctx).unwrap_err();
        assert_eq!(err.error_code(), ErrorCode::NonceMismatch);

        // Step 2: signed by someone other than the issuer.
        let env = renewal_response_envelope(&x.holder, &x.renewed, &x.nonce, Uuid::new_v4(), x.now)
            .unwrap();
        let err = verify_renewal_response(&env, &ctx).unwrap_err();
        assert_eq!(err.error_code(), ErrorCode::PeerMismatch);

        // Step 1: outside the timestamp window.
        let env = renewal_response_envelope(
            &x.issuer,
            &x.renewed,
            &x.nonce,
            Uuid::new_v4(),
            Timestamp(x.now.0 - 3600),
        )
        .unwrap();
        let err = verify_renewal_response(&env, &ctx).unwrap_err();
        assert_eq!(err.error_code(), ErrorCode::TimestampExpired);

        // Step 6: a grant the current TCT does not carry.
        let wider = TctBuilder::new(&x.issuer)
            .subject(x.holder.aid().clone())
            .audience(x.holder.aid().clone())
            .grants(["demo.echo", "demo.admin"])
            .ttl_secs(600)
            .subject_pubkey(x.holder.verifying_key())
            .issued_at(x.now)
            .build()
            .unwrap();
        let env =
            renewal_response_envelope(&x.issuer, &wider, &x.nonce, Uuid::new_v4(), x.now).unwrap();
        let err = verify_renewal_response(&env, &ctx).unwrap_err();
        assert_eq!(err.error_code(), ErrorCode::GrantOverflow);
    }

    #[tokio::test]
    async fn holder_surfaces_an_issuer_refusal() {
        let x = exchange().await;
        let ctx = RenewalResponseContext::new(x.holder.aid(), &x.current, &x.nonce, x.now);
        let env = renewal_error_envelope(
            &x.issuer,
            ErrorCode::TctRevoked,
            "revoked",
            false,
            Uuid::new_v4(),
            x.now,
        )
        .unwrap();
        let err = verify_renewal_response(&env, &ctx).unwrap_err();
        assert!(
            matches!(
                &err,
                RenewalResponseError::Refused {
                    code: ErrorCode::TctRevoked,
                    ..
                }
            ),
            "got {err:?}"
        );
        assert_eq!(err.error_code(), ErrorCode::TctRevoked);
    }
}
