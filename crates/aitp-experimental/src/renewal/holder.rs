//! Holder side of TCT renewal (RFC-AITP-0013 §3, §6.1).

use crate::renewal::peek::peek_claims;
use crate::renewal::{
    renewal_pop_input, RenewalError, RenewalErrorPayload, RenewalResponseError,
    RenewalResponsePayload, TctRenewalPayload, RENEWAL_RESPONSE_PAYLOAD_MEMBERS,
};
use aitp::__private::check_members;
use aitp::core::{base64url, Aid, AitpEnvelope, MessageType, Timestamp};
use aitp::crypto::{sign_jcs, AitpSigner, AitpVerifyingKey, CryptoError, Digest32};
use aitp::envelope::verify_envelope_signature;
use aitp::tct::{verify_tct, TctError, TctVerifyContext, VerifiedTct};

/// Build a [`TctRenewalPayload`] on the holder side (RFC-AITP-0013 §3).
///
/// `pop_nonce` is a fresh 22-character base64url nonce. The holder signs
/// `sha256(`[`renewal_pop_input`]`)` over the current TCT's `iss` and
/// `jti`, read from `current_tct`.
///
/// Accepts any [`AitpSigner`] (in-process key, KMS, HSM); a backend
/// failure returns `RenewalError::Tct(TctError::Crypto(CryptoError::Signer(_)))`.
pub fn build_renewal_request(
    holder_key: &dyn AitpSigner,
    current_tct: String,
    pop_nonce: String,
) -> Result<TctRenewalPayload, RenewalError> {
    let nonce_bytes = base64url::decode_strict(&pop_nonce)
        .map_err(|e| RenewalError::NonceMalformed(e.to_string()))?;
    let current = peek_claims(&current_tct)?;
    let input = renewal_pop_input(current.iss.as_str(), &current.jti.to_string(), &nonce_bytes);
    let digest = Digest32::sha256(&input);
    let pop_signature = sign_jcs(holder_key, &digest)
        .map_err(|e| TctError::Crypto(CryptoError::Signer(e)))?
        .into_string();
    Ok(TctRenewalPayload {
        current_tct,
        pop_nonce,
        pop_signature,
    })
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

/// Holder side: check the issuer's answer to a renewal request
/// (RFC-AITP-0013 §6.1 steps 1 to 6), stopping at the first failure.
/// The envelope has already passed [`aitp::core::parse_envelope_wire`]
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
    verify_envelope_signature(envelope, &sender_pk)
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
    let builder = TctVerifyContext::builder()
        .expected_audience(ctx.self_aid)
        .issuer(&current.iss)
        .now(ctx.now)
        .revocation(aitp::tct::RevocationSource::FailOpen);
    let builder = match ctx.issuer_manifest_expires_at {
        Some(exp) => builder.issuer_manifest_expires_at(exp),
        None => builder.skip_manifest_expiry_cap_dangerous(),
    };
    let verify_ctx = builder.build().expect("both decisions are made");
    let renewed = verify_tct(&payload.tct, &verify_ctx).map_err(RenewalResponseError::Tct)?;

    // Step 5.
    if &renewed.claims().sub != ctx.self_aid || renewed.claims().cnf.jkt != current.cnf.jkt {
        return Err(RenewalResponseError::AudienceMismatch);
    }

    // Step 6.
    if renewed
        .claims()
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
