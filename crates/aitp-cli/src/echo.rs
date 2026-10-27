//! Wire format of the interop peer's `/echo` (`aitp echo` /
//! `aitp serve --interop`), shared by client and server.
//!
//! `/echo` is where you present the TCT the peer issued you back to it.
//! The peer is the TCT's issuer acting as resource server, so it accepts
//! the token only with downstream proof of possession over a challenge
//! it issued for that token's `jti` (RFC-AITP-0005 §10.5, §6.1):
//!
//! ```text
//! POST /echo/challenge  {tct}                -> pop_challenge envelope, signed by the peer
//! POST /echo            {tct, pop_response}  -> {echo: <verified claims>}
//! ```
//!
//! Both PoP messages are standard AITP envelopes (RFC-AITP-0005 §6.1),
//! carried in the HTTP bodies (§6.3). Refusals carry registered AITP
//! codes (`POP_RESPONSE_INVALID`, `TCT_EXPIRED`, …), except the transport
//! ones (`bad_request`, `rate_limited`, `echo_busy`).

use aitp::core::{Aid, AitpEnvelope, MessageType, Timestamp};
use aitp::crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp::envelope::{sign_envelope, verify_envelope_signature};
use aitp::tct::{sign_pop_response, PopChallenge};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The one capability the interop peer requests and grants.
pub(crate) const ECHO_CAP: &str = "aitp.interop.echo";
/// Challenge route.
pub(crate) const CHALLENGE_PATH: &str = "/echo/challenge";
/// Echo route.
pub(crate) const ECHO_PATH: &str = "/echo";

/// `POST /echo/challenge` request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChallengeRequest {
    /// The TCT the peer issued, compact JWS.
    pub tct: String,
}

/// `POST /echo` request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EchoRequest {
    /// The same TCT.
    pub tct: String,
    /// The `pop_response` envelope, signed by the TCT's subject. Kept as
    /// raw JSON: the peer parses it with the strict envelope parser.
    pub pop_response: serde_json::Value,
}

/// `pop_challenge` payload (RFC-AITP-0005 §6.1 step 1).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChallengePayload {
    /// JTI of the TCT being challenged.
    pub tct_jti: Uuid,
    /// 128 random bits, base64url without padding.
    pub nonce: String,
}

/// Check the peer's `pop_challenge` envelope for the TCT `jti` and
/// answer it with a `pop_response` envelope signed by `key`.
pub(crate) fn respond(
    key: &AitpSigningKey,
    peer_aid: &Aid,
    jti: Uuid,
    challenge: AitpEnvelope,
) -> Result<AitpEnvelope, String> {
    if challenge.message_type != MessageType::PopChallenge {
        return Err("the peer's challenge is not a pop_challenge envelope".into());
    }
    if challenge.sender.agent_id != *peer_aid {
        return Err(format!(
            "the challenge is from {}, not the peer {peer_aid}",
            challenge.sender.agent_id
        ));
    }
    let peer_key = AitpVerifyingKey::from_aid(peer_aid).map_err(|e| e.to_string())?;
    verify_envelope_signature(&challenge, &peer_key)
        .map_err(|e| format!("the challenge signature does not verify: {e}"))?;
    let payload: ChallengePayload = serde_json::from_value(challenge.payload)
        .map_err(|e| format!("malformed challenge payload: {e}"))?;
    if payload.tct_jti != jti {
        return Err("the challenge names a different TCT".into());
    }
    let response = sign_pop_response(
        // `expires_at` is not part of the signing input; the peer
        // enforces expiry.
        &PopChallenge::new(jti, payload.nonce, Timestamp::now()),
        key,
    )
    .map_err(|e| e.to_string())?;
    sign_envelope(
        key,
        MessageType::PopResponse,
        serde_json::to_value(response).map_err(|e| e.to_string())?,
    )
}
