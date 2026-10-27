//! Downstream proof-of-possession binding (RFC-AITP-0005 §6).
//!
//! The consuming peer challenges the holder of a presented TCT, the holder
//! signs `sha256(base64url_decode(nonce))` with the key its `sub` AID
//! encodes, and the consumer verifies every §6.2 step. The JSON values
//! passed here are the `pop_challenge` / `pop_response` *payloads*; wrap
//! them in signed envelopes (`signEnvelope`) for the wire.
//!
//! Nonce single use (RFC-AITP-0001 §5.5) stays with the caller: the SDK
//! keeps no record of the challenges it issued or the responses it saw.

use aitp::core::{base64url, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::tct::{PopChallenge, PopResponse, TctClaims, TctError};
use napi::bindgen_prelude::*;
use napi::Env;
use napi_derive::napi;
use rand::TryRng;
use serde::Deserialize;
use uuid::Uuid;

use crate::tct::peek_tct_claims;
use crate::throw_with_code;

/// A malformed or stale challenge (RFC-AITP-0005 §6.2).
pub const POP_CHALLENGE_INVALID: &str = "POP_CHALLENGE_INVALID";
/// A response that fails any §6.2 step.
pub const POP_RESPONSE_INVALID: &str = "POP_RESPONSE_INVALID";

/// Nonce length: 128 bits (RFC-AITP-0005 §6.1).
const NONCE_BYTES: usize = 16;

/// A downstream PoP exchange for `verifyTct(..., pop)`: the challenge from
/// `newPopChallenge` and the holder's `signPopResponse` reply.
#[napi(object)]
pub struct PopExchange {
    /// The `pop_challenge` payload JSON this verifier issued.
    pub challenge: String,
    /// The holder's `pop_response` payload JSON.
    pub response: String,
}

/// The challenge as the holder may receive it: the wire payload
/// (`tct_jti`, `nonce`), or the consumer's full [`PopChallenge`] with its
/// local `expires_at`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceivedChallenge {
    tct_jti: Uuid,
    nonce: String,
    #[serde(default)]
    expires_at: Option<Timestamp>,
}

/// Refuse a nonce that is not 128 bits of unpadded base64url.
fn check_nonce(env: Env, nonce: &str) -> Result<()> {
    match base64url::decode_strict(nonce) {
        Ok(bytes) if bytes.len() == NONCE_BYTES => Ok(()),
        _ => Err(throw_with_code(
            env,
            POP_CHALLENGE_INVALID,
            format!("PoP challenge nonce is not 128 bits of base64url: {nonce:?}"),
        )),
    }
}

/// Parse the consumer's own challenge, as `newPopChallenge` returned it.
pub fn parse_challenge(env: Env, challenge_json: &str) -> Result<PopChallenge> {
    let challenge: PopChallenge = serde_json::from_str(challenge_json).map_err(|e| {
        throw_with_code(
            env,
            POP_CHALLENGE_INVALID,
            format!("malformed PoP challenge: {e}"),
        )
    })?;
    check_nonce(env, &challenge.nonce)?;
    Ok(challenge)
}

/// Parse a holder's `pop_response` payload.
pub fn parse_response(env: Env, response_json: &str) -> Result<PopResponse> {
    serde_json::from_str(response_json).map_err(|e| {
        throw_with_code(
            env,
            POP_RESPONSE_INVALID,
            format!("malformed PoP response: {e}"),
        )
    })
}

/// Run every RFC-AITP-0005 §6.2 check of `response` against `challenge`
/// and the TCT `claims`: jti, nonce echo, challenge expiry, the signature
/// under the key `sub` encodes, and `cnf.jkt`. A stale challenge throws
/// `POP_CHALLENGE_INVALID`, any other failure `POP_RESPONSE_INVALID`.
pub fn verify_against(
    env: Env,
    challenge: &PopChallenge,
    response: &PopResponse,
    claims: &TctClaims,
) -> Result<()> {
    aitp::tct::verify_pop_response(challenge, response, claims, Timestamp::now()).map_err(|e| {
        match e {
            TctError::PopChallengeExpired => throw_with_code(
                env,
                POP_CHALLENGE_INVALID,
                format!("PoP challenge stale: {e}"),
            ),
            _ => throw_with_code(
                env,
                POP_RESPONSE_INVALID,
                format!("PoP response invalid: {e}"),
            ),
        }
    })
}

/// Consumer side: a `pop_challenge` for the presented `tct_token`, with a
/// fresh CSPRNG 128-bit nonce, expiring `ttl_secs` from now.
pub fn new_pop_challenge_js(tct_token: &str, ttl_secs: i64) -> Result<String> {
    if ttl_secs < 1 {
        return Err(Error::from_reason(format!(
            "ttlSecs must be >= 1, got {ttl_secs}"
        )));
    }
    let claims = peek_tct_claims(tct_token)?;
    let mut nonce = [0u8; NONCE_BYTES];
    rand::rngs::SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| Error::from_reason(format!("rng failure: {e}")))?;
    let challenge = PopChallenge::new(
        claims.jti,
        base64url::encode(&nonce),
        Timestamp::now().plus_secs(ttl_secs),
    );
    serde_json::to_string(&challenge).map_err(|e| Error::from_reason(e.to_string()))
}

/// Holder side: sign a received challenge with `holder_key` (§6.1). An
/// `expires_at` already past is refused.
pub fn sign_pop_response_js(
    env: Env,
    holder_key: &AitpSigningKey,
    challenge_json: &str,
) -> Result<String> {
    let received: ReceivedChallenge = serde_json::from_str(challenge_json).map_err(|e| {
        throw_with_code(
            env,
            POP_CHALLENGE_INVALID,
            format!("malformed PoP challenge: {e}"),
        )
    })?;
    check_nonce(env, &received.nonce)?;
    let now = Timestamp::now();
    if received.expires_at.is_some_and(|exp| now.0 > exp.0) {
        return Err(throw_with_code(
            env,
            POP_CHALLENGE_INVALID,
            "PoP challenge stale: expired".into(),
        ));
    }
    let challenge = PopChallenge::new(
        received.tct_jti,
        received.nonce,
        received.expires_at.unwrap_or(now),
    );
    let response = aitp::tct::sign_pop_response(&challenge, holder_key)
        .map_err(|e| Error::from_reason(format!("PoP signing failed: {e}")))?;
    serde_json::to_string(&response).map_err(|e| Error::from_reason(e.to_string()))
}

/// Verify a holder's PoP response for `tctToken` (RFC-AITP-0005 §6.2) and
/// return the proven holder AID (the TCT's `sub`).
///
/// This proves possession of the key `sub` encodes. It does **not**
/// verify the TCT itself; `AitpAgent.verifyTct(..., pop)` does both. A
/// malformed or stale challenge throws with `code ===
/// 'POP_CHALLENGE_INVALID'`, any other failure with `code ===
/// 'POP_RESPONSE_INVALID'`.
#[napi(js_name = "verifyPopResponse")]
pub fn verify_pop_response_js(
    env: Env,
    challenge_json: String,
    response_json: String,
    tct_token: String,
) -> Result<String> {
    let challenge = parse_challenge(env, &challenge_json)?;
    let response = parse_response(env, &response_json)?;
    let claims = peek_tct_claims(&tct_token)?;
    verify_against(env, &challenge, &response, &claims)?;
    Ok(claims.sub.to_string())
}
