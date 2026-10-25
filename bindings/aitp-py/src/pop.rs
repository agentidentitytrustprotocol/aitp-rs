//! Downstream proof-of-possession binding (RFC-AITP-0005 §6).
//!
//! The consuming peer challenges the holder of a presented TCT, the holder
//! signs `sha256(base64url_decode(nonce))` with the key its `sub` AID
//! encodes, and the consumer verifies every §6.2 step. The JSON values
//! passed here are the `pop_challenge` / `pop_response` *payloads*; wrap
//! them in signed envelopes (`sign_envelope`) for the wire.
//!
//! Nonce single use (RFC-AITP-0001 §5.5) stays with the caller: the SDK
//! keeps no record of the challenges it issued or the responses it saw.

use aitp_core::{base64url, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_tct::{PopChallenge, PopResponse, TctClaims, TctError};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use rand::TryRng;
use serde::Deserialize;
use uuid::Uuid;

use crate::helpers::runtime_error;
use crate::tct::decode_tct_claims_unverified;

/// A malformed or stale challenge (RFC-AITP-0005 §6.2).
pub const POP_CHALLENGE_INVALID: &str = "POP_CHALLENGE_INVALID";
/// A response that fails any §6.2 step.
pub const POP_RESPONSE_INVALID: &str = "POP_RESPONSE_INVALID";

/// Nonce length: 128 bits (RFC-AITP-0005 §6.1).
const NONCE_BYTES: usize = 16;

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

fn challenge_error(message: String) -> PyErr {
    runtime_error(message, Some(POP_CHALLENGE_INVALID))
}

fn response_error(message: String) -> PyErr {
    runtime_error(message, Some(POP_RESPONSE_INVALID))
}

/// Refuse a nonce that is not 128 bits of unpadded base64url.
fn check_nonce(nonce: &str) -> PyResult<()> {
    match base64url::decode_strict(nonce) {
        Ok(bytes) if bytes.len() == NONCE_BYTES => Ok(()),
        _ => Err(challenge_error(format!(
            "PoP challenge nonce is not 128 bits of base64url: {nonce:?}"
        ))),
    }
}

/// Parse the consumer's own challenge, as [`new_pop_challenge_py`]
/// returned it.
pub fn parse_challenge(challenge_json: &str) -> PyResult<PopChallenge> {
    let challenge: PopChallenge = serde_json::from_str(challenge_json)
        .map_err(|e| challenge_error(format!("malformed PoP challenge: {e}")))?;
    check_nonce(&challenge.nonce)?;
    Ok(challenge)
}

/// Parse a holder's `pop_response` payload.
pub fn parse_response(response_json: &str) -> PyResult<PopResponse> {
    serde_json::from_str(response_json)
        .map_err(|e| response_error(format!("malformed PoP response: {e}")))
}

/// Run every RFC-AITP-0005 §6.2 check of `response` against `challenge`
/// and the TCT `claims`: jti, nonce echo, challenge expiry, the signature
/// under the key `sub` encodes, and `cnf.jkt`. A stale challenge raises
/// `POP_CHALLENGE_INVALID`, any other failure `POP_RESPONSE_INVALID`.
pub fn verify_against(
    challenge: &PopChallenge,
    response: &PopResponse,
    claims: &TctClaims,
) -> PyResult<()> {
    aitp_tct::verify_pop_response(challenge, response, claims, Timestamp::now()).map_err(
        |e| match e {
            TctError::PopChallengeExpired => challenge_error(format!("PoP challenge stale: {e}")),
            _ => response_error(format!("PoP response invalid: {e}")),
        },
    )
}

/// Consumer side: a `pop_challenge` for the presented `tct_token`, with a
/// fresh CSPRNG 128-bit nonce, expiring `ttl_secs` from now.
pub fn new_pop_challenge_py(tct_token: &str, ttl_secs: i64) -> PyResult<String> {
    if ttl_secs < 1 {
        return Err(PyValueError::new_err(format!(
            "ttl_secs must be >= 1, got {ttl_secs}"
        )));
    }
    let claims = decode_tct_claims_unverified(tct_token)?;
    let mut nonce = [0u8; NONCE_BYTES];
    rand::rngs::SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| PyRuntimeError::new_err(format!("rng failure: {e}")))?;
    let challenge = PopChallenge {
        tct_jti: claims.jti,
        nonce: base64url::encode(&nonce),
        expires_at: Timestamp::now().plus_secs(ttl_secs),
    };
    serde_json::to_string(&challenge).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Holder side: sign a received challenge with `holder_key` (§6.1). An
/// `expires_at` already past is refused.
pub fn sign_pop_response_py(holder_key: &AitpSigningKey, challenge_json: &str) -> PyResult<String> {
    let received: ReceivedChallenge = serde_json::from_str(challenge_json)
        .map_err(|e| challenge_error(format!("malformed PoP challenge: {e}")))?;
    check_nonce(&received.nonce)?;
    let now = Timestamp::now();
    if received.expires_at.is_some_and(|exp| now.0 > exp.0) {
        return Err(challenge_error("PoP challenge stale: expired".into()));
    }
    let challenge = PopChallenge {
        tct_jti: received.tct_jti,
        nonce: received.nonce,
        expires_at: received.expires_at.unwrap_or(now),
    };
    let response = aitp_tct::sign_pop_response(&challenge, holder_key)
        .map_err(|e| PyRuntimeError::new_err(format!("PoP signing failed: {e}")))?;
    serde_json::to_string(&response).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Verify a holder's PoP response for `tct_token` and return the proven
/// holder AID (the TCT's `sub`).
///
/// This proves possession of the key `sub` encodes. It does **not**
/// verify the TCT itself; `AitpAgent.verify_tct(..., pop=...)` does both.
#[pyfunction]
#[pyo3(name = "verify_pop_response")]
pub fn verify_pop_response_py(
    challenge_json: &str,
    response_json: &str,
    tct_token: &str,
) -> PyResult<String> {
    let challenge = parse_challenge(challenge_json)?;
    let response = parse_response(response_json)?;
    let claims = decode_tct_claims_unverified(tct_token)?;
    verify_against(&challenge, &response, &claims)?;
    Ok(claims.sub.to_string())
}
