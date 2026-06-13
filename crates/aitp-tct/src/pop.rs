//! Downstream Proof-of-Possession exchange (RFC-AITP-0005 §6).
//!
//! After the handshake, a peer presenting a TCT may be challenged by the
//! consuming peer. The exchange is two messages:
//!
//! 1. **Challenge.** Consumer sends a random `nonce` plus the TCT's `jti`.
//! 2. **Response.** Holder echoes the nonce and signs
//!    `sha256(base64url_decode(nonce))` with the private key bound by
//!    the TCT's `sub` AID / `cnf.jkt`. Per RFC-AITP-0005 §6.1+§6.2, the
//!    hash input is the **decoded raw bytes** of the nonce, NOT its
//!    ASCII string form.

use crate::types::TctClaims;
use crate::TctError;
use aitp_core::{base64url, Timestamp};
use aitp_crypto::{AitpVerifyingKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// PoP challenge sent by a consuming peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PopChallenge {
    /// JTI of the TCT being challenged.
    pub tct_jti: Uuid,
    /// Random base64url nonce — the holder MUST sign over this in the response.
    pub nonce: String,
    /// Expiry of the challenge.
    pub expires_at: Timestamp,
}

/// PoP response signed by the TCT holder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PopResponse {
    /// JTI of the TCT being proven.
    pub tct_jti: Uuid,
    /// The challenge nonce, echoed.
    pub nonce_echo: String,
    /// Holder's signature: `sign(holder_priv, sha256(base64url_decode(nonce)))`.
    pub pop_signature: String,
}

/// Sign a PoP challenge.
///
/// Per RFC-AITP-0005 §6.1+§6.2 (rc.2), the signing input is the
/// SHA-256 of the **decoded raw bytes** of the nonce — not its ASCII
/// string form. This brings TCT PoP into alignment with RFC-AITP-0002
/// §3.1's `pop_nonce_decoded_bytes` rule for the handshake pinned-key
/// proof.
pub fn sign_pop_response(
    challenge: &PopChallenge,
    holder_key: &aitp_crypto::AitpSigningKey,
) -> Result<PopResponse, TctError> {
    let nonce_bytes =
        base64url::decode_strict(&challenge.nonce).map_err(|_| TctError::PopFailed)?;
    let digest = Sha256::digest(&nonce_bytes);
    let sig = holder_key.sign(&digest);
    Ok(PopResponse {
        tct_jti: challenge.tct_jti,
        nonce_echo: challenge.nonce.clone(),
        pop_signature: sig.into_string(),
    })
}

/// Verify a PoP response.
///
/// 1. `response.tct_jti == challenge.tct_jti` (else [`TctError::PopJtiMismatch`])
/// 2. `response.nonce_echo == challenge.nonce` (else [`TctError::PopNonceMismatch`])
/// 3. `now <= challenge.expires_at` (else [`TctError::PopChallengeExpired`])
/// 4. The signature verifies over
///    `sha256(base64url_decode(challenge.nonce))` using the key encoded
///    in `claims.sub` — the AID is authoritative for the bound key
///    (RFC-AITP-0005 §3). Else [`TctError::PopFailed`].
/// 5. `claims.cnf.jkt` equals that key's RFC 7638 thumbprint
///    (RFC-AITP-0005 §6.2 step 4).
pub fn verify_pop_response(
    challenge: &PopChallenge,
    response: &PopResponse,
    claims: &TctClaims,
    now: Timestamp,
) -> Result<(), TctError> {
    if response.tct_jti != challenge.tct_jti || response.tct_jti != claims.jti {
        return Err(TctError::PopJtiMismatch);
    }
    if response.nonce_echo != challenge.nonce {
        return Err(TctError::PopNonceMismatch);
    }
    if now.is_in_the_future(challenge.expires_at) {
        return Err(TctError::PopChallengeExpired);
    }

    // The subject AID encodes the bound key; cnf.jkt is its
    // (deliberately redundant) RFC 7638 thumbprint. Cross-check both
    // before trusting the key for PoP (RFC-AITP-0005 §6.2 step 4).
    let holder_pk = AitpVerifyingKey::from_aid(&claims.sub).map_err(|_| TctError::CnfMalformed)?;
    let expected_jkt = holder_pk
        .to_jwk_thumbprint()
        .map_err(|_| TctError::CnfMalformed)?;
    if claims.cnf.jkt != expected_jkt {
        return Err(TctError::CnfMalformed);
    }
    let nonce_bytes =
        base64url::decode_strict(&challenge.nonce).map_err(|_| TctError::PopFailed)?;
    let digest = Sha256::digest(&nonce_bytes);
    let sig = Signature::parse(&response.pop_signature).map_err(|_| TctError::PopFailed)?;
    holder_pk
        .verify(&digest, &sig)
        .map_err(|_| TctError::PopFailed)?;
    Ok(())
}
