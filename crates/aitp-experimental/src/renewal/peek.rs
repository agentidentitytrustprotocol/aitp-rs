//! Unverified TCT claim decode and `pop_nonce` decode.

use crate::renewal::RenewalError;
use aitp::core::nonce_store::{Nonce, NONCE_LEN};
use aitp::core::{base64url, check_members, from_serde_error, reject_duplicate_keys};
use aitp::crypto::jws::{decode_payload_unverified, peek_typ, TYP_TCT};
use aitp::tct::{TctClaims, TctError, TCT_CLAIMS_MEMBERS};

/// The claims of a TCT, decoded without verifying it. Strict as
/// `verify_tct`'s parse: a repeated key is [`TctError::ClaimsMalformed`]
/// and, when the header `typ` is the TCT one, an unknown claim is
/// [`TctError::UnknownField`] (a `typ` confusion is left to
/// `verify_tct`'s own check).
pub(crate) fn peek_claims(token: &str) -> Result<TctClaims, TctError> {
    let peek = decode_payload_unverified(token).map_err(TctError::Crypto)?;
    reject_duplicate_keys(&peek).map_err(TctError::ClaimsMalformed)?;
    let value: serde_json::Value =
        serde_json::from_slice(&peek).map_err(|e| TctError::ClaimsMalformed(e.to_string()))?;
    if peek_typ(token).as_deref() == Some(TYP_TCT) {
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
pub(crate) fn decode_renewal_nonce(pop_nonce: &str) -> Result<Nonce, RenewalError> {
    let bytes = base64url::decode_strict(pop_nonce)
        .map_err(|e| RenewalError::NonceMalformed(e.to_string()))?;
    bytes.try_into().map_err(|b: Vec<u8>| {
        RenewalError::NonceMalformed(format!(
            "must decode to exactly {NONCE_LEN} bytes, got {}",
            b.len()
        ))
    })
}
