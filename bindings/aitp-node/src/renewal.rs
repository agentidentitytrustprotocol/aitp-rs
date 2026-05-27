//! TCT in-band renewal (RFC-AITP-0005 §10) — Node SDK.
//!
//! Gated by the `experimental-renewal` Cargo feature: post-v0.1, no
//! wire-stability guarantee until the feature graduates.

use aitp_core::{base64url, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_tct::{build_renewal_request, process_renewal_request, TctEnvelope, TctRenewalPayload};
use napi::bindgen_prelude::*;
use rand::RngCore;

/// Holder side: build a `TctRenewalPayload` JSON. SDK generates the
/// fresh 128-bit `pop_nonce` internally.
pub(crate) fn build_renewal_request_js(
    holder_key: &AitpSigningKey,
    current_tct_envelope_json: &str,
) -> Result<String> {
    let envelope: TctEnvelope = serde_json::from_str(current_tct_envelope_json)
        .map_err(|e| Error::from_reason(format!("invalid current TCT JSON: {e}")))?;
    let mut nonce_bytes = [0u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| Error::from_reason(format!("rng failure: {e}")))?;
    let pop_nonce = base64url::encode(&nonce_bytes);

    let payload: TctRenewalPayload = build_renewal_request(holder_key, envelope, pop_nonce)
        .map_err(|e| Error::from_reason(format!("renewal request build failed: {e}")))?;

    serde_json::to_string(&payload).map_err(|e| Error::from_reason(e.to_string()))
}

/// Issuer side: verify a renewal request and mint a fresh `TctEnvelope`
/// JSON.
pub(crate) fn process_renewal_request_js(
    issuer_key: &AitpSigningKey,
    request_payload_json: &str,
    manifest_exp_unix_secs: i64,
    new_ttl_secs: i64,
) -> Result<String> {
    let request: TctRenewalPayload = serde_json::from_str(request_payload_json)
        .map_err(|e| Error::from_reason(format!("invalid renewal payload JSON: {e}")))?;
    let tct = process_renewal_request(
        &request,
        issuer_key,
        Timestamp(manifest_exp_unix_secs),
        Timestamp::now(),
        new_ttl_secs,
    )
    .map_err(|e| Error::from_reason(format!("renewal request rejected: {e}")))?;
    serde_json::to_string(&TctEnvelope { tct }).map_err(|e| Error::from_reason(e.to_string()))
}
