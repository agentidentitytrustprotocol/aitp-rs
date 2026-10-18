//! TCT in-band renewal (RFC-AITP-0013).
//!
//! Gated by the `renewal` Cargo feature: post-v0.1, no
//! wire-stability guarantee until the feature graduates.

use aitp_core::nonce_store::InMemoryNonceStore;
use aitp_core::{base64url, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_tct::{build_renewal_request, process_renewal_request, RenewalContext, TctRenewalPayload};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use rand::TryRng;
use std::collections::HashSet;
use std::future::Future;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use uuid::Uuid;

/// Holder side: build a `TctRenewalPayload` JSON.
///
/// `current_tct_token` is the currently-held TCT as a compact-JWS string.
/// The SDK generates a fresh 128-bit `pop_nonce` internally; callers
/// don't have to manage it.
pub fn build_renewal_request_py(
    holder_key: &AitpSigningKey,
    current_tct_token: &str,
) -> PyResult<String> {
    let mut nonce_bytes = [0u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| PyRuntimeError::new_err(format!("rng failure: {e}")))?;
    let pop_nonce = base64url::encode(&nonce_bytes);

    let payload: TctRenewalPayload =
        build_renewal_request(holder_key, current_tct_token.to_string(), pop_nonce)
            .map_err(|e| PyRuntimeError::new_err(format!("renewal request build failed: {e}")))?;

    serde_json::to_string(&payload).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Issuer side: verify a renewal request and mint a fresh TCT.
///
/// `manifest_exp_unix_secs` bounds the new TCT's expiry to the issuer
/// manifest's window; `new_ttl_secs` is the requested lifetime (capped
/// by the bound). `offered_grants` is the issuer Manifest's current
/// `offered_capabilities`: grants it no longer offers are dropped, and
/// none left refuses the renewal. `revoked_jtis` lists the issuer's
/// revoked TCT `jti`s; a revoked TCT is refused. Each `pop_nonce` is
/// recorded in a process-wide replay guard and a repeat is refused
/// (RFC-AITP-0004 §8.1). Returns a JSON object
/// `{"tct": "<compact JWS>", "grant_voucher": "<compact JWS>" | null}`.
pub fn process_renewal_request_py(
    issuer_key: &AitpSigningKey,
    request_payload_json: &str,
    manifest_exp_unix_secs: i64,
    new_ttl_secs: i64,
    offered_grants: &[String],
    revoked_jtis: &[String],
) -> PyResult<String> {
    let request: TctRenewalPayload = serde_json::from_str(request_payload_json)
        .map_err(|e| PyValueError::new_err(format!("invalid renewal payload JSON: {e}")))?;
    let revoked = revoked_jtis
        .iter()
        .map(|j| Uuid::parse_str(j))
        .collect::<Result<HashSet<Uuid>, _>>()
        .map_err(|e| PyValueError::new_err(format!("invalid revoked jti: {e}")))?;
    let revocation_check = move |jti: &Uuid| revoked.contains(jti);
    let ctx = RenewalContext::new(
        Timestamp(manifest_exp_unix_secs),
        offered_grants,
        &revocation_check,
        renewal_nonce_store(),
        Timestamp::now(),
    )
    .ttl_secs(new_ttl_secs);
    let issued = poll_ready(process_renewal_request(&request, issuer_key, &ctx))
        .ok_or_else(|| PyRuntimeError::new_err("renewal replay guard did not complete"))?
        .map_err(|e| PyRuntimeError::new_err(format!("renewal request rejected: {e}")))?;
    let out = serde_json::json!({
        "tct": issued.token,
        "grant_voucher": issued.voucher,
    });
    serde_json::to_string(&out).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// The process-wide renewal replay guard. Shared by every agent in the
/// process; holds each nonce until the presented TCT expires.
fn renewal_nonce_store() -> &'static InMemoryNonceStore {
    static STORE: OnceLock<InMemoryNonceStore> = OnceLock::new();
    STORE.get_or_init(InMemoryNonceStore::default)
}

/// Poll a future once. Renewal against the in-memory store never
/// suspends, so it is always ready; `None` would mean it did.
fn poll_ready<F: Future>(fut: F) -> Option<F::Output> {
    let mut fut = std::pin::pin!(fut);
    match fut
        .as_mut()
        .poll(&mut Context::from_waker(std::task::Waker::noop()))
    {
        Poll::Ready(out) => Some(out),
        Poll::Pending => None,
    }
}
