//! TCT in-band renewal (RFC-AITP-0013) — Node SDK.
//!
//! Gated by the `experimental-renewal` Cargo feature, which the
//! published package does not enable. No stability promise.
//!
//! In v0.2 the current TCT is an **opaque compact-JWS token string**, and
//! the renewal request / fresh TCT are likewise tokens (the renewal
//! payload is a small JSON object wrapping the token).

use aitp::core::nonce_store::InMemoryNonceStore;
use aitp::core::{base64url, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp_experimental::renewal::{
    build_renewal_request, process_renewal_request, RenewalContext, TctRenewalPayload,
};
use napi::bindgen_prelude::*;
use rand::TryRng;
use std::future::Future;
use std::sync::OnceLock;
use std::task::{Context, Poll};

use crate::tct::JsIssuedTct;

/// Holder side: build a `TctRenewalPayload` JSON. SDK generates the
/// fresh 128-bit `pop_nonce` internally.
///
/// `current_tct_token` is the holder's current TCT as a compact-JWS
/// string (the `tct` field from `complete()` / `processCommit()`).
pub(crate) fn build_renewal_request_js(
    holder_key: &AitpSigningKey,
    current_tct_token: &str,
) -> Result<String> {
    let mut nonce_bytes = [0u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| Error::from_reason(format!("rng failure: {e}")))?;
    let pop_nonce = base64url::encode(&nonce_bytes);

    let payload: TctRenewalPayload =
        build_renewal_request(holder_key, current_tct_token.to_string(), pop_nonce)
            .map_err(|e| Error::from_reason(format!("renewal request build failed: {e}")))?;

    serde_json::to_string(&payload).map_err(|e| Error::from_reason(e.to_string()))
}

/// Issuer side: verify a renewal request and mint a fresh TCT. Returns
/// `{ tct, grantVoucher }` — the fresh TCT compact JWS plus its companion
/// grant voucher (`null` when none was minted).
///
/// `offered_grants` is the issuer Manifest's current
/// `offered_capabilities`: grants it no longer offers are dropped, and
/// none left refuses the renewal. `revoked_jtis` lists the issuer's
/// revoked TCT `jti`s; a revoked TCT is refused. The list is a lookup key,
/// so each entry is normalized (any RFC 9562 text form is accepted) and an
/// entry that is not a UUID at all is refused. Each `pop_nonce` is
/// recorded in a process-wide replay guard and a repeat is refused
/// (RFC-AITP-0013).
pub(crate) fn process_renewal_request_js(
    issuer_key: &AitpSigningKey,
    request_payload_json: &str,
    manifest_exp_unix_secs: f64,
    new_ttl_secs: i64,
    offered_grants: &[String],
    revoked_jtis: &[String],
) -> Result<JsIssuedTct> {
    let request: TctRenewalPayload = serde_json::from_str(request_payload_json)
        .map_err(|e| Error::from_reason(format!("invalid renewal payload JSON: {e}")))?;
    let revoked = crate::helpers::parse_revoked_jtis(revoked_jtis.iter().map(String::as_str))
        .map_err(Error::from_reason)?;
    // The issuer's own list is authoritative, so an empty one is "nothing
    // revoked", never "unavailable".
    let revocation_check = move |q: &aitp::tct::RevocationQuery<'_>| {
        Ok(if revoked.contains(q.jti) {
            aitp::tct::RevocationStatus::Revoked
        } else {
            aitp::tct::RevocationStatus::Clear
        })
    };
    let ctx = RenewalContext::new(
        crate::helpers::finite_unix_secs("manifestExpUnixSecs", manifest_exp_unix_secs)?,
        offered_grants,
        aitp::tct::RevocationSource::Check(&revocation_check),
        renewal_nonce_store(),
        Timestamp::now(),
    )
    .ttl(std::time::Duration::from_secs(
        u64::try_from(new_ttl_secs).unwrap_or(0),
    ));
    let issued = poll_ready(process_renewal_request(&request, issuer_key, &ctx))
        .ok_or_else(|| Error::from_reason("renewal replay guard did not complete"))?
        .map_err(|e| Error::from_reason(format!("renewal request rejected: {e}")))?;
    Ok(issued.into())
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
