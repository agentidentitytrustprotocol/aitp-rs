//! The holder's TCT renewal HTTP client (RFC-AITP-0013 §2, §3, §6.1).

use crate::renewal::{
    build_renewal_request, renew_uri_from_manifest, verify_renewal_response, RenewalError,
    RenewalResponseContext, RenewalResponseError, RenewedTct,
};
use aitp::core::{base64url, parse_envelope_wire, CheckedJson, EnvelopeParseError, Timestamp};
use aitp::crypto::AitpSigner;
use aitp::manifest::Manifest;
use aitp::transport::HostGuard;
use std::time::Duration;

/// Maximum renewal response body size.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Request timeout.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Why [`renew_tct`] failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RenewClientError {
    /// The issuer Manifest advertises no usable
    /// `rfc-aitp-0005.renew_uri`. Run a full Mutual Handshake instead.
    #[error("issuer Manifest advertises no rfc-aitp-0005.renew_uri; run a full handshake")]
    NotAdvertised,
    /// The endpoint was refused by the host guard, or the HTTP exchange
    /// failed.
    #[error("http: {0}")]
    Http(String),
    /// The request could not be built.
    #[error("renewal request: {0}")]
    Request(#[from] RenewalError),
    /// The issuer's answer failed RFC-AITP-0013 §6.1, or the issuer
    /// refused the renewal ([`RenewalResponseError::Refused`]).
    #[error("renewal response: {0}")]
    Response(#[from] RenewalResponseError),
}

/// Renew `current` at the endpoint `issuer_manifest` advertises as
/// `rfc-aitp-0005.renew_uri` (RFC-AITP-0013 §2).
///
/// `issuer_manifest` is the issuer's verified Manifest. Only an `https`
/// `renew_uri` is used; see [`renew_tct_with_insecure_localhost`]. With
/// no usable `renew_uri` this returns [`RenewClientError::NotAdvertised`]
/// without sending anything. The endpoint is resolved through a default
/// [`HostGuard`], with redirects off and a 10 s timeout. The answer is
/// checked with [`verify_renewal_response`] before the renewed TCT is
/// returned.
pub async fn renew_tct(
    holder_key: &dyn AitpSigner,
    current: String,
    issuer_manifest: &Manifest,
) -> Result<RenewedTct, RenewClientError> {
    renew(holder_key, current, issuer_manifest, false).await
}

/// [`renew_tct`] that also accepts a plain-`http` `renew_uri` on
/// `localhost` / `127.0.0.1` and admits loopback addresses through the
/// host guard ([`HostGuard::allow_loopback_dangerous`]). Never use it in
/// production.
pub async fn renew_tct_with_insecure_localhost(
    holder_key: &dyn AitpSigner,
    current: String,
    issuer_manifest: &Manifest,
) -> Result<RenewedTct, RenewClientError> {
    renew(holder_key, current, issuer_manifest, true).await
}

async fn renew(
    holder_key: &dyn AitpSigner,
    current: String,
    issuer_manifest: &Manifest,
    allow_insecure_localhost: bool,
) -> Result<RenewedTct, RenewClientError> {
    let url = renew_uri_from_manifest(issuer_manifest, allow_insecure_localhost)
        .ok_or(RenewClientError::NotAdvertised)?;
    let pop_nonce = base64url::encode(&rand_bytes_16());
    let request = build_renewal_request(holder_key, current, pop_nonce)?;

    let mut guard = HostGuard::default();
    if allow_insecure_localhost {
        guard = guard.allow_loopback_dangerous();
    }
    let addrs = guard
        .resolve_checked(&url)
        .await
        .map_err(|e| RenewClientError::Http(format!("renewal endpoint rejected: {e}")))?;
    let mut builder = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(url::Host::Domain(domain)) = url.host() {
        builder = builder.resolve_to_addrs(domain, &addrs);
    }
    let client = builder
        .build()
        .map_err(|e| RenewClientError::Http(e.to_string()))?;
    let resp = client
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(|e| RenewClientError::Http(e.to_string()))?;
    // RFC-AITP-0013 §6: the holder decides from the envelope, whatever
    // the HTTP status.
    let body = read_capped(resp).await?;
    let value = CheckedJson::from_slice(&body)
        .map_err(|e| RenewClientError::Http(format!("malformed JSON in renewal response: {e}")))?;
    let envelope = parse_envelope_wire(&value).map_err(|e| match e {
        EnvelopeParseError::UnknownField(field) => RenewalResponseError::UnknownField(field),
        other => RenewalResponseError::InvalidEnvelope(other.to_string()),
    })?;
    let ctx = RenewalResponseContext::new(
        holder_key.aid(),
        &request.current_tct,
        &request.pop_nonce,
        Timestamp::now(),
    )
    .issuer_manifest_expires_at(issuer_manifest.expires_at);
    Ok(verify_renewal_response(&envelope, &ctx)?)
}

/// The response body, refused once it exceeds [`MAX_RESPONSE_BYTES`].
async fn read_capped(mut resp: reqwest::Response) -> Result<Vec<u8>, RenewClientError> {
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
    {
        return Err(RenewClientError::Http(format!(
            "response exceeds {MAX_RESPONSE_BYTES}-byte limit"
        )));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| RenewClientError::Http(e.to_string()))?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(RenewClientError::Http(format!(
                "response exceeds {MAX_RESPONSE_BYTES}-byte limit"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn rand_bytes_16() -> [u8; 16] {
    // `SysRng` is fallible; `UnwrapErr` panics if the OS randomness
    // source fails rather than falling back to a weaker generator.
    use rand::Rng;
    let mut buf = [0u8; 16];
    rand::rand_core::UnwrapErr(rand::rngs::SysRng).fill_bytes(&mut buf);
    buf
}
