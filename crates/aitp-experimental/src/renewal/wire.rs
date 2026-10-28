//! Renewal wire shapes and the `rfc-aitp-0005.renew_uri` Manifest
//! extension (RFC-AITP-0013 §2, §3, §6).

use crate::renewal::RenewalErrorCode;
use aitp::manifest::Manifest;
use serde::{Deserialize, Serialize};

/// Manifest extension key carrying the issuer's TCT renewal endpoint
/// (registered Provisional in the spec's `registries/extension-keys.md`).
///
/// ```json
/// "extensions": {
///   "rfc-aitp-0005.renew_uri": "https://issuer.example/aitp/handshake/renew"
/// }
/// ```
///
/// A holder renews only at that URL. When the key is absent the holder
/// runs a full Mutual Handshake and never probes a guessed path.
pub const RENEW_URI_EXT: &str = "rfc-aitp-0005.renew_uri";

/// The renewal endpoint a Manifest advertises, if any.
///
/// Returns `None` when the extension is missing, not a string, not a URL,
/// or not HTTPS. Plain `http` is accepted only for `localhost` and
/// `127.0.0.1`, and only when `allow_insecure_localhost` is `true`.
/// Never enable it in production.
pub fn renew_uri_from_manifest(
    manifest: &Manifest,
    allow_insecure_localhost: bool,
) -> Option<url::Url> {
    manifest
        .extensions
        .as_ref()?
        .get(RENEW_URI_EXT)
        .and_then(|v| v.as_str())
        .and_then(|s| url::Url::parse(s).ok())
        .filter(|u| match u.scheme() {
            "https" => true,
            "http" => {
                allow_insecure_localhost && matches!(u.host_str(), Some("localhost" | "127.0.0.1"))
            }
            _ => false,
        })
}

/// TCT renewal request body (RFC-AITP-0013 §3).
///
/// The holder presents the currently-held TCT (opaque compact string),
/// a fresh `pop_nonce`, and a `pop_signature` over
/// `sha256(`[`crate::renewal::renewal_pop_input`]`)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TctRenewalPayload {
    /// The currently-held TCT compact JWS being renewed.
    pub current_tct: String,
    /// Holder-supplied fresh nonce (22-char base64url, 16 bytes).
    pub pop_nonce: String,
    /// `sign(holder_key, sha256(renewal_pop_input))` (RFC-AITP-0013 §3.1).
    pub pop_signature: String,
}

impl TctRenewalPayload {
    /// A request body from its three members.
    pub fn new(current_tct: String, pop_nonce: String, pop_signature: String) -> Self {
        Self {
            current_tct,
            pop_nonce,
            pop_signature,
        }
    }
}

/// Payload of a `tct` renewal response envelope (RFC-AITP-0013 §6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RenewalResponsePayload {
    /// The renewed TCT, compact JWS.
    pub tct: String,
    /// The renewed TCT's companion grant voucher, when minted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_voucher: Option<String>,
    /// The request's `pop_nonce`, byte for byte.
    pub pop_nonce_echo: String,
}

/// Members of [`RenewalResponsePayload`].
pub const RENEWAL_RESPONSE_PAYLOAD_MEMBERS: &[&str] = &["tct", "grant_voucher", "pop_nonce_echo"];

/// Payload of an `error` envelope (RFC-AITP-0001 §5.6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct RenewalErrorPayload {
    /// The registered error code.
    pub code: RenewalErrorCode,
    /// Informational text; never used for decisions.
    #[serde(default)]
    pub reason: String,
    /// Whether the holder may retry the same request later.
    #[serde(default)]
    pub retryable: bool,
}
