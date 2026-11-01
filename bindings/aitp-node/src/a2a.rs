//! A2A Agent Card binding, client verification (RFC-AITP-0014, Draft) —
//! Node SDK.
//!
//! Gated by the `experimental-a2a-agent-card` Cargo feature, which the
//! published package does not enable. No stability promise. No I/O: the
//! caller fetches the Manifest.

use aitp::core::{CheckedJson, ErrorCode};
use aitp_experimental::a2a::{
    locate_aitp_extension, verify_agent_card_binding, A2aBindingError, BindingContext,
    ManifestFetch,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::helpers::coded_error;

fn failed(env: Env, e: &A2aBindingError) -> Error {
    coded_error(env, Some(e.code().as_str()), e.to_string())
}

fn card(env: Env, card_json: &str) -> Result<CheckedJson> {
    card_json.parse().map_err(|_| {
        coded_error(
            env,
            Some(ErrorCode::IdentityFailed.as_str()),
            "agent card is not valid JSON".to_owned(),
        )
    })
}

/// What an Agent Card's AITP extension points at. Both values are unverified.
#[napi(object)]
pub struct JsA2aCardPointer {
    /// `params.aid`.
    pub aid: String,
    /// `params.manifestUrl`, chosen by the Card's author. Fetch it as any
    /// untrusted URL.
    pub manifest_url: String,
}

/// The RFC-AITP-0014 §4.3 effective values, all from the verified Manifest.
#[napi(object)]
pub struct JsA2aBoundCard {
    /// The server's identity: the Manifest's own AID string.
    pub aid: String,
    /// The identity types the server accepts.
    pub accepted_identity_types: Vec<String>,
    /// The trust anchors the server accepts.
    pub accepted_trust_anchors: Vec<String>,
    /// The capabilities the server can grant.
    pub offered_capabilities: Vec<String>,
    /// The endpoint to run the Mutual Handshake against.
    pub handshake_endpoint: String,
    /// The interface URL that was accepted, the only one that may receive
    /// the TCT.
    pub interface_url: String,
}

/// RFC-AITP-0014 §4.2 step 2: read the AITP extension from an Agent Card.
/// Failure throws with `error.code === 'IDENTITY_FAILED'`.
#[napi(js_name = "a2aCardManifestUrl")]
pub fn a2a_card_manifest_url_js(env: Env, card_json: String) -> Result<JsA2aCardPointer> {
    let pointer = locate_aitp_extension(&card(env, &card_json)?).map_err(|e| failed(env, &e))?;
    Ok(JsA2aCardPointer {
        aid: pointer.aid().as_str().to_owned(),
        manifest_url: pointer.manifest_url().as_str().to_owned(),
    })
}

/// RFC-AITP-0014 §4.2 steps 2 to 5: bind an Agent Card to the agent's
/// signed Manifest.
///
/// `manifestJson` is the 2xx body fetched from `manifestUrl`: the Manifest
/// or its `{"manifest": {...}}` wrapper. `null` means the fetch failed.
/// `selectedInterfaceUrl` is the `url` of the AgentInterface the client
/// intends to call, matched byte for byte. `nowUnixSecs` defaults to the
/// current time.
///
/// A binding failure throws with the registered code on `error.code`:
/// `IDENTITY_FAILED`, `MANIFEST_NOT_FOUND`, or a code of the Manifest's
/// verification. Steps 6 and 7 stay with the caller.
#[napi(js_name = "verifyA2aAgentCardBinding")]
pub fn verify_a2a_agent_card_binding_js(
    env: Env,
    card_json: String,
    selected_interface_url: String,
    manifest_json: Option<String>,
    now_unix_secs: Option<f64>,
) -> Result<JsA2aBoundCard> {
    let fetch = match &manifest_json {
        Some(json) => ManifestFetch::Fetched(json.as_bytes()),
        None => ManifestFetch::Unreachable,
    };
    let now = crate::helpers::now_or_system(now_unix_secs)?;
    let bound = verify_agent_card_binding(
        &card(env, &card_json)?,
        &selected_interface_url,
        fetch,
        &BindingContext::at(now),
    )
    .map_err(|e| failed(env, &e))?;

    Ok(JsA2aBoundCard {
        aid: bound.aid().as_str().to_owned(),
        accepted_identity_types: bound.accepted_identity_types(),
        accepted_trust_anchors: bound
            .accepted_trust_anchors()
            .iter()
            .map(|a| a.as_str().to_owned())
            .collect(),
        offered_capabilities: bound.offered_capabilities().to_vec(),
        handshake_endpoint: bound.handshake_endpoint().as_str().to_owned(),
        interface_url: bound.interface_url().to_owned(),
    })
}
