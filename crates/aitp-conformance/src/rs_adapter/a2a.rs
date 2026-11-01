//! A2A Agent Card binding op (RFC-AITP-0014, Draft;
//! `aitp_experimental::a2a`).
//!
//! `verify_a2a_agent_card_binding` runs §4.2 steps 1 to 5 and reports the
//! §4.3 effective values (§8). The op fetches nothing: `manifest` is the
//! body the fixture says was fetched, `manifest_fetch` records that the
//! fetch failed. `self_aid` belongs to step 6 and `card_signature_valid`
//! changes nothing (§4.4), so neither is read.

use super::{checked, err, AdapterState};
use aitp::core::Timestamp;
use aitp_experimental::a2a::{verify_agent_card_binding, BindingContext, ManifestFetch};
use serde_json::{json, Value};

pub(super) fn verify_binding_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    let Some(card) = params.get("agent_card") else {
        return err(id, "INVALID_REQUEST", "missing agent_card");
    };
    let Some(url) = params.get("selected_interface_url").and_then(Value::as_str) else {
        return err(id, "INVALID_REQUEST", "missing selected_interface_url");
    };
    let body = match (params.get("manifest"), params.get("manifest_fetch")) {
        (Some(manifest), None) => Some(manifest.to_string()),
        (None, Some(_)) => None,
        _ => {
            return err(
                id,
                "INVALID_REQUEST",
                "exactly one of manifest and manifest_fetch is required",
            )
        }
    };
    let fetch = match &body {
        Some(bytes) => ManifestFetch::Fetched(bytes.as_bytes()),
        None => ManifestFetch::Unreachable,
    };
    let now = params
        .get("now")
        .and_then(Value::as_i64)
        .map(Timestamp)
        .unwrap_or_else(|| state.now());

    match verify_agent_card_binding(&checked(card), url, fetch, &BindingContext::at(now)) {
        Ok(bound) => json!({
            "id": id,
            "ok": true,
            "result": {
                "effective": {
                    "aid": bound.aid().as_str(),
                    "accepted_identity_types": bound.accepted_identity_types(),
                    "offered_capabilities": bound.offered_capabilities(),
                    "handshake_endpoint": bound.handshake_endpoint().as_str(),
                },
            },
        }),
        // `Display` holds no Card or Manifest text.
        Err(e) => err(id, e.code().as_str(), &e.to_string()),
    }
}
