//! A2A Agent Card binding, client verification (RFC-AITP-0014, Draft) —
//! Python SDK.
//!
//! Gated by the `experimental-a2a-agent-card` Cargo feature, which the
//! published package does not enable. No stability promise. No I/O: the
//! caller fetches the Manifest.

use aitp::core::{CheckedJson, ErrorCode, Timestamp};
use aitp_experimental::a2a::{
    locate_aitp_extension, verify_agent_card_binding, A2aBindingError, BindingContext,
    ManifestFetch,
};
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::helpers::runtime_error;

fn failed(e: &A2aBindingError) -> PyErr {
    runtime_error(e.to_string(), Some(e.code().as_str()))
}

fn card(card_json: &str) -> PyResult<CheckedJson> {
    card_json.parse().map_err(|_| {
        runtime_error(
            "agent card is not valid JSON".to_owned(),
            Some(ErrorCode::IdentityFailed.as_str()),
        )
    })
}

/// RFC-AITP-0014 §4.2 step 2: read the AITP extension from an Agent Card.
///
/// Returns `{"aid", "manifest_url"}`, both unverified. `manifest_url` is
/// chosen by the Card's author, so fetch it as any untrusted URL. Failure
/// raises `RuntimeError` with `.code == "IDENTITY_FAILED"`.
#[pyfunction]
#[pyo3(name = "a2a_card_manifest_url")]
pub fn a2a_card_manifest_url_py<'py>(
    py: Python<'py>,
    card_json: &str,
) -> PyResult<Bound<'py, PyDict>> {
    let pointer = locate_aitp_extension(&card(card_json)?).map_err(|e| failed(&e))?;
    let out = PyDict::new(py);
    out.set_item("aid", pointer.aid().as_str())?;
    out.set_item("manifest_url", pointer.manifest_url().as_str())?;
    Ok(out)
}

/// RFC-AITP-0014 §4.2 steps 2 to 5: bind an Agent Card to the agent's
/// signed Manifest.
///
/// `manifest_json` is the 2xx body fetched from `manifest_url`: the Manifest
/// or its `{"manifest": {...}}` wrapper. `None` means the fetch failed.
/// `selected_interface_url` is the `url` of the AgentInterface the client
/// intends to call, matched byte for byte. `now_unix_secs` defaults to the
/// current time.
///
/// Returns the §4.3 effective values, all from the Manifest:
/// `{"aid", "accepted_identity_types", "accepted_trust_anchors",
/// "offered_capabilities", "handshake_endpoint", "interface_url"}`. Failure
/// raises `RuntimeError` with the registered code on `.code`:
/// `IDENTITY_FAILED`, `MANIFEST_NOT_FOUND`, or a code of the Manifest's
/// verification. Steps 6 and 7 stay with the caller.
#[pyfunction]
#[pyo3(
    name = "verify_a2a_agent_card_binding",
    signature = (card_json, selected_interface_url, manifest_json = None, now_unix_secs = None)
)]
pub fn verify_a2a_agent_card_binding_py<'py>(
    py: Python<'py>,
    card_json: &str,
    selected_interface_url: &str,
    manifest_json: Option<&str>,
    now_unix_secs: Option<i64>,
) -> PyResult<Bound<'py, PyDict>> {
    let fetch = match manifest_json {
        Some(json) => ManifestFetch::Fetched(json.as_bytes()),
        None => ManifestFetch::Unreachable,
    };
    let now = now_unix_secs.map_or_else(Timestamp::now, Timestamp);
    let bound = verify_agent_card_binding(
        &card(card_json)?,
        selected_interface_url,
        fetch,
        &BindingContext::at(now),
    )
    .map_err(|e| failed(&e))?;

    let anchors: Vec<&str> = bound
        .accepted_trust_anchors()
        .iter()
        .map(|a| a.as_str())
        .collect();
    let out = PyDict::new(py);
    out.set_item("aid", bound.aid().as_str())?;
    out.set_item("accepted_identity_types", bound.accepted_identity_types())?;
    out.set_item("accepted_trust_anchors", anchors)?;
    out.set_item("offered_capabilities", bound.offered_capabilities())?;
    out.set_item("handshake_endpoint", bound.handshake_endpoint().as_str())?;
    out.set_item("interface_url", bound.interface_url())?;
    Ok(out)
}
