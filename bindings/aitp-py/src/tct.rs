//! TCT verification binding.

use aitp_core::{Aid, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp_tct::{verify_tct, TctEnvelope, TctVerifyContext};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

/// The verified peer identity carried by a TCT.
#[pyclass(name = "TctIdentity", frozen)]
pub struct PyTctIdentity {
    /// AID of the agent that issued (and is bound by) the TCT.
    #[pyo3(get)]
    pub peer_aid: String,
    /// Capability grants the TCT authorizes.
    #[pyo3(get)]
    pub grants: Vec<String>,
    /// Expiry, Unix seconds.
    #[pyo3(get)]
    pub expires_at: i64,
    /// TCT unique identifier (`jti`).
    #[pyo3(get)]
    pub jti: String,
}

/// Verify `tct_json`, requiring `required_grant` to be present in its grants.
///
/// The audience check is controlled by `expected_audience`:
/// - `None` (default): use `our_key.aid()` — the **holder-receipt** model
///   from RFC-AITP-0005 §9, where the holder verifies a TCT it received as
///   its own receipt. Backward-compatible with v0.1 callers.
/// - `Some(aid)`: use the supplied AID — the **presented-TCT** model used
///   by resource servers verifying a TCT a peer presents in
///   `X-AITP-TCT`. The caller is responsible for asserting the
///   presenter's AID (typically by reading the TCT's own `audience`
///   field, which in v0.1 must equal `subject`).
///
/// The signature check is the security gate in either mode: the TCT is
/// verified against `tct.issuer`'s pubkey.
pub fn py_verify_tct(
    our_key: &AitpSigningKey,
    tct_json: &str,
    required_grant: &str,
    expected_audience: Option<&str>,
) -> PyResult<PyTctIdentity> {
    let envelope: TctEnvelope = serde_json::from_str(tct_json)
        .map_err(|e| PyValueError::new_err(format!("invalid TCT JSON: {e}")))?;

    let issuer_pk = AitpVerifyingKey::from_aid(&envelope.tct.issuer)
        .map_err(|e| PyValueError::new_err(format!("bad issuer AID: {e}")))?;

    let audience_owned: Aid;
    let aud_ref: &Aid = match expected_audience {
        Some(s) => {
            audience_owned = Aid::parse(s).map_err(|e| {
                PyValueError::new_err(format!("bad expected_audience AID '{s}': {e}"))
            })?;
            &audience_owned
        }
        None => our_key.aid(),
    };

    let ctx = TctVerifyContext {
        expected_audience: aud_ref,
        issuer_pubkey: &issuer_pk,
        now: Timestamp::now(),
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };

    let tct = verify_tct(&envelope.tct, &ctx)
        .map_err(|e| PyRuntimeError::new_err(format!("TCT verification failed: {e}")))?;

    if !tct.grants.iter().any(|g| g == required_grant) {
        return Err(PyRuntimeError::new_err(format!(
            "TCT does not grant '{required_grant}'; grants: {:?}",
            tct.grants
        )));
    }

    Ok(PyTctIdentity {
        peer_aid: tct.issuer.to_string(),
        grants: tct.grants.clone(),
        expires_at: tct.expires_at.0,
        jti: tct.jti.to_string(),
    })
}
