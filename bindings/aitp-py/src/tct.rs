//! TCT verification binding.

use aitp_core::Timestamp;
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

/// Verify `tct_json` against `our_key` as the audience, requiring
/// `required_grant` to be present. Raises on any verification failure.
pub fn py_verify_tct(
    our_key: &AitpSigningKey,
    tct_json: &str,
    required_grant: &str,
) -> PyResult<PyTctIdentity> {
    let envelope: TctEnvelope = serde_json::from_str(tct_json)
        .map_err(|e| PyValueError::new_err(format!("invalid TCT JSON: {e}")))?;

    let issuer_pk = AitpVerifyingKey::from_aid(&envelope.tct.issuer)
        .map_err(|e| PyValueError::new_err(format!("bad issuer AID: {e}")))?;

    let ctx = TctVerifyContext {
        expected_audience: our_key.aid(),
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
