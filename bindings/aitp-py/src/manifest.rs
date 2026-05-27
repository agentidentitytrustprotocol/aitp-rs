//! Manifest verification binding.
//!
//! Mirrors the Node SDK's `verifyManifestJson` free function. Used by the
//! AITP Control Plane during agent enrollment.

use aitp_core::Timestamp;
use aitp_manifest::{verify_manifest, ManifestEnvelope, VerifyManifestContext};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

/// Verify a `ManifestEnvelope` JSON string. Raises on signature,
/// proof-of-possession, expiry, or identity-hint shape failures.
#[pyfunction]
#[pyo3(name = "verify_manifest_json")]
pub fn verify_manifest_json_py(manifest_envelope_json: &str) -> PyResult<()> {
    let envelope: ManifestEnvelope = serde_json::from_str(manifest_envelope_json)
        .map_err(|e| PyValueError::new_err(format!("invalid manifest JSON: {e}")))?;
    verify_manifest(
        &envelope.manifest,
        &VerifyManifestContext {
            now: Timestamp::now(),
        },
    )
    .map_err(|e| PyRuntimeError::new_err(format!("manifest verification failed: {e}")))?;
    Ok(())
}
