//! Manifest verification binding.
//!
//! Mirrors the Node SDK's `verifyManifestJson`. Used by the AITP Control
//! Plane during agent enrollment, and by any consumer that reads an AID or an
//! endpoint out of a peer's manifest.

use aitp_core::Timestamp;
use aitp_manifest::{verify_manifest, ManifestEnvelope, ManifestError, VerifyManifestContext};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

// pyo3 0.22's `create_exception!` expands a `#[cfg(feature = ...)]` naming a
// feature of *pyo3*, not of this crate, which trips `unexpected_cfgs`. CI runs
// clippy with `-D warnings`, so scope an allow to the macro rather than
// loosening the lint crate-wide.
#[allow(unexpected_cfgs)]
mod verification_error_type {
    use pyo3::create_exception;
    use pyo3::exceptions::PyRuntimeError;

    create_exception!(
        aitp,
        ManifestVerificationError,
        // Inherits RuntimeError, not Exception: this binding raised a bare
        // RuntimeError before it was typed, and existing callers catch that.
        // Adding a machine-readable `.code` should not break anyone who was
        // already handling the failure.
        PyRuntimeError,
        "A manifest envelope failed verification.\n\n\
         Carries a stable machine-readable `code` attribute — one of \
         `signature_invalid`, `pop_failed`, `aid_mismatch`, `expired`, \
         `version_unknown`, `identity_hint_malformed`, \
         `incompatible_identity_type`, `malformed`. Branch on `code`, never \
         on the message text: matching an exception message pins program \
         output as an expected value, which is the bug class the 0.5.0 \
         signing-input change exposed."
    );
}

pub use verification_error_type::ManifestVerificationError;

/// Map a `ManifestError` onto a stable cause code.
///
/// The codes are the binding's public contract; the wording of the message is
/// not. This mirrors `revocation::verification_cause` — the two verify paths
/// had asymmetric error surfaces until 0.6.1, which meant a caller wanting to
/// tell "this manifest expired" from "this manifest is forged" had to
/// substring-match prose on one side and could branch on `.code` on the other.
fn verification_cause(err: &ManifestError) -> &'static str {
    match err {
        ManifestError::Expired => "expired",
        ManifestError::SignatureInvalid => "signature_invalid",
        ManifestError::PopFailed => "pop_failed",
        ManifestError::AidMismatch => "aid_mismatch",
        ManifestError::VersionUnknown => "version_unknown",
        ManifestError::IdentityHintMalformed(_) => "identity_hint_malformed",
        ManifestError::IncompatibleIdentityType(_) => "incompatible_identity_type",
        _ => "malformed",
    }
}

fn verification_error(code: &str, message: String) -> PyErr {
    let err = ManifestVerificationError::new_err(message);
    Python::with_gil(|py| {
        // Best-effort: if setting the attribute fails the exception still
        // carries its message, so verification still fails closed.
        let _ = err.value_bound(py).setattr("code", code);
    });
    err
}

/// Verify a `ManifestEnvelope` JSON string. Raises on signature,
/// proof-of-possession, expiry, or identity-hint shape failures.
///
/// On failure raises `ManifestVerificationError` with a stable `.code`.
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
    .map_err(|e| {
        verification_error(
            verification_cause(&e),
            format!("manifest verification failed: {e}"),
        )
    })?;
    Ok(())
}
