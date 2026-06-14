//! SHA-256 SPKI certificate pinning — Python binding.
//!
//! Gated by `spki-pinning`. Thin: just `compute_spki_hash` and
//! `SpkiPinVerifier.is_pinned`. The SDK doesn't bring rustls into the
//! wheel — callers wire the verifier into their own HTTP client (httpx,
//! requests) via a `checkServerIdentity`-style hook.
//!
//! Compatible with `aitp_transport_http::tls_pinning::compute_spki_hash`:
//! both implementations hash the SPKI DER bytes of the same X.509 cert
//! and produce the same 32-byte output. Test fixtures generated against
//! one implementation will validate against the other.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use sha2::{Digest, Sha256};

/// Compute the SHA-256 SPKI hash for an X.509 DER certificate. Returns
/// a 32-byte `bytes`. Raises `ValueError` if `cert_der` is not a
/// parseable certificate.
#[pyfunction]
pub fn compute_spki_hash<'py>(py: Python<'py>, cert_der: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| PyValueError::new_err(format!("invalid X.509 certificate (DER): {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(cert.tbs_certificate.subject_pki.raw);
    let digest = hasher.finalize();
    Ok(PyBytes::new_bound(py, &digest))
}

/// Holds a list of 32-byte SPKI pins and tells you whether a candidate
/// cert is pinned. Use this with your HTTP client's
/// "check-server-identity" hook: hash the leaf, compare against the
/// pinned set, reject otherwise.
#[pyclass(name = "SpkiPinVerifier")]
pub struct PySpkiPinVerifier {
    pins: Vec<[u8; 32]>,
}

#[pymethods]
impl PySpkiPinVerifier {
    /// Construct from a list of 32-byte `bytes` pins. Raises if any pin
    /// is not exactly 32 bytes.
    #[new]
    fn new(pins: Vec<Vec<u8>>) -> PyResult<Self> {
        let mut out = Vec::with_capacity(pins.len());
        for (i, p) in pins.into_iter().enumerate() {
            let arr: [u8; 32] = p.as_slice().try_into().map_err(|_| {
                PyValueError::new_err(format!(
                    "pin at index {i} must be exactly 32 bytes (got {})",
                    p.len()
                ))
            })?;
            out.push(arr);
        }
        Ok(Self { pins: out })
    }

    /// Returns True iff the SPKI hash of `cert_der` is in the pin list.
    fn is_pinned(&self, cert_der: &[u8]) -> PyResult<bool> {
        let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
            .map_err(|e| PyValueError::new_err(format!("invalid X.509 certificate (DER): {e}")))?;
        let mut hasher = Sha256::new();
        hasher.update(cert.tbs_certificate.subject_pki.raw);
        let digest = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        Ok(self.pins.iter().any(|p| p == &arr))
    }

    /// Number of pins currently held.
    #[getter]
    fn len(&self) -> usize {
        self.pins.len()
    }
}
