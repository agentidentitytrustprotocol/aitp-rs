//! Revocation-list signing binding.
//!
//! Mirrors the Node SDK's `AitpAgent.signRevocationList`. The AITP Control
//! Plane uses this to publish a signed list of revoked TCT jtis a peer's
//! verifiers should reject.

use aitp_core::{Timestamp, PROTOCOL_VERSION};
use aitp_crypto::AitpSigningKey;
use aitp_tct::{sign_revocation_list, RevocationEntry, RevocationList};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use uuid::Uuid;

/// Convert a Python list of revocation-entry dicts into Rust `RevocationEntry`
/// values. Each dict accepts: `jti` (str, UUID), optional `revoked_at` (int
/// unix seconds, defaults to `now`), optional `reason` (str).
fn parse_entries(entries: &Bound<'_, PyList>, now: Timestamp) -> PyResult<Vec<RevocationEntry>> {
    let mut out = Vec::with_capacity(entries.len());
    for (i, item) in entries.iter().enumerate() {
        let d: &Bound<'_, PyDict> = item.downcast().map_err(|_| {
            PyValueError::new_err(format!(
                "entries[{i}] must be a dict with at least a 'jti' key"
            ))
        })?;

        let jti_str: String = match d.get_item("jti")? {
            Some(v) => v
                .extract()
                .map_err(|_| PyValueError::new_err(format!("entries[{i}].jti must be a string")))?,
            None => {
                return Err(PyValueError::new_err(format!(
                    "entries[{i}].jti is required"
                )))
            }
        };
        let jti = Uuid::parse_str(&jti_str).map_err(|_| {
            PyValueError::new_err(format!("entries[{i}].jti is not a valid UUID: {jti_str}"))
        })?;

        let revoked_at = match d.get_item("revoked_at")? {
            Some(v) if v.is_none() => now,
            None => now,
            Some(v) => {
                let secs: i64 = v.extract().map_err(|_| {
                    PyValueError::new_err(format!(
                        "entries[{i}].revoked_at must be an int (unix seconds)"
                    ))
                })?;
                Timestamp(secs)
            }
        };

        let reason: Option<String> = match d.get_item("reason")? {
            Some(v) if v.is_none() => None,
            None => None,
            Some(v) => Some(v.extract().map_err(|_| {
                PyValueError::new_err(format!("entries[{i}].reason must be a string"))
            })?),
        };

        out.push(RevocationEntry {
            jti,
            revoked_at,
            reason,
        });
    }
    Ok(out)
}

/// Sign a `RevocationList` with `issuer_key`. Returns the on-wire
/// `RevocationListEnvelope` JSON.
pub fn sign_revocation_list_py(
    issuer_key: &AitpSigningKey,
    entries: &Bound<'_, PyList>,
    expires_in_secs: Option<i64>,
) -> PyResult<String> {
    let now = Timestamp::now();
    let parsed = parse_entries(entries, now)?;
    let body = RevocationList {
        version: PROTOCOL_VERSION.into(),
        issuer: issuer_key.aid().clone(),
        published_at: now,
        expires_at: Timestamp(now.0 + expires_in_secs.unwrap_or(3600)),
        entries: parsed,
    };
    let envelope = sign_revocation_list(body, issuer_key)
        .map_err(|e| PyRuntimeError::new_err(format!("sign_revocation_list failed: {e}")))?;
    serde_json::to_string(&envelope).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}
