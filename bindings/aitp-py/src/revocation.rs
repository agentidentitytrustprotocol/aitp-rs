//! Revocation-list signing *and verification* bindings.
//!
//! The signing half mirrors the Node SDK's `AitpAgent.signRevocationList`;
//! the AITP Control Plane uses it to publish a signed list of revoked TCT
//! jtis a peer's verifiers should reject.
//!
//! The verifying half is the other side of that, and it was missing until
//! 0.6.0 — both bindings exposed `sign_revocation_list` and neither exposed
//! `verify_revocation_list`, even though `verify_revocation_snapshot` is a
//! Tier C conformance operation the Rust adapter implements
//! (`docs/conformance.md`). Downstreams did the locally-reasonable thing:
//! one hand-rolled a verifier in a test, one skipped verification entirely,
//! one rendered "signed by CP" from the presence of a JSON key. A signing
//! convention change then crossed a whole release family with one accidental
//! interlock standing in its way. That was one missing binding, three times.

use aitp_core::{Aid, Timestamp, PROTOCOL_VERSION};
use aitp_crypto::AitpSigningKey;
use aitp_tct::{
    revocation_signing_bytes, sign_revocation_list, verify_revocation_list, RevocationEntry,
    RevocationList, RevocationListEnvelope, TctError, VerifyRevocationListContext,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use uuid::Uuid;

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
        RevocationVerificationError,
        // Inherits RuntimeError, not Exception: this binding raised a bare
        // RuntimeError before it was typed, and existing callers catch that.
        // Adding a machine-readable `.code` should not break anyone who was
        // already handling the failure.
        PyRuntimeError,
        "A revocation snapshot failed verification.\n\n\
         Carries a stable machine-readable `code` attribute — one of \
         `signature_invalid`, `issuer_mismatch`, `version_unknown`, `expired`, \
         `malformed`. Branch on `code`, never on the message text: callers that \
         string-match an exception message are pinning program output as an \
         expected value, which is the bug class the 0.5.0 signing-input change \
         exposed."
    );
}

pub use verification_error_type::RevocationVerificationError;

/// Map a `TctError` from revocation verification onto a stable cause code.
///
/// The codes are the binding's public contract; the wording of `message` is
/// not. Note `IssuerMismatch` became distinguishable from `ClaimsMalformed`
/// only in 0.6.0 — before that both surfaced as `CnfMalformed`, so a caller
/// could not tell "signed by the wrong issuer" from "garbage".
fn verification_cause(err: &TctError) -> &'static str {
    match err {
        TctError::SignatureInvalid => "signature_invalid",
        TctError::IssuerMismatch => "issuer_mismatch",
        TctError::VersionUnknown => "version_unknown",
        TctError::Expired => "expired",
        _ => "malformed",
    }
}

fn verification_error(code: &str, message: String) -> PyErr {
    let err = RevocationVerificationError::new_err(message);
    Python::with_gil(|py| {
        // Best-effort: if setting the attribute fails the exception still
        // carries its message, so verification still fails closed.
        let _ = err.value_bound(py).setattr("code", code);
    });
    err
}

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

/// Verify a `RevocationListEnvelope` JSON string against a pinned issuer.
///
/// Returns `None` on success; raises `RevocationVerificationError` with a
/// `.code` otherwise.
///
/// Establishes **authenticity and non-expiry only**: that the snapshot was
/// signed by the holder of `expected_issuer_aid` and that its `expires_at`
/// has not passed. It deliberately does **not** check `published_at`
/// staleness — RFC-AITP-0008 puts freshness policy at the consuming peer
/// (§3), and collapsing authenticity and freshness into one switch is how a
/// `soft_fail` mode ends up reporting a *forged* snapshot as not-revoked.
/// Callers own the staleness budget; `published_at` is on the body for that.
#[pyfunction]
#[pyo3(name = "verify_revocation_list", signature = (envelope_json, expected_issuer_aid, now_unix_secs=None))]
pub fn verify_revocation_list_py(
    envelope_json: &str,
    expected_issuer_aid: &str,
    now_unix_secs: Option<i64>,
) -> PyResult<()> {
    let envelope: RevocationListEnvelope = serde_json::from_str(envelope_json).map_err(|e| {
        verification_error(
            "malformed",
            format!("invalid revocation envelope JSON: {e}"),
        )
    })?;
    let expected = Aid::parse(expected_issuer_aid).map_err(|e| {
        // A bad AID is the caller's error, not the snapshot's — do not
        // report it as a verification cause.
        PyValueError::new_err(format!("invalid expected_issuer_aid: {e}"))
    })?;
    let now = Timestamp(now_unix_secs.unwrap_or_else(|| Timestamp::now().0));
    let ctx = VerifyRevocationListContext::new(&expected, now);
    verify_revocation_list(&envelope, &ctx).map_err(|e| {
        verification_error(
            verification_cause(&e),
            format!("revocation snapshot verification failed: {e}"),
        )
    })
}

/// The exact bytes a revocation snapshot's signature is computed over:
/// `JCS(revocation_list)` — the **inner** body, not the transport wrapper.
///
/// Exposed so a caller needing the signed bytes (an independent verifier, an
/// HSM signing path, a debugging tool) obtains them instead of reconstructing
/// the shape at the call site. Reconstructing it is exactly how signer,
/// verifier and conformance fixture drifted apart before 0.5.0.
#[pyfunction]
#[pyo3(name = "revocation_signing_bytes")]
pub fn revocation_signing_bytes_py(py: Python<'_>, envelope_json: &str) -> PyResult<Py<PyBytes>> {
    let envelope: RevocationListEnvelope = serde_json::from_str(envelope_json)
        .map_err(|e| PyValueError::new_err(format!("invalid revocation envelope JSON: {e}")))?;
    let bytes = revocation_signing_bytes(&envelope.revocation_list)
        .map_err(|e| PyRuntimeError::new_err(format!("canonicalization failed: {e}")))?;
    Ok(PyBytes::new_bound(py, &bytes).unbind())
}
