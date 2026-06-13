//! Session Trust Bundle (RFC-AITP-0010) — Python binding.
//!
//! Gated by the `experimental-bundle` Cargo feature.

use std::sync::Arc;

use aitp_core::{Aid, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_session_bundle::{
    verify_session_bundle, BundleOutcome, ParticipantEntry, SessionBundleBuilder,
    SessionBundleEnvelope, VerifySessionBundleContext,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use uuid::Uuid;

use crate::agent::PyAitpAgent;

/// Revocation-check closure: maps a TCT `jti` to "is it revoked?".
type RevocationFn = Box<dyn Fn(&Uuid) -> bool>;

/// Fluent builder for issuing a `SessionBundleEnvelope`. Constructed
/// from the coordinator's [`AitpAgent`]; chain `participant()` calls for
/// each participant, then `build()` to sign + serialize.
#[pyclass(name = "SessionBundleBuilder")]
pub struct PySessionBundleBuilder {
    key: Arc<AitpSigningKey>,
    session_id: Option<Uuid>,
    issued_at: Option<Timestamp>,
    participants: Vec<ParticipantEntry>,
}

#[pymethods]
impl PySessionBundleBuilder {
    /// Construct a builder backed by `coordinator.key` (the coordinator
    /// agent's long-term signing key).
    #[new]
    fn new(coordinator: &PyAitpAgent) -> Self {
        Self {
            key: coordinator.signing_key(),
            session_id: None,
            issued_at: None,
            participants: Vec::new(),
        }
    }

    /// Set the session ID (UUIDv4 string). If unset, a fresh one is
    /// generated at `build()` time.
    fn session_id<'py>(
        mut slf: PyRefMut<'py, Self>,
        uuid_str: &str,
    ) -> PyResult<PyRefMut<'py, Self>> {
        let id = Uuid::parse_str(uuid_str)
            .map_err(|e| PyValueError::new_err(format!("invalid uuid: {e}")))?;
        slf.session_id = Some(id);
        Ok(slf)
    }

    /// Override `issued_at` (unix seconds). Defaults to "now" at build.
    fn issued_at<'py>(mut slf: PyRefMut<'py, Self>, unix_secs: i64) -> PyRefMut<'py, Self> {
        slf.issued_at = Some(Timestamp(unix_secs));
        slf
    }

    /// Add a participant entry. `tct_token` is the participant's TCT as a
    /// compact-JWS string; its issuer MUST equal the coordinator's AID
    /// and its audience MUST equal `aid` (checked at `build()` time).
    fn participant<'py>(
        mut slf: PyRefMut<'py, Self>,
        aid: &str,
        tct_token: &str,
    ) -> PyResult<PyRefMut<'py, Self>> {
        let participant_aid = Aid::parse(aid)
            .map_err(|e| PyValueError::new_err(format!("invalid participant AID: {e}")))?;
        slf.participants.push(ParticipantEntry {
            aid: participant_aid,
            tct: tct_token.to_string(),
        });
        Ok(slf)
    }

    /// Construct, sign, and return the `SessionBundleEnvelope` JSON.
    fn build(&self) -> PyResult<String> {
        let mut builder = SessionBundleBuilder::new(&self.key);
        if let Some(id) = self.session_id {
            builder = builder.session_id(id);
        }
        if let Some(ts) = self.issued_at {
            builder = builder.issued_at(ts);
        }
        for entry in &self.participants {
            builder = builder.participant(entry.aid.clone(), entry.tct.clone());
        }
        let bundle = builder
            .build()
            .map_err(|e| PyRuntimeError::new_err(format!("bundle build failed: {e}")))?;
        serde_json::to_string(&SessionBundleEnvelope {
            session_bundle: bundle,
        })
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}

/// Verify a `SessionBundleEnvelope` JSON.
///
/// Returns a dict with the verification outcome:
/// - `{"kind": "clear", "active_aids": [...]}` — every participant TCT verified.
/// - `{"kind": "degraded", "active_aids": [...], "dropped_aids": [...]}` —
///   one or more participant TCTs were revoked.
///
/// `revocation_check` is an optional callable that receives a TCT jti
/// (UUID string) and returns True if revoked.
#[pyfunction]
#[pyo3(name = "verify_session_bundle", signature = (
    bundle_envelope_json,
    verifier_aid,
    now_unix_secs = None,
    revocation_check = None,
))]
pub fn verify_session_bundle_py<'py>(
    py: Python<'py>,
    bundle_envelope_json: &str,
    verifier_aid: &str,
    now_unix_secs: Option<i64>,
    revocation_check: Option<Py<PyAny>>,
) -> PyResult<Bound<'py, PyDict>> {
    let envelope: SessionBundleEnvelope = serde_json::from_str(bundle_envelope_json)
        .map_err(|e| PyValueError::new_err(format!("invalid bundle envelope JSON: {e}")))?;
    let verifier = Aid::parse(verifier_aid)
        .map_err(|e| PyValueError::new_err(format!("invalid verifier AID: {e}")))?;
    let now = Timestamp(now_unix_secs.unwrap_or_else(|| Timestamp::now().0));

    // Translate the optional Python callback into the borrowed closure
    // the Rust API expects.
    let cb_holder = revocation_check;
    let cb_fn: Option<RevocationFn> = cb_holder.as_ref().map(|callable| {
        let callable = callable.clone_ref(py);
        let f: RevocationFn = Box::new(move |jti: &Uuid| {
            Python::with_gil(|py| {
                let bound = callable.bind(py);
                match bound.call1((jti.to_string(),)) {
                    Ok(r) => r.extract::<bool>().unwrap_or(false),
                    Err(_) => false,
                }
            })
        });
        f
    });

    let outcome = verify_session_bundle(
        &envelope.session_bundle,
        &VerifySessionBundleContext {
            verifier_aid: &verifier,
            now,
            revocation_check: cb_fn.as_deref().map(|b: &dyn Fn(&Uuid) -> bool| b),
        },
    )
    .map_err(|e| PyRuntimeError::new_err(format!("bundle verification failed: {e}")))?;

    let out = PyDict::new_bound(py);
    match outcome {
        BundleOutcome::Clear { active_aids } => {
            out.set_item("kind", "clear")?;
            out.set_item(
                "active_aids",
                active_aids
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>(),
            )?;
            out.set_item("dropped_aids", Vec::<String>::new())?;
        }
        BundleOutcome::DegradedSubset {
            active_aids,
            dropped_aids,
        } => {
            out.set_item("kind", "degraded")?;
            out.set_item(
                "active_aids",
                active_aids
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>(),
            )?;
            out.set_item(
                "dropped_aids",
                dropped_aids
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>(),
            )?;
        }
    }
    Ok(out)
}
