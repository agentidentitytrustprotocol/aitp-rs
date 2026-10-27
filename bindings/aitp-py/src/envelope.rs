//! Envelope signing *and verification* bindings (issue #256).
//!
//! Until 0.17.0 the bindings exposed envelope types but no way to check an
//! envelope's outer signature: only the HTTP server and the `aitp` facade
//! did, so a binding caller receiving an envelope outside a session had to
//! trust it unverified or hand-roll the `aitp/0.3` signing input.
//!
//! Both halves wrap the Rust implementation — [`wire::envelope`] for the
//! first two steps of the RFC-AITP-0001 §5.4 check order and
//! [`aitp::envelope::verify_envelope_signature`] /
//! [`aitp::envelope::sign_prepared_envelope`] for the signature — so the
//! binding cannot drift from the server.

use aitp::core::{Aid, AitpEnvelope, ExtensionsMap, MessageType, Timestamp};
use aitp::crypto::{AitpSigningKey, AitpVerifyingKey};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use uuid::Uuid;

use crate::wire::{self, WireError};

mod verification_error_type {
    use pyo3::create_exception;
    use pyo3::exceptions::PyRuntimeError;

    create_exception!(
        aitp,
        EnvelopeVerificationError,
        // Inherits RuntimeError, like ManifestVerificationError and
        // RevocationVerificationError, so one `except RuntimeError` keeps
        // catching every verification failure.
        PyRuntimeError,
        "An AITP envelope failed verification.\n\n\
         Carries a stable machine-readable `code` attribute: the registered \
         RFC-AITP-0001 §5.7 error code of the first failed step of the §5.4 \
         check order — one of `UNKNOWN_VERSION`, `UNKNOWN_FIELD`, \
         `INVALID_ENVELOPE`, `INVALID_SIGNATURE`. Branch on `code`, never on \
         the message text."
    );
}

pub use verification_error_type::EnvelopeVerificationError;

fn verification_error(code: &str, message: String) -> PyErr {
    let err = EnvelopeVerificationError::new_err(message);
    Python::attach(|py| {
        // Best-effort: if setting the attribute fails the exception still
        // carries its message, so verification still fails closed.
        let _ = err.value(py).setattr("code", code);
    });
    err
}

/// The registered wire code for a check-order step 1 or 2 failure.
fn wire_code(err: &WireError) -> &'static str {
    match err {
        WireError::UnknownVersion(_) => "UNKNOWN_VERSION",
        WireError::UnknownField(_) => "UNKNOWN_FIELD",
        WireError::Malformed(_) => "INVALID_ENVELOPE",
    }
}

/// Verify an `AitpEnvelope` JSON string sent by `expected_sender_aid`.
///
/// Returns `None` on success; raises `EnvelopeVerificationError` whose
/// `.code` is the first failing step of the RFC-AITP-0001 §5.4 check order:
///
/// 1. `version` absent or not `aitp/0.3` → `UNKNOWN_VERSION` (no
///    dual-accept: `aitp/0.2` is as unknown as `aitp/9.9`);
/// 2. a member outside the schema and outside `extensions` →
///    `UNKNOWN_FIELD`; any other structural defect (a duplicate key,
///    RFC-AITP-0001 §5.4.5, a missing member, an unregistered
///    `message_type`, a non-v4 `message_id`, a non-object `payload`, a
///    negative `timestamp`, a `signature` outside the schema pattern) →
///    `INVALID_ENVELOPE`;
/// 3. a signature that does not verify over `sig_input_v2` under the
///    expected sender's key → `INVALID_SIGNATURE`. An envelope whose
///    `sender.agent_id` is not `expected_sender_aid` fails here too: it is
///    not signed by the key the caller trusts.
///
/// The key comes from `expected_sender_aid` (every AID encodes its public
/// key), as `verify_revocation_list` takes its pinned issuer. A malformed
/// `expected_sender_aid` is the caller's error and raises `ValueError`.
///
/// Establishes **authenticity and structure only**. Replay and freshness
/// (RFC-AITP-0001 §5.5: the timestamp window and `message_id`
/// deduplication) are not checked; they belong to the receiving endpoint's
/// RFC-AITP-0009 §3.1 order, which the caller owns.
#[pyfunction]
#[pyo3(name = "verify_envelope", signature = (envelope_json, expected_sender_aid))]
pub fn verify_envelope_py(envelope_json: &str, expected_sender_aid: &str) -> PyResult<()> {
    let envelope = wire::envelope(envelope_json)
        .map_err(|e| verification_error(wire_code(&e), format!("invalid envelope JSON: {e}")))?;
    // A bad AID is the caller's error, not the envelope's — do not report
    // it as a verification cause.
    let expected = Aid::parse(expected_sender_aid)
        .map_err(|e| PyValueError::new_err(format!("invalid expected_sender_aid: {e}")))?;
    let key = AitpVerifyingKey::from_aid(&expected)
        .map_err(|e| PyValueError::new_err(format!("invalid expected_sender_aid: {e}")))?;
    if envelope.sender.agent_id != expected {
        return Err(verification_error(
            "INVALID_SIGNATURE",
            format!(
                "envelope sender `{}` is not the expected sender `{}`",
                envelope.sender.agent_id, expected
            ),
        ));
    }
    aitp::envelope::verify_envelope_signature(&envelope, &key).map_err(|e| {
        verification_error(
            "INVALID_SIGNATURE",
            format!("envelope signature invalid: {e}"),
        )
    })
}

/// Sign an envelope with `key` (RFC-AITP-0001 §5.4) and return its JSON.
///
/// `message_id` defaults to a fresh UUID v4 and `timestamp` to now. A
/// supplied `message_id` must be the lowercase hyphenated v4 wire form
/// (RFC-AITP-0001 §5.2); uppercase, braced, `urn:uuid:`, unhyphenated and
/// non-v4 forms raise `ValueError` rather than being normalized.
pub fn sign_envelope_py(
    key: &AitpSigningKey,
    message_type: &str,
    payload_json: &str,
    extensions_json: Option<&str>,
    message_id: Option<&str>,
    timestamp: Option<i64>,
) -> PyResult<String> {
    let message_type: MessageType =
        serde_json::from_value(serde_json::Value::String(message_type.to_string()))
            .map_err(|_| PyValueError::new_err(format!("unknown message_type '{message_type}'")))?;
    let payload: serde_json::Value = serde_json::from_str(payload_json)
        .map_err(|e| PyValueError::new_err(format!("invalid payload JSON: {e}")))?;
    if !payload.is_object() {
        return Err(PyValueError::new_err("payload must be a JSON object"));
    }
    let extensions = extensions_json
        .map(serde_json::from_str::<ExtensionsMap>)
        .transpose()
        .map_err(|e| PyValueError::new_err(format!("invalid extensions JSON: {e}")))?;
    let message_id = match message_id {
        Some(s) => {
            crate::helpers::parse_strict_v4("message_id", s).map_err(PyValueError::new_err)?
        }
        None => Uuid::new_v4(),
    };
    let envelope = {
        let mut envelope = AitpEnvelope::unsigned(
            key.aid().clone(),
            message_type,
            payload,
            message_id,
            timestamp.map(Timestamp).unwrap_or_else(Timestamp::now),
        );
        envelope.extensions = extensions;
        envelope
    };
    // Refuses a non-v4 `message_id` and a negative `timestamp` before
    // signing: whatever a verifier rejects is not signed.
    let signed = aitp::envelope::sign_prepared_envelope(key, envelope)
        .map_err(|e| PyValueError::new_err(format!("sign_envelope failed: {e}")))?;
    serde_json::to_string(&signed).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}
