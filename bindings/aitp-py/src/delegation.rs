//! Delegation token binding — RFC-AITP-0006.
//!
//! Wraps `aitp_delegation::DelegationBuilder` and `verify_delegation`. The
//! Python side calls into this for the demo's "researcher → writer → sub-
//! researcher" trust chain.

use aitp_core::{base64url, Aid, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp_delegation::{
    verify_delegation, DelegationBuilder, DelegationEnvelope, DelegationToken,
    VerifyDelegationContext, DEFAULT_MAX_HOPS,
};
use aitp_tct::{Tct, TctEnvelope};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

/// The verified delegation token's salient fields, returned to Python after
/// `verify_delegation` succeeds.
#[pyclass(name = "DelegationVerified", frozen)]
pub struct PyDelegationVerified {
    /// AID of the ultimate grantor — the original TCT issuer that gave grants
    /// to `issued_by`. The responder side checks this matches its own AID
    /// before redeeming.
    #[pyo3(get)]
    pub delegator: String,
    /// AID of the recipient (C) — who will receive a fresh TCT.
    #[pyo3(get)]
    pub delegatee: String,
    /// AID of the agent that issued this delegation (B in the RFC).
    #[pyo3(get)]
    pub issued_by: String,
    /// Capabilities being delegated. Always a subset of the source TCT's grants.
    #[pyo3(get)]
    pub grants: Vec<String>,
    /// Unix-seconds expiry of the delegation token itself.
    #[pyo3(get)]
    pub expires_at: i64,
    /// Delegatee's raw Ed25519 public key, base64url-encoded (43 chars). This
    /// is the `cnf` binding — proves which key the issuer should bind to the
    /// fresh TCT it mints.
    #[pyo3(get)]
    pub cnf: String,
}

/// Verify a `DelegationEnvelope` JSON. `verifier_aid` is the verifier's own
/// AID string — verification fails if it doesn't match the token's
/// `delegator` field. `max_hops` defaults to `DEFAULT_MAX_HOPS` (3) when 0;
/// pass a positive value to override.
///
/// Returns the verified token's salient fields. Raises `PyValueError` for
/// malformed JSON and `PyRuntimeError` for verification failure.
#[pyfunction]
#[pyo3(name = "verify_delegation", signature = (envelope_json, verifier_aid, max_hops = 0))]
pub fn verify_delegation_py(
    envelope_json: &str,
    verifier_aid: &str,
    max_hops: u32,
) -> PyResult<PyDelegationVerified> {
    let DelegationEnvelope { delegation: token } = serde_json::from_str(envelope_json)
        .map_err(|e| PyValueError::new_err(format!("invalid delegation envelope JSON: {e}")))?;
    let verifier = Aid::parse(verifier_aid)
        .map_err(|e| PyValueError::new_err(format!("invalid verifier AID: {e}")))?;

    let hops = if max_hops == 0 { DEFAULT_MAX_HOPS } else { max_hops };
    let ctx = VerifyDelegationContext::new(&verifier, Timestamp::now()).with_max_hops(hops);

    verify_delegation(&token, &ctx)
        .map_err(|e| PyRuntimeError::new_err(format!("delegation verification failed: {e}")))?;

    Ok(PyDelegationVerified {
        delegator: token.delegator.to_string(),
        delegatee: token.delegatee.to_string(),
        issued_by: token.issued_by.to_string(),
        grants: token.scope.clone(),
        expires_at: token.expires_at.0,
        cnf: token.cnf.clone(),
    })
}

/// Helpers used by `agent.rs` — exported as crate-private so the
/// `AitpAgent.build_delegation` / `issue_tct_for_delegatee` methods can call
/// them with a borrowed `&AitpSigningKey`.

/// Build a `DelegationToken` and serialize it as a `DelegationEnvelope` JSON.
///
/// * `held_tct_envelope_json` — the TCT envelope the delegator received from
///   the original issuer.
/// * `delegatee_aid_str` — recipient's AID.
/// * `delegatee_pk_b64u` — recipient's raw Ed25519 public key, base64url
///   (43 chars). Typically pulled from the delegatee's manifest's
///   `identity_hint.public_key`.
/// * `scope` — subset of the held TCT's grants to delegate.
/// * `ttl_secs` — token lifetime; `None` uses `DEFAULT_DELEGATION_TTL_SECS`.
pub(crate) fn build_delegation_token_json(
    issuer_key: &AitpSigningKey,
    held_tct_envelope_json: &str,
    delegatee_aid_str: &str,
    delegatee_pk_b64u: &str,
    scope: Vec<String>,
    ttl_secs: Option<i64>,
) -> PyResult<String> {
    let TctEnvelope { tct: held_tct } = serde_json::from_str(held_tct_envelope_json)
        .map_err(|e| PyValueError::new_err(format!("invalid held TCT JSON: {e}")))?;
    let delegatee_aid = Aid::parse(delegatee_aid_str)
        .map_err(|e| PyValueError::new_err(format!("invalid delegatee AID: {e}")))?;
    let delegatee_pk = decode_pubkey_b64u(delegatee_pk_b64u)?;

    let mut builder = DelegationBuilder::new(issuer_key, &held_tct)
        .delegatee(delegatee_aid)
        .delegatee_pubkey(delegatee_pk)
        .scope(scope);
    if let Some(ttl) = ttl_secs {
        builder = builder.ttl_secs(ttl);
    }

    let token: DelegationToken = builder
        .build()
        .map_err(|e| PyRuntimeError::new_err(format!("delegation build failed: {e}")))?;

    serde_json::to_string(&DelegationEnvelope { delegation: token })
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Mint a fresh TCT for the delegatee after `verify_delegation` succeeded.
///
/// In v0.1 audience MUST equal subject, so both are set to the delegatee's
/// AID. The subject's public key is decoded from the verified token's `cnf`
/// field — that's the binding the SDK enforces when the delegatee later
/// presents this TCT.
///
/// Returns a `TctEnvelope` JSON string.
pub(crate) fn issue_tct_for_delegatee_json(
    issuer_key: &AitpSigningKey,
    verified: &PyDelegationVerified,
    ttl_secs: Option<i64>,
) -> PyResult<String> {
    let delegatee_aid = Aid::parse(&verified.delegatee)
        .map_err(|e| PyValueError::new_err(format!("invalid delegatee AID: {e}")))?;
    let delegatee_pk = decode_pubkey_b64u(&verified.cnf)?;

    let mut builder = aitp_tct::TctBuilder::new(issuer_key)
        .subject(delegatee_aid.clone())
        .audience(delegatee_aid)
        .grants(verified.grants.clone())
        .subject_pubkey(delegatee_pk);
    if let Some(ttl) = ttl_secs {
        builder = builder.ttl_secs(ttl);
    }

    let tct: Tct = builder
        .build()
        .map_err(|e| PyRuntimeError::new_err(format!("TCT mint failed: {e}")))?;

    serde_json::to_string(&TctEnvelope { tct })
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

fn decode_pubkey_b64u(b64u: &str) -> PyResult<AitpVerifyingKey> {
    let bytes = base64url::decode_strict(b64u)
        .map_err(|e| PyValueError::new_err(format!("invalid base64url pubkey: {e}")))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        PyValueError::new_err(format!(
            "pubkey must be 32 bytes (got {})",
            bytes.len(),
        ))
    })?;
    AitpVerifyingKey::from_bytes(&arr)
        .map_err(|e| PyValueError::new_err(format!("invalid Ed25519 pubkey: {e}")))
}
