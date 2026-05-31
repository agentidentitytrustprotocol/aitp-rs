//! Delegation token binding — RFC-AITP-0006.
//!
//! Wraps `aitp_delegation::DelegationBuilder` and `verify_delegation`. The
//! Python side calls into this for the demo's "researcher → writer → sub-
//! researcher" trust chain.

use aitp_core::{base64url, Aid, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp_delegation::{
    verify_delegation, DelegationBuilder, DelegationEnvelope, DelegationToken,
    VerifyDelegationContext,
};
// RFC-AITP-0011 multi-hop ceiling — only referenced by the experimental
// opt-in verifier, so the import is feature-gated to avoid an unused-import
// warning in the default (strict v0.1) build.
#[cfg(feature = "experimental-multihop-delegation")]
use aitp_delegation::DEFAULT_MAX_HOPS;
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

/// Verify a `DelegationEnvelope` JSON under **strict AITP v0.1**
/// (RFC-AITP-0006 single-hop). `verifier_aid` is the verifier's own AID
/// string — verification fails if it doesn't match the token's `delegator`
/// field.
///
/// Any token carrying a non-empty `chain` (a draft RFC-AITP-0011 multi-hop
/// delegation) is **rejected** with `DELEGATION_MULTIHOP_NOT_SUPPORTED`,
/// matching the Rust core default. To opt into multi-hop, build the SDK with
/// the `experimental-multihop-delegation` feature and call
/// `verify_delegation_experimental_multihop`.
///
/// Returns the verified token's salient fields. Raises `PyValueError` for
/// malformed JSON and `PyRuntimeError` for verification failure.
#[pyfunction]
#[pyo3(name = "verify_delegation", signature = (envelope_json, verifier_aid))]
pub fn verify_delegation_py(
    envelope_json: &str,
    verifier_aid: &str,
) -> PyResult<PyDelegationVerified> {
    let token = parse_envelope(envelope_json)?;
    let verifier = parse_verifier(verifier_aid)?;

    // `VerifyDelegationContext::new` ships `max_hops = V0_1_STRICT_MAX_HOPS`
    // (0), so a non-empty chain fails before any per-hop work runs.
    let ctx = VerifyDelegationContext::new(&verifier, Timestamp::now());

    verify_delegation(&token, &ctx)
        .map_err(|e| PyRuntimeError::new_err(format!("delegation verification failed: {e}")))?;

    Ok(to_verified(&token))
}

/// Verify a `DelegationEnvelope` JSON allowing **draft RFC-AITP-0011
/// multi-hop** chains up to `max_hops` total hops (`chain.len() + 1`).
///
/// This opts into behavior that is **not** part of AITP v0.1. It is only
/// compiled in under the `experimental-multihop-delegation` feature; a
/// default build exposes only the strict [`verify_delegation_py`].
///
/// `max_hops` defaults to `DEFAULT_MAX_HOPS` (3, the RFC-AITP-0011 §2
/// recommended ceiling). Pass a smaller value for a tighter bound;
/// `max_hops = 0` reverts to strict v0.1 (rejects any non-empty chain).
#[cfg(feature = "experimental-multihop-delegation")]
#[pyfunction]
#[pyo3(
    name = "verify_delegation_experimental_multihop",
    signature = (envelope_json, verifier_aid, max_hops = DEFAULT_MAX_HOPS)
)]
pub fn verify_delegation_experimental_multihop_py(
    envelope_json: &str,
    verifier_aid: &str,
    max_hops: u32,
) -> PyResult<PyDelegationVerified> {
    let token = parse_envelope(envelope_json)?;
    let verifier = parse_verifier(verifier_aid)?;

    let ctx = VerifyDelegationContext::new(&verifier, Timestamp::now()).with_max_hops(max_hops);

    verify_delegation(&token, &ctx)
        .map_err(|e| PyRuntimeError::new_err(format!("delegation verification failed: {e}")))?;

    Ok(to_verified(&token))
}

/// Parse a `DelegationEnvelope` JSON into its inner token.
fn parse_envelope(envelope_json: &str) -> PyResult<DelegationToken> {
    let DelegationEnvelope { delegation } = serde_json::from_str(envelope_json)
        .map_err(|e| PyValueError::new_err(format!("invalid delegation envelope JSON: {e}")))?;
    Ok(delegation)
}

/// Parse the verifier's own AID string.
fn parse_verifier(verifier_aid: &str) -> PyResult<Aid> {
    Aid::parse(verifier_aid)
        .map_err(|e| PyValueError::new_err(format!("invalid verifier AID: {e}")))
}

/// Project a verified token's salient fields into the Python-facing type.
fn to_verified(token: &DelegationToken) -> PyDelegationVerified {
    PyDelegationVerified {
        delegator: token.delegator.to_string(),
        delegatee: token.delegatee.to_string(),
        issued_by: token.issued_by.to_string(),
        grants: token.scope.clone(),
        expires_at: token.expires_at.0,
        cnf: token.cnf.clone(),
    }
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

    serde_json::to_string(&TctEnvelope { tct }).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

fn decode_pubkey_b64u(b64u: &str) -> PyResult<AitpVerifyingKey> {
    let bytes = base64url::decode_strict(b64u)
        .map_err(|e| PyValueError::new_err(format!("invalid base64url pubkey: {e}")))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        PyValueError::new_err(format!("pubkey must be 32 bytes (got {})", bytes.len(),))
    })?;
    AitpVerifyingKey::from_bytes(&arr)
        .map_err(|e| PyValueError::new_err(format!("invalid Ed25519 pubkey: {e}")))
}
