//! Delegation token binding — RFC-AITP-0006 (single-hop) / RFC-AITP-0011
//! (multi-hop).
//!
//! Wraps `aitp_delegation::DelegationBuilder` and `verify_delegation`. The
//! Python side calls into this for the demo's "researcher → writer → sub-
//! researcher" trust chain.
//!
//! v0.2 wire shape: a delegation token, like a TCT and a grant voucher, is
//! an **opaque compact JWS string** — not a JSON envelope. B delegates from
//! the **grant voucher** it received alongside its TCT in the handshake
//! commit, and A (the verifier / original grantor) re-mints a fresh TCT for
//! the delegatee once verification passes.

use aitp_core::{Aid, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_crypto::AitpVerifyingKey;
use aitp_delegation::{verify_delegation, DelegationBuilder, VerifyDelegationContext};
// RFC-AITP-0011 multi-hop ceiling — only referenced by the multi-hop
// opt-in verifier, so the import is feature-gated to avoid an unused-import
// warning in the default (strict v0.1) build.
#[cfg(feature = "multihop-delegation")]
use aitp_delegation::DEFAULT_MAX_HOPS;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

/// The verified delegation token's salient fields, returned to Python after
/// `verify_delegation` succeeds.
#[pyclass(name = "DelegationVerified", frozen)]
pub struct PyDelegationVerified {
    /// AID of the ultimate grantor — the original TCT/voucher issuer (A).
    /// The verifier side checks this matches its own AID before redeeming;
    /// `verify_delegation` already enforces it (`voucher.iss == verifier`).
    #[pyo3(get)]
    pub delegator: String,
    /// AID of the recipient (C) — who will receive a fresh TCT. This is the
    /// outer token's `sub`.
    #[pyo3(get)]
    pub delegatee: String,
    /// AID of the agent that issued this delegation (B in the RFC) — the
    /// outer token's `iss`.
    #[pyo3(get)]
    pub issued_by: String,
    /// Capabilities being delegated. Always a subset of the source voucher's
    /// grants.
    #[pyo3(get)]
    pub grants: Vec<String>,
    /// Unix-seconds expiry of the delegation token itself.
    #[pyo3(get)]
    pub expires_at: i64,
    /// The delegatee's `cnf.jkt` — the RFC 7638 JWK thumbprint binding the
    /// delegatee's key. Redundant with the key encoded in `delegatee`'s AID
    /// (the AID is authoritative), but surfaced for JOSE-generic callers.
    #[pyo3(get)]
    pub cnf: String,
}

/// Verify a delegation token (compact-JWS string) under **strict AITP v0.1**
/// (RFC-AITP-0006 single-hop). `verifier_aid` is the verifier's own AID
/// string — verification fails unless it equals the embedded voucher's `iss`
/// (the original grantor A) and every hop's `aud`.
///
/// Any token carrying a non-empty `chain` (a draft RFC-AITP-0011 multi-hop
/// delegation) is **rejected**, matching the Rust core default. To opt into
/// multi-hop, build the SDK with the `multihop-delegation`
/// feature and call `verify_delegation_multihop`.
///
/// Returns the verified token's salient fields. Raises `PyValueError` for a
/// malformed AID and `PyRuntimeError` for verification failure.
#[pyfunction]
#[pyo3(name = "verify_delegation", signature = (delegation_token, verifier_aid))]
pub fn verify_delegation_py(
    delegation_token: &str,
    verifier_aid: &str,
) -> PyResult<PyDelegationVerified> {
    let verifier = parse_verifier(verifier_aid)?;

    // `VerifyDelegationContext::new` ships `max_hops = 0` (single-hop
    // strict), so a non-empty chain fails before any per-hop work runs.
    let ctx = VerifyDelegationContext::new(&verifier, Timestamp::now());

    let verified = verify_delegation(delegation_token, &ctx)
        .map_err(|e| PyRuntimeError::new_err(format!("delegation verification failed: {e}")))?;

    Ok(to_verified(&verified))
}

/// Verify a delegation token (compact-JWS string) allowing **draft
/// RFC-AITP-0011 multi-hop** chains up to `max_hops` total hops.
///
/// This opts into behavior that is **not** part of AITP v0.1. It is only
/// compiled in under the `multihop-delegation` feature; a
/// default build exposes only the strict [`verify_delegation_py`].
///
/// `max_hops` defaults to `DEFAULT_MAX_HOPS` (the RFC-AITP-0011 §2
/// recommended ceiling). Pass a smaller value for a tighter bound;
/// `max_hops = 0` reverts to strict v0.1 (rejects any non-empty chain).
#[cfg(feature = "multihop-delegation")]
#[pyfunction]
#[pyo3(
    name = "verify_delegation_multihop",
    signature = (delegation_token, verifier_aid, max_hops = DEFAULT_MAX_HOPS)
)]
pub fn verify_delegation_multihop_py(
    delegation_token: &str,
    verifier_aid: &str,
    max_hops: usize,
) -> PyResult<PyDelegationVerified> {
    let verifier = parse_verifier(verifier_aid)?;

    let ctx = VerifyDelegationContext::new(&verifier, Timestamp::now()).with_max_hops(max_hops);

    let verified = verify_delegation(delegation_token, &ctx)
        .map_err(|e| PyRuntimeError::new_err(format!("delegation verification failed: {e}")))?;

    Ok(to_verified(&verified))
}

/// Parse the verifier's own AID string.
fn parse_verifier(verifier_aid: &str) -> PyResult<Aid> {
    Aid::parse(verifier_aid)
        .map_err(|e| PyValueError::new_err(format!("invalid verifier AID: {e}")))
}

/// Project a [`aitp_delegation::VerifiedDelegation`] into the Python-facing
/// type. The "delegator" (ultimate grantor A) is the root voucher's `iss`.
fn to_verified(verified: &aitp_delegation::VerifiedDelegation) -> PyDelegationVerified {
    PyDelegationVerified {
        delegator: verified.voucher.iss.to_string(),
        delegatee: verified.claims.sub.to_string(),
        issued_by: verified.claims.iss.to_string(),
        grants: verified.claims.scope.clone(),
        expires_at: verified.claims.exp.0,
        cnf: verified.claims.cnf.jkt.clone(),
    }
}

// Helpers used by `agent.rs` — exported as crate-private so the
// `AitpAgent.build_delegation` / `issue_tct_for_delegatee` methods can call
// them with a borrowed `&AitpSigningKey`.

/// Build a single-hop delegation token (compact JWS) from a held grant
/// voucher (RFC-AITP-0006).
///
/// * `voucher_token` — the grant-voucher compact JWS the delegator (B)
///   received from the original issuer (A) in the handshake commit. The
///   voucher's `sub` MUST equal the delegator's own AID.
/// * `delegatee_aid_str` — recipient (C)'s AID. Its `cnf.jkt` binding is
///   derived from the key the AID encodes — no separate pubkey argument is
///   needed (the AID is authoritative).
/// * `scope` — subset of the voucher's grants to delegate.
/// * `ttl_secs` — token lifetime; `None` uses the crate default (capped at
///   the voucher's `exp`).
pub(crate) fn build_delegation_token(
    delegator_key: &AitpSigningKey,
    voucher_token: &str,
    delegatee_aid_str: &str,
    scope: Vec<String>,
    ttl_secs: Option<i64>,
) -> PyResult<String> {
    let delegatee_aid = Aid::parse(delegatee_aid_str)
        .map_err(|e| PyValueError::new_err(format!("invalid delegatee AID: {e}")))?;

    let mut builder = DelegationBuilder::new(delegator_key, voucher_token)
        .map_err(|e| PyRuntimeError::new_err(format!("delegation build failed: {e}")))?
        .delegatee(delegatee_aid)
        .scope(scope);
    if let Some(ttl) = ttl_secs {
        builder = builder.ttl_secs(ttl);
    }

    builder
        .build()
        .map_err(|e| PyRuntimeError::new_err(format!("delegation build failed: {e}")))
}

/// Mint a fresh TCT for the delegatee after `verify_delegation` succeeded.
///
/// In v0.2 audience MUST equal subject, so both are set to the delegatee's
/// AID. The subject's public key is derived from the delegatee's AID — the
/// AID encodes it, and `verify_delegation` already cross-checked the
/// delegation's `cnf.jkt` against that key. Returns a JSON object
/// `{"tct": "<compact JWS>", "grant_voucher": "<compact JWS>" | null}`.
pub(crate) fn issue_tct_for_delegatee_json(
    issuer_key: &AitpSigningKey,
    verified: &PyDelegationVerified,
    ttl_secs: Option<i64>,
) -> PyResult<String> {
    let delegatee_aid = Aid::parse(&verified.delegatee)
        .map_err(|e| PyValueError::new_err(format!("invalid delegatee AID: {e}")))?;
    let delegatee_pk = AitpVerifyingKey::from_aid(&delegatee_aid)
        .map_err(|e| PyValueError::new_err(format!("delegatee AID has invalid key bytes: {e}")))?;

    let mut builder = aitp_tct::TctBuilder::new(issuer_key)
        .subject(delegatee_aid.clone())
        .audience(delegatee_aid)
        .grants(verified.grants.clone())
        .subject_pubkey(delegatee_pk);
    if let Some(ttl) = ttl_secs {
        builder = builder.ttl_secs(ttl);
    }

    let issued = builder
        .build()
        .map_err(|e| PyRuntimeError::new_err(format!("TCT mint failed: {e}")))?;

    let out = serde_json::json!({
        "tct": issued.token,
        "grant_voucher": issued.voucher,
    });
    serde_json::to_string(&out).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}
