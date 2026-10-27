//! Delegation token binding — RFC-AITP-0006 (single-hop) / RFC-AITP-0011
//! (multi-hop).
//!
//! Wraps `aitp::delegation::DelegationBuilder` and `verify_delegation`. The
//! Python side calls into this for the demo's "researcher → writer → sub-
//! researcher" trust chain.
//!
//! v0.2 wire shape: a delegation token, like a TCT and a grant voucher, is
//! an **opaque compact JWS string** — not a JSON envelope. B delegates from
//! the **grant voucher** it received alongside its TCT in the handshake
//! commit, and A (the verifier / original grantor) re-mints a fresh TCT for
//! the delegatee once verification passes.

use aitp::core::{Aid, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::crypto::AitpVerifyingKey;
use aitp::delegation::{
    verify_delegation, DelegationBuilder, DelegationRevocation, VerifyDelegationContext,
};

use crate::helpers::{
    binding_revocation, delegation_revocation_code, runtime_error, BindingRevocation,
};
// RFC-AITP-0011 multi-hop ceiling — only referenced by the multi-hop
// opt-in verifier, so the import is feature-gated to avoid an unused-import
// warning in the default (strict v0.1) build.
#[cfg(feature = "multihop-delegation")]
use aitp::delegation::DEFAULT_MAX_DELEGATION_HOPS;
use pyo3::exceptions::{PyDeprecationWarning, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::collections::HashSet;
use uuid::Uuid;

/// Parse a verify call's deny list and `revocation` mode.
///
/// The list is captured **by value** rather than wrapping a Python
/// callable, mirroring `tct.rs`: the verify call then runs entirely in Rust
/// with no re-entrancy into the interpreter, and a raising callback cannot
/// be swallowed as "not revoked".
///
/// **Issuer attribution.** RFC-AITP-0011 §6 specifies each hop `jti` be
/// looked up against the deny list of *that hop's issuer*. A flat set cannot
/// express that, so the same set is applied to every hop: a `jti` present in
/// it is rejected whichever peer issued that hop. The deviation is
/// conservative (it can only reject more, never accept a revoked hop) and
/// `jti`s are UUIDv4, so cross-issuer collision is not a practical concern.
/// It does mean a caller aggregating several issuers' lists — an AITP
/// control plane, say — grants every contributor the power to revoke any
/// hop. Callers needing per-issuer isolation should verify against the Rust
/// API directly, where `hop_revocation_check` receives the issuer AID.
///
/// **Normalization.** The set is a lookup key, so each entry may be in any
/// RFC 9562 text form (uppercase, braced, `urn:uuid:`, unhyphenated) and is
/// normalized before matching. An entry that is not a UUID raises
/// `ValueError` rather than silently never matching.
fn delegation_revocation(
    revoked_jtis: Option<&HashSet<String>>,
    revocation: Option<&str>,
) -> PyResult<BindingRevocation> {
    binding_revocation(
        revoked_jtis.map(|s| s.iter().map(String::as_str)),
        revocation,
    )
    .map_err(PyValueError::new_err)
}

/// A delegation verification failure, coded for revocation rejections.
fn verify_failed(e: aitp::delegation::DelegationError) -> PyErr {
    runtime_error(
        format!("delegation verification failed: {e}"),
        delegation_revocation_code(&e),
    )
}

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
    /// Named after the claim path, matching Node's `cnfJkt` and
    /// `compute_aid_jkt` (#240).
    #[pyo3(get)]
    pub cnf_jkt: String,
}

#[pymethods]
impl PyDelegationVerified {
    /// Deprecated alias for `cnf_jkt`, kept so 0.15 callers keep working
    /// (#240). Emits a `DeprecationWarning` on every read.
    #[getter]
    fn cnf(&self, py: Python<'_>) -> PyResult<String> {
        PyErr::warn(
            py,
            &py.get_type::<PyDeprecationWarning>(),
            c"DelegationVerified.cnf is deprecated; use cnf_jkt",
            1,
        )?;
        Ok(self.cnf_jkt.clone())
    }
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
/// `issuer_manifests` is the delegator's (B's) Manifest, each entry a
/// `{"manifest": {...}}` envelope JSON string. RFC-AITP-0006 §4 step 1
/// verifies the token under the key resolved from its issuer's verified
/// Manifest; a token whose issuer has no valid Manifest here fails with
/// `KEY_RESOLUTION_FAILED`. Each Manifest is verified (RFC-AITP-0003 §5)
/// before use; when several designate one AID the newest `published_at`
/// wins.
///
/// Returns the verified token's salient fields. Raises `PyValueError` for a
/// malformed AID or Manifest and `PyRuntimeError` for verification failure.
///
/// `revoked_jtis` is A's own deny list (a set of revoked `jti` strings). A
/// token whose `voucher.src_jti` is in it is rejected after every signature
/// check passes (RFC-AITP-0006 §4 step 7, ordered per RFC-AITP-0008 §3.3).
/// Revocation is `fail_closed`: **without `revoked_jtis` every token is
/// rejected** with `RuntimeError.code == "DELEGATION_SOURCE_TCT_REVOKED"`
/// and a "revocation source unavailable" message. Pass an empty set when
/// nothing is revoked, or `revocation="fail_open"` to skip the check.
/// Entries are normalized (any RFC 9562 text form matches); one that is
/// not a UUID raises `ValueError`.
#[pyfunction]
#[pyo3(name = "verify_delegation", signature = (delegation_token, verifier_aid, issuer_manifests, revoked_jtis = None, revocation = None))]
pub fn verify_delegation_py(
    delegation_token: &str,
    verifier_aid: &str,
    issuer_manifests: Vec<String>,
    revoked_jtis: Option<HashSet<String>>,
    revocation: Option<&str>,
) -> PyResult<PyDelegationVerified> {
    let verifier = parse_verifier(verifier_aid)?;
    let deny = delegation_revocation(revoked_jtis.as_ref(), revocation)?;
    let manifests = parse_issuer_manifests(&issuer_manifests)?;

    // `VerifyDelegationContext::new` ships `max_delegation_hops = 0` (single-hop
    // strict), so a non-empty chain fails before any per-hop work runs — which
    // is also why only the root check is wired here: there are no hops.
    let root = |jti: &Uuid| deny.delegation_status(jti);
    let source = if deny.is_fail_open() {
        DelegationRevocation::FailOpen
    } else {
        DelegationRevocation::Check(&root)
    };
    let ctx = VerifyDelegationContext::new(&verifier, Timestamp::now(), source)
        .with_issuer_manifests(&manifests);

    let verified = verify_delegation(delegation_token, &ctx).map_err(verify_failed)?;

    Ok(to_verified(&verified))
}

/// Verify a delegation token (compact-JWS string) allowing **draft
/// RFC-AITP-0011 multi-hop** chains up to `max_delegation_hops` total hops.
///
/// This opts into behavior that is **not** part of AITP v0.1. It is only
/// compiled in under the `multihop-delegation` feature; a
/// default build exposes only the strict [`verify_delegation_py`].
///
/// `max_delegation_hops` defaults to `DEFAULT_MAX_DELEGATION_HOPS` (the RFC-AITP-0011 §2
/// recommended ceiling). Pass a smaller value for a tighter bound;
/// `max_delegation_hops = 0` reverts to strict v0.1 (rejects any non-empty chain).
///
/// `revoked_jtis` is consulted twice, both after every signature check:
/// once for the root `voucher.src_jti` (RFC-AITP-0006 §4 step 7) and once
/// per hop — every chain entry and the outer token — per RFC-AITP-0011 §6,
/// which makes both a MUST-reject. See [`delegation_revocation`] for why one
/// flat set stands in for §6's per-issuer deny lists. `revoked_jtis` and
/// `revocation` are otherwise as in `verify_delegation` (`fail_closed`).
///
/// `issuer_manifests` is the hop issuers' Manifests, each a
/// `{"manifest": {...}}` envelope JSON string. RFC-AITP-0011 §3 step 1
/// verifies every hop under the key resolved from its issuer's verified
/// Manifest; a hop whose issuer has no valid Manifest here fails with
/// `KEY_RESOLUTION_FAILED`. Each Manifest is verified (RFC-AITP-0003 §5)
/// before use; when several designate one AID the newest `published_at`
/// wins.
#[cfg(feature = "multihop-delegation")]
#[pyfunction]
#[pyo3(
    name = "verify_delegation_multihop",
    signature = (delegation_token, verifier_aid, issuer_manifests, max_delegation_hops = DEFAULT_MAX_DELEGATION_HOPS, revoked_jtis = None, revocation = None)
)]
pub fn verify_delegation_multihop_py(
    delegation_token: &str,
    verifier_aid: &str,
    issuer_manifests: Vec<String>,
    max_delegation_hops: usize,
    revoked_jtis: Option<HashSet<String>>,
    revocation: Option<&str>,
) -> PyResult<PyDelegationVerified> {
    let verifier = parse_verifier(verifier_aid)?;
    let deny = delegation_revocation(revoked_jtis.as_ref(), revocation)?;
    let manifests = parse_issuer_manifests(&issuer_manifests)?;

    let root = |jti: &Uuid| deny.delegation_status(jti);
    let hop = |_issuer: &Aid, jti: &Uuid| deny.delegation_status(jti);
    let source = if deny.is_fail_open() {
        DelegationRevocation::FailOpen
    } else {
        DelegationRevocation::Check(&root)
    };
    let ctx = VerifyDelegationContext::new(&verifier, Timestamp::now(), source)
        .with_max_delegation_hops(max_delegation_hops)
        .with_issuer_manifests(&manifests)
        .with_hop_revocation_check(&hop);

    let verified = verify_delegation(delegation_token, &ctx).map_err(verify_failed)?;

    Ok(to_verified(&verified))
}

/// Parse the issuer Manifests (`{"manifest": {...}}` envelope JSON strings)
/// a verify call resolves delegation issuer keys from.
fn parse_issuer_manifests(issuer_manifests: &[String]) -> PyResult<Vec<aitp::manifest::Manifest>> {
    issuer_manifests
        .iter()
        .map(|json| {
            crate::wire::manifest(json)
                .map_err(|e| PyValueError::new_err(format!("invalid issuer manifest JSON: {e}")))
        })
        .collect()
}

/// Parse the verifier's own AID string.
fn parse_verifier(verifier_aid: &str) -> PyResult<Aid> {
    Aid::parse(verifier_aid)
        .map_err(|e| PyValueError::new_err(format!("invalid verifier AID: {e}")))
}

/// Project a [`aitp::delegation::VerifiedDelegation`] into the Python-facing
/// type. The "delegator" (ultimate grantor A) is the root voucher's `iss`.
fn to_verified(verified: &aitp::delegation::VerifiedDelegation) -> PyDelegationVerified {
    PyDelegationVerified {
        delegator: verified.voucher.iss.to_string(),
        delegatee: verified.claims.sub.to_string(),
        issued_by: verified.claims.iss.to_string(),
        grants: verified.claims.scope.clone(),
        expires_at: verified.claims.exp.0,
        cnf_jkt: verified.claims.cnf.jkt.clone(),
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

    let mut builder = aitp::tct::TctBuilder::new(issuer_key)
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
