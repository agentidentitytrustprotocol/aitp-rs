//! Delegation token binding — RFC-AITP-0006 (voucher-based, v0.2).
//!
//! In v0.2 a delegation is an **opaque compact-JWS string** rooted in a
//! **grant voucher** (`typ: aitp-grant+jwt`) the delegator received
//! alongside its TCT during the handshake. The binding wraps
//! `aitp_delegation::DelegationBuilder` and `verify_delegation` so a Node
//! consumer can mint a delegation from its held voucher, verify a peer's
//! delegation, and (as the original grantor) mint a fresh TCT bound to
//! the delegatee's key.

use aitp_core::{Aid, Timestamp};
use aitp_crypto::AitpVerifyingKey;
use aitp_delegation::{verify_delegation, DelegationBuilder, VerifyDelegationContext};
// RFC-AITP-0011 multi-hop ceiling — only referenced by the multi-hop
// opt-in verifier, so the import is feature-gated to avoid an unused-import
// warning in the default (strict single-hop) build.
#[cfg(feature = "multihop-delegation")]
use aitp_delegation::DEFAULT_MAX_HOPS;
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// The verified delegation's salient fields. Returned from
/// `verifyDelegation` and consumed by `AitpAgent.issueTctForDelegatee`.
#[napi(object)]
pub struct JsDelegationVerified {
    /// AID of the ultimate grantor (the original TCT issuer that gave
    /// grants to `issuedBy`). Equal to the delegation's `aud` and to the
    /// embedded voucher's `iss`. The responder side checks this matches
    /// its own AID before redeeming.
    pub delegator: String,
    /// AID of the recipient (C) — who will receive a fresh TCT (`sub`).
    pub delegatee: String,
    /// AID of the agent that issued this delegation (B in the RFC) (`iss`).
    pub issued_by: String,
    /// Capabilities being delegated (`scope`). Always a subset of the
    /// root voucher's grants.
    pub grants: Vec<String>,
    /// Unix-seconds expiry of the delegation token itself (`exp`).
    pub expires_at: f64,
    /// RFC 7638 JWK thumbprint of the delegatee's key (`cnf.jkt`). In
    /// v0.2 this is derived from — and must match — the key encoded in
    /// `delegatee`'s AID; the fresh TCT's key binding is taken from the
    /// AID, not from this field.
    pub cnf_jkt: String,
}

/// Verify a delegation compact JWS under **strict AITP v0.2**
/// (RFC-AITP-0006 single-hop). `verifierAid` is the verifier's own AID
/// string — it MUST equal the delegation's `aud` (the root grantor), and
/// the embedded voucher MUST verify under the verifier's own key.
///
/// Any token carrying a non-empty `chain` (an RFC-AITP-0011 multi-hop
/// delegation) is **rejected** with `DELEGATION_MULTIHOP_NOT_SUPPORTED`,
/// matching the Rust core default. To allow multi-hop chains, call
/// `verifyDelegationMultihop` instead.
#[napi(js_name = "verifyDelegation")]
pub fn verify_delegation_js(token: String, verifier_aid: String) -> Result<JsDelegationVerified> {
    let verifier = parse_verifier(&verifier_aid)?;

    // `VerifyDelegationContext::new` ships `max_hops = 0`, so a non-empty
    // chain fails before any per-hop work runs.
    let ctx = VerifyDelegationContext::new(&verifier, Timestamp::now());

    let verified = verify_delegation(&token, &ctx)
        .map_err(|e| Error::from_reason(format!("delegation verification failed: {e}")))?;

    Ok(to_verified(&verified))
}

/// Verify a delegation compact JWS allowing **RFC-AITP-0011 multi-hop**
/// chains up to `maxHops` total hops (`chain.length + 1`).
///
/// The strict single-hop `verifyDelegation` is the safe default; this
/// function additionally allows multi-hop chains. Present by default (the
/// `multihop-delegation` feature); a `--no-default-features` build omits it.
///
/// `maxHops` defaults to `DEFAULT_MAX_HOPS` (3, the RFC-AITP-0011 §2
/// recommended ceiling). Pass a smaller value for a tighter bound;
/// `maxHops = 0` reverts to strict single-hop (rejects any non-empty chain).
#[cfg(feature = "multihop-delegation")]
#[napi(js_name = "verifyDelegationMultihop")]
pub fn verify_delegation_multihop_js(
    token: String,
    verifier_aid: String,
    max_hops: Option<u32>,
) -> Result<JsDelegationVerified> {
    let verifier = parse_verifier(&verifier_aid)?;

    let hops = max_hops.unwrap_or(DEFAULT_MAX_HOPS as u32) as usize;
    let ctx = VerifyDelegationContext::new(&verifier, Timestamp::now()).with_max_hops(hops);

    let verified = verify_delegation(&token, &ctx)
        .map_err(|e| Error::from_reason(format!("delegation verification failed: {e}")))?;

    Ok(to_verified(&verified))
}

/// Parse the verifier's own AID string.
fn parse_verifier(verifier_aid: &str) -> Result<Aid> {
    Aid::parse(verifier_aid).map_err(|e| Error::from_reason(format!("invalid verifier AID: {e}")))
}

/// Project a verified delegation's salient fields into the Node-facing type.
fn to_verified(verified: &aitp_delegation::VerifiedDelegation) -> JsDelegationVerified {
    let claims = &verified.claims;
    JsDelegationVerified {
        // The ultimate grantor is the delegation's audience (the verifier),
        // which equals the embedded voucher's issuer.
        delegator: claims.aud.to_string(),
        delegatee: claims.sub.to_string(),
        issued_by: claims.iss.to_string(),
        grants: claims.scope.clone(),
        expires_at: claims.exp.0 as f64,
        cnf_jkt: claims.cnf.jkt.clone(),
    }
}

/// Build a delegation compact JWS from a held **grant voucher**
/// (RFC-AITP-0006). Returns the opaque token string.
///
/// * `voucher_token` — the grant voucher the delegator received from the
///   original issuer (delivered alongside its TCT in the handshake
///   commit; surfaced by `complete()` / `processCommit()` as
///   `grantVoucher`).
/// * `delegatee_aid_str` — recipient's AID. Its embedded key drives
///   `cnf.jkt`; no separate public-key argument is needed in v0.2.
/// * `scope` — subset of the voucher's grants to delegate.
/// * `ttl_secs` — token lifetime; `None` uses `DEFAULT_DELEGATION_TTL_SECS`
///   (capped at the voucher's expiry).
pub(crate) fn build_delegation_token_json(
    issuer_key: &aitp_crypto::AitpSigningKey,
    voucher_token: &str,
    delegatee_aid_str: &str,
    scope: Vec<String>,
    ttl_secs: Option<i64>,
) -> Result<String> {
    let delegatee_aid = Aid::parse(delegatee_aid_str)
        .map_err(|e| Error::from_reason(format!("invalid delegatee AID: {e}")))?;

    let mut builder = DelegationBuilder::new(issuer_key, voucher_token)
        .map_err(|e| Error::from_reason(format!("delegation build failed: {e}")))?
        .delegatee(delegatee_aid)
        .scope(scope);
    if let Some(ttl) = ttl_secs {
        builder = builder.ttl_secs(ttl);
    }

    builder
        .build()
        .map_err(|e| Error::from_reason(format!("delegation build failed: {e}")))
}

/// Mint a fresh TCT compact JWS for the delegatee after `verifyDelegation`
/// succeeded. Returns the opaque token string.
///
/// In v0.2 audience MUST equal subject, so both are set to the delegatee's
/// AID. The subject's public key is decoded from the delegatee AID itself
/// (the AID encodes the key); the TCT builder re-checks that the key's
/// thumbprint matches the AID's `cnf.jkt`.
pub(crate) fn issue_tct_for_delegatee_json(
    issuer_key: &aitp_crypto::AitpSigningKey,
    verified: &JsDelegationVerified,
    ttl_secs: Option<i64>,
) -> Result<String> {
    let delegatee_aid = Aid::parse(&verified.delegatee)
        .map_err(|e| Error::from_reason(format!("invalid delegatee AID: {e}")))?;
    let delegatee_pk = AitpVerifyingKey::from_aid(&delegatee_aid)
        .map_err(|e| Error::from_reason(format!("delegatee AID has invalid key: {e}")))?;

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
        .map_err(|e| Error::from_reason(format!("TCT mint failed: {e}")))?;

    Ok(issued.token)
}
