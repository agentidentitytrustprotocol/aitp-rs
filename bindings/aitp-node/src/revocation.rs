//! Revocation-snapshot verification binding.
//!
//! `AitpAgent.signRevocationList` (see `agent.rs`) has existed since the
//! control plane needed to publish deny lists. Its counterpart did not: until
//! 0.6.0 both the Node and Python bindings exposed the signing half and
//! neither exposed `verify_revocation_list`, even though
//! `verify_revocation_snapshot` is a Tier C conformance operation the Rust
//! adapter implements (`docs/conformance.md`).
//!
//! That asymmetry had consequences downstream. `aitp-control-plane` hand-rolled
//! a verifier in a test; `aitp-playground` skipped verification entirely;
//! `aitp-ui-console` rendered "signed by CP" from the presence of a JSON key.
//! The 0.5.0 signing-input change then crossed the whole release family with a
//! single accidental interlock standing in its way. One missing binding, three
//! times.

use aitp_core::{Aid, Timestamp};
use aitp_tct::{
    revocation_signing_bytes, verify_revocation_list, RevocationListEnvelope, TctError,
    VerifyRevocationListContext,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Stable machine-readable cause for a verification failure.
///
/// Thrown errors carry this as `error.code`. Branch on it, never on
/// `error.message`: matching message text pins program output as an expected
/// value, which is the bug class the 0.5.0 signing-input change exposed.
fn verification_cause(err: &TctError) -> &'static str {
    match err {
        TctError::SignatureInvalid => "signature_invalid",
        TctError::IssuerMismatch => "issuer_mismatch",
        TctError::VersionUnknown => "version_unknown",
        TctError::Expired => "expired",
        _ => "malformed",
    }
}

/// Throw a JS `Error` whose `code` property is the stable cause.
///
/// `Error::new(Status::GenericFailure, ..)` will NOT do this: the status
/// surfaced as `error.code` is whichever `Status` was passed, so every cause
/// would arrive as `"GenericFailure"` and the only way to recover the real one
/// would be parsing `error.message`. That is the anti-pattern this binding
/// exists to remove — a caller string-matching an error message is pinning
/// program output as an expected value.
///
/// `Env::throw_error(msg, Some(code))` sets the property directly. Returning
/// `Status::PendingException` afterwards tells napi a JS exception is already
/// queued so it does not throw a second one over the top.
fn throw_verification_error(env: Env, code: &str, message: String) -> Error {
    match env.throw_error(&message, Some(code)) {
        Ok(()) => Error::new(Status::PendingException, message),
        Err(e) => e,
    }
}

/// Verify a `RevocationListEnvelope` JSON string against a pinned issuer.
///
/// Resolves on success; on failure throws an `Error` whose **`code`** property
/// is one of `signature_invalid`, `issuer_mismatch`, `version_unknown`,
/// `expired`, `malformed`. Branch on `error.code`, never on `error.message`:
/// the code is the contract, the message wording is not.
///
/// Establishes **authenticity and non-expiry only** — that the snapshot was
/// signed by the holder of `expectedIssuerAid` and that its `expires_at` has
/// not passed. It deliberately does not check `published_at` staleness:
/// RFC-AITP-0008 §3 puts freshness policy at the consuming peer, and
/// collapsing authenticity and freshness into a single switch is how a
/// `soft_fail` mode ends up reporting a *forged* snapshot as not-revoked.
/// The caller owns the staleness budget.
#[napi(js_name = "verifyRevocationList")]
pub fn verify_revocation_list_js(
    env: Env,
    envelope_json: String,
    expected_issuer_aid: String,
    now_unix_secs: Option<i64>,
) -> Result<()> {
    let envelope: RevocationListEnvelope = serde_json::from_str(&envelope_json).map_err(|e| {
        throw_verification_error(
            env,
            "malformed",
            format!("invalid revocation envelope JSON: {e}"),
        )
    })?;
    // A bad AID is the caller's error, not the snapshot's — do not report it
    // as a verification cause.
    let expected = Aid::parse(&expected_issuer_aid)
        .map_err(|e| Error::from_reason(format!("invalid expectedIssuerAid: {e}")))?;
    let now = Timestamp(now_unix_secs.unwrap_or_else(|| Timestamp::now().0));
    let ctx = VerifyRevocationListContext::new(&expected, now);
    verify_revocation_list(&envelope, &ctx).map_err(|e| {
        throw_verification_error(
            env,
            verification_cause(&e),
            format!("revocation snapshot verification failed: {e}"),
        )
    })
}

/// The exact bytes a revocation snapshot's signature is computed over:
/// `JCS(revocation_list)` — the **inner** body, not the transport wrapper.
///
/// Exposed so a caller needing the signed bytes (an independent verifier, an
/// HSM signing path, a debugging tool) obtains them rather than reconstructing
/// the shape at the call site. Reconstructing it is how signer, verifier and
/// conformance fixture drifted apart before 0.5.0.
#[napi(js_name = "revocationSigningBytes")]
pub fn revocation_signing_bytes_js(envelope_json: String) -> Result<Buffer> {
    let envelope: RevocationListEnvelope = serde_json::from_str(&envelope_json)
        .map_err(|e| Error::from_reason(format!("invalid revocation envelope JSON: {e}")))?;
    let bytes = revocation_signing_bytes(&envelope.revocation_list)
        .map_err(|e| Error::from_reason(format!("canonicalization failed: {e}")))?;
    Ok(Buffer::from(bytes))
}
