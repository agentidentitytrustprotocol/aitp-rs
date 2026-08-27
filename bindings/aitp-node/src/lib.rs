//! AITP Node.js SDK — Agent Identity & Trust Protocol.
//!
//! Thin NAPI-rs binding over the pure-Rust AITP protocol crates. Every
//! method consumes and produces JSON strings that are HTTP request /
//! response bodies, so agent code never sees a Rust type across the
//! boundary.
//!
//! `#![forbid(unsafe_code)]` is intentionally omitted: the NAPI-rs
//! export macros expand to `unsafe` glue. The underlying protocol
//! crates keep the forbid attribute.

// In a `cfg(test)` build of this cdylib the NAPI-rs registration glue —
// which is what actually references the `#[napi]` exports — is not emitted,
// so those FFI entry points look unused. They are exercised from JS via
// `node --test tests/*.mjs`, not Rust unit tests, so silence dead-code in
// test builds rather than littering each export with `#[allow]`.
#![cfg_attr(test, allow(dead_code))]

mod agent;
#[cfg(feature = "session-bundle")]
mod bundle;
mod delegation;
mod helpers;
mod oidc;
#[cfg(feature = "spki-pinning")]
mod pinning;
#[cfg(feature = "renewal")]
mod renewal;
mod revocation;
mod session;
mod tct;

use aitp_core::Timestamp;
use aitp_manifest::{verify_manifest, ManifestEnvelope, ManifestError, VerifyManifestContext};
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Map a `ManifestError` onto a stable cause code.
///
/// The codes are the binding's public contract; the message wording is not.
/// Mirrors `revocation::verification_cause` — the two verify paths had
/// asymmetric error surfaces until 0.6.1, so a caller wanting to tell "this
/// manifest expired" from "this manifest is forged" had to substring-match
/// prose on one side while the other offered `error.code`.
fn manifest_verification_cause(err: &ManifestError) -> &'static str {
    match err {
        ManifestError::Expired => "expired",
        ManifestError::SignatureInvalid => "signature_invalid",
        ManifestError::PopFailed => "pop_failed",
        ManifestError::AidMismatch => "aid_mismatch",
        ManifestError::VersionUnknown => "version_unknown",
        ManifestError::IdentityHintMalformed(_) => "identity_hint_malformed",
        ManifestError::IncompatibleIdentityType(_) => "incompatible_identity_type",
        _ => "malformed",
    }
}

/// Verify a `ManifestEnvelope` JSON string. Used by the AITP Control Plane
/// during agent enrollment, and by any consumer reading an AID or endpoint
/// out of a peer's manifest.
///
/// On failure throws an `Error` whose **`code`** property is one of
/// `signature_invalid`, `pop_failed`, `aid_mismatch`, `expired`,
/// `version_unknown`, `identity_hint_malformed`,
/// `incompatible_identity_type`, `malformed`. Branch on `error.code`, never
/// on `error.message`: the code is the contract, the wording is not.
#[napi]
pub fn verify_manifest_json(env: Env, manifest_envelope_json: String) -> Result<()> {
    let envelope: ManifestEnvelope = serde_json::from_str(&manifest_envelope_json)
        .map_err(|e| throw_with_code(env, "malformed", format!("invalid manifest JSON: {e}")))?;
    verify_manifest(
        &envelope.manifest,
        &VerifyManifestContext {
            now: Timestamp::now(),
        },
    )
    .map_err(|e| {
        throw_with_code(
            env,
            manifest_verification_cause(&e),
            format!("manifest verification failed: {e}"),
        )
    })?;
    Ok(())
}

/// Throw a JS `Error` whose `code` property is the stable cause.
///
/// `Error::new(Status::GenericFailure, ..)` will NOT do this — the status
/// surfaced as `error.code` is whichever `Status` was passed, so every cause
/// would arrive as `"GenericFailure"` and the only way back to the real one
/// would be parsing `error.message`. `Env::throw_error` sets the property
/// directly; returning `Status::PendingException` tells napi an exception is
/// already queued so it does not throw a second one over the top.
fn throw_with_code(env: Env, code: &str, message: String) -> Error {
    match env.throw_error(&message, Some(code)) {
        Ok(()) => Error::new(Status::PendingException, message),
        Err(e) => e,
    }
}
