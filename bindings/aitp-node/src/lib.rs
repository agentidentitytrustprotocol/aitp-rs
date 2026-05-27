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

mod agent;
#[cfg(feature = "experimental-bundle")]
mod bundle;
mod delegation;
mod helpers;
mod oidc;
#[cfg(feature = "experimental-pinning")]
mod pinning;
#[cfg(feature = "experimental-renewal")]
mod renewal;
mod session;
mod tct;

use aitp_core::Timestamp;
use aitp_manifest::{verify_manifest, ManifestEnvelope, VerifyManifestContext};
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Verify a `ManifestEnvelope` JSON string. Throws on signature,
/// proof-of-possession, expiry, or identity-hint shape failures.
/// Used by the AITP Control Plane during agent enrollment.
#[napi]
pub fn verify_manifest_json(manifest_envelope_json: String) -> Result<()> {
    let envelope: ManifestEnvelope = serde_json::from_str(&manifest_envelope_json)
        .map_err(|e| Error::from_reason(format!("invalid manifest JSON: {e}")))?;
    verify_manifest(
        &envelope.manifest,
        &VerifyManifestContext {
            now: Timestamp::now(),
        },
    )
    .map_err(|e| Error::from_reason(format!("manifest verification failed: {e}")))?;
    Ok(())
}
