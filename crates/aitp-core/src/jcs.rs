//! RFC 8785 JSON Canonicalization Scheme (JCS).
//!
//! AITP signatures are computed over JCS-canonical JSON. JCS specifies
//! deterministic serialization with no whitespace, lexicographically sorted
//! object keys (UTF-16 code-unit ordering), ECMAScript-style number formatting,
//! and well-defined Unicode handling.
//!
//! This module wraps the `serde_jcs` crate. We may fork or replace the backing
//! crate if we discover correctness gaps; the public API here is the stable
//! contract that protocol crates depend on.
//!
//! See [`docs/design/01-jcs.md`](../../../../docs/design/01-jcs.md) for
//! the test vector strategy.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Errors that can occur during canonicalization.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JcsError {
    /// JSON contained a non-finite number (NaN or Infinity); RFC 8785 forbids these.
    #[error("number is not finite (NaN or Infinity is not permitted in JSON)")]
    NonFiniteNumber,

    /// Reserved. Duplicate object keys are *not* detected here: this
    /// module canonicalizes an already-parsed [`serde_json::Value`], and
    /// `serde_json` (built with `preserve_order`) collapses duplicate
    /// keys last-wins at parse time, before canonicalization. Since both
    /// signer and verifier canonicalize the same parsed value, there is
    /// no signature split-brain (RFC 8785 operates on parsed JSON). This
    /// variant is retained for API stability and is never constructed by
    /// [`canonicalize`]; reject duplicate keys at a raw-bytes
    /// deserialization step if a deployment's threat model requires it.
    #[error("duplicate key '{0}' in JSON object")]
    DuplicateKey(String),

    /// Underlying serde error.
    #[error("serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Serialize a JSON value to RFC 8785 canonical JSON bytes.
///
/// The output is suitable as a signing input. Two implementations of JCS
/// MUST produce byte-identical output for the same logical JSON document.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, JcsError> {
    serde_jcs::to_vec(value).map_err(JcsError::from)
}

/// Convenience: canonicalize any serde-Serializable value.
pub fn canonicalize_serializable<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, JcsError> {
    serde_jcs::to_vec(value).map_err(JcsError::from)
}

/// Compute the SHA-256 of the canonical JSON.
///
/// This is the standard signing input for AITP signatures: every signed object
/// is canonicalized then hashed, and the hash is signed with Ed25519.
pub fn canonicalize_and_hash<T: serde::Serialize>(value: &T) -> Result<[u8; 32], JcsError> {
    let bytes = canonicalize_serializable(value)?;
    let digest = Sha256::digest(&bytes);
    Ok(digest.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalize_empty_object() {
        let v: Value = json!({});
        let out = canonicalize(&v).unwrap();
        assert_eq!(std::str::from_utf8(&out).unwrap(), "{}");
    }

    #[test]
    fn canonicalize_sorts_keys() {
        let v: Value = json!({"b": 1, "a": 2});
        let out = canonicalize(&v).unwrap();
        assert_eq!(std::str::from_utf8(&out).unwrap(), r#"{"a":2,"b":1}"#);
    }

    // Full test vector suite lives in tests/jcs_standard_vectors.rs and
    // tests/aitp_signing_vectors.rs.
}
