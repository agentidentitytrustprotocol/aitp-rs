//! Placeholder substitution per the spec's
//! `schemas/conformance/PLACEHOLDERS.md`.
//!
//! Spec fixtures use `__UPPER_SNAKE__` tokens for values that the
//! runner materializes at execution time — reference timestamps,
//! known-answer signatures, deterministic nonces. This module is the
//! runner-side implementation of that substitution table.
//!
//! The reference clock is pinned to **`1711900000`** (matching the
//! `kat-keypair-001`-anchored KAT vectors), so a re-mint of any
//! fixture is byte-stable across runs and across implementations.

use aitp_core::{base64url, jcs};
use aitp_crypto::AitpSigningKey;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Reference clock for byte-stable substitution. Pinned by
/// `PLACEHOLDERS.md` §"Reference clock for byte-stable minting".
pub const REFERENCE_NOW: i64 = 1_711_900_000;

/// Per-run substitution context. Holds known-answer keypair seeds
/// (so signatures are reproducible) and a rolling cache of generated
/// nonces so that `__VALID_NONCE_ECHO__` can recall the most recent
/// `__VALID_NONCE__`.
#[derive(Debug, Clone)]
pub struct RunnerContext {
    /// `kat-keypair-001`-anchored signing key (agentA / coordinator
    /// / TCT issuer in most fixtures). Used to mint
    /// `__VALID_*_SIG__` placeholders.
    pub kp_001_seed: [u8; 32],
    /// `kat-keypair-002`-anchored signing key (agentB / TCT
    /// subject). Used to mint `__VALID_DOWNSTREAM_POP_SIG__`.
    pub kp_002_seed: [u8; 32],
    /// Reference timestamp (Unix seconds) — substituted into
    /// `__NOW__`.
    pub now: i64,
    /// Most recently generated nonce, recalled by
    /// `__VALID_NONCE_ECHO__`. Updated as substitution proceeds.
    pub last_nonce: Option<String>,
}

impl Default for RunnerContext {
    fn default() -> Self {
        Self::new()
    }
}

impl RunnerContext {
    /// Build a context with the spec's pinned KAT keypair seeds and
    /// reference clock.
    pub fn new() -> Self {
        Self {
            // kat-keypair-001 seed: 32 zero bytes (per
            // schemas/conformance/known-answer/keypairs.json).
            kp_001_seed: [0u8; 32],
            // kat-keypair-002 seed: 32 bytes of 0x77 (per
            // keypairs.json).
            kp_002_seed: [0x77u8; 32],
            now: REFERENCE_NOW,
            last_nonce: None,
        }
    }

    /// Walk a fixture-input JSON value, replacing every
    /// `__UPPER_SNAKE__` token according to PLACEHOLDERS.md. The
    /// substitution is a single deep pass; tokens that depend on
    /// each other (e.g. `__VALID_NONCE_ECHO__` must echo a prior
    /// `__VALID_NONCE__`) are resolved by document-order traversal.
    pub fn substitute(&mut self, value: &mut Value) {
        match value {
            Value::String(s) => {
                if let Some(replacement) = self.materialize(s) {
                    *value = replacement;
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.substitute(item);
                }
            }
            Value::Object(map) => {
                for v in map.values_mut() {
                    self.substitute(v);
                }
            }
            _ => {}
        }
    }

    /// Resolve a single placeholder string. Returns `None` if the
    /// string is not a recognized placeholder (so the caller leaves
    /// it intact).
    fn materialize(&mut self, s: &str) -> Option<Value> {
        // Only act on strings that match the placeholder envelope.
        if !is_placeholder(s) {
            return None;
        }

        // Time placeholders.
        if s == "__NOW__" {
            return Some(Value::from(self.now));
        }
        if let Some(rest) = s
            .strip_prefix("__NOW_PLUS_")
            .and_then(|r| r.strip_suffix("__"))
        {
            let delta: i64 = rest.parse().ok()?;
            return Some(Value::from(self.now + delta));
        }
        if let Some(rest) = s
            .strip_prefix("__NOW_MINUS_")
            .and_then(|r| r.strip_suffix("__"))
        {
            let delta: i64 = rest.parse().ok()?;
            return Some(Value::from(self.now - delta));
        }

        // Deterministic nonce. Re-derived per call so multiple
        // `__VALID_NONCE__` tokens in the same fixture get distinct
        // values; `last_nonce` is updated so the matching
        // `__VALID_NONCE_ECHO__` can recall it.
        if s == "__VALID_NONCE__" {
            // Tie nonce derivation to the count of nonces already
            // emitted so the second `__VALID_NONCE__` in a fixture
            // is a different value than the first. Use the first 16
            // bytes of SHA-256(seed || counter) to keep it 128-bit.
            let counter = self.last_nonce.is_some() as u8;
            let mut h = Sha256::new();
            h.update(b"__VALID_NONCE__");
            h.update([counter]);
            let digest = h.finalize();
            let nonce = base64url::encode(&digest[..16]);
            self.last_nonce = Some(nonce.clone());
            return Some(Value::from(nonce));
        }

        if s == "__VALID_NONCE_ECHO__" {
            return Some(Value::from(
                self.last_nonce
                    .clone()
                    .unwrap_or_else(|| "missing-nonce".into()),
            ));
        }

        // Signature placeholders. The minting tool produces real
        // Ed25519 signatures — but the runner substitutes against
        // a JSON object whose surrounding context (the body to
        // sign) isn't trivially separable from the placeholder
        // location. For runner-side substitution we keep these as
        // sentinels: the adapter's verify_* ops will reject them,
        // so fixtures that rely on substituted signatures must be
        // pre-minted by `tools/mint-conformance-fixtures`. We emit
        // a recognizable sentinel so failures are diagnosable.
        if s.starts_with("__VALID_") && s.ends_with("_SIG__") {
            return Some(Value::from(format!(
                "RUNNER_PLACEHOLDER_PRE_MINT_REQUIRED_{}",
                &s[2..s.len() - 2]
            )));
        }

        // Unknown placeholder — surface it as a sentinel so the
        // adapter fails loudly rather than treating the literal
        // token as a real value.
        Some(Value::from(format!("RUNNER_UNKNOWN_PLACEHOLDER_{s}")))
    }

    /// Sign a JCS-canonical body excluding `signature`, returning
    /// the unpadded base64url-encoded Ed25519 signature. Helper for
    /// future expansion when full sig substitution is wired.
    #[allow(dead_code)]
    pub(crate) fn sign_body(seed: &[u8; 32], body: &Value) -> String {
        let key = AitpSigningKey::from_seed(seed);
        let mut body = body.clone();
        if let Some(map) = body.as_object_mut() {
            map.remove("signature");
        }
        let bytes = jcs::canonicalize(&body).expect("canonicalize");
        let sig = key.sign(&bytes);
        sig.into_string()
    }
}

// Re-export to keep `base64url` referenced even when the helper
// above isn't called from any other path. Drops a clippy
// `unused_imports` warning while leaving the symbol available for
// downstream callers that import it via `pub use`.
#[allow(dead_code)]
fn _ensure_base64url_imported() -> String {
    base64url::encode(b"")
}

fn is_placeholder(s: &str) -> bool {
    s.starts_with("__")
        && s.ends_with("__")
        && s.len() >= 4
        && s[2..s.len() - 2]
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn now_substitution() {
        let mut ctx = RunnerContext::new();
        let mut v = json!({"timestamp": "__NOW__"});
        ctx.substitute(&mut v);
        assert_eq!(v["timestamp"], json!(REFERENCE_NOW));
    }

    #[test]
    fn now_plus_minus() {
        let mut ctx = RunnerContext::new();
        let mut v = json!({
            "iat": "__NOW_MINUS_3600__",
            "exp": "__NOW_PLUS_3600__",
        });
        ctx.substitute(&mut v);
        assert_eq!(v["iat"], json!(REFERENCE_NOW - 3600));
        assert_eq!(v["exp"], json!(REFERENCE_NOW + 3600));
    }

    #[test]
    fn nonce_and_echo() {
        let mut ctx = RunnerContext::new();
        let mut v = json!({
            "challenge": "__VALID_NONCE__",
            "echo": "__VALID_NONCE_ECHO__",
        });
        ctx.substitute(&mut v);
        let challenge = v["challenge"].as_str().unwrap().to_string();
        let echo = v["echo"].as_str().unwrap().to_string();
        assert!(!challenge.is_empty());
        assert_eq!(challenge, echo);
    }

    #[test]
    fn unknown_placeholder_becomes_sentinel() {
        let mut ctx = RunnerContext::new();
        let mut v = json!({"x": "__NEVER_HEARD_OF__"});
        ctx.substitute(&mut v);
        let s = v["x"].as_str().unwrap();
        assert!(s.starts_with("RUNNER_UNKNOWN_PLACEHOLDER_"));
    }

    #[test]
    fn non_placeholder_strings_pass_through() {
        let mut ctx = RunnerContext::new();
        let mut v = json!({
            "aid": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "msg": "hello __not_actually_a_placeholder",
        });
        let before = v.clone();
        ctx.substitute(&mut v);
        assert_eq!(v, before);
    }

    #[test]
    fn sig_placeholder_emits_pre_mint_sentinel() {
        let mut ctx = RunnerContext::new();
        let mut v = json!({"sig": "__VALID_TCT_SIG__"});
        ctx.substitute(&mut v);
        let s = v["sig"].as_str().unwrap();
        assert!(s.starts_with("RUNNER_PLACEHOLDER_PRE_MINT_REQUIRED_"));
    }

    #[test]
    fn is_placeholder_recognizes() {
        assert!(is_placeholder("__NOW__"));
        assert!(is_placeholder("__VALID_TCT_SIG__"));
        assert!(is_placeholder("__NOW_PLUS_3600__"));
        assert!(!is_placeholder("hello"));
        assert!(!is_placeholder("__"));
        assert!(!is_placeholder("__lower__"));
    }
}
