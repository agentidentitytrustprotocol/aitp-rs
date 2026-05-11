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

/// Internal sentinel: the scalar pass writes this string into any
/// `__VALID_*_SIG__` placeholder. The signature pass scans for it
/// and replaces it with a real signature over the surrounding
/// body. Distinct from any base64url string so the second pass
/// can identify it unambiguously.
const SIG_PENDING_SENTINEL: &str = "__RUNNER_SIG_PENDING__";

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
    /// Monotonic counter mixed into nonce derivation so that
    /// repeated `__VALID_NONCE__` tokens within a single fixture
    /// produce distinct values. Reset between fixtures via
    /// [`Self::reset_per_fixture`].
    nonce_counter: u32,
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
            // kat-keypair-002 seed:
            // `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
            // per `schemas/conformance/known-answer/keypairs.json`.
            // (The earlier `[0x77u8; 32]` value was a stale guess; it
            // produced a pubkey that didn't match the spec's pinned
            // kat-keypair-002 AID `aid:pubkey:A6EHv_…`.)
            kp_002_seed: {
                let mut s = [0u8; 32];
                let mut i = 0;
                while i < 32 {
                    s[i] = i as u8;
                    i += 1;
                }
                s
            },
            now: REFERENCE_NOW,
            last_nonce: None,
            nonce_counter: 0,
        }
    }

    /// Reset per-fixture state: the nonce counter and the last
    /// emitted nonce. Called by the runner before each fixture so
    /// the second fixture's first `__VALID_NONCE__` is the same
    /// byte sequence as the first fixture's first nonce
    /// (deterministic, byte-stable runs).
    pub fn reset_per_fixture(&mut self) {
        self.last_nonce = None;
        self.nonce_counter = 0;
    }

    /// Walk a fixture-input JSON value, replacing every
    /// `__UPPER_SNAKE__` token according to PLACEHOLDERS.md.
    ///
    /// Two-pass:
    /// 1. **Scalar pass.** Replaces `__NOW__`, `__NOW_PLUS_n__`,
    ///    `__NOW_MINUS_n__`, `__VALID_NONCE__`, and
    ///    `__VALID_NONCE_ECHO__` (no surrounding-body context
    ///    needed). Signature placeholders are temporarily
    ///    converted to a `__SIG_PENDING__` sentinel.
    ///
    /// 2. **Signature pass.** Walks the tree again. Any object
    ///    whose `signature` field is the `__SIG_PENDING__`
    ///    sentinel gets that field replaced with a real Ed25519
    ///    signature over the JCS canonicalization of the body
    ///    (excluding `signature`). Signing key is `kat-keypair-001`
    ///    (the spec's pinned issuer); fixtures that need a
    ///    different key still need pre-minting.
    pub fn substitute(&mut self, value: &mut Value) {
        self.substitute_scalars(value);
        self.substitute_signatures(value);
    }

    fn substitute_scalars(&mut self, value: &mut Value) {
        match value {
            Value::String(s) => {
                if let Some(replacement) = self.materialize(s) {
                    *value = replacement;
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.substitute_scalars(item);
                }
            }
            Value::Object(map) => {
                for v in map.values_mut() {
                    self.substitute_scalars(v);
                }
            }
            _ => {}
        }
    }

    fn substitute_signatures(&self, value: &mut Value) {
        match value {
            Value::Array(items) => {
                for item in items {
                    self.substitute_signatures(item);
                }
            }
            Value::Object(map) => {
                // Recurse first so nested bodies are signed before
                // the parent's `signature` field is computed (the
                // parent's canonical bytes include the now-signed
                // children).
                for v in map.values_mut() {
                    self.substitute_signatures(v);
                }
                // `pop_signature` (downstream PoP response, RFC-AITP-0005 §6.2):
                // signing input is `sha256(base64url_decode(nonce))`
                // where `nonce` is the matching challenge's nonce.
                // The fixture supplies it as `payload.nonce_echo`
                // alongside `pop_signature`. Sign with kat-keypair-002
                // (the holder; AIDS in tct-006 set subject=A6EH...).
                if let Some(pop_sig_value) = map.get("pop_signature").cloned() {
                    if pop_sig_value.as_str() == Some(SIG_PENDING_SENTINEL) {
                        if let Some(echo) = map.get("nonce_echo").and_then(|v| v.as_str()) {
                            if let Ok(nonce_bytes) = base64url::decode_strict(echo) {
                                let pop_input = Sha256::digest(&nonce_bytes);
                                let key = AitpSigningKey::from_seed(&self.kp_002_seed);
                                let sig = key.sign(&pop_input);
                                map.insert("pop_signature".into(), Value::from(sig.into_string()));
                            }
                        }
                    }
                }
                if let Some(sig_value) = map.get("signature").cloned() {
                    if sig_value.as_str() == Some(SIG_PENDING_SENTINEL) {
                        // Pick the right signing-input convention
                        // based on object shape:
                        //
                        // - **Envelope** — has `message_id`,
                        //   `timestamp`, `sender`, `payload`. The
                        //   signing input per RFC-AITP-0001 §5.4 is
                        //   `message_id|timestamp|sender.agent_id|
                        //   hex(sha256(payload_canonical_json))`. The
                        //   sender's KAT-keypair is used (we map the
                        //   agent_id back to a seed).
                        //
                        // - **Generic body** — TCT, manifest,
                        //   delegation, bundle. Sign the JCS
                        //   canonicalization of the body excluding
                        //   `signature`, with `kat-keypair-001`
                        //   (the spec's pinned issuer).
                        let signed = if is_envelope_shape(map) {
                            sign_envelope_shape(map)
                        } else {
                            sign_generic_body(&self.kp_001_seed, map)
                        };
                        if let Some(s) = signed {
                            map.insert("signature".into(), Value::from(s));
                        }
                    }
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
        // values. `last_nonce` is updated so the matching
        // `__VALID_NONCE_ECHO__` can recall the most recent nonce.
        if s == "__VALID_NONCE__" {
            // Use a true incrementing counter mixed into SHA-256.
            // Without this, `last_nonce.is_some() as u8` collapsed
            // every nonce after the first to the same byte (the
            // 2nd, 3rd, … all collided), reintroducing the replay
            // surface the placeholder was meant to defend against.
            // Take the first 16 bytes (128 bits) of the digest.
            let counter = self.nonce_counter.to_be_bytes();
            self.nonce_counter = self.nonce_counter.wrapping_add(1);
            let mut h = Sha256::new();
            h.update(b"__VALID_NONCE__");
            h.update(counter);
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

        // Signature placeholders. Defer the actual signing to
        // pass 2 — at this point we don't have parent-body
        // context. Emit a sentinel that the second pass scans
        // for and replaces with a real signature over the
        // enclosing object (excluding `signature`).
        if s.starts_with("__VALID_") && s.ends_with("_SIG__") {
            return Some(Value::from(SIG_PENDING_SENTINEL));
        }

        // Unknown placeholder — surface it as a sentinel so the
        // adapter fails loudly rather than treating the literal
        // token as a real value.
        Some(Value::from(format!("RUNNER_UNKNOWN_PLACEHOLDER_{s}")))
    }
}

fn is_placeholder(s: &str) -> bool {
    s.starts_with("__")
        && s.ends_with("__")
        && s.len() >= 4
        && s[2..s.len() - 2]
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn is_envelope_shape(map: &serde_json::Map<String, Value>) -> bool {
    map.contains_key("message_id")
        && map.contains_key("timestamp")
        && map.contains_key("sender")
        && map.contains_key("payload")
        && map.contains_key("signature")
}

fn sign_generic_body(seed: &[u8; 32], map: &serde_json::Map<String, Value>) -> Option<String> {
    let mut body = serde_json::Map::new();
    for (k, v) in map.iter() {
        if k != "signature" {
            body.insert(k.clone(), v.clone());
        }
    }
    let canonical = jcs::canonicalize(&Value::Object(body)).ok()?;
    let key = AitpSigningKey::from_seed(seed);
    let digest = Sha256::digest(&canonical);
    Some(key.sign(&digest).into_string())
}

fn sign_envelope_shape(map: &serde_json::Map<String, Value>) -> Option<String> {
    // RFC-AITP-0001 §5.4 envelope signing input:
    //   message_id | timestamp | sender.agent_id | hex(sha256(payload_canonical_json))
    let message_id = map.get("message_id")?.as_str()?;
    let timestamp = map.get("timestamp")?.as_i64()?;
    let sender_aid = map.get("sender")?.get("agent_id")?.as_str()?;
    let payload = map.get("payload")?;
    let payload_canonical = jcs::canonicalize(payload).ok()?;
    let payload_hash = Sha256::digest(&payload_canonical);
    let signing_input = format!(
        "{}|{}|{}|{}",
        message_id,
        timestamp,
        sender_aid,
        hex::encode(payload_hash)
    );
    let seed = kat_seed_for_aid(sender_aid)?;
    let key = AitpSigningKey::from_seed(&seed);
    Some(key.sign(signing_input.as_bytes()).into_string())
}

/// Map a sender AID to its KAT-keypair seed. The runner only knows
/// about the four pinned KAT keypairs; envelopes signed by other
/// keys can't be runner-substituted (caller must pre-mint).
fn kat_seed_for_aid(aid: &str) -> Option<[u8; 32]> {
    match aid {
        "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik" => Some([0u8; 32]),
        "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg" => {
            let mut s = [0u8; 32];
            for (i, b) in s.iter_mut().enumerate() {
                *b = i as u8;
            }
            Some(s)
        }
        "aid:pubkey:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU" => Some([0xffu8; 32]),
        "aid:pubkey:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w" => Some([1u8; 32]),
        _ => None,
    }
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
    fn multiple_nonces_in_same_fixture_are_distinct() {
        // Regression: the prior implementation derived the counter
        // from `last_nonce.is_some()`, which collapsed every nonce
        // after the first to the same value. Three nonces in one
        // fixture must produce three distinct strings.
        let mut ctx = RunnerContext::new();
        let mut v = json!({
            "first": "__VALID_NONCE__",
            "second": "__VALID_NONCE__",
            "third": "__VALID_NONCE__",
        });
        ctx.substitute(&mut v);
        let a = v["first"].as_str().unwrap();
        let b = v["second"].as_str().unwrap();
        let c = v["third"].as_str().unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn nonce_counter_resets_between_fixtures() {
        // Two fixtures running through the same context must each
        // start from counter=0; otherwise re-mints diverge.
        let mut ctx = RunnerContext::new();
        let mut v1 = json!({"x": "__VALID_NONCE__"});
        ctx.substitute(&mut v1);
        let first_run = v1["x"].as_str().unwrap().to_string();

        ctx.reset_per_fixture();
        let mut v2 = json!({"x": "__VALID_NONCE__"});
        ctx.substitute(&mut v2);
        let second_run = v2["x"].as_str().unwrap().to_string();

        assert_eq!(first_run, second_run);
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
    fn sig_placeholder_outside_signature_field_keeps_pending_sentinel() {
        // When a `__VALID_*_SIG__` placeholder appears in a field
        // that isn't named `signature`, the second pass leaves the
        // pending sentinel intact (no surrounding body to sign).
        // The adapter will reject downstream — that's expected for
        // unusual placements.
        let mut ctx = RunnerContext::new();
        let mut v = json!({"sig": "__VALID_TCT_SIG__"});
        ctx.substitute(&mut v);
        let s = v["sig"].as_str().unwrap();
        assert_eq!(s, SIG_PENDING_SENTINEL);
    }

    #[test]
    fn sig_placeholder_in_signature_field_is_signed() {
        // The common case: an enclosing object has a
        // `signature: "__VALID_*_SIG__"` field. The runner signs
        // the body (excluding `signature`) with kp-001 and replaces
        // the placeholder with a real Ed25519 signature.
        use aitp_core::base64url;
        use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
        use sha2::{Digest, Sha256};
        let mut ctx = RunnerContext::new();
        let mut v = json!({
            "version": "aitp/0.1",
            "issuer": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "signature": "__VALID_TCT_SIG__",
        });
        ctx.substitute(&mut v);
        let sig_b64 = v["signature"].as_str().unwrap().to_string();
        // The signature must verify against kp-001.
        let mut body = v.clone();
        body.as_object_mut().unwrap().remove("signature");
        let canon = aitp_core::jcs::canonicalize(&body).unwrap();
        let digest = Sha256::digest(&canon);
        let key = AitpSigningKey::from_seed(&[0u8; 32]);
        let pubkey = AitpVerifyingKey::from_aid(key.aid()).unwrap();
        let sig = aitp_crypto::Signature::parse(&sig_b64).unwrap();
        pubkey.verify(&digest, &sig).expect("signature verifies");
        let _ = base64url::encode(b"");
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
