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

/// Internal sentinel: written by the scalar pass for the spec's
/// `__TAMPERED_SIG__` / `__TAMPERED_SIGNATURE__` placeholders
/// (PLACEHOLDERS.md §129–130). The signature pass replaces it with a
/// real signature over the body, then flips the least-significant bit
/// of the last raw signature byte. The result is a syntactically
/// valid 86-char base64url signature that fails `verify_strict()` —
/// so fixtures like `rev-004` exercise the cryptographic-failure code
/// path rather than a base64url decode error.
const SIG_TAMPER_PENDING_SENTINEL: &str = "__RUNNER_SIG_TAMPER_PENDING__";

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
        // Compact-JWS token family (PLACEHOLDERS.md §"Compact-JWS token
        // placeholders") — after scalars (claims siblings may contain
        // `__NOW_*__` values) and before JCS signatures (envelope
        // payloads may embed the minted tokens).
        self.substitute_jws_tokens(value);
        self.substitute_signatures(value);
    }

    /// Resolve the v0.2 compact-JWS whole-token placeholders using the
    /// claims-sibling convention: a string field `X` valued
    /// `__JWS_*__` has a sibling `X_claims` carrying the decoded
    /// payload to mint. Inner tokens (a delegation claims object's
    /// `voucher`, `chain` entries) resolve innermost-first; every
    /// `*_claims` companion is stripped from the **minted payload**
    /// but left in place in the fixture for auditability (adapters
    /// ignore them).
    fn substitute_jws_tokens(&self, value: &mut Value) {
        match value {
            Value::Array(items) => {
                for item in items {
                    self.substitute_jws_tokens(item);
                }
            }
            Value::Object(map) => {
                // Depth-first so nested structures (envelope payloads,
                // sequence steps) resolve their own pairs.
                for v in map.values_mut() {
                    self.substitute_jws_tokens(v);
                }
                self.resolve_jws_pairs(map);
            }
            _ => {}
        }
    }

    /// Resolve `X` / `X_claims` pairs at one object level — both the
    /// scalar form (`"tct_token": "__JWS_TCT__"`) and the array form
    /// (`"chain": ["__JWS_DELEGATION__"]` with a `chain_claims`
    /// array).
    fn resolve_jws_pairs(&self, map: &mut serde_json::Map<String, Value>) {
        let keys: Vec<String> = map.keys().cloned().collect();
        for key in keys {
            let claims_key = format!("{key}_claims");
            let Some(claims_value) = map.get(&claims_key).cloned() else {
                continue;
            };
            match map.get(&key) {
                Some(Value::String(token)) if is_jws_placeholder(token) => {
                    let kind = token.clone();
                    let mut claims = claims_value;
                    self.prepare_claims(&mut claims);
                    if let Some(minted) = self.mint_jws(&kind, &claims) {
                        map.insert(key.clone(), Value::from(minted));
                    }
                }
                Some(Value::Array(entries)) => {
                    let Some(claims_arr) = claims_value.as_array() else {
                        continue;
                    };
                    let mut minted_entries = entries.clone();
                    for (i, entry) in minted_entries.iter_mut().enumerate() {
                        if let Value::String(token) = entry {
                            if is_jws_placeholder(token) {
                                let kind = token.clone();
                                let mut claims = claims_arr.get(i).cloned().unwrap_or(Value::Null);
                                self.prepare_claims(&mut claims);
                                if let Some(minted) = self.mint_jws(&kind, &claims) {
                                    *entry = Value::from(minted);
                                }
                            }
                        }
                    }
                    map.insert(key.clone(), Value::Array(minted_entries));
                }
                _ => {}
            }
        }
        // `__COMPUTED_CHAIN_HASH__` / `__ANY_CHAIN_HASH__`: computed
        // over the (now-minted) chain entry strings at this level.
        if let Some(hash_marker) = map.get("chain_hash").and_then(|v| v.as_str()) {
            if hash_marker == "__COMPUTED_CHAIN_HASH__" || hash_marker == "__ANY_CHAIN_HASH__" {
                let entries: Vec<String> = map
                    .get("chain")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|e| e.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                map.insert(
                    "chain_hash".into(),
                    Value::from(compute_chain_hash(&entries)),
                );
            }
        }
    }

    /// Prepare a claims object for minting: resolve inner JWS pairs
    /// (voucher, nested chain) innermost-first, then strip every
    /// `*_claims` companion — companions are minting inputs, never
    /// wire bytes.
    fn prepare_claims(&self, claims: &mut Value) {
        self.substitute_jws_tokens(claims);
        strip_claims_companions(claims);
    }

    /// Mint one compact-JWS token per the PLACEHOLDERS.md recipe table.
    fn mint_jws(&self, kind: &str, claims: &Value) -> Option<String> {
        use aitp_crypto::jws;
        let typ = match kind {
            "__JWS_TCT__"
            | "__JWS_TCT_TAMPERED_SIG__"
            | "__JWS_TCT_ALG_NONE__"
            | "__JWS_TCT_WRONG_ALG__" => jws::TYP_TCT,
            "__JWS_GRANT_VOUCHER__" | "__JWS_VOUCHER_TAMPERED_SIG__" => jws::TYP_GRANT_VOUCHER,
            "__JWS_DELEGATION__" | "__JWS_DELEGATION_TAMPERED_SIG__" | "__ANY_JWS__" => {
                jws::TYP_DELEGATION
            }
            _ => return None,
        };
        // `__ANY_JWS__` may appear with no meaningful claims; mint a
        // syntactically valid token from whatever is supplied (or a
        // minimal object) per the spec's "any syntactically valid
        // three-segment compact JWS" rule.
        let claims = if claims.is_object() {
            claims.clone()
        } else {
            serde_json::json!({ "ver": "aitp/0.2" })
        };
        let seed = claims
            .get("iss")
            .and_then(|v| v.as_str())
            .and_then(kat_seed_for_aid)
            .unwrap_or(self.kp_001_seed);
        let key = AitpSigningKey::from_seed(&seed);

        match kind {
            "__JWS_TCT__" | "__JWS_GRANT_VOUCHER__" | "__JWS_DELEGATION__" | "__ANY_JWS__" => {
                jws::sign_compact(&key, typ, &claims).ok()
            }
            "__JWS_TCT_TAMPERED_SIG__"
            | "__JWS_DELEGATION_TAMPERED_SIG__"
            | "__JWS_VOUCHER_TAMPERED_SIG__" => {
                // Mint normally, then flip the LSB of the last raw
                // signature byte (same recipe as __TAMPERED_SIGNATURE__).
                let token = jws::sign_compact(&key, typ, &claims).ok()?;
                let (head, sig) = token.rsplit_once('.')?;
                Some(format!("{head}.{}", tamper_signature(sig)))
            }
            "__JWS_TCT_ALG_NONE__" => {
                // Header `{"alg":"none","typ":…}`; third segment =
                // base64url of 64 zero bytes so the failure is the
                // `alg` pin, not segment syntax.
                let header = format!("{{\"alg\":\"none\",\"typ\":\"{typ}\"}}");
                let payload = jcs::canonicalize(&claims).ok()?;
                Some(format!(
                    "{}.{}.{}",
                    base64url::encode(header.as_bytes()),
                    base64url::encode(&payload),
                    base64url::encode(&[0u8; 64])
                ))
            }
            "__JWS_TCT_WRONG_ALG__" => {
                // Header claims ES256 while the iss AID is Ed25519;
                // signed with the Ed25519 key over the signing input
                // (deterministic bytes — never checked, the alg pin
                // rejects first).
                let header = format!("{{\"alg\":\"ES256\",\"typ\":\"{typ}\"}}");
                let payload = jcs::canonicalize(&claims).ok()?;
                let signing_input = format!(
                    "{}.{}",
                    base64url::encode(header.as_bytes()),
                    base64url::encode(&payload)
                );
                let sig = key.sign(signing_input.as_bytes());
                Some(format!("{signing_input}.{}", sig.as_str()))
            }
            _ => None,
        }
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
                // Manifest-shaped objects: mint the PoP first (it's a
                // signature over `sha256(base64url_decode(challenge))`
                // with the manifest agent's key — NOT a JCS body
                // signature), so the generic child recursion below
                // doesn't mis-sign the `{challenge, signature}` pair.
                if map.contains_key("proof_of_possession") && map.contains_key("aid") {
                    let aid = map.get("aid").and_then(|v| v.as_str()).map(String::from);
                    if let Some(pop) = map
                        .get_mut("proof_of_possession")
                        .and_then(|v| v.as_object_mut())
                    {
                        let pending = matches!(
                            pop.get("signature").and_then(|v| v.as_str()),
                            Some(SIG_PENDING_SENTINEL)
                        );
                        if pending {
                            if let (Some(challenge), Some(key)) = (
                                pop.get("challenge").and_then(|v| v.as_str()),
                                aid.as_deref().and_then(kat_key_for_aid),
                            ) {
                                if let Ok(bytes) = base64url::decode_strict(challenge) {
                                    let sig = key.sign(&Sha256::digest(&bytes));
                                    pop.insert("signature".into(), Value::from(sig.into_string()));
                                }
                            }
                        }
                    }
                }
                // Recurse first so nested bodies are signed before
                // the parent's `signature` field is computed (the
                // parent's canonical bytes include the now-signed
                // children).
                for v in map.values_mut() {
                    self.substitute_signatures(v);
                }
                // `pop_signature` (downstream PoP response per
                // RFC-AITP-0005 §6.2, or the handshake round-2 PoP in
                // commit payloads per RFC-AITP-0004 §3): signing input
                // is `sha256(base64url_decode(nonce))`. The nonce is
                // `nonce_echo` (downstream PoP) or `pop_nonce_echo`
                // (commit payloads). Signer: the commit sender — the
                // issuer of the TCT carried alongside (read from the
                // `tct_claims` minting companion) — falling back to
                // kat-keypair-002 (the holder in tct-006's downstream
                // PoP exchange).
                if let Some(pop_sig_value) = map.get("pop_signature").cloned() {
                    if pop_sig_value.as_str() == Some(SIG_PENDING_SENTINEL) {
                        let echo = map
                            .get("nonce_echo")
                            .or_else(|| map.get("pop_nonce_echo"))
                            .and_then(|v| v.as_str())
                            .map(String::from);
                        if let Some(echo) = echo {
                            if let Ok(nonce_bytes) = base64url::decode_strict(&echo) {
                                let pop_input = Sha256::digest(&nonce_bytes);
                                let key = map
                                    .get("tct_claims")
                                    .and_then(|c| c.get("iss"))
                                    .and_then(|v| v.as_str())
                                    .and_then(kat_key_for_aid)
                                    .unwrap_or_else(|| {
                                        AitpSigningKey::from_seed(&self.kp_002_seed)
                                    });
                                let sig = key.sign(&pop_input);
                                map.insert("pop_signature".into(), Value::from(sig.into_string()));
                            }
                        }
                    }
                }
                if let Some(sig_value) = map.get("signature").cloned() {
                    let pending = sig_value.as_str();
                    let tamper = pending == Some(SIG_TAMPER_PENDING_SENTINEL);
                    let want_sign = pending == Some(SIG_PENDING_SENTINEL) || tamper;
                    if want_sign {
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
                        //   `signature` with the keypair matching the
                        //   `issuer` AID (falling back to
                        //   `kat-keypair-001` when none can be
                        //   resolved, which preserves earlier behavior
                        //   for fixtures that don't carry an issuer).
                        let signed = if is_envelope_shape(map) {
                            sign_envelope_shape(map)
                        } else {
                            // Signing-key resolution for generic JCS
                            // bodies: `issuer` (TCT-era bodies,
                            // revocation lists), `aid` (manifests),
                            // `coordinator` (bundles), the wrapped
                            // revocation snapshot's inner issuer, then
                            // the kp-001 fallback.
                            let key = ["issuer", "aid", "coordinator"]
                                .iter()
                                .find_map(|k| map.get(*k).and_then(|v| v.as_str()))
                                .or_else(|| {
                                    map.get("revocation_list")
                                        .and_then(|v| v.get("issuer"))
                                        .and_then(|v| v.as_str())
                                })
                                .or_else(|| {
                                    map.get("session_bundle")
                                        .and_then(|v| v.get("coordinator"))
                                        .and_then(|v| v.as_str())
                                })
                                .and_then(kat_key_for_aid)
                                .unwrap_or_else(|| AitpSigningKey::from_seed(&self.kp_001_seed));
                            sign_generic_body(&key, map)
                        };
                        if let Some(s) = signed {
                            // PLACEHOLDERS.md §129–130: sign properly,
                            // then flip the LSB of the last raw
                            // signature byte. The tampered value is
                            // a syntactically valid 86-char base64url
                            // string but fails `verify_strict()` —
                            // so `rev-004` reaches the crypto layer
                            // rather than decoding off at the parser.
                            let final_sig = if tamper { tamper_signature(&s) } else { s };
                            map.insert("signature".into(), Value::from(final_sig));
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

        // Compact-JWS whole-token and chain-hash markers resolve in the
        // dedicated JWS pass (claims-sibling convention) — leave them
        // for `substitute_jws_tokens`.
        if is_jws_placeholder(s) || s == "__COMPUTED_CHAIN_HASH__" || s == "__ANY_CHAIN_HASH__" {
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

        // Tampered signature placeholders (PLACEHOLDERS.md §129–130).
        // The second pass signs properly then flips the LSB of the
        // last raw signature byte to produce a syntactically valid
        // base64url signature that fails `verify_strict()`. Used by
        // `rev-004` to assert that revocation lookup is NOT called
        // when TCT signature verification fails.
        if s == "__TAMPERED_SIG__" || s == "__TAMPERED_SIGNATURE__" {
            return Some(Value::from(SIG_TAMPER_PENDING_SENTINEL));
        }

        // Unknown placeholder — surface it as a sentinel so the
        // adapter fails loudly rather than treating the literal
        // token as a real value.
        Some(Value::from(format!("RUNNER_UNKNOWN_PLACEHOLDER_{s}")))
    }
}

fn is_jws_placeholder(s: &str) -> bool {
    matches!(
        s,
        "__JWS_TCT__"
            | "__JWS_GRANT_VOUCHER__"
            | "__JWS_DELEGATION__"
            | "__JWS_TCT_TAMPERED_SIG__"
            | "__JWS_DELEGATION_TAMPERED_SIG__"
            | "__JWS_VOUCHER_TAMPERED_SIG__"
            | "__JWS_TCT_ALG_NONE__"
            | "__JWS_TCT_WRONG_ALG__"
            | "__ANY_JWS__"
    )
}

/// Strip every `*_claims` companion key, recursively — companions are
/// minting inputs and MUST NOT appear in wire bytes (PLACEHOLDERS.md
/// claims-sibling convention, step 2).
fn strip_claims_companions(value: &mut Value) {
    match value {
        Value::Array(items) => {
            for item in items {
                strip_claims_companions(item);
            }
        }
        Value::Object(map) => {
            let companion_keys: Vec<String> = map
                .keys()
                .filter(|k| k.ends_with("_claims"))
                .cloned()
                .collect();
            for k in companion_keys {
                map.remove(&k);
            }
            for v in map.values_mut() {
                strip_claims_companions(v);
            }
        }
        _ => {}
    }
}

/// RFC-AITP-0011 §5 digest-array chain hash:
/// `base64url(sha256(JCS([base64url(sha256(ASCII(chain[i])))…])))`.
fn compute_chain_hash(chain: &[String]) -> String {
    let digests: Vec<String> = chain
        .iter()
        .map(|entry| base64url::encode(&Sha256::digest(entry.as_bytes())))
        .collect();
    let canonical = jcs::canonicalize_serializable(&digests).unwrap_or_default();
    base64url::encode(&Sha256::digest(&canonical))
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

/// Apply the spec's LSB-flip tamper recipe (PLACEHOLDERS.md §129–130)
/// to a base64url-encoded Ed25519 signature: decode, flip the LSB of
/// the last raw signature byte, re-encode. The result is a
/// syntactically valid 86-char base64url signature that fails
/// `Ed25519::verify_strict()`. If decode fails (caller fed a
/// malformed string), the input is returned verbatim so downstream
/// callers surface a parse error rather than masking it.
fn tamper_signature(sig: &str) -> String {
    let Ok(mut bytes) = base64url::decode_strict(sig) else {
        return sig.to_string();
    };
    if let Some(last) = bytes.last_mut() {
        *last ^= 0x01;
    }
    base64url::encode(&bytes)
}

fn sign_generic_body(key: &AitpSigningKey, map: &serde_json::Map<String, Value>) -> Option<String> {
    let mut body = serde_json::Map::new();
    for (k, v) in map.iter() {
        if k != "signature" {
            body.insert(k.clone(), v.clone());
        }
    }
    // The wire bytes never contain `*_claims` minting companions
    // (PLACEHOLDERS.md claims-sibling convention) — e.g. a session
    // bundle's participant `tct_claims` siblings — so the signature
    // covers the companion-stripped body, matching what verifiers see.
    let mut body = Value::Object(body);
    strip_claims_companions(&mut body);
    let canonical = jcs::canonicalize(&body).ok()?;
    let digest = Sha256::digest(&canonical);
    Some(key.sign(&digest).into_string())
}

fn sign_envelope_shape(map: &mut serde_json::Map<String, Value>) -> Option<String> {
    // RFC-AITP-0001 §5.4 envelope signing input:
    //   message_id | timestamp | sender.agent_id | hex(sha256(payload_canonical_json))
    let message_id = map.get("message_id")?.as_str()?.to_string();
    let timestamp = map.get("timestamp")?.as_i64()?;
    let sender_aid = map.get("sender")?.get("agent_id")?.as_str()?.to_string();
    let sender_key = kat_key_for_aid(&sender_aid);

    // Round-2 PoP inside commit payloads: signed by the envelope
    // sender over `sha256(base64url_decode(pop_nonce_echo))`. Resolved
    // here because the payload-level pass has no sender context.
    if let Some(payload_obj) = map.get_mut("payload").and_then(|v| v.as_object_mut()) {
        let pending = matches!(
            payload_obj.get("pop_signature").and_then(|v| v.as_str()),
            Some(SIG_PENDING_SENTINEL)
        );
        if pending {
            if let (Some(echo), Some(key)) = (
                payload_obj
                    .get("pop_nonce_echo")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                sender_key.as_ref(),
            ) {
                if let Ok(bytes) = base64url::decode_strict(&echo) {
                    let sig = key.sign(&Sha256::digest(&bytes));
                    payload_obj.insert("pop_signature".into(), Value::from(sig.into_string()));
                }
            }
        }
    }

    // The signed payload bytes are the **companion-stripped** payload:
    // `*_claims` siblings are minting inputs, never wire bytes
    // (PLACEHOLDERS.md claims-sibling convention) — verifiers strip
    // them before computing the digest.
    let mut payload = map.get("payload")?.clone();
    strip_claims_companions(&mut payload);
    let payload_canonical = jcs::canonicalize(&payload).ok()?;
    let payload_hash = Sha256::digest(&payload_canonical);
    let signing_input = format!(
        "{}|{}|{}|{}",
        message_id,
        timestamp,
        sender_aid,
        hex::encode(payload_hash)
    );
    // Unknown sender AIDs (e.g. mh-002's one-shot attacker key, whose
    // seed is not published) get a syntactically valid filler signed
    // by kp-001 — those fixtures reject on a check that runs before
    // the envelope signature (RFC-AITP-0004 §5.1 verifies the
    // Manifest and identity first), so the value is never verified.
    let key = sender_key.unwrap_or_else(|| AitpSigningKey::from_seed(&[0u8; 32]));
    // v0.2 envelope convention: the Ed25519/ES256 message is
    // `sha256(signing_input)` (aitp_core::envelope_signing_digest),
    // not the raw input bytes.
    Some(
        key.sign(&Sha256::digest(signing_input.as_bytes()))
            .into_string(),
    )
}

/// Map a sender AID to its KAT-keypair seed. The runner only knows
/// about the pinned KAT keypairs; envelopes signed by other keys
/// can't be runner-substituted (caller must pre-mint).
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

/// Map an AID to its pinned KAT signing key — the four Ed25519
/// keypairs plus `kat-keypair-005-p256` (private scalar `0x05` × 32,
/// per `known-answer/keypairs.json`).
fn kat_key_for_aid(aid: &str) -> Option<AitpSigningKey> {
    if let Some(seed) = kat_seed_for_aid(aid) {
        return Some(AitpSigningKey::from_seed(&seed));
    }
    if aid == "aid:pubkey:p256:AweBDql0zqV3PmO4l_N-O-mgnnpf6blxpE0QZawqOpMR" {
        return AitpSigningKey::from_p256_seed(&[0x05u8; 32]).ok();
    }
    None
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
            "version": "aitp/0.2",
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
    fn tampered_sig_placeholder_is_syntactically_valid_but_fails_verify() {
        // `__TAMPERED_SIG__` (PLACEHOLDERS.md §129–130): the second
        // pass signs properly with kp-001, then flips the LSB of the
        // last raw signature byte. The resulting string MUST parse
        // as a 86-char base64url Ed25519 signature AND MUST fail
        // `verify_strict()` — that's precisely what `rev-004` needs
        // to reach the crypto layer instead of bouncing at the
        // base64url parser.
        use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
        use sha2::{Digest, Sha256};
        let mut ctx = RunnerContext::new();
        let mut v = json!({
            "version": "aitp/0.2",
            "issuer": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "signature": "__TAMPERED_SIG__",
        });
        ctx.substitute(&mut v);
        let sig_b64 = v["signature"].as_str().unwrap().to_string();

        // Syntactically valid base64url signature (parses cleanly).
        let sig = aitp_crypto::Signature::parse(&sig_b64).expect("parses as base64url sig");

        // But fails Ed25519 verify_strict() under kp-001 (the key
        // that signed before the tamper).
        let mut body = v.clone();
        body.as_object_mut().unwrap().remove("signature");
        let canon = aitp_core::jcs::canonicalize(&body).unwrap();
        let digest = Sha256::digest(&canon);
        let key = AitpSigningKey::from_seed(&[0u8; 32]);
        let pubkey = AitpVerifyingKey::from_aid(key.aid()).unwrap();
        assert!(
            pubkey.verify(&digest, &sig).is_err(),
            "tampered signature must fail verify_strict"
        );
    }

    #[test]
    fn tampered_signature_alias_long_form() {
        // `__TAMPERED_SIGNATURE__` is the spec's primary token;
        // `__TAMPERED_SIG__` is the alias. Both MUST resolve to the
        // sign-then-flip-LSB recipe.
        let mut ctx = RunnerContext::new();
        let mut v = json!({
            "version": "aitp/0.2",
            "issuer": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "signature": "__TAMPERED_SIGNATURE__",
        });
        ctx.substitute(&mut v);
        let sig_b64 = v["signature"].as_str().unwrap();
        assert_eq!(sig_b64.len(), 86, "Ed25519 sig is 86 base64url chars");
        assert!(
            aitp_crypto::Signature::parse(sig_b64).is_ok(),
            "tampered sig must remain syntactically valid base64url"
        );
    }

    #[test]
    fn tamper_signature_flips_last_lsb() {
        // Unit-level recipe check: encoding(decode(x) with LSB
        // flipped on the last byte) round-trips correctly and only
        // touches the last byte.
        let original =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let tampered = tamper_signature(original);
        let orig_bytes = base64url::decode_strict(original).unwrap();
        let tamp_bytes = base64url::decode_strict(&tampered).unwrap();
        assert_eq!(orig_bytes.len(), tamp_bytes.len());
        assert_eq!(
            &orig_bytes[..orig_bytes.len() - 1],
            &tamp_bytes[..tamp_bytes.len() - 1]
        );
        assert_eq!(
            orig_bytes.last().unwrap() ^ tamp_bytes.last().unwrap(),
            0x01
        );
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
