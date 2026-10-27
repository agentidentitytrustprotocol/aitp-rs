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

use aitp::core::{base64url, jcs};
use aitp::crypto::AitpSigningKey;
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

/// Stand-in for `__INVALID_POP_SIG__` / `__INVALID_POP_SIG_OVER_WRONG_NONCE__`
/// until the signature pass: a real PoP signature by the right key over
/// the bitwise complement of the challenge or nonce.
const POP_WRONG_INPUT_PENDING_SENTINEL: &str = "__RUNNER_POP_WRONG_INPUT_PENDING__";

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
    /// Placeholders this fixture used that the runner cannot mint,
    /// in first-seen order. Each resolved to a
    /// `RUNNER_UNKNOWN_PLACEHOLDER_*` sentinel, so a failure fixture
    /// that uses one can pass without exercising its check. Reset by
    /// [`Self::reset_per_fixture`].
    unminted: Vec<String>,
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
            unminted: Vec::new(),
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
        self.unminted.clear();
    }

    /// Placeholders seen since [`Self::reset_per_fixture`] that the
    /// runner could not mint.
    pub fn unminted(&self) -> &[String] {
        &self.unminted
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
        // `__VALID_JWT__` (an OIDC identity proof, not an AITP-profile
        // compact JWS) — its own pass, not folded into
        // `substitute_jws_tokens`/`is_jws_placeholder`: it has no
        // `X_claims` sibling, and its claims are assembled from
        // several sibling fields instead (see `substitute_valid_jwt`).
        // Runs after scalars (needs `pop_nonce` already resolved) and
        // before JCS signatures (the minted JWT lives inside a signed
        // envelope/manifest body).
        self.substitute_valid_jwt(value);
        // RFC-AITP-0002 §3.1 pinned-key proof negatives: after scalars
        // (the envelope `timestamp` may be `__NOW__`) and before JCS
        // signatures (the proof sits inside the signed envelope).
        self.substitute_pinned_proofs(value);
        // RFC-AITP-0002 §6 SPIFFE authorities, SVIDs and X509-SVID
        // proofs: after scalars, before JCS signatures, like the
        // pinned-key proofs.
        let self_aid = value
            .get("self_aid")
            .and_then(|v| v.as_str())
            .map(String::from);
        super::spiffe::substitute(value, self_aid.as_deref(), self.now);
        self.substitute_signatures(value);
    }

    /// Mint the pinned-key proofs (PLACEHOLDERS.md): the valid
    /// `__VALID_PINNED_PROOF__`, and the negatives
    /// `__PINNED_PROOF_OVER_WRONG_NONCE__`, `__CAPTURED_PROOF_FROM_ORIGINAL_HANDSHAKE__`
    /// and `__LEGACY_PINNED_PROOF__`. Each is a real signature by the
    /// sender's KAT key over an input that differs from the one the
    /// verifier reconstructs, so the fixture fails at §3.2 step 5 rather
    /// than at decoding. The receiver is the fixture root's `self_aid`.
    fn substitute_pinned_proofs(&self, value: &mut Value) {
        let self_aid = value
            .get("self_aid")
            .and_then(|v| v.as_str())
            .map(String::from);
        if let Some(self_aid) = self_aid {
            substitute_pinned_proofs_at(value, &self_aid);
        }
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
        use aitp::crypto::jws;
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
            serde_json::json!({ "ver": aitp::core::PROTOCOL_VERSION })
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
                let sig = base64url::encode(&key.sign_raw(signing_input.as_bytes()));
                Some(format!("{signing_input}.{sig}"))
            }
            _ => None,
        }
    }

    /// Mint `__VALID_JWT__` wherever it appears as an OIDC identity
    /// descriptor's `proof`. Unlike the `__JWS_*__` family, this has no
    /// `X_claims` sibling — the claims are assembled from other fields
    /// already present at the same object level (issue #144 Phase 5;
    /// see the plan's Phase 5 Approach for the full per-fixture safety
    /// trace this design is based on).
    ///
    /// Depth-first tree walk, mirroring `substitute_jws_tokens`. At each
    /// object level that has an `identity.proof == "__VALID_JWT__"`,
    /// mints using siblings **of that same object**: `identity.issuer`,
    /// `identity.subject`, `manifest.aid` (→ `cnf.jkt`'s thumbprint),
    /// and `pop_nonce` (→ `nonce`; the sibling of `identity`, not
    /// `pop_nonce_echo` or a root-level `sent_pop_nonce`). `aud` has no
    /// uniform sibling source: use the fixture root's `self_aid` when
    /// present, else the same hardcoded fallback AID
    /// `verify_handshake_payload_op` itself falls back to
    /// (`crates/aitp-conformance/src/rs_adapter/mod.rs`) — safe only because every
    /// fixture that omits `self_aid` never reaches JWT parsing (see the
    /// plan's per-fixture trace table); this is a documented convention
    /// duplication, not a spec mechanism.
    fn substitute_valid_jwt(&self, value: &mut Value) {
        let self_aid = value
            .get("self_aid")
            .and_then(|v| v.as_str())
            .map(String::from);
        self.substitute_valid_jwt_at(value, self_aid.as_deref());
    }

    fn substitute_valid_jwt_at(&self, value: &mut Value, self_aid: Option<&str>) {
        match value {
            Value::Array(items) => {
                for item in items {
                    self.substitute_valid_jwt_at(item, self_aid);
                }
            }
            Value::Object(map) => {
                for v in map.values_mut() {
                    self.substitute_valid_jwt_at(v, self_aid);
                }
                self.mint_identity_jwt_if_present(map, self_aid);
            }
            _ => {}
        }
    }

    fn mint_identity_jwt_if_present(
        &self,
        map: &mut serde_json::Map<String, Value>,
        self_aid: Option<&str>,
    ) {
        let Some(variant) = map
            .get("identity")
            .and_then(|i| i.get("proof"))
            .and_then(|p| p.as_str())
            .and_then(JwtVariant::from_placeholder)
        else {
            return;
        };
        let Some(minted) = (|| {
            let identity = map.get("identity")?;
            let issuer = identity.get("issuer")?.as_str()?;
            let subject = identity.get("subject")?.as_str()?;
            let nonce = map.get("pop_nonce")?.as_str()?;
            let manifest_aid = map.get("manifest")?.get("aid")?.as_str()?;
            let subject_aid = aitp::core::Aid::parse(manifest_aid).ok()?;
            let cnf_jkt = aitp::crypto::AitpVerifyingKey::from_aid(&subject_aid)
                .ok()?
                .to_jwk_thumbprint()
                .ok()?;
            let audience = self_aid.unwrap_or(OIDC_TEST_ADAPTER_FALLBACK_AUD);
            Some(mint_oidc_jwt(
                issuer, subject, audience, nonce, &cnf_jkt, self.now, variant,
            ))
        })() else {
            return;
        };
        if let Some(identity) = map.get_mut("identity").and_then(|v| v.as_object_mut()) {
            identity.insert("proof".into(), Value::from(minted));
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
                        let wrong_input = matches!(
                            pop.get("signature").and_then(|v| v.as_str()),
                            Some(POP_WRONG_INPUT_PENDING_SENTINEL)
                        );
                        let pending = wrong_input
                            || matches!(
                                pop.get("signature").and_then(|v| v.as_str()),
                                Some(SIG_PENDING_SENTINEL)
                            );
                        if pending {
                            if let (Some(challenge), Some(key)) = (
                                pop.get("challenge").and_then(|v| v.as_str()),
                                aid.as_deref().and_then(kat_key_for_aid),
                            ) {
                                if let Ok(mut bytes) = base64url::decode_strict(challenge) {
                                    if wrong_input {
                                        complement(&mut bytes);
                                    }
                                    let sig = key.sign_jcs(&aitp::crypto::Digest32::sha256(&bytes));
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
                    let wrong_input =
                        pop_sig_value.as_str() == Some(POP_WRONG_INPUT_PENDING_SENTINEL);
                    if wrong_input || pop_sig_value.as_str() == Some(SIG_PENDING_SENTINEL) {
                        let echo = map
                            .get("nonce_echo")
                            .or_else(|| map.get("pop_nonce_echo"))
                            .and_then(|v| v.as_str())
                            .map(String::from);
                        if let Some(echo) = echo {
                            if let Ok(mut nonce_bytes) = base64url::decode_strict(&echo) {
                                if wrong_input {
                                    complement(&mut nonce_bytes);
                                }
                                let pop_input = aitp::crypto::Digest32::sha256(&nonce_bytes);
                                let key = map
                                    .get("tct_claims")
                                    .and_then(|c| c.get("iss"))
                                    .and_then(|v| v.as_str())
                                    .and_then(kat_key_for_aid)
                                    .unwrap_or_else(|| {
                                        AitpSigningKey::from_seed(&self.kp_002_seed)
                                    });
                                let sig = key.sign_jcs(&pop_input);
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
                        //   `"aitp-envelope-v2" || 0x00 ||
                        //   JCS(envelope without signature)`. The
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
        // for `substitute_jws_tokens`. `__VALID_JWT__` (an OIDC
        // identity proof) resolves in its own dedicated pass,
        // `substitute_valid_jwt` — leave it for that pass too, same
        // reasoning as the JWS family (mechanical trap #1, issue #144
        // Phase 5: it has no `X_claims` sibling, so it must not be
        // treated as either a resolvable scalar or an unknown
        // placeholder here).
        if is_jws_placeholder(s)
            || s == "__COMPUTED_CHAIN_HASH__"
            || s == "__ANY_CHAIN_HASH__"
            || JwtVariant::from_placeholder(s).is_some()
            || is_pinned_proof_placeholder(s)
            || super::spiffe::is_spiffe_placeholder(s)
        {
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

        // Ignored-value placeholders (PLACEHOLDERS.md): never verified,
        // but MUST be syntactically valid. Mint the RECOMMENDED real
        // signature over the enclosing body.
        if s == "__ANY_CHAIN_STEP_SIG__" || s == "__ANY_DELEGATION_SIG__" {
            return Some(Value::from(SIG_PENDING_SENTINEL));
        }

        if s == "__INVALID_POP_SIG__" || s == "__INVALID_POP_SIG_OVER_WRONG_NONCE__" {
            return Some(Value::from(POP_WRONG_INPUT_PENDING_SENTINEL));
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
        // token as a real value, and record it so the runner can say
        // a pass did not exercise the check.
        if !self.unminted.iter().any(|u| u == s) {
            self.unminted.push(s.to_string());
        }
        Some(Value::from(format!("RUNNER_UNKNOWN_PLACEHOLDER_{s}")))
    }
}

const VALID_PINNED_PROOF: &str = "__VALID_PINNED_PROOF__";
const PINNED_PROOF_OVER_WRONG_NONCE: &str = "__PINNED_PROOF_OVER_WRONG_NONCE__";
const CAPTURED_PINNED_PROOF: &str = "__CAPTURED_PROOF_FROM_ORIGINAL_HANDSHAKE__";
const LEGACY_PINNED_PROOF: &str = "__LEGACY_PINNED_PROOF__";

fn is_pinned_proof_placeholder(s: &str) -> bool {
    matches!(
        s,
        VALID_PINNED_PROOF
            | PINNED_PROOF_OVER_WRONG_NONCE
            | CAPTURED_PINNED_PROOF
            | LEGACY_PINNED_PROOF
    )
}

/// The RFC-AITP-0002 §3.1 proof input:
/// `"aitp-pinned-key-v1" 0x00 sender 0x00 receiver 0x00 message_id 0x00
/// timestamp 0x00 base64url_decode(pop_nonce)`. Built here, not borrowed
/// from `aitp::handshake`, so the runner does not share the code under
/// test; `pinned_proof_input_reproduces_kat_001` pins it to the spec
/// bytes.
fn pinned_proof_input(
    sender: &str,
    receiver: &str,
    message_id: &str,
    timestamp: i64,
    pop_nonce: &str,
) -> Option<Vec<u8>> {
    handshake_proof_input(
        b"aitp-pinned-key-v1\0",
        sender,
        receiver,
        message_id,
        timestamp,
        pop_nonce,
    )
}

/// The §3.1 field encoding behind `domain`: shared by the pinned-key
/// input and the §6.4.1 X509-SVID input.
pub(super) fn handshake_proof_input(
    domain: &[u8],
    sender: &str,
    receiver: &str,
    message_id: &str,
    timestamp: i64,
    pop_nonce: &str,
) -> Option<Vec<u8>> {
    let nonce = base64url::decode_strict(pop_nonce).ok()?;
    let mut out = domain.to_vec();
    for field in [sender, receiver, message_id, &timestamp.to_string()] {
        out.extend_from_slice(field.as_bytes());
        out.push(0);
    }
    out.extend_from_slice(&nonce);
    Some(out)
}

/// A §3.1-style signature by `key`: `sign_jcs` over `SHA-256(input)`.
fn sign_pinned_input(key: &AitpSigningKey, input: &[u8]) -> String {
    let digest = aitp::crypto::Digest32::sha256(input);
    key.sign_jcs(&digest).into_string()
}

/// Walk `value`, minting the pinned-key proofs at each envelope.
fn substitute_pinned_proofs_at(value: &mut Value, self_aid: &str) {
    match value {
        Value::Array(items) => {
            for item in items {
                substitute_pinned_proofs_at(item, self_aid);
            }
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                substitute_pinned_proofs_at(v, self_aid);
            }
            if let Some(minted) = mint_pinned_proof(map, self_aid) {
                map["payload"]["identity"]["proof"] = Value::from(minted);
            }
        }
        _ => {}
    }
}

/// Flip every bit: a different input of the same length.
fn complement(bytes: &mut [u8]) {
    for b in bytes {
        *b = !*b;
    }
}

/// A 16-byte nonce that is not `nonce`: its [`complement`].
fn other_pop_nonce(nonce: &str) -> Option<String> {
    let mut bytes = base64url::decode_strict(nonce).ok()?;
    complement(&mut bytes);
    Some(base64url::encode(&bytes))
}

/// If `map` is an envelope whose `payload.identity.proof` is a
/// pinned-proof placeholder, mint it. `None` when it is not, or when the
/// sender has no KAT key.
fn mint_pinned_proof(map: &serde_json::Map<String, Value>, self_aid: &str) -> Option<String> {
    let payload = map.get("payload")?;
    let placeholder = payload.get("identity")?.get("proof")?.as_str()?;
    if !is_pinned_proof_placeholder(placeholder) {
        return None;
    }
    let sender = map.get("sender")?.get("agent_id")?.as_str()?;
    let message_id = map.get("message_id")?.as_str()?;
    let timestamp = map.get("timestamp")?.as_i64()?;
    let pop_nonce = payload.get("pop_nonce")?.as_str()?;
    let key = kat_key_for_aid(sender)?;
    let input = match placeholder {
        // The real proof over the envelope as it stands after
        // substitution, so it covers a run-time `__ISSUED_NONCE_<n>__`.
        VALID_PINNED_PROOF => {
            pinned_proof_input(sender, self_aid, message_id, timestamp, pop_nonce)?
        }
        PINNED_PROOF_OVER_WRONG_NONCE => pinned_proof_input(
            sender,
            self_aid,
            message_id,
            timestamp,
            &other_pop_nonce(pop_nonce)?,
        )?,
        // A proof from an earlier handshake with another peer: every
        // field but the sender differs.
        CAPTURED_PINNED_PROOF => pinned_proof_input(
            sender,
            CAPTURED_PROOF_ORIGINAL_RECEIVER,
            CAPTURED_PROOF_ORIGINAL_MESSAGE_ID,
            timestamp - 3600,
            &other_pop_nonce(pop_nonce)?,
        )?,
        // Pre-v0.1: `message_id|timestamp`, no domain, receiver or nonce.
        LEGACY_PINNED_PROOF => format!("{message_id}|{timestamp}").into_bytes(),
        _ => return None,
    };
    Some(sign_pinned_input(&key, &input))
}

/// The "original" peer a `__CAPTURED_PROOF_FROM_ORIGINAL_HANDSHAKE__`
/// proof was addressed to: kat-keypair-002.
const CAPTURED_PROOF_ORIGINAL_RECEIVER: &str =
    "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
const CAPTURED_PROOF_ORIGINAL_MESSAGE_ID: &str = "770e8400-e29b-41d4-a716-4466554400ff";

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
pub(crate) fn strip_claims_companions(value: &mut Value) {
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

/// Artifact-naming keys that are pure transport routing metadata, whose
/// artifacts carry `signature` as a **sibling** of the wrapped body rather
/// than a member of it.
///
/// For these, stripping `signature` leaves `{"<wrapper>": {…}}` — the
/// transport envelope, NOT the signing input. Per RFC-AITP-0001 §5.4.1 the
/// naming key is never part of the signing bytes, so it must be unwrapped
/// before canonicalizing (RFC-AITP-0008 §1.5, RFC-AITP-0010 §3).
///
/// The manifest is deliberately absent: its `signature` is a member of the
/// body, so stripping it already yields the correct inner form and the
/// single-key case never arises.
const TRANSPORT_WRAPPERS: &[&str] = &["revocation_list", "session_bundle"];

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
    //
    // Strip BEFORE unwrapping: a companion sitting as a sibling of the
    // wrapper key would otherwise leave the map at two keys, skip the
    // unwrap below, and silently sign the wrapped form again. No fixture
    // has that shape today; ordering it this way means none ever can.
    let mut body = Value::Object(body);
    strip_claims_companions(&mut body);

    // Unwrap the transport envelope. Without this the harness mints over
    // `{"revocation_list": {…}}` while the implementation verifies the inner
    // body — and because the harness both mints and checks, every
    // implementation would pass against its own convention while disagreeing
    // on the wire. That re-minting escape hatch is why a two-implementation
    // divergence survived a full release at 51/51 conformance.
    let body = match body.as_object() {
        Some(m) if m.len() == 1 => match m.iter().next() {
            Some((k, v)) if TRANSPORT_WRAPPERS.contains(&k.as_str()) => v.clone(),
            _ => body,
        },
        _ => body,
    };
    let canonical = jcs::canonicalize(&body).ok()?;
    let digest = aitp::crypto::Digest32::sha256(&canonical);
    Some(key.sign_jcs(&digest).into_string())
}

fn sign_envelope_shape(map: &mut serde_json::Map<String, Value>) -> Option<String> {
    // RFC-AITP-0001 §5.4 envelope signing input (aitp/0.3):
    //   "aitp-envelope-v2" || 0x00 || JCS(envelope without `signature`)
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
                    let sig = key.sign_jcs(&aitp::crypto::Digest32::sha256(&bytes));
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
    let mut unsigned = map.clone();
    unsigned.remove("signature");
    unsigned.insert("payload".into(), payload);
    let canonical = jcs::canonicalize(&Value::Object(unsigned)).ok()?;
    let mut signing_input = aitp::core::ENVELOPE_SIGNING_DOMAIN_TAG.to_vec();
    signing_input.push(0x00);
    signing_input.extend_from_slice(&canonical);
    // Unknown sender AIDs get a syntactically valid filler signed by
    // kp-001; no fixture reaches the envelope signature with one.
    let key = sender_key.unwrap_or_else(|| AitpSigningKey::from_seed(&[0u8; 32]));
    // The Ed25519/ES256 message is `d = sha256(sig_input_v2)`
    // (aitp::core::envelope_signing_digest), hashed once, never the raw
    // input bytes.
    Some(
        key.sign_jcs(&aitp::crypto::Digest32::sha256(&signing_input))
            .into_string(),
    )
}

const KAT_KEYPAIRS: &str = include_str!("../../../../tests/schemas/known-answer/keypairs.json");

/// The `keypairs.json` vector whose `aid` is `aid`.
fn kat_vector(aid: &str) -> Option<Value> {
    let doc: Value = serde_json::from_str(KAT_KEYPAIRS).expect("keypairs.json parses");
    doc["vectors"]
        .as_array()?
        .iter()
        .find(|v| v["aid"] == aid)
        .cloned()
}

fn hex32(hex_str: &str) -> Option<[u8; 32]> {
    hex::decode(hex_str).ok()?.try_into().ok()
}

/// Map an AID to its Ed25519 KAT-keypair seed, read from the pinned
/// `known-answer/keypairs.json`: the role keys and
/// `kat-keypair-006-attacker`, the untrusted key mh-002's attacker
/// signs its own Manifest PoP with. Envelopes signed by any other key
/// can't be runner-substituted (caller must pre-mint).
fn kat_seed_for_aid(aid: &str) -> Option<[u8; 32]> {
    hex32(kat_vector(aid)?["seed_hex"].as_str()?)
}

/// Map an AID to its pinned KAT signing key: an Ed25519 seed, or
/// `kat-keypair-005-p256`'s `private_scalar_hex`.
fn kat_key_for_aid(aid: &str) -> Option<AitpSigningKey> {
    let v = kat_vector(aid)?;
    if let Some(seed) = v["seed_hex"].as_str().and_then(hex32) {
        return Some(AitpSigningKey::from_seed(&seed));
    }
    let scalar = v["private_scalar_hex"].as_str().and_then(hex32)?;
    AitpSigningKey::from_p256_seed(&scalar).ok()
}

/// The spec's OIDC test-issuer keys (`known-answer/oidc-test-issuers.json`),
/// vendored at the pinned spec commit; CI's `spec-schemas` job keeps the
/// copy byte-identical to the spec. `aitp-rs-adapter` reads the same
/// file, so the key the runner signs with and the key the adapter trusts
/// cannot drift.
const OIDC_TEST_ISSUERS: &str =
    include_str!("../../../../tests/schemas/known-answer/oidc-test-issuers.json");

/// The Ed25519 seed of the `oidc-test-issuers.json` vector `id`.
fn oidc_issuer_seed(id: &str) -> [u8; 32] {
    let doc: Value =
        serde_json::from_str(OIDC_TEST_ISSUERS).expect("oidc-test-issuers.json parses");
    let hex_seed = doc["vectors"]
        .as_array()
        .and_then(|v| v.iter().find(|v| v["id"] == id))
        .and_then(|v| v["seed_hex"].as_str())
        .unwrap_or_else(|| panic!("oidc-test-issuers.json has no seed for {id}"));
    hex::decode(hex_seed)
        .ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or_else(|| panic!("{id}: seed_hex is not 32 bytes of hex"))
}

/// Seed of kat-oidc-issuer-001, the trusted test issuer
/// (`https://auth.openai.com`): it signs `__VALID_JWT__` and every OIDC
/// `__JWT_*__` negative.
fn oidc_test_issuer_seed() -> [u8; 32] {
    oidc_issuer_seed("kat-oidc-issuer-001")
}

/// `aud` fallback for a minted `__VALID_JWT__` when the fixture omits
/// `self_aid` at its root — mirrors
/// `crates/aitp-conformance/src/rs_adapter/mod.rs`'s `verify_handshake_payload_op`
/// hardcoded fallback AID. Only safe because every fixture that omits
/// `self_aid` never reaches JWT parsing (the plan's Phase 5 trace
/// table) — an imprecise `aud` on their minted-but-unverified JWT is
/// inconsequential. If a future fixture uses `__VALID_JWT__` with no
/// `self_aid` AND reaches `verify_oidc` for real, this fallback stops
/// being safe.
const OIDC_TEST_ADAPTER_FALLBACK_AUD: &str =
    "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";

/// Mint an OIDC-profile JWT (RFC-AITP-0002 §2) acceptable to
/// `aitp::handshake::identity_oidc::verify_oidc`. Ported from
/// `crates/aitp/tests/handshake_fixtures/mock_oidc.rs`'s
/// `MockOidcIssuer::mint_jwt`/`mint_aitp_jwt` (test-only there,
/// unreachable from this crate as a module import) — same hand-built
/// three-segment compact JWT, plain (non-JCS) JSON, no `kid` in the
/// header (the adapter's matching resolver returns exactly one
/// candidate key, so `verify_oidc`'s no-`kid` single-key fallback
/// applies).
/// Which OIDC identity JWT a placeholder asks for (PLACEHOLDERS.md).
/// Every variant is signed and well formed; each negative differs from
/// `__VALID_JWT__` in exactly one property.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JwtVariant {
    /// `__VALID_JWT__`.
    Valid,
    /// `__JWT_MISSING_AUD_CLAIM__`: no `aud`.
    MissingAud,
    /// `__JWT_AUD_TARGETS_DIFFERENT_PEER__`: `aud` is another peer's AID.
    AudOtherPeer,
    /// `__JWT_MISSING_CNF_JKT_CLAIM__`: no `cnf`.
    MissingCnfJkt,
    /// `__VALID_JWT_FROM_UNKNOWN_ISSUER__`: valid, but signed by a key
    /// the adapter's test-issuer resolver does not hold.
    UnknownIssuer,
}

impl JwtVariant {
    fn from_placeholder(s: &str) -> Option<Self> {
        Some(match s {
            "__VALID_JWT__" => Self::Valid,
            "__JWT_MISSING_AUD_CLAIM__" => Self::MissingAud,
            "__JWT_AUD_TARGETS_DIFFERENT_PEER__" => Self::AudOtherPeer,
            "__JWT_MISSING_CNF_JKT_CLAIM__" => Self::MissingCnfJkt,
            "__VALID_JWT_FROM_UNKNOWN_ISSUER__" => Self::UnknownIssuer,
            _ => return None,
        })
    }
}

/// The peer a `__JWT_AUD_TARGETS_DIFFERENT_PEER__` token names:
/// kat-keypair-004, which is no fixture's `self_aid`.
const JWT_OTHER_PEER_AUD: &str = "aid:pubkey:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w";

/// Seed of kat-oidc-issuer-002-unknown, which signs
/// `__VALID_JWT_FROM_UNKNOWN_ISSUER__`; no resolver may trust it.
fn oidc_unknown_issuer_seed() -> [u8; 32] {
    oidc_issuer_seed("kat-oidc-issuer-002-unknown")
}

#[allow(clippy::too_many_arguments)]
fn mint_oidc_jwt(
    issuer: &str,
    subject: &str,
    audience: &str,
    nonce: &str,
    cnf_jkt: &str,
    now: i64,
    variant: JwtVariant,
) -> String {
    let seed = match variant {
        JwtVariant::UnknownIssuer => oidc_unknown_issuer_seed(),
        _ => oidc_test_issuer_seed(),
    };
    let key = AitpSigningKey::from_seed(&seed);
    let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
    let mut claims = serde_json::json!({
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": now,
        "exp": now + 3600,
        "nonce": nonce,
        "cnf": { "jkt": cnf_jkt },
    });
    let obj = claims.as_object_mut().expect("claims object");
    match variant {
        JwtVariant::MissingAud => {
            obj.remove("aud");
        }
        JwtVariant::AudOtherPeer => {
            obj.insert("aud".into(), Value::from(JWT_OTHER_PEER_AUD));
        }
        JwtVariant::MissingCnfJkt => {
            obj.remove("cnf");
        }
        JwtVariant::Valid | JwtVariant::UnknownIssuer => {}
    }
    let header_b64 = base64url::encode(header.as_bytes());
    let payload_b64 = base64url::encode(claims.to_string().as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = base64url::encode(&key.sign_raw(signing_input.as_bytes()));
    format!("{signing_input}.{sig}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const WORKER_A: &str = "aid:pubkey:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU";
    const SELF_AID: &str = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";

    fn kat_vector(id: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/schemas/known-answer/jcs-sha256.json");
        let doc: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        doc["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == id)
            .unwrap()
            .clone()
    }

    /// Both seeds derive to the public keys the spec publishes beside
    /// them, so a minted JWT verifies under the published key of the
    /// issuer it claims (and the unknown issuer's under its own only).
    #[test]
    fn kat_keys_derive_to_their_published_aids() {
        let doc: Value = serde_json::from_str(KAT_KEYPAIRS).unwrap();
        for v in doc["vectors"].as_array().unwrap() {
            let aid = v["aid"].as_str().unwrap();
            let key = kat_key_for_aid(aid).unwrap_or_else(|| panic!("{aid}: no key"));
            let published = aitp::core::Aid::parse(aid).unwrap();
            let published = aitp::crypto::AitpVerifyingKey::from_aid(&published).unwrap();
            assert!(key.verifying_key() == published, "{aid}: key mismatch");
        }
    }

    #[test]
    fn oidc_issuer_seeds_match_the_published_keys() {
        let doc: Value = serde_json::from_str(OIDC_TEST_ISSUERS).unwrap();
        for v in doc["vectors"].as_array().unwrap() {
            let id = v["id"].as_str().unwrap();
            let key = AitpSigningKey::from_seed(&oidc_issuer_seed(id));
            let x = key.verifying_key().try_to_ed25519_bytes().unwrap();
            assert_eq!(
                base64url::encode(&x),
                v["pubkey_b64url"].as_str().unwrap(),
                "{id}"
            );
        }
        assert_ne!(oidc_test_issuer_seed(), oidc_unknown_issuer_seed());
    }

    #[test]
    fn pinned_proof_input_reproduces_kat_001() {
        let v = kat_vector("kat-pinned-key-proof-001");
        let input = pinned_proof_input(
            v["sender_aid"].as_str().unwrap(),
            v["receiver_aid"].as_str().unwrap(),
            v["message_id"].as_str().unwrap(),
            v["timestamp"].as_i64().unwrap(),
            v["pop_nonce"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(hex::encode(&input), v["proof_input_hex"].as_str().unwrap());
        let key = kat_key_for_aid(v["sender_aid"].as_str().unwrap()).unwrap();
        assert_eq!(
            sign_pinned_input(&key, &input),
            v["signature_b64url"].as_str().unwrap()
        );
    }

    fn pinned_envelope(proof: &str) -> Value {
        json!({
            "self_aid": SELF_AID,
            "envelope": {
                "message_id": "770e8400-e29b-41d4-a716-446655440601",
                "timestamp": "__NOW__",
                "sender": { "agent_id": WORKER_A },
                "payload": {
                    "identity": { "type": "pinned_key", "proof": proof },
                    "pop_nonce": "AAAAAAAAAAAAAAAAAAAAAA"
                },
                "signature": "__VALID_ENVELOPE_SIG__"
            }
        })
    }

    /// `__VALID_PINNED_PROOF__` over id-019's envelope reproduces the
    /// committed proof byte for byte (Ed25519 is deterministic).
    #[test]
    fn valid_pinned_proof_reproduces_id_019() {
        let mut v = json!({
            "self_aid": SELF_AID,
            "envelope": {
                "message_id": "770e8400-e29b-41d4-a716-446655440901",
                "timestamp": 1711900000,
                "sender": { "agent_id": WORKER_A },
                "payload": {
                    "identity": { "type": "pinned_key", "proof": VALID_PINNED_PROOF },
                    "pop_nonce": "AQIDBAUGBwgJCgsMDQ4PEA"
                },
                "signature": "__VALID_ENVELOPE_SIG__"
            }
        });
        let mut ctx = RunnerContext::new();
        ctx.substitute(&mut v);
        assert!(ctx.unminted().is_empty(), "{:?}", ctx.unminted());
        assert_eq!(
            v["envelope"]["payload"]["identity"]["proof"],
            "C7z8HKjjcw0uK9rZaIhxf7V8dW1UJvzal0pJCxrv0y1R7xri3I2kZ7LyxgJY3R96qd0h3FysO_YOOtKLcuPkCw"
        );
    }

    /// Each negative is a real signature by the sender's key that does
    /// not verify over the input the verifier reconstructs, while a
    /// proof over that input does: the fixture fails only at step 5.
    #[test]
    fn pinned_proof_negatives_are_real_and_fail_reconstruction() {
        let key = kat_key_for_aid(WORKER_A).unwrap();
        let vk = key.verifying_key();
        let true_input = pinned_proof_input(
            WORKER_A,
            SELF_AID,
            "770e8400-e29b-41d4-a716-446655440601",
            REFERENCE_NOW,
            "AAAAAAAAAAAAAAAAAAAAAA",
        )
        .unwrap();
        let true_digest = aitp::crypto::Digest32::sha256(&true_input);
        let good = aitp::crypto::Signature::parse(&sign_pinned_input(&key, &true_input)).unwrap();
        vk.verify_jcs(&true_digest, &good).unwrap();

        for placeholder in [
            PINNED_PROOF_OVER_WRONG_NONCE,
            CAPTURED_PINNED_PROOF,
            LEGACY_PINNED_PROOF,
        ] {
            let mut ctx = RunnerContext::new();
            let mut v = pinned_envelope(placeholder);
            ctx.substitute(&mut v);
            assert!(
                ctx.unminted().is_empty(),
                "{placeholder}: {:?}",
                ctx.unminted()
            );
            let proof = v["envelope"]["payload"]["identity"]["proof"]
                .as_str()
                .unwrap();
            let sig = aitp::crypto::Signature::parse(proof)
                .unwrap_or_else(|e| panic!("{placeholder} minted {proof}: {e}"));
            assert!(
                vk.verify_jcs(&true_digest, &sig).is_err(),
                "{placeholder} verifies over the envelope's own input"
            );
            // The envelope is still signed over the minted proof.
            assert_ne!(v["envelope"]["signature"], json!(SIG_PENDING_SENTINEL));
        }

        // Wrong nonce really is the only differing field.
        let mut v = pinned_envelope(PINNED_PROOF_OVER_WRONG_NONCE);
        RunnerContext::new().substitute(&mut v);
        let wrong = pinned_proof_input(
            WORKER_A,
            SELF_AID,
            "770e8400-e29b-41d4-a716-446655440601",
            REFERENCE_NOW,
            &other_pop_nonce("AAAAAAAAAAAAAAAAAAAAAA").unwrap(),
        )
        .unwrap();
        let sig = aitp::crypto::Signature::parse(
            v["envelope"]["payload"]["identity"]["proof"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        vk.verify_jcs(&aitp::crypto::Digest32::sha256(&wrong), &sig)
            .expect("signed over the envelope tuple with the other nonce");
    }

    fn jwt_claims(token: &str) -> Value {
        let payload = token.split('.').nth(1).unwrap();
        serde_json::from_slice(&base64url::decode_strict(payload).unwrap()).unwrap()
    }

    fn jwt_verifies_under(token: &str, seed: [u8; 32]) -> bool {
        let (input, sig) = token.rsplit_once('.').unwrap();
        let sig: [u8; 64] = base64url::decode_strict(sig).unwrap().try_into().unwrap();
        AitpSigningKey::from_seed(&seed)
            .verifying_key()
            .verify_raw_jose(input.as_bytes(), &sig)
            .is_ok()
    }

    /// Each JWT negative is signed and well formed and differs from
    /// `__VALID_JWT__` only in the property its name gives.
    #[test]
    fn jwt_negatives_differ_in_one_property() {
        let mint = |placeholder: &str| {
            let mut ctx = RunnerContext::new();
            let mut v = json!({
                "self_aid": SELF_AID,
                "envelope": { "payload": {
                    "identity": {
                        "type": "oidc",
                        "issuer": "https://auth.openai.com",
                        "subject": "agent-A",
                        "proof": placeholder
                    },
                    "manifest": { "aid": SELF_AID },
                    "pop_nonce": "DLdiOypCLaEk3O1-E8a5TA"
                }}
            });
            ctx.substitute(&mut v);
            assert!(ctx.unminted().is_empty(), "{placeholder}");
            v["envelope"]["payload"]["identity"]["proof"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let valid = mint("__VALID_JWT__");
        let base = jwt_claims(&valid);
        assert!(jwt_verifies_under(&valid, oidc_test_issuer_seed()));

        let t = mint("__JWT_MISSING_AUD_CLAIM__");
        let mut want = base.clone();
        want.as_object_mut().unwrap().remove("aud");
        assert_eq!(jwt_claims(&t), want);
        assert!(jwt_verifies_under(&t, oidc_test_issuer_seed()));

        let t = mint("__JWT_AUD_TARGETS_DIFFERENT_PEER__");
        let mut want = base.clone();
        want["aud"] = json!(JWT_OTHER_PEER_AUD);
        assert_ne!(JWT_OTHER_PEER_AUD, SELF_AID);
        assert_eq!(jwt_claims(&t), want);
        assert!(jwt_verifies_under(&t, oidc_test_issuer_seed()));

        let t = mint("__JWT_MISSING_CNF_JKT_CLAIM__");
        let mut want = base.clone();
        want.as_object_mut().unwrap().remove("cnf");
        assert_eq!(jwt_claims(&t), want);
        assert!(jwt_verifies_under(&t, oidc_test_issuer_seed()));

        let t = mint("__VALID_JWT_FROM_UNKNOWN_ISSUER__");
        assert_eq!(jwt_claims(&t), base);
        assert!(jwt_verifies_under(&t, oidc_unknown_issuer_seed()));
        assert!(!jwt_verifies_under(&t, oidc_test_issuer_seed()));
    }

    /// The PoP negatives are real signatures by the right key over the
    /// complement of the input the verifier checks.
    #[test]
    fn pop_negatives_sign_the_wrong_input() {
        let vk = kat_key_for_aid(SELF_AID).unwrap().verifying_key();
        let check = |b64: &str, sig: &str| {
            let mut bytes = base64url::decode_strict(b64).unwrap();
            let sig = aitp::crypto::Signature::parse(sig).unwrap();
            let right = vk
                .verify_jcs(&aitp::crypto::Digest32::sha256(&bytes), &sig)
                .is_ok();
            complement(&mut bytes);
            let wrong = vk
                .verify_jcs(&aitp::crypto::Digest32::sha256(&bytes), &sig)
                .is_ok();
            (right, wrong)
        };

        let mut ctx = RunnerContext::new();
        let mut v = json!({ "manifest": {
            "aid": SELF_AID,
            "proof_of_possession": {
                "challenge": "E1P1xitRfiKsGDoeyKCI0w",
                "signature": "__INVALID_POP_SIG__"
            },
            "signature": "__VALID_MANIFEST_SIG__"
        }});
        ctx.substitute(&mut v);
        assert!(ctx.unminted().is_empty());
        let sig = v["manifest"]["proof_of_possession"]["signature"]
            .as_str()
            .unwrap();
        assert_eq!(check("E1P1xitRfiKsGDoeyKCI0w", sig), (false, true));

        let mut ctx = RunnerContext::new();
        let mut v = json!({ "envelope": { "payload": {
            "tct_claims": { "iss": SELF_AID },
            "pop_signature": "__INVALID_POP_SIG_OVER_WRONG_NONCE__",
            "pop_nonce_echo": "awVp2Fly6Is8p899W-ALmw"
        }}});
        ctx.substitute(&mut v);
        assert!(ctx.unminted().is_empty());
        let sig = v["envelope"]["payload"]["pop_signature"].as_str().unwrap();
        assert_eq!(check("awVp2Fly6Is8p899W-ALmw", sig), (false, true));
    }

    #[test]
    fn ignored_value_signatures_are_syntactically_valid() {
        let mut ctx = RunnerContext::new();
        let mut v = json!({ "delegation": {
            "chain": [{ "hop": 1, "signature": "__ANY_CHAIN_STEP_SIG__" }],
            "signature": "__ANY_DELEGATION_SIG__"
        }});
        ctx.substitute(&mut v);
        assert!(ctx.unminted().is_empty());
        for sig in [
            &v["delegation"]["chain"][0]["signature"],
            &v["delegation"]["signature"],
        ] {
            aitp::crypto::Signature::parse(sig.as_str().unwrap()).unwrap();
        }
    }

    #[test]
    fn unknown_placeholder_is_recorded_and_reset() {
        let mut ctx = RunnerContext::new();
        let mut v = json!({"a": "__NOT_A_REAL_PLACEHOLDER__", "b": "__NOT_A_REAL_PLACEHOLDER__"});
        ctx.substitute(&mut v);
        assert_eq!(ctx.unminted(), ["__NOT_A_REAL_PLACEHOLDER__"]);
        ctx.reset_per_fixture();
        assert!(ctx.unminted().is_empty());
    }

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
        use aitp::core::base64url;
        use aitp::crypto::{AitpSigningKey, AitpVerifyingKey};
        let mut ctx = RunnerContext::new();
        let mut v = json!({
            "version": "aitp/0.3",
            "issuer": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "signature": "__VALID_TCT_SIG__",
        });
        ctx.substitute(&mut v);
        let sig_b64 = v["signature"].as_str().unwrap().to_string();
        // The signature must verify against kp-001.
        let mut body = v.clone();
        body.as_object_mut().unwrap().remove("signature");
        let canon = aitp::core::jcs::canonicalize(&body).unwrap();
        let digest = aitp::crypto::Digest32::sha256(&canon);
        let key = AitpSigningKey::from_seed(&[0u8; 32]);
        let pubkey = AitpVerifyingKey::from_aid(key.aid()).unwrap();
        let sig = aitp::crypto::Signature::parse(&sig_b64).unwrap();
        pubkey
            .verify_jcs(&digest, &sig)
            .expect("signature verifies");
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
        use aitp::crypto::{AitpSigningKey, AitpVerifyingKey};
        let mut ctx = RunnerContext::new();
        let mut v = json!({
            "version": "aitp/0.3",
            "issuer": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "signature": "__TAMPERED_SIG__",
        });
        ctx.substitute(&mut v);
        let sig_b64 = v["signature"].as_str().unwrap().to_string();

        // Syntactically valid base64url signature (parses cleanly).
        let sig = aitp::crypto::Signature::parse(&sig_b64).expect("parses as base64url sig");

        // But fails Ed25519 verify_strict() under kp-001 (the key
        // that signed before the tamper).
        let mut body = v.clone();
        body.as_object_mut().unwrap().remove("signature");
        let canon = aitp::core::jcs::canonicalize(&body).unwrap();
        let digest = aitp::crypto::Digest32::sha256(&canon);
        let key = AitpSigningKey::from_seed(&[0u8; 32]);
        let pubkey = AitpVerifyingKey::from_aid(key.aid()).unwrap();
        assert!(
            pubkey.verify_jcs(&digest, &sig).is_err(),
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
            "version": "aitp/0.3",
            "issuer": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "signature": "__TAMPERED_SIGNATURE__",
        });
        ctx.substitute(&mut v);
        let sig_b64 = v["signature"].as_str().unwrap();
        assert_eq!(sig_b64.len(), 86, "Ed25519 sig is 86 base64url chars");
        assert!(
            aitp::crypto::Signature::parse(sig_b64).is_ok(),
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

    /// Issue #144 Phase 5. A `mutual_hello`-shaped payload whose
    /// `identity.proof` is `__VALID_JWT__` gets a real, decodable,
    /// verifiable JWT minted from its sibling fields — `iss`/`sub` from
    /// `identity`, `nonce` from the payload's `pop_nonce`, `cnf.jkt`
    /// from `manifest.aid`'s public thumbprint, `aud` from the fixture
    /// root's `self_aid`.
    #[test]
    fn valid_jwt_placeholder_mints_a_real_oidc_jwt() {
        const KP_001_AID: &str = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";
        let mut ctx = RunnerContext::new();
        let mut v = json!({
            "self_aid": KP_001_AID,
            "envelope": {
                "payload": {
                    "identity": {
                        "type": "oidc",
                        "issuer": "https://auth.openai.com",
                        "subject": "agent-A",
                        "proof": "__VALID_JWT__",
                    },
                    "manifest": { "aid": KP_001_AID },
                    "pop_nonce": "DLdiOypCLaEk3O1-E8a5TA",
                },
            },
        });
        ctx.substitute(&mut v);

        let proof = v["envelope"]["payload"]["identity"]["proof"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(proof, "__VALID_JWT__", "placeholder must be replaced");
        let segments: Vec<&str> = proof.split('.').collect();
        assert_eq!(segments.len(), 3, "must be a 3-segment compact JWT");

        let header: Value =
            serde_json::from_slice(&base64url::decode_strict(segments[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], json!("EdDSA"));

        let claims: Value =
            serde_json::from_slice(&base64url::decode_strict(segments[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], json!("https://auth.openai.com"));
        assert_eq!(claims["sub"], json!("agent-A"));
        assert_eq!(claims["aud"], json!(KP_001_AID));
        assert_eq!(claims["nonce"], json!("DLdiOypCLaEk3O1-E8a5TA"));
        assert_eq!(claims["iat"], json!(ctx.now));
        assert_eq!(claims["exp"], json!(ctx.now + 3600));
        let expected_jkt =
            aitp::crypto::AitpVerifyingKey::from_aid(&aitp::core::Aid::parse(KP_001_AID).unwrap())
                .unwrap()
                .to_jwk_thumbprint()
                .unwrap();
        assert_eq!(claims["cnf"]["jkt"], json!(expected_jkt));

        // The signature segment must actually verify under the OIDC
        // test issuer's key (same signer `OidcTestIssuerResolver` in
        // `aitp-rs-adapter` resolves for `OIDC_TEST_ISSUER`).
        let signing_input = format!("{}.{}", segments[0], segments[1]);
        let sig = aitp::crypto::Signature::parse(segments[2]).unwrap();
        let issuer_key = AitpSigningKey::from_seed(&oidc_test_issuer_seed());
        issuer_key
            .verifying_key()
            .verify_raw(
                signing_input.as_bytes(),
                &base64url::decode_strict(sig.as_str()).unwrap(),
            )
            .expect("minted JWT signature must verify under the OIDC test issuer key");
    }

    /// When the fixture root has no `self_aid` (`mh-002`/`mh-003`/
    /// `mh-005`'s shape), minting falls back to the same hardcoded AID
    /// `verify_handshake_payload_op` itself falls back to — safe only
    /// because those fixtures never reach JWT parsing (Phase 5's plan
    /// section trace table).
    #[test]
    fn valid_jwt_falls_back_to_default_aud_when_self_aid_absent() {
        const KP_001_AID: &str = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";
        let mut ctx = RunnerContext::new();
        let mut v = json!({
            "envelope": {
                "payload": {
                    "identity": {
                        "type": "oidc",
                        "issuer": "https://auth.openai.com",
                        "subject": "agent-A",
                        "proof": "__VALID_JWT__",
                    },
                    "manifest": { "aid": KP_001_AID },
                    "pop_nonce": "DLdiOypCLaEk3O1-E8a5TA",
                },
            },
        });
        ctx.substitute(&mut v);
        let proof = v["envelope"]["payload"]["identity"]["proof"]
            .as_str()
            .unwrap();
        let payload_b64 = proof.split('.').nth(1).unwrap();
        let claims: Value =
            serde_json::from_slice(&base64url::decode_strict(payload_b64).unwrap()).unwrap();
        assert_eq!(claims["aud"], json!(OIDC_TEST_ADAPTER_FALLBACK_AUD));
    }

    /// When a sibling field minting needs (`pop_nonce`, here) is absent,
    /// `mint_identity_jwt_if_present` must leave the `__VALID_JWT__`
    /// sentinel literally in place rather than silently substituting
    /// something else — so a fixture that reaches JWT parsing without the
    /// fields minting requires fails loudly on the sentinel string, not
    /// quietly on a malformed token that looks like an accident.
    #[test]
    fn valid_jwt_placeholder_left_intact_when_sibling_fields_missing() {
        const KP_001_AID: &str = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";
        let mut ctx = RunnerContext::new();
        let mut v = json!({
            "envelope": {
                "payload": {
                    "identity": {
                        "type": "oidc",
                        "issuer": "https://auth.openai.com",
                        "subject": "agent-A",
                        "proof": "__VALID_JWT__",
                    },
                    "manifest": { "aid": KP_001_AID },
                    // `pop_nonce` deliberately omitted.
                },
            },
        });
        ctx.substitute(&mut v);
        assert_eq!(
            v["envelope"]["payload"]["identity"]["proof"],
            json!("__VALID_JWT__"),
            "minting must no-op, not fabricate a token, when a required sibling is absent"
        );
    }

    /// Issue #144 Phase 5, acceptance criterion 4. The minting pass must
    /// run before `substitute_signatures`: the minted JWT lives inside
    /// the payload the envelope signature covers, so the final
    /// signature must verify over the *minted* bytes, not the
    /// placeholder string. If the ordering regressed (signing before
    /// minting), the stored signature would verify against stale bytes
    /// and this check — recomputed against the final, post-mint
    /// payload — would fail.
    #[test]
    fn valid_jwt_minting_runs_before_envelope_signature_pass() {
        const KP_001_AID: &str = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";
        let message_id = uuid::Uuid::parse_str("770e8400-e29b-41d4-a716-446655440901").unwrap();
        let mut ctx = RunnerContext::new();
        let mut v = json!({
            "self_aid": KP_001_AID,
            "envelope": {
                "version": "aitp/0.3",
                "message_type": "mutual_hello",
                "message_id": message_id,
                "timestamp": ctx.now,
                "sender": { "agent_id": KP_001_AID },
                "payload": {
                    "identity": {
                        "type": "oidc",
                        "issuer": "https://auth.openai.com",
                        "subject": "agent-A",
                        "proof": "__VALID_JWT__",
                    },
                    "manifest": { "aid": KP_001_AID },
                    "pop_nonce": "DLdiOypCLaEk3O1-E8a5TA",
                },
                "signature": "__VALID_ENVELOPE_SIG__",
            },
        });
        ctx.substitute(&mut v);

        let envelope = &v["envelope"];
        let proof = envelope["payload"]["identity"]["proof"].as_str().unwrap();
        assert_ne!(proof, "__VALID_JWT__", "must have been minted already");

        let sender_aid = aitp::core::Aid::parse(KP_001_AID).unwrap();
        let typed: aitp::core::AitpEnvelope = serde_json::from_value(envelope.clone()).unwrap();
        assert_eq!(typed.message_id, message_id);
        let digest = aitp::core::envelope_signing_digest(&typed).unwrap();
        let sig_b64 = envelope["signature"].as_str().unwrap();
        let sig = aitp::crypto::Signature::parse(sig_b64).unwrap();
        let pubkey = aitp::crypto::AitpVerifyingKey::from_aid(&sender_aid).unwrap();
        pubkey.verify_jcs(&digest.into(), &sig).expect(
            "envelope signature must verify over the post-JWT-minting payload bytes \
             (proves the minting pass ran before the signature pass, not after)",
        );
    }
}
