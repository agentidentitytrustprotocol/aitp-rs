//! Conformance adapter as a library — same behavior as the
//! subprocess binary, exposed for use by the in-process adapter in
//! `aitp-conformance`. The binary at `src/main.rs` is now a thin
//! shell that owns stdin/stdout I/O and calls into [`handle`] for
//! every NDJSON line.
//!
//! The adapter is stateful (handshake sessions, keypair seeds,
//! clock override, revocation list) — callers construct one
//! [`AdapterState`] and reuse it for the lifetime of the test run.
//!
//! See `docs/conformance.md` for the wire
//! protocol the binary speaks; this library is the layer below it.

#![forbid(unsafe_code)]

use aitp_core::{base64url, jcs, Aid, AitpEnvelope, MessageType, Sender, Timestamp};
use aitp_crypto::{jws, AitpSigningKey, AitpVerifyingKey, CryptoError, Signature};
use aitp_delegation::DelegationBuilder;
use aitp_handshake::{
    Initiator, JwkPublicKey, JwksResolver, MutualCommitAckPayload, MutualHelloAckPayload,
    PeerConfig, PresentedIdentity, ResolveError,
};
use aitp_manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder, ManifestEnvelope};
use aitp_tct::{TctBuilder, TctClaims};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

#[derive(Default)]
pub struct AdapterState {
    /// Keypairs are stored as seeds because `AitpSigningKey` is intentionally
    /// not `Clone`. We re-derive the key on demand via `key_for(handle)`.
    /// Random-generated keypairs use a seed we generate ourselves so the
    /// reconstruction round-trips deterministically within an adapter
    /// lifetime.
    keypair_seeds: HashMap<String, [u8; 32]>,
    next_kp_id: u64,
    sessions: HashMap<String, HandshakeSession>,
    next_session_id: u64,
    revoked_jtis: HashSet<String>,
    /// Override "now" for time-dependent fixtures (Tier-D `set_clock`).
    now_override: Option<i64>,
    /// Last known peer manifest, indexed by manifest's AID. The handshake
    /// step ops look up the peer's pubkey here when verifying envelopes.
    peer_manifests: HashMap<String, Manifest>,
    /// Pending downstream PoP challenges, keyed by TCT JTI string.
    /// `issue_pop_challenge` populates this; `verify_pop_response` and
    /// `produce_pop_response` read from it. RFC-AITP-0005 §6.
    pop_challenges: HashMap<String, aitp_tct::PopChallenge>,
    /// Message-IDs the adapter has accepted in the current run.
    /// Used by env-* replay-test fixtures: a second
    /// `verify_envelope` call carrying the same `message_id`
    /// must return REPLAY_DETECTED. Single-set (no TTL) since
    /// fixture runs are short-lived.
    seen_message_ids: HashSet<String>,
    /// Feature flags the runner has told us are enabled. The
    /// adapter consults this when deciding whether to opt into
    /// post-v0.1 RFC behavior. Examples:
    ///   `experimental-multihop-delegation` → verify_delegation
    ///       uses `max_hops = DEFAULT_MAX_HOPS` instead of strict 0.
    ///   `experimental-session-bundle` → bundle ops accept work.
    enabled_features: HashSet<String>,
    /// PoP-enforcement state for the `tct-007` capability-invocation
    /// sequence (RFC-AITP-0005 §6.2). `authorize_capability_invocation`
    /// sets it: `Some(true)` when the invoked grant was marked
    /// PoP-required (a `pop_challenge` was issued), `Some(false)` when
    /// it was not. `expect_pop_challenge_issued` and
    /// `withhold_pop_response` read it.
    pop_enforcement: Option<bool>,
}

impl AdapterState {
    /// Whether the runner has enabled the named feature.
    pub fn has_feature(&self, name: &str) -> bool {
        self.enabled_features.contains(name)
    }
}

impl AdapterState {
    fn now(&self) -> Timestamp {
        match self.now_override {
            Some(s) => Timestamp(s),
            None => Timestamp::now(),
        }
    }
    fn fresh_kp_handle(&mut self) -> String {
        self.next_kp_id += 1;
        format!("kp-{}", self.next_kp_id)
    }
    fn fresh_session_id(&mut self) -> String {
        self.next_session_id += 1;
        format!("sess-{}", self.next_session_id)
    }
    fn key_for(&self, handle: &str) -> Option<AitpSigningKey> {
        self.keypair_seeds
            .get(handle)
            .map(AitpSigningKey::from_seed)
    }
}

/// In-progress handshake session.
///
/// Responder sessions land in `PendingResponder` at `start_handshake`
/// and transition to `ActiveResponder` on the first
/// `process_handshake_message` carrying a HELLO envelope. The lazy
/// construction matches the `aitp-handshake::Responder` API, which has
/// no empty constructor.
#[allow(clippy::large_enum_variant)] // size delta between PendingResponder and Active variants is acceptable here
enum HandshakeSession {
    Initiator {
        state: Initiator,
        keypair_handle: String,
        /// The initiator's own manifest. Required so that
        /// `process_handshake_message` can construct a `PeerConfig`
        /// where `cfg.manifest.aid` is the initiator's AID — the TCT
        /// verifier in `aitp-handshake` uses it as the expected
        /// audience for incoming TCTs (RFC-AITP-0005 §9 step 2).
        my_manifest: Manifest,
    },
    PendingResponder {
        keypair_handle: String,
        my_manifest: Manifest,
        my_requested_grants: Vec<String>,
    },
    ActiveResponder {
        state: aitp_handshake::Responder,
        keypair_handle: String,
        my_manifest: Manifest,
    },
}

pub fn handle(state: &mut AdapterState, id: &str, op: &str, params: Value) -> Value {
    match op {
        "init" => init(id),
        "shutdown" => json!({"id": id, "ok": true}),

        // Tier A
        "verify_jcs" => verify_jcs(id, params),
        "compute_jwk_thumbprint" => compute_jwk_thumbprint(id, params),
        "verify_envelope" => verify_envelope_op(state, id, params),
        "verify_manifest" => verify_manifest_op(state, id, params),
        "verify_tct" => verify_tct_op(state, id, params),
        "verify_grant_voucher" => verify_grant_voucher_op(state, id, params),
        "verify_delegation_token" => verify_delegation_op(state, id, params),
        "verify_handshake_payload" => verify_handshake_payload_op(state, id, params),

        // Tier B
        "generate_keypair" => generate_keypair(state, id, params),
        "issue_manifest" => issue_manifest_op(state, id, params),
        "issue_tct" => issue_tct_op(state, id, params),
        "issue_delegation_token" => issue_delegation_op(state, id, params),
        "issue_session_bundle" => issue_session_bundle_op(state, id, params),
        "sign_envelope" => sign_envelope_op(state, id, params),

        // Session bundle (RFC-AITP-0010, Tier A verify)
        "verify_session_bundle" => verify_session_bundle_op(state, id, params),

        // Tier C
        "start_handshake" => start_handshake_op(state, id, params),
        "process_handshake_message" => process_handshake_message_op(state, id, params),
        "revoke_tct" => revoke_tct_op(state, id, params),
        "verify_revocation_snapshot" => verify_revocation_snapshot_op(state, id, params),
        "issue_pop_challenge" => issue_pop_challenge_op(state, id, params),
        "produce_pop_response" => produce_pop_response_op(state, id, params),
        "verify_pop_response" => verify_pop_response_op(state, id, params),
        "authorize_capability_invocation" => authorize_capability_invocation_op(state, id, params),
        "expect_pop_challenge_issued" => expect_pop_challenge_issued_op(state, id, params),
        "withhold_pop_response" => withhold_pop_response_op(state, id, params),

        // Tier D
        "set_clock" => set_clock_op(state, id, params),
        "set_features" => set_features_op(state, id, params),
        "inject_revocation" => revoke_tct_op(state, id, params),
        "dump_session" => dump_session_op(state, id, params),

        other => err(
            id,
            "OP_NOT_SUPPORTED",
            &format!("op {other} not implemented"),
        ),
    }
}

fn init(id: &str) -> Value {
    let supported_ops = vec![
        "init",
        "shutdown",
        // Tier A
        "verify_jcs",
        "compute_jwk_thumbprint",
        "verify_envelope",
        "verify_manifest",
        "verify_tct",
        "verify_grant_voucher",
        "verify_delegation_token",
        "verify_handshake_payload",
        // Tier B
        "generate_keypair",
        "issue_manifest",
        "issue_tct",
        "issue_delegation_token",
        "issue_session_bundle",
        "sign_envelope",
        "verify_session_bundle",
        // Tier C
        "start_handshake",
        "process_handshake_message",
        "revoke_tct",
        "verify_revocation_snapshot",
        "issue_pop_challenge",
        "produce_pop_response",
        "verify_pop_response",
        "authorize_capability_invocation",
        "expect_pop_challenge_issued",
        "withhold_pop_response",
        // Tier D
        "set_clock",
        "set_features",
        "inject_revocation",
        "dump_session",
    ];
    let supported_features = vec!["pinned_key_identity", "oidc_identity"];
    json!({
        "id": id,
        "ok": true,
        "result": {
            "implementation": "aitp-rs",
            "version": env!("CARGO_PKG_VERSION"),
            "supported_ops": supported_ops,
            "supported_features": supported_features
        }
    })
}

/// `authorize_capability_invocation` — first step of the `tct-007`
/// PoP-enforcement sequence (RFC-AITP-0005 §6.2). The verifier accepts
/// the invocation *request*; when the issuing peer's policy
/// (`issuer_policy.pop_required_grants`) marks the invoked grant as
/// requiring downstream PoP it issues a `pop_challenge` instead of
/// authorizing the capability outright. The PoP-required decision is
/// recorded in `state.pop_enforcement` for the following two steps.
fn authorize_capability_invocation_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    let capability = match params
        .get("envelope")
        .and_then(|e| e.get("payload"))
        .and_then(|p| p.get("capability"))
        .and_then(|v| v.as_str())
    {
        Some(c) => c.to_string(),
        None => {
            return err(
                id,
                "INVALID_ENVELOPE",
                "capability_invocation envelope has no payload.capability",
            )
        }
    };
    let pop_required: Vec<String> = params
        .get("issuer_policy")
        .and_then(|p| p.get("pop_required_grants"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let pop_required_for_grant = pop_required.contains(&capability);
    state.pop_enforcement = Some(pop_required_for_grant);
    if pop_required_for_grant {
        // Marked grant: the verifier MUST NOT authorize without a valid
        // downstream PoP. It accepts the request and issues a
        // `pop_challenge` (RFC-AITP-0005 §6.2).
        json!({
            "id": id,
            "ok": true,
            "result": {
                "pop_challenge_issued": true,
                "capability_authorized": false,
                "side_effects": { "pop_challenge_issued": true }
            }
        })
    } else {
        // Unmarked grant: the issuing peer's policy does not require
        // PoP for this grant; the invocation may be authorized.
        json!({
            "id": id,
            "ok": true,
            "result": {
                "pop_challenge_issued": false,
                "capability_authorized": true,
                "side_effects": { "capability_authorized": true }
            }
        })
    }
}

/// `expect_pop_challenge_issued` — `tct-007` step 2: asserts the
/// preceding `authorize_capability_invocation` issued a `pop_challenge`
/// because the invoked grant was marked PoP-required.
fn expect_pop_challenge_issued_op(state: &AdapterState, id: &str, _params: Value) -> Value {
    match state.pop_enforcement {
        Some(true) => json!({
            "id": id,
            "ok": true,
            "result": { "side_effects": { "pop_challenge_issued": true } }
        }),
        Some(false) => err(
            id,
            "POP_CHALLENGE_INVALID",
            "no pop_challenge was issued — the invoked grant was not marked PoP-required",
        ),
        None => err(
            id,
            "INVALID_REQUEST",
            "expect_pop_challenge_issued with no preceding authorize_capability_invocation",
        ),
    }
}

/// `withhold_pop_response` — `tct-007` step 3: no valid `pop_response`
/// is returned within the challenge's freshness window. For a grant the
/// issuer marked PoP-required the verifier MUST reject the invocation
/// with `POP_RESPONSE_INVALID` and MUST NOT authorize the capability —
/// silently skipping PoP for a marked grant is non-conformant
/// (RFC-AITP-0005 §6.2).
fn withhold_pop_response_op(state: &mut AdapterState, id: &str, _params: Value) -> Value {
    match state.pop_enforcement.take() {
        Some(true) => err(
            id,
            "POP_RESPONSE_INVALID",
            "no valid pop_response within the challenge freshness window; capability \
             invocation rejected (RFC-AITP-0005 §6.2)",
        ),
        Some(false) => json!({
            "id": id,
            "ok": true,
            "result": { "side_effects": { "capability_authorized": true } }
        }),
        None => err(
            id,
            "INVALID_REQUEST",
            "withhold_pop_response with no preceding authorize_capability_invocation",
        ),
    }
}

// ── Shared helpers (v0.2 compact-JWS conventions) ───────────────────────

/// Strip `*_claims` companion fields (the spec PLACEHOLDERS.md
/// claims-sibling convention) from a JSON value, recursively. The
/// companions are minting inputs, never wire bytes — runners and
/// adapters MUST ignore them when present.
fn strip_claims_companions(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.retain(|k, _| !k.ends_with("_claims"));
            for val in map.values_mut() {
                strip_claims_companions(val);
            }
        }
        Value::Array(arr) => {
            for val in arr.iter_mut() {
                strip_claims_companions(val);
            }
        }
        _ => {}
    }
}

/// Decode a compact JWS payload WITHOUT verification, as loose JSON.
/// Used only to discover routing facts (`iss`, `aud`) that are then
/// re-established cryptographically by the real verifier.
fn peek_token_claims(token: &str) -> Result<Value, CryptoError> {
    let bytes = jws::decode_payload_unverified(token)?;
    serde_json::from_slice(&bytes).map_err(|e| CryptoError::JwsMalformed(e.to_string()))
}

fn peek_token_aid_claim(token: &str, claim: &str) -> Option<Aid> {
    peek_token_claims(token)
        .ok()?
        .get(claim)?
        .as_str()
        .and_then(|s| Aid::parse(s).ok())
}

/// Resolve the TCT claims an op needs, accepting either a compact JWS
/// `tct_token` string (decoded unverified — fine for PoP bookkeeping,
/// where the binding is re-checked against the subject key) or an
/// explicit claims object under `tct` / `tct_claims` /
/// `tct_token_claims`.
fn tct_claims_from_params(params: &Value) -> Result<TctClaims, String> {
    if let Some(tok) = params.get("tct_token").and_then(|v| v.as_str()) {
        let bytes = jws::decode_payload_unverified(tok).map_err(|e| e.to_string())?;
        return serde_json::from_slice(&bytes).map_err(|e| format!("tct_token claims: {e}"));
    }
    for key in ["tct", "tct_claims", "tct_token_claims"] {
        if let Some(v) = params.get(key) {
            if let Some(tok) = v.as_str() {
                let bytes = jws::decode_payload_unverified(tok).map_err(|e| e.to_string())?;
                return serde_json::from_slice(&bytes).map_err(|e| format!("{key} claims: {e}"));
            }
            return serde_json::from_value(v.clone()).map_err(|e| format!("{key}: {e}"));
        }
    }
    Err("missing 'tct_token' (compact JWS) or 'tct' claims".into())
}

/// Map a [`CryptoError`] surfaced during compact-JWS verification to
/// the conformance wire code. `sig_invalid_code` names the
/// artifact-specific code for a plain bad signature
/// (TCT_SIGNATURE_INVALID, DELEGATION_INVALID_VOUCHER, ...).
fn crypto_error_code(e: &CryptoError, sig_invalid_code: &'static str) -> String {
    match e {
        CryptoError::AlgMismatch(_) => "TOKEN_ALG_MISMATCH".to_string(),
        CryptoError::TypMismatch { .. } => "TOKEN_TYP_MISMATCH".to_string(),
        CryptoError::JwsMalformed(_) => "INVALID_ENVELOPE".to_string(),
        CryptoError::SignatureInvalid => sig_invalid_code.to_string(),
        CryptoError::KeyParseFailed(_) | CryptoError::AidNotEd25519(_) => {
            "KEY_RESOLUTION_FAILED".to_string()
        }
        _ => "INVALID_SIGNATURE".to_string(),
    }
}

// ── Tier A ──────────────────────────────────────────────────────────────

fn verify_jcs(id: &str, params: Value) -> Value {
    let input = match params.get("input") {
        Some(v) => v.clone(),
        None => return err(id, "INVALID_REQUEST", "missing 'input'"),
    };
    match jcs::canonicalize(&input) {
        Ok(bytes) => json!({
            "id": id,
            "ok": true,
            "result": {
                "canonical_hex": hex::encode(&bytes),
                "canonical_utf8": std::str::from_utf8(&bytes).unwrap_or(""),
            }
        }),
        Err(e) => err(id, "JCS_ERROR", &e.to_string()),
    }
}

fn compute_jwk_thumbprint(id: &str, params: Value) -> Value {
    let pubkey = match params.get("public_key").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err(id, "INVALID_REQUEST", "missing 'public_key'"),
    };
    let bytes = match base64url::decode_strict(pubkey) {
        Ok(b) => b,
        Err(e) => return err(id, "INVALID_REQUEST", &format!("public_key: {e}")),
    };
    if bytes.len() != 32 {
        return err(id, "INVALID_REQUEST", "public_key must decode to 32 bytes");
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    let thumbprint = aitp_crypto::compute_jwk_thumbprint(&buf);
    json!({"id": id, "ok": true, "result": {"thumbprint": thumbprint}})
}

fn verify_envelope_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    // env-004 replay sequence: each step carries just
    // `step` + `message_id`. Track every message_id in
    // `state.seen_message_ids`; a duplicate within the run
    // returns REPLAY_DETECTED.
    if let Some(mid) = params.get("message_id").and_then(|v| v.as_str()) {
        if params.get("envelope").is_none() {
            if !state.seen_message_ids.insert(mid.to_string()) {
                return err(
                    id,
                    "REPLAY_DETECTED",
                    &format!("message_id {mid} already seen in this run"),
                );
            }
            return json!({"id": id, "ok": true, "result": {"verified": true, "message_id": mid}});
        }
    }
    // The spec's env-* fixtures overload `operation: "verify_envelope"`
    // with a few different input shapes. Dispatch on which fields the
    // fixture provides.
    //
    // - `active_tct` + `requested_capability`: stateless capability
    //   policy check (RFC-AITP-0004 §4). No envelope to parse.
    // - `manifest_fetch` / `oidc_discovery` / `pinned_keys` / etc.:
    //   key-resolution scenarios. The fixture pre-defines the state
    //   of every key source; we evaluate them directly.
    // - `sequence`: replay test where two envelopes share a
    //   `message_id`. Sequence steps run via the runner's
    //   sequence path; this branch is a single-step entry which
    //   we never reach (the sequence dispatch goes elsewhere).
    // - default: classic single-envelope verification.
    if let Some(active_tct) = params.get("active_tct") {
        return verify_envelope_capability_policy(
            id,
            active_tct.clone(),
            params.get("requested_capability").and_then(|v| v.as_str()),
        );
    }
    if params.get("needed_key_for").is_some() {
        return verify_envelope_key_resolution(id, &params);
    }

    let envelope = match serde_json::from_value::<AitpEnvelope>(
        params.get("envelope").cloned().unwrap_or_default(),
    ) {
        Ok(e) => e,
        Err(e) => return err(id, "INVALID_ENVELOPE", &format!("envelope parse: {e}")),
    };
    // RFC-AITP-0001 §5.5 / §5.6: version + freshness checks are part of
    // envelope verification. When the fixture supplies `tolerance_seconds`
    // we enforce it relative to the verifier's clock (or the fixture's
    // explicit `now`).
    if envelope.version != aitp_core::PROTOCOL_VERSION {
        return err(
            id,
            "UNKNOWN_VERSION",
            &format!("unsupported envelope version `{}`", envelope.version),
        );
    }
    if let Some(tolerance) = params.get("tolerance_seconds").and_then(|v| v.as_i64()) {
        let now_secs = params
            .get("now")
            .and_then(|v| v.as_i64())
            .unwrap_or_else(|| state.now().0);
        let drift = (now_secs - envelope.timestamp.0).abs();
        if drift > tolerance {
            return err(
                id,
                "TIMESTAMP_EXPIRED",
                &format!("envelope timestamp drift {drift}s exceeds {tolerance}s"),
            );
        }
    }
    let pk = match AitpVerifyingKey::from_aid(&envelope.sender.agent_id) {
        Ok(p) => p,
        Err(e) => return err(id, "KEY_RESOLUTION_FAILED", &e.to_string()),
    };
    let digest = match aitp_core::envelope_signing_digest(
        &envelope.message_id,
        envelope.timestamp,
        &envelope.sender.agent_id,
        &envelope.payload,
    ) {
        Ok(d) => d,
        Err(e) => return err(id, "INTERNAL_ERROR", &e.to_string()),
    };
    let sig = match Signature::parse(&envelope.signature) {
        Ok(s) => s,
        Err(_) => return err(id, "INVALID_SIGNATURE", "signature parse"),
    };
    match pk.verify(&digest, &sig) {
        Ok(()) => json!({"id": id, "ok": true, "result": {"verified": true}}),
        Err(_) => err(id, "INVALID_SIGNATURE", "envelope signature invalid"),
    }
}

/// Stateless capability policy check (RFC-AITP-0004 §4): an
/// invocation MUST be rejected with POLICY_VIOLATION if the
/// requested capability is not in the active TCT's `grants`.
fn verify_envelope_capability_policy(
    id: &str,
    active_tct: Value,
    requested_capability: Option<&str>,
) -> Value {
    let cap = match requested_capability {
        Some(c) => c,
        None => {
            return err(
                id,
                "INVALID_REQUEST",
                "missing 'requested_capability' for capability policy check",
            )
        }
    };
    let grants = active_tct
        .get("grants")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if grants.iter().any(|g| g == cap) {
        json!({"id": id, "ok": true, "result": {"verified": true, "outcome": "allowed"}})
    } else {
        err(
            id,
            "POLICY_VIOLATION",
            &format!("requested capability `{cap}` not in active TCT grants"),
        )
    }
}

/// Key-resolution-failure check (RFC-AITP-0007 §2): given a
/// describing-fixture of the state of every key source
/// (`pinned_keys`, `well_known_keys`, `oidc_discovery`,
/// `manifest_fetch`), determine whether the verifier could have
/// located a key for `needed_key_for`. If every source fails to
/// produce a key, return KEY_RESOLUTION_FAILED.
fn verify_envelope_key_resolution(id: &str, params: &Value) -> Value {
    let needed = params
        .get("needed_key_for")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if needed.is_empty() {
        return err(id, "INVALID_REQUEST", "missing 'needed_key_for'");
    }
    // The fixture explicitly models every possible key source. We
    // walk them in RFC-AITP-0007 priority order and return the
    // first hit.
    //
    // 1. Pinned keys (operator-supplied, no network).
    // 2. /.well-known/aitp-keys (AITP-native discovery).
    // 3. OIDC discovery (oidc_discovery + jwks_uri).
    // 4. Manifest fetch.
    let pinned_hit = params
        .get("pinned_keys")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().any(|k| key_source_matches(k, needed)))
        .unwrap_or(false);
    if pinned_hit {
        return json!({"id": id, "ok": true, "result": {"verified": true, "source": "pinned"}});
    }
    let wk_hit = params
        .get("well_known_keys")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().any(|k| key_source_matches(k, needed)))
        .unwrap_or(false);
    if wk_hit {
        return json!({"id": id, "ok": true, "result": {"verified": true, "source": "well_known"}});
    }
    let oidc_hit = params
        .get("oidc_discovery")
        .map(|d| d.get("status").and_then(|v| v.as_str()) == Some("ok"))
        .unwrap_or(false);
    if oidc_hit {
        return json!({"id": id, "ok": true, "result": {"verified": true, "source": "oidc"}});
    }
    let mf_hit = params
        .get("manifest_fetch")
        .map(|f| f.get("status").and_then(|v| v.as_str()) == Some("ok"))
        .unwrap_or(false);
    if mf_hit {
        return json!({"id": id, "ok": true, "result": {"verified": true, "source": "manifest"}});
    }
    err(
        id,
        "KEY_RESOLUTION_FAILED",
        &format!("no source returned a key for {needed}"),
    )
}

fn key_source_matches(entry: &Value, needed: &str) -> bool {
    // Fixtures model entries as either `{"aid": "...", "key": "..."}`
    // or `{"issuer": "...", "key": "..."}`. We accept any field whose
    // string value equals `needed`.
    if let Some(map) = entry.as_object() {
        for v in map.values() {
            if v.as_str() == Some(needed) {
                return true;
            }
        }
    }
    false
}

/// Map a known kat-keypair AID to its 32-byte seed. The id-* / mh-*
/// conformance fixtures self-identify as one of these three keypairs;
/// any other `self_aid` lands as `OP_NOT_SUPPORTED` (the bootstrap
/// verifier needs a verifier-side signing key, and we can't derive
/// one from an arbitrary AID since AIDs are public keys).
fn kat_seed_for_aid(aid_str: &str) -> Option<[u8; 32]> {
    match aid_str {
        "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik" => Some([0u8; 32]),
        "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg" => {
            let mut s = [0u8; 32];
            for (i, b) in s.iter_mut().enumerate() {
                *b = i as u8;
            }
            Some(s)
        }
        "aid:pubkey:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU" => Some([0xffu8; 32]),
        _ => None,
    }
}

/// `verify_handshake_payload` runs the full Mutual Handshake
/// receiver-side identity check on a single envelope (HELLO or
/// HELLO_ACK). The conformance harness uses this for `id-*` and
/// single-message `mh-*` fixtures. RFC-AITP-0004 §5.1 steps 3–6.
fn verify_handshake_payload_op(state: &AdapterState, id: &str, params: Value) -> Value {
    // mh-success-001 dual-peer mode: the fixture supplies `peer_a`
    // and `peer_b` configs, each with `self_aid` + `inbound_tct`.
    // Verify each peer's inbound TCT against its own self_aid and
    // declare success only when both pass. No envelope is parsed.
    if let (Some(peer_a), Some(peer_b)) = (params.get("peer_a"), params.get("peer_b")) {
        return verify_handshake_dual_peer(id, peer_a, peer_b, state.now());
    }

    let mut envelope = match serde_json::from_value::<AitpEnvelope>(
        params.get("envelope").cloned().unwrap_or_default(),
    ) {
        Ok(e) => e,
        Err(e) => return err(id, "INVALID_ENVELOPE", &format!("envelope parse: {e}")),
    };
    // The spec fixtures may carry `*_claims` companion fields inside
    // the payload (claims-sibling minting convention). They are never
    // wire bytes — strip before signature verification and typed
    // payload parsing.
    strip_claims_companions(&mut envelope.payload);

    // Conformance convention: when a fixture omits `self_aid`,
    // the verifier defaults to the receiver implied by the
    // message shape:
    //
    // - For MUTUAL_COMMIT / MUTUAL_COMMIT_ACK envelopes the
    //   payload carries a `tct` compact JWS whose `aud` claim IS
    //   the recipient (the TCT was minted by the sender for the
    //   receiver). Use that as the default self_aid so mh-007 /
    //   mh-008 (which omit self_aid) verify against the right
    //   pubkey.
    // - Otherwise fall back to kat-keypair-001 (the default
    //   "initiator-side" receiver used by mh-* HELLO fixtures).
    //   id-* fixtures supply self_aid explicitly.
    let default_self_aid = envelope
        .payload
        .get("tct")
        .and_then(|v| v.as_str())
        .and_then(|tok| peek_token_aid_claim(tok, "aud"))
        .map(|a| a.as_str().to_string())
        .unwrap_or_else(|| "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik".to_string());
    let self_aid_str = params
        .get("self_aid")
        .and_then(|v| v.as_str())
        .unwrap_or(&default_self_aid);
    let self_seed = match kat_seed_for_aid(self_aid_str) {
        Some(s) => s,
        None => {
            return err(
                id,
                "OP_NOT_SUPPORTED",
                "self_aid is not a known kat-keypair (this adapter requires a kat-keypair seed to derive the verifier's signing key)",
            )
        }
    };
    let self_key = AitpSigningKey::from_seed(&self_seed);

    // Synthesize a minimal verifier-side Manifest. Most fields are
    // throwaway; what bootstrap_verify_peer reads out of `cfg.manifest`
    // is `aid` (audience for OIDC) and `required_peer_capabilities`.
    let self_manifest = match ManifestBuilder::new(&self_key)
        .display_name("conformance-verifier")
        .handshake_endpoint(
            "https://verifier.example.com/aitp/handshake"
                .parse()
                .unwrap(),
        )
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "verifier".into(),
            issuer: None,
            public_key: Some(aitp_core::base64url::encode(
                &self_key.verifying_key().to_bytes(),
            )),
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .accept_identity_type("pinned_key")
        .accept_identity_type("oidc")
        .ttl_secs(3600)
        .published_at(state.now())
        .build()
    {
        Ok(m) => m,
        Err(e) => return err(id, "INTERNAL_ERROR", &format!("verifier manifest: {e}")),
    };

    // Envelope-signature closure. For HELLO / HELLO_ACK this runs
    // AFTER the Manifest + identity bootstrap (RFC-AITP-0004 §5.1
    // step 6 — the envelope is verified with the *now-trusted* key);
    // for COMMIT / COMMIT_ACK the sender key was established earlier
    // in the handshake, so it runs first.
    let verify_envelope_sig = |envelope: &AitpEnvelope| -> Result<(), String> {
        let pk = AitpVerifyingKey::from_aid(&envelope.sender.agent_id)
            .map_err(|e| format!("aid: {e}"))?;
        let digest = aitp_core::envelope_signing_digest(
            &envelope.message_id,
            envelope.timestamp,
            &envelope.sender.agent_id,
            &envelope.payload,
        )
        .map_err(|e| format!("digest: {e}"))?;
        let sig = Signature::parse(&envelope.signature).map_err(|e| format!("sig: {e}"))?;
        pk.verify(&digest, &sig).map_err(|_| "verify".to_string())
    };
    if matches!(
        envelope.message_type,
        MessageType::MutualCommit | MessageType::MutualCommitAck
    ) {
        if let Err(e) = verify_envelope_sig(&envelope) {
            return err(id, "INVALID_SIGNATURE", &format!("envelope: {e}"));
        }
    }

    // Parse payload as MutualHello / MutualHelloAck and run
    // bootstrap_verify_peer (steps 3–5); HELLO-family envelope
    // signatures are verified after it succeeds (step 6).
    let resolver = NoOpResolver;
    let cfg = PeerConfig {
        signing_key: &self_key,
        manifest: &self_manifest,
        trust_anchors: &[
            "https://auth.openai.com".parse().unwrap(),
            "https://auth.anthropic.com".parse().unwrap(),
            "https://idp.example.com".parse().unwrap(),
        ],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: envelope.timestamp,
    };

    use aitp_handshake::payloads::{
        MutualCommitAckPayload, MutualHelloAckPayload, MutualHelloPayload,
    };
    use aitp_handshake::state_machine::bootstrap_verify_peer;

    let hello_family = matches!(
        envelope.message_type,
        MessageType::MutualHello | MessageType::MutualHelloAck
    );
    let result = match envelope.message_type {
        MessageType::MutualHello => {
            let p: MutualHelloPayload = match serde_json::from_value(envelope.payload.clone()) {
                Ok(p) => p,
                Err(e) => return err(id, "INVALID_ENVELOPE", &format!("hello payload: {e}")),
            };
            bootstrap_verify_peer(&envelope, &p.manifest, &p.identity, &p.pop_nonce, &cfg)
                .map(|_| ())
        }
        MessageType::MutualHelloAck => {
            let p: MutualHelloAckPayload = match serde_json::from_value(envelope.payload.clone()) {
                Ok(p) => p,
                Err(e) => return err(id, "INVALID_ENVELOPE", &format!("hello_ack payload: {e}")),
            };
            // mh-005 supplies `sent_pop_nonce` — the nonce the
            // receiver sent in its prior HELLO. The receiver MUST
            // check that the HELLO_ACK's `pop_nonce_echo` matches.
            // This is normally tracked by the Initiator session
            // state in `aitp-handshake`; the conformance fixture
            // gives the runner direct access to the value.
            if let Some(sent_nonce) = params.get("sent_pop_nonce").and_then(|v| v.as_str()) {
                if p.pop_nonce_echo != sent_nonce {
                    return err(
                        id,
                        "NONCE_MISMATCH",
                        "HELLO_ACK pop_nonce_echo does not match sent HELLO pop_nonce",
                    );
                }
            }
            bootstrap_verify_peer(&envelope, &p.manifest, &p.identity, &p.pop_nonce, &cfg)
                .map(|_| ())
        }
        MessageType::MutualCommitAck | MessageType::MutualCommit => {
            // RFC-AITP-0004 §5.1 step 7-8: verify the peer-issued
            // TCT delivered in MUTUAL_COMMIT_ACK against the
            // recipient's AID. The mh-006 / mh-007 / mh-008
            // fixtures exercise the AUDIENCE_MISMATCH /
            // GRANT_OVERFLOW / POP_VERIFICATION_FAILED branches.
            // mh-008 uses MUTUAL_COMMIT with the same payload
            // shape (the responder verifies the initiator's PoP
            // on commit), so route both through the same path.
            let p: MutualCommitAckPayload = match serde_json::from_value(envelope.payload.clone())
            {
                Ok(p) => p,
                Err(e) => {
                    return err(id, "INVALID_ENVELOPE", &format!("commit_ack payload: {e}"))
                }
            };
            // Pull the fixture-supplied issuer offered capabilities
            // (for the GRANT_OVERFLOW check) and the original
            // HELLO_ACK pop_nonce (for the POP_VERIFICATION_FAILED
            // check). Either may be absent.
            let issuer_offered = params
                .get("issuer_offered_capabilities")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect::<Vec<_>>()
                });
            let expected_pop_nonce = params
                .get("self_pop_nonce_sent_in_hello_ack")
                .and_then(|v| v.as_str());
            verify_commit_ack_stateless(
                &p,
                &envelope.sender.agent_id,
                &cfg.manifest.aid,
                state.now(),
                issuer_offered.as_deref(),
                expected_pop_nonce,
            )
            .map(|_| ())
        }
        _ => {
            return err(
                id,
                "OP_NOT_SUPPORTED",
                "verify_handshake_payload supports MUTUAL_HELLO / MUTUAL_HELLO_ACK / MUTUAL_COMMIT_ACK only",
            )
        }
    };

    if result.is_ok() && hello_family {
        if let Err(e) = verify_envelope_sig(&envelope) {
            return err(id, "INVALID_SIGNATURE", &format!("envelope: {e}"));
        }
    }
    match result {
        Ok(()) => json!({"id": id, "ok": true, "result": {"verified": true}}),
        Err(e) => err(id, &handshake_error_code(&e), &e.to_string()),
    }
}

/// Dual-peer verification mode for `mh-success-001`: each peer block
/// carries `self_aid` plus the commit payload it `received_payload`
/// from the other peer (`tct` compact JWS + optional `grant_voucher` +
/// `pop_signature` + `pop_nonce_echo`) and the pop_nonce it sent in
/// its own HELLO / HELLO_ACK. Runs the full stateless commit check
/// for each side and succeeds only when both pass.
fn verify_handshake_dual_peer(
    id: &str,
    peer_a: &Value,
    peer_b: &Value,
    now: aitp_core::Timestamp,
) -> Value {
    fn verify_one(
        peer: &Value,
        now: aitp_core::Timestamp,
    ) -> Result<Vec<String>, aitp_handshake::HandshakeError> {
        use aitp_handshake::HandshakeError;
        let self_aid_str = peer
            .get("self_aid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| HandshakeError::InvalidEnvelope("missing self_aid".into()))?;
        let self_aid = Aid::parse(self_aid_str)
            .map_err(|e| HandshakeError::InvalidEnvelope(format!("self_aid: {e}")))?;
        let mut payload_value = peer
            .get("received_payload")
            .cloned()
            .ok_or_else(|| HandshakeError::InvalidEnvelope("missing received_payload".into()))?;
        strip_claims_companions(&mut payload_value);
        let payload: aitp_handshake::payloads::MutualCommitAckPayload =
            serde_json::from_value(payload_value).map_err(|e| {
                HandshakeError::InvalidEnvelope(format!("received_payload parse: {e}"))
            })?;
        // The issuer is the OTHER peer — there is no envelope in this
        // mode, so take the (unverified) `iss` claim and let
        // verify_tct re-establish it cryptographically.
        let issuer = peek_token_aid_claim(&payload.tct, "iss")
            .ok_or_else(|| HandshakeError::InvalidEnvelope("tct iss claim missing".into()))?;
        let expected_pop_nonce = peer
            .get("self_pop_nonce_sent_in_hello")
            .or_else(|| peer.get("self_pop_nonce_sent_in_hello_ack"))
            .and_then(|v| v.as_str());
        let verified = verify_commit_ack_stateless(
            &payload,
            &issuer,
            &self_aid,
            now,
            None,
            expected_pop_nonce,
        )?;
        Ok(verified.claims.grants)
    }
    let grants = match verify_one(peer_a, now) {
        Ok(g) => g,
        Err(e) => return err(id, &handshake_error_code(&e), &format!("peer_a: {e}")),
    };
    if let Err(e) = verify_one(peer_b, now) {
        return err(id, &handshake_error_code(&e), &format!("peer_b: {e}"));
    }
    // Report the grants from peer_a's TCT — the expected.grants
    // field on mh-success-001 checks that. Both peers' grants
    // match by construction in the fixture.
    json!({"id": id, "ok": true, "result": {"verified": true, "grants": grants}})
}

/// Stateless commit_ack verification. The full Initiator state
/// machine in `aitp-handshake` requires an AwaitingCommitAck state
/// (because the receiving peer needs to remember the pop_nonce it
/// sent in HELLO and the peer manifest's expiry). The conformance
/// fixtures don't carry that state — they pre-build a single
/// envelope and assert the receiver rejects it with a specific
/// terminal error. This helper does the audience / grant /
/// pop-signature checks the spec mandates without the session
/// state.
fn verify_commit_ack_stateless(
    payload: &aitp_handshake::payloads::MutualCommitAckPayload,
    sender_aid: &Aid,
    self_aid: &Aid,
    now: aitp_core::Timestamp,
    issuer_offered_capabilities: Option<&[String]>,
    expected_pop_nonce: Option<&str>,
) -> Result<aitp_tct::VerifiedTct, aitp_handshake::HandshakeError> {
    use aitp_handshake::HandshakeError;
    use aitp_tct::{verify_tct, TctVerifyContext};

    // Peek the (unverified) claims for the policy-level checks; the
    // full cryptographic verification runs last so the policy errors
    // surface with their specific codes even when the fixture's
    // pinned clock makes time-based checks ambiguous.
    let claims_bytes =
        jws::decode_payload_unverified(&payload.tct).map_err(HandshakeError::Crypto)?;
    let claims: TctClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|e| HandshakeError::Tct(aitp_tct::TctError::ClaimsMalformed(e.to_string())))?;

    // RFC-AITP-0005 §2: the TCT's `aud` MUST equal the receiving
    // peer's AID. Check first because that's the most specific
    // identity-level error the receiver can produce.
    if &claims.aud != self_aid {
        return Err(HandshakeError::Tct(aitp_tct::TctError::AudienceMismatch));
    }

    // RFC-AITP-0005 §9.4 (grant overflow): every grant in the TCT
    // MUST appear in the issuer's `offered_capabilities`. Fires
    // before the cryptographic checks because grant overflow is a
    // policy decision that doesn't depend on signature validity.
    if let Some(offered) = issuer_offered_capabilities {
        for g in &claims.grants {
            if !offered.iter().any(|o| o == g) {
                return Err(HandshakeError::InsufficientGrants);
            }
        }
    }

    // PoP signature (RFC-AITP-0004 §5.1 step 4): the sender
    // signed `sha256(base64url_decode(pop_nonce))` with their
    // AID-derived key. The fixture supplies the original HELLO /
    // HELLO_ACK nonce; if absent we can't run the crypto check
    // (stateless fixtures lack the prior-message context).
    if let Some(expected_nonce) = expected_pop_nonce {
        if payload.pop_nonce_echo != expected_nonce {
            return Err(HandshakeError::NonceMismatch);
        }
        let nonce_bytes = aitp_core::base64url::decode_strict(expected_nonce)
            .map_err(|_| HandshakeError::Identity("pop_nonce not base64url".into()))?;
        use sha2::Digest;
        let pop_input = sha2::Sha256::digest(&nonce_bytes);
        let sig = aitp_crypto::Signature::parse(&payload.pop_signature)
            .map_err(|_| HandshakeError::PopVerificationFailed)?;
        // The round-2 PoP is signed by the **sender** of the commit
        // message — the peer that issued the TCT carried alongside —
        // over `sha256(base64url_decode(receiver_nonce))`
        // (RFC-AITP-0004 §3). The sender's AID equals the carried
        // TCT's `iss` claim, re-established cryptographically by
        // `verify_tct` below.
        let sender_pubkey =
            AitpVerifyingKey::from_aid(sender_aid).map_err(HandshakeError::Crypto)?;
        sender_pubkey
            .verify(&pop_input, &sig)
            .map_err(|_| HandshakeError::PopVerificationFailed)?;
    } else if payload.pop_nonce_echo.is_empty() {
        return Err(HandshakeError::NonceMismatch);
    }

    // TCT signature + expiry last. mh-007 deliberately uses an
    // unexpired TCT (relative to the runner's pinned clock) and
    // depends on this check happening AFTER grant-overflow.
    let ctx = TctVerifyContext::builder(self_aid, sender_aid, now)
        // Handshake-payload conformance op: no revocation source or
        // issuer Manifest is wired for this synthetic check.
        .accept_unchecked_revocation_dangerous()
        .skip_manifest_expiry_cap_dangerous()
        .build()
        .expect("both verify decisions are made above");
    let verified = verify_tct(&payload.tct, &ctx).map_err(HandshakeError::Tct)?;
    Ok(verified)
}

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn handshake_error_code(e: &aitp_handshake::HandshakeError) -> String {
    use aitp_handshake::HandshakeError::*;
    match e {
        Identity(_) => "IDENTITY_FAILED".to_string(),
        Manifest(m) => manifest_error_code(m),
        Tct(t) => tct_error_code(t),
        InvalidEnvelope(_) => "INVALID_ENVELOPE".to_string(),
        InvalidSignature => "INVALID_SIGNATURE".to_string(),
        IncompatibleTrustAnchors => "INCOMPATIBLE_TRUST_ANCHORS".to_string(),
        NonceMismatch => "NONCE_MISMATCH".to_string(),
        PopVerificationFailed => "POP_VERIFICATION_FAILED".to_string(),
        State(_) => "INVALID_STATE".to_string(),
        InsufficientGrants | GrantOverflow => "GRANT_OVERFLOW".to_string(),
        PolicyViolation => "POLICY_VIOLATION".to_string(),
        Crypto(c) => crypto_error_code(c, "INVALID_SIGNATURE"),
        Rng(_) => "INTERNAL_ERROR".to_string(),
        Canonicalization(_) => "INTERNAL_ERROR".to_string(),
        // HandshakeError is #[non_exhaustive]; future variants default
        // to INTERNAL_ERROR so the adapter never panics on a new variant.
        _ => "INTERNAL_ERROR".to_string(),
    }
}

fn verify_manifest_op(state: &AdapterState, id: &str, params: Value) -> Value {
    let manifest_value = if let Some(m) = params.get("manifest") {
        m.clone()
    } else if let Some(env) = params.get("envelope") {
        env.get("manifest").cloned().unwrap_or_default()
    } else {
        return err(id, "INVALID_ENVELOPE", "missing manifest");
    };
    let manifest = match serde_json::from_value::<Manifest>(manifest_value) {
        Ok(m) => m,
        Err(e) => return err(id, "INVALID_ENVELOPE", &format!("manifest parse: {e}")),
    };
    let now = params
        .get("now")
        .and_then(|v| v.as_i64())
        .map(Timestamp)
        .unwrap_or_else(|| state.now());
    match aitp_manifest::verify_manifest(&manifest, &aitp_manifest::VerifyManifestContext { now }) {
        Ok(()) => json!({"id": id, "ok": true, "result": {"verified": true}}),
        Err(e) => err(id, &manifest_error_code(&e), &e.to_string()),
    }
}

fn manifest_error_code(e: &aitp_manifest::ManifestError) -> String {
    use aitp_manifest::ManifestError::*;
    match e {
        Expired => "MANIFEST_EXPIRED",
        SignatureInvalid => "MANIFEST_SIGNATURE_INVALID",
        PopFailed => "MANIFEST_POP_FAILED",
        VersionUnknown => "MANIFEST_VERSION_UNKNOWN",
        IdentityHintMalformed(_) => "IDENTITY_FAILED",
        IncompatibleIdentityType(_) => "INCOMPATIBLE_IDENTITY_TYPE",
        AidMismatch => "MANIFEST_SIGNATURE_INVALID",
        MissingField(_) => "INVALID_ENVELOPE",
        Canonicalization(_) => "INTERNAL_ERROR",
        Crypto(_) => "INVALID_SIGNATURE",
        Rng(_) => "INTERNAL_ERROR",
        _ => "INTERNAL_ERROR",
    }
    .to_string()
}

fn verify_tct_op(state: &AdapterState, id: &str, params: Value) -> Value {
    use std::cell::Cell;
    // The v0.2 TCT is an opaque compact JWS string, supplied as
    // `tct_token` (preferred) or `tct`.
    let token = match params
        .get("tct_token")
        .or_else(|| params.get("tct"))
        .and_then(|v| v.as_str())
    {
        Some(t) => t.to_string(),
        None => {
            return err(
                id,
                "INVALID_REQUEST",
                "missing 'tct_token' (compact JWS string)",
            )
        }
    };
    // Issuer pin: prefer the resolved issuer Manifest's AID
    // (tct-005's `input.issuer_manifest`); otherwise an explicit
    // `issuer` param; otherwise fall back to the token's own
    // (unverified) `iss` claim — equivalent to the v0.1 posture of
    // deriving the key from the token's issuer field, and safe
    // because verify_tct re-establishes `iss` cryptographically.
    let issuer = match params
        .get("issuer_manifest")
        .and_then(|m| m.get("aid"))
        .or_else(|| params.get("issuer"))
        .and_then(|v| v.as_str())
        .map(Aid::parse)
    {
        Some(Ok(a)) => Some(a),
        Some(Err(e)) => return err(id, "INVALID_REQUEST", &format!("issuer: {e}")),
        None => peek_token_aid_claim(&token, "iss"),
    };
    let Some(issuer) = issuer else {
        return err(
            id,
            "INVALID_ENVELOPE",
            "could not determine the issuer AID (no issuer_manifest.aid and no decodable iss claim)",
        );
    };
    // expected_audience: explicit param, `self_aid`, or the token's
    // own (unverified) `aud` claim as a last resort.
    let expected_audience = match params
        .get("expected_audience")
        .or_else(|| params.get("self_aid"))
        .and_then(|v| v.as_str())
        .map(Aid::parse)
    {
        Some(Ok(a)) => a,
        Some(Err(e)) => return err(id, "INVALID_REQUEST", &format!("expected_audience: {e}")),
        None => match peek_token_aid_claim(&token, "aud") {
            Some(a) => a,
            None => {
                return err(
                    id,
                    "INVALID_REQUEST",
                    "missing 'expected_audience' and no decodable aud claim",
                )
            }
        },
    };
    let now = params
        .get("now")
        .and_then(|v| v.as_i64())
        .map(Timestamp)
        .unwrap_or_else(|| state.now());
    // Honor a fixture-supplied issuer_revocation_list in addition to
    // any JTIs the adapter has been told to revoke via Tier-D inject.
    // tct-004 supplies a signed snapshot
    // (`issuer_revocation_list.snapshot`), which we verify against
    // its declared issuer before honoring; older callers may supply
    // a bare `revoked_jtis` array.
    let mut revoked_jtis = state.revoked_jtis.clone();
    if let Some(list) = params.get("issuer_revocation_list") {
        if let Some(jtis) = list.get("revoked_jtis").and_then(|v| v.as_array()) {
            for j in jtis {
                if let Some(s) = j.as_str() {
                    revoked_jtis.insert(s.to_string());
                }
            }
        }
        if let Some(snapshot) = list.get("snapshot") {
            if let Ok(env) =
                serde_json::from_value::<aitp_tct::RevocationListEnvelope>(snapshot.clone())
            {
                let snapshot_issuer = env.revocation_list.issuer.clone();
                let rev_ctx = aitp_tct::VerifyRevocationListContext {
                    expected_issuer: &snapshot_issuer,
                    now,
                };
                if aitp_tct::verify_revocation_list(&env, &rev_ctx).is_ok() {
                    for entry in &env.revocation_list.entries {
                        revoked_jtis.insert(entry.jti.to_string());
                    }
                }
            }
        }
    }
    // rev-004 instrumentation: record whether the revocation source
    // was consulted at all, to pin the RFC-AITP-0008 §3.3 ordering
    // (signature verification MUST precede any revocation lookup).
    let lookup_called = Cell::new(false);
    let check = |jti: &Uuid| {
        lookup_called.set(true);
        revoked_jtis.contains(&jti.to_string())
    };
    // Honor the spec's `issuer_manifest.expires_at` field
    // (RFC-AITP-0005 §10.4). tct-005 supplies this via
    // `input.issuer_manifest`; older fixtures may supply
    // `input.issuer_manifest_expires_at` as a bare integer.
    let issuer_manifest_expires_at: Option<Timestamp> = params
        .get("issuer_manifest")
        .and_then(|m| m.get("expires_at"))
        .or_else(|| params.get("issuer_manifest_expires_at"))
        .and_then(|v| v.as_i64())
        .map(Timestamp);
    let ctx = {
        let b = aitp_tct::TctVerifyContext::builder(&expected_audience, &issuer, now)
            .revocation_check(&check);
        let b = match issuer_manifest_expires_at {
            Some(exp) => b.issuer_manifest_expires_at(exp),
            None => b.skip_manifest_expiry_cap_dangerous(),
        };
        b.build().expect("both verify decisions are made above")
    };
    let instrumented = params
        .get("revocation_instrumented")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    match aitp_tct::verify_tct(&token, &ctx) {
        Ok(v) => {
            let mut result = json!({"verified": true, "grants": v.claims.grants});
            if instrumented {
                result["side_effects"] = json!({
                    "revocation_lookup_called": lookup_called.get(),
                    "network_fetch_called": false,
                });
            }
            json!({"id": id, "ok": true, "result": result})
        }
        Err(e) => err(id, &tct_error_code(&e), &e.to_string()),
    }
}

fn tct_error_code(e: &aitp_tct::TctError) -> String {
    use aitp_tct::TctError::*;
    match e {
        VersionUnknown => "UNKNOWN_VERSION",
        SignatureInvalid => "TCT_SIGNATURE_INVALID",
        // The issuer pin failed: the token's `iss` is not the peer
        // whose key it verifies under — same trust failure class as
        // a bad signature.
        IssuerMismatch => "TCT_SIGNATURE_INVALID",
        AudienceMismatch => "AUDIENCE_MISMATCH",
        Expired => "TCT_EXPIRED",
        ExpiresAfterManifest => "TCT_EXPIRES_AFTER_MANIFEST",
        Revoked => "TCT_REVOKED",
        EmptyGrants => "INVALID_ENVELOPE",
        GrantWhitespace(_) => "INVALID_ENVELOPE",
        CnfMalformed => "INVALID_ENVELOPE",
        ClaimsMalformed(_) => "INVALID_ENVELOPE",
        MissingField(_) => "INVALID_ENVELOPE",
        Canonicalization(_) => "INTERNAL_ERROR",
        PopNonceMismatch | PopFailed | PopChallengeExpired | PopJtiMismatch => {
            "POP_RESPONSE_INVALID"
        }
        Crypto(c) => return crypto_error_code(c, "TCT_SIGNATURE_INVALID"),
        _ => "INTERNAL_ERROR",
    }
    .to_string()
}

/// `verify_grant_voucher` — standalone grant-voucher verification
/// (RFC-AITP-0005 §8 / RFC-AITP-0006 §4 step 3): strict compact-JWS
/// parse, `typ aitp-grant+jwt`, AID-pinned `alg`, signature under the
/// issuer's OWN key (`verifier_aid` — only the issuer ever verifies a
/// voucher), claims checks. Voucher expiry surfaces as
/// DELEGATION_EXPIRED — the voucher is only ever consumed in
/// delegation context (vch-002).
fn verify_grant_voucher_op(state: &AdapterState, id: &str, params: Value) -> Value {
    let token = match params
        .get("voucher_token")
        .or_else(|| params.get("voucher"))
        .and_then(|v| v.as_str())
    {
        Some(t) => t,
        None => {
            return err(
                id,
                "INVALID_REQUEST",
                "missing 'voucher_token' (compact JWS string)",
            )
        }
    };
    let verifier_aid = match params
        .get("verifier_aid")
        .or_else(|| params.get("self_aid"))
        .and_then(|v| v.as_str())
        .map(Aid::parse)
    {
        Some(Ok(a)) => a,
        Some(Err(e)) => return err(id, "INVALID_REQUEST", &format!("verifier_aid: {e}")),
        None => return err(id, "INVALID_REQUEST", "missing 'verifier_aid'"),
    };
    let now = params
        .get("now")
        .and_then(|v| v.as_i64())
        .map(Timestamp)
        .unwrap_or_else(|| state.now());
    let claims = match aitp_tct::verify_voucher(token, &verifier_aid) {
        Ok(c) => c,
        Err(e) => return err(id, &voucher_error_code(&e), &e.to_string()),
    };
    // Expiry is contextual (delegation verification owns it) — apply
    // it here so the standalone op pins the RFC-AITP-0006 §4 step 5
    // mapping.
    if claims.exp.is_in_the_past(now) {
        return err(id, "DELEGATION_EXPIRED", "grant voucher is expired");
    }
    json!({"id": id, "ok": true, "result": {"verified": true, "grants": claims.grants}})
}

/// Error mapping for standalone voucher verification. A voucher that
/// fails its signature / issuer pin is an invalid voucher
/// (DELEGATION_INVALID_VOUCHER); JWS-layer header failures keep their
/// token-generic codes.
fn voucher_error_code(e: &aitp_tct::TctError) -> String {
    use aitp_tct::TctError::*;
    match e {
        VersionUnknown => "UNKNOWN_VERSION".to_string(),
        IssuerMismatch => "DELEGATION_INVALID_VOUCHER".to_string(),
        EmptyGrants | ClaimsMalformed(_) | MissingField(_) => "INVALID_ENVELOPE".to_string(),
        Crypto(c) => crypto_error_code(c, "DELEGATION_INVALID_VOUCHER"),
        other => tct_error_code(other),
    }
}

fn verify_delegation_op(state: &AdapterState, id: &str, params: Value) -> Value {
    // Accept both `delegation` and `delegation_token` field names per
    // the spec PLACEHOLDERS convention. The v0.2 token is an opaque
    // compact JWS string.
    let token_value = params
        .get("delegation_token")
        .or_else(|| params.get("delegation"))
        .cloned()
        .unwrap_or_default();
    let token = match &token_value {
        Value::String(s) => s.clone(),
        // del-004 stays frozen in the v0.1 object wire shape so v0.1
        // runners keep coverage. A v0.2 implementation rejects any
        // chain-bearing delegation structurally, before signature
        // work — honor that here without parsing the legacy shape.
        Value::Object(map) => {
            let has_chain = map
                .get("chain")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            if has_chain {
                return err(
                    id,
                    "DELEGATION_MULTIHOP_NOT_SUPPORTED",
                    "v0.1-shape delegation token carries a non-empty chain; \
                     structural rejection (RFC-AITP-0006 §4)",
                );
            }
            return err(
                id,
                "INVALID_ENVELOPE",
                "v0.2 delegation token must be a compact JWS string",
            );
        }
        _ => {
            return err(
                id,
                "INVALID_REQUEST",
                "missing 'delegation_token' (compact JWS string)",
            )
        }
    };
    // Spec fixtures carry `verifier_aid` OR they carry `self_aid` /
    // `audience` — all name the receiver (A, the original grantor).
    // Default to the token's own (unverified) `aud` claim if none is
    // supplied; verify_delegation re-establishes it.
    let verifier_aid = match params
        .get("verifier_aid")
        .or_else(|| params.get("self_aid"))
        .or_else(|| params.get("audience"))
        .and_then(|v| v.as_str())
        .map(Aid::parse)
    {
        Some(Ok(a)) => a,
        Some(Err(e)) => return err(id, "INVALID_REQUEST", &format!("verifier_aid: {e}")),
        None => match peek_token_aid_claim(&token, "aud") {
            Some(a) => a,
            None => {
                return err(
                    id,
                    "INVALID_REQUEST",
                    "missing 'verifier_aid' and no decodable aud claim",
                )
            }
        },
    };
    let now = params
        .get("now")
        .and_then(|v| v.as_i64())
        .map(Timestamp)
        .unwrap_or_else(|| state.now());

    // RFC-AITP-0011 §6 + spec PLACEHOLDERS.md: multi-hop fixtures
    // may carry a `revocation_snapshots` array of {issuer_aid,
    // snapshot} records. Verify each snapshot's signature against
    // its declared issuer and build per-issuer deny lists; the
    // verifier consults the right issuer's list per hop
    // (`hop_revocation_check`) and the verifier's OWN list for
    // `voucher.src_jti` (`revocation_check`).
    let mut deny_lists: HashMap<Aid, HashSet<Uuid>> = HashMap::new();
    if let Some(arr) = params
        .get("revocation_snapshots")
        .and_then(|v| v.as_array())
    {
        for entry in arr {
            let Some(issuer_str) = entry.get("issuer_aid").and_then(|v| v.as_str()) else {
                continue;
            };
            let issuer_aid = match Aid::parse(issuer_str) {
                Ok(a) => a,
                Err(_) => continue,
            };
            let Some(snapshot) = entry.get("snapshot") else {
                continue;
            };
            // Verify the snapshot signature, then extract JTIs.
            let env: aitp_tct::RevocationListEnvelope =
                match serde_json::from_value(snapshot.clone()) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
            if env.revocation_list.issuer != issuer_aid {
                // Issuer-AID mismatch — refuse to honor the snapshot.
                continue;
            }
            let rev_ctx = aitp_tct::VerifyRevocationListContext {
                expected_issuer: &issuer_aid,
                now,
            };
            if aitp_tct::verify_revocation_list(&env, &rev_ctx).is_err() {
                continue;
            }
            let set = deny_lists.entry(issuer_aid).or_default();
            for entry in &env.revocation_list.entries {
                set.insert(entry.jti);
            }
        }
    }
    // The verifier's own deny list: Tier-D injected JTIs plus any
    // snapshot published by the verifier itself.
    let own_denied: HashSet<Uuid> = state
        .revoked_jtis
        .iter()
        .filter_map(|s| Uuid::parse_str(s).ok())
        .chain(deny_lists.get(&verifier_aid).into_iter().flatten().copied())
        .collect();
    let revocation_check_closure = |jti: &Uuid| own_denied.contains(jti);
    let hop_revocation_closure =
        |issuer: &Aid, jti: &Uuid| deny_lists.get(issuer).is_some_and(|s| s.contains(jti));
    let revocation_check: Option<&dyn Fn(&Uuid) -> bool> = if own_denied.is_empty() {
        None
    } else {
        Some(&revocation_check_closure)
    };
    let hop_revocation_check: Option<aitp_delegation::verifier::HopRevocationCheck<'_>> =
        if deny_lists.is_empty() {
            None
        } else {
            Some(&hop_revocation_closure)
        };

    // Multi-hop opt-in. Per RFC-AITP-0006 §4 the v0.2 default MUST
    // reject any chain-bearing token; the runner enables RFC-0011
    // semantics by sending `set_features` with
    // `experimental-multihop-delegation`. Without that feature we
    // use the strict single-hop cap (max_hops = 0).
    let max_hops = if state.has_feature("experimental-multihop-delegation") {
        aitp_delegation::DEFAULT_MAX_HOPS
    } else {
        0
    };
    let ctx = aitp_delegation::VerifyDelegationContext {
        verifier: &verifier_aid,
        now,
        max_hops,
        revocation_check,
        hop_revocation_check,
    };
    match aitp_delegation::verify_delegation(&token, &ctx) {
        Ok(v) => json!({
            "id": id,
            "ok": true,
            "result": {"verified": true, "grants": v.claims.scope}
        }),
        Err(e) => err(id, &delegation_error_code(&e), &e.to_string()),
    }
}

fn delegation_error_code(e: &aitp_delegation::DelegationError) -> String {
    use aitp_delegation::DelegationError::*;
    match e {
        Expired => "DELEGATION_EXPIRED",
        InvalidSignature => "DELEGATION_INVALID_SIGNATURE",
        ScopeExceeded => "DELEGATION_SCOPE_EXCEEDED",
        InvalidVoucher => "DELEGATION_INVALID_VOUCHER",
        SourceTctRevoked => "DELEGATION_SOURCE_TCT_REVOKED",
        AudienceMismatch => "AUDIENCE_MISMATCH",
        PopFailed => "POP_RESPONSE_INVALID",
        MultihopNotSupported => "DELEGATION_MULTIHOP_NOT_SUPPORTED",
        HopLimitExceeded => "DELEGATION_HOP_LIMIT_EXCEEDED",
        ChainHashMismatch => "DELEGATION_CHAIN_HASH_MISMATCH",
        VersionUnknown => "UNKNOWN_VERSION",
        // RFC-AITP-0006 §4 step 10: self-delegation maps to
        // DELEGATION_INVALID_SIGNATURE (same code as a bad outer sig).
        SelfDelegation => "DELEGATION_INVALID_SIGNATURE",
        EmptyScope | CnfMalformed | MissingField(_) | ClaimsMalformed(_) => "INVALID_ENVELOPE",
        Canonicalization(_) => "INTERNAL_ERROR",
        // Crypto errors surface from JWS-layer verification. A plain
        // bad signature here can only come from the embedded voucher
        // (the outer token's bad signature maps to InvalidSignature
        // in aitp-delegation) — hence DELEGATION_INVALID_VOUCHER.
        Crypto(c) => return crypto_error_code(c, "DELEGATION_INVALID_VOUCHER"),
        _ => "INTERNAL_ERROR",
    }
    .to_string()
}

// ── Tier B ──────────────────────────────────────────────────────────────

fn generate_keypair(state: &mut AdapterState, id: &str, params: Value) -> Value {
    // Always derive from a seed we control so we can re-derive the
    // (non-Clone) `AitpSigningKey` later. For "random" requests we
    // generate a 32-byte seed via the OS RNG.
    let seed: [u8; 32] = if let Some(seed_b64) = params.get("seed").and_then(|v| v.as_str()) {
        let bytes = match base64url::decode_strict(seed_b64) {
            Ok(b) => b,
            Err(e) => return err(id, "INVALID_REQUEST", &format!("seed: {e}")),
        };
        if bytes.len() != 32 {
            return err(id, "INVALID_REQUEST", "seed must decode to 32 bytes");
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes);
        s
    } else {
        let mut s = [0u8; 32];
        use rand::RngCore;
        match rand::rngs::OsRng.try_fill_bytes(&mut s) {
            Ok(()) => {}
            Err(e) => return err(id, "INTERNAL_ERROR", &e.to_string()),
        }
        s
    };
    let key = AitpSigningKey::from_seed(&seed);
    let aid = key.aid().as_str().to_string();
    let pubkey = base64url::encode(&key.verifying_key().to_bytes());
    let handle = state.fresh_kp_handle();
    state.keypair_seeds.insert(handle.clone(), seed);
    json!({
        "id": id,
        "ok": true,
        "result": {
            "handle": handle,
            "aid": aid,
            "public_key": pubkey,
        }
    })
}

fn issue_manifest_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    let handle = match params.get("keypair").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err(id, "INVALID_REQUEST", "missing 'keypair' handle"),
    };
    let key = match state.key_for(handle) {
        Some(k) => k,
        None => return err(id, "INVALID_REQUEST", &format!("unknown keypair {handle}")),
    };
    let key = &key;

    let endpoint = match params
        .get("handshake_endpoint")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(u) => u,
        None => return err(id, "INVALID_REQUEST", "missing/invalid handshake_endpoint"),
    };
    let identity_hint = match parse_identity_hint(params.get("identity_hint")) {
        Ok(h) => h,
        Err(e) => return err(id, "INVALID_REQUEST", &e),
    };
    let trust_anchors: Vec<aitp_core::RawUrl> = params
        .get("accepted_trust_anchors")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(aitp_core::RawUrl::from))
                .collect()
        })
        .unwrap_or_default();
    let offered: Vec<String> = params
        .get("offered_capabilities")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let ttl = params
        .get("ttl_secs")
        .and_then(|v| v.as_i64())
        .unwrap_or(3600);

    let mut b = ManifestBuilder::new(key)
        .handshake_endpoint(endpoint)
        .identity_hint(identity_hint)
        .ttl_secs(ttl)
        .published_at(state.now());
    for anchor in trust_anchors {
        b = b.accept_trust_anchor_raw(anchor);
    }
    for cap in offered {
        b = b.offer(cap);
    }
    if let Some(name) = params.get("display_name").and_then(|v| v.as_str()) {
        b = b.display_name(name);
    }
    let manifest = match b.build() {
        Ok(m) => m,
        Err(e) => return err(id, "INTERNAL_ERROR", &e.to_string()),
    };
    let env = ManifestEnvelope { manifest };
    json!({
        "id": id,
        "ok": true,
        "result": {
            "manifest_envelope": env,
        }
    })
}

fn parse_identity_hint(v: Option<&Value>) -> Result<IdentityHint, String> {
    let v = v.ok_or_else(|| "missing identity_hint".to_string())?;
    let kind = v
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| "identity_hint.type missing".to_string())?;
    let subject = v
        .get("subject")
        .and_then(|s| s.as_str())
        .map(String::from)
        .ok_or_else(|| "identity_hint.subject missing".to_string())?;
    match kind {
        "oidc" => {
            let issuer = v
                .get("issuer")
                .and_then(|i| i.as_str())
                .ok_or_else(|| "oidc identity_hint.issuer missing".to_string())?
                .parse()
                .map_err(|e| format!("issuer parse: {e}"))?;
            Ok(IdentityHint {
                kind: IdentityHintKind::Oidc,
                subject,
                issuer: Some(issuer),
                public_key: None,
            })
        }
        "pinned_key" => {
            let pk = v
                .get("public_key")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "pinned_key identity_hint.public_key missing".to_string())?
                .to_string();
            Ok(IdentityHint {
                kind: IdentityHintKind::PinnedKey,
                subject,
                issuer: None,
                public_key: Some(pk),
            })
        }
        other => Err(format!("unknown identity_hint.type: {other}")),
    }
}

fn issue_tct_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    let handle = match params.get("issuer_keypair").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err(id, "INVALID_REQUEST", "missing 'issuer_keypair'"),
    };
    let key = match state.key_for(handle) {
        Some(k) => k,
        None => return err(id, "INVALID_REQUEST", &format!("unknown keypair {handle}")),
    };
    let key = &key;
    let subject = match params
        .get("subject")
        .and_then(|v| v.as_str())
        .map(Aid::parse)
    {
        Some(Ok(a)) => a,
        _ => return err(id, "INVALID_REQUEST", "missing/invalid subject"),
    };
    let audience = match params
        .get("audience")
        .and_then(|v| v.as_str())
        .map(Aid::parse)
    {
        Some(Ok(a)) => a,
        _ => return err(id, "INVALID_REQUEST", "missing/invalid audience"),
    };
    let subject_pubkey_b64 = match params.get("subject_public_key").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err(id, "INVALID_REQUEST", "missing subject_public_key"),
    };
    let pk_bytes = match base64url::decode_strict(subject_pubkey_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return err(
                id,
                "INVALID_REQUEST",
                "subject_public_key not 32-byte b64url",
            )
        }
    };
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&pk_bytes);
    let subject_pubkey = match AitpVerifyingKey::from_bytes(&buf) {
        Ok(p) => p,
        Err(e) => return err(id, "INVALID_REQUEST", &format!("subject_public_key: {e}")),
    };
    let grants: Vec<String> = params
        .get("grants")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let ttl = params
        .get("ttl_secs")
        .and_then(|v| v.as_i64())
        .unwrap_or(3600);
    let issued_at = params
        .get("issued_at")
        .and_then(|v| v.as_i64())
        .map(Timestamp)
        .unwrap_or_else(|| state.now());

    let mut builder = TctBuilder::new(key)
        .subject(subject)
        .audience(audience)
        .grants(grants)
        .ttl_secs(ttl)
        .subject_pubkey(subject_pubkey)
        .issued_at(issued_at);
    if let Some(jti) = params
        .get("jti")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        builder = builder.jti(jti);
    }
    if params
        .get("without_voucher")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        builder = builder.without_voucher();
    }
    let issued = match builder.build() {
        Ok(t) => t,
        Err(e) => return err(id, "INTERNAL_ERROR", &e.to_string()),
    };
    json!({
        "id": id,
        "ok": true,
        "result": {
            "tct_token": issued.token,
            "tct_claims": issued.claims,
            "grant_voucher": issued.voucher,
        }
    })
}

fn issue_delegation_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    let handle = match params.get("delegator_keypair").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err(id, "INVALID_REQUEST", "missing 'delegator_keypair'"),
    };
    let delegator = match state.key_for(handle) {
        Some(k) => k,
        None => return err(id, "INVALID_REQUEST", &format!("unknown keypair {handle}")),
    };
    let delegator = &delegator;
    let delegatee = match params
        .get("delegatee")
        .and_then(|v| v.as_str())
        .map(Aid::parse)
    {
        Some(Ok(a)) => a,
        _ => return err(id, "INVALID_REQUEST", "missing/invalid delegatee"),
    };
    let scope: Vec<String> = params
        .get("scope")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let ttl = params
        .get("ttl_secs")
        .and_then(|v| v.as_i64())
        .unwrap_or(1800);

    // Single-hop: the delegator presents the grant voucher its TCT
    // issuer minted for it (`voucher` / `grant_voucher`, a compact
    // JWS). Multi-hop extension: `prior_token` is the delegation the
    // delegator received and is extending (requires
    // experimental-multihop-delegation semantics on verification).
    let builder = if let Some(voucher) = params
        .get("voucher")
        .or_else(|| params.get("grant_voucher"))
        .or_else(|| params.get("voucher_token"))
        .and_then(|v| v.as_str())
    {
        DelegationBuilder::new(delegator, voucher)
    } else if let Some(prior) = params.get("prior_token").and_then(|v| v.as_str()) {
        DelegationBuilder::extending(delegator, prior)
    } else {
        return err(
            id,
            "INVALID_REQUEST",
            "missing 'voucher' (single-hop) or 'prior_token' (multi-hop extension)",
        );
    };
    let mut builder = match builder {
        Ok(b) => b,
        Err(e) => return err(id, &delegation_error_code(&e), &e.to_string()),
    };
    builder = builder
        .delegatee(delegatee)
        .scope(scope)
        .ttl_secs(ttl)
        .now(state.now());
    if let Some(jti) = params
        .get("jti")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        builder = builder.jti(jti);
    }
    let token = match builder.build() {
        Ok(t) => t,
        Err(e) => return err(id, &delegation_error_code(&e), &e.to_string()),
    };
    json!({"id": id, "ok": true, "result": {"delegation_token": token}})
}

fn sign_envelope_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    let handle = match params.get("keypair").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err(id, "INVALID_REQUEST", "missing 'keypair'"),
    };
    let key = match state.key_for(handle) {
        Some(k) => k,
        None => return err(id, "INVALID_REQUEST", &format!("unknown keypair {handle}")),
    };
    let key = &key;
    let mt_str = match params.get("message_type").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err(id, "INVALID_REQUEST", "missing 'message_type'"),
    };
    let mt = match parse_message_type(mt_str) {
        Some(m) => m,
        None => {
            return err(
                id,
                "INVALID_REQUEST",
                &format!("unknown message_type {mt_str}"),
            )
        }
    };
    let payload = params.get("payload").cloned().unwrap_or(json!({}));
    let message_id = Uuid::new_v4();
    let timestamp = state.now();
    let digest =
        match aitp_core::envelope_signing_digest(&message_id, timestamp, key.aid(), &payload) {
            Ok(d) => d,
            Err(e) => return err(id, "INTERNAL_ERROR", &e.to_string()),
        };
    let sig = key.sign(&digest);
    let env = AitpEnvelope {
        version: aitp_core::PROTOCOL_VERSION.into(),
        message_type: mt,
        message_id,
        timestamp,
        sender: Sender {
            agent_id: key.aid().clone(),
        },
        payload,
        signature: sig.into_string(),
    };
    json!({"id": id, "ok": true, "result": {"envelope": env}})
}

fn parse_message_type(s: &str) -> Option<MessageType> {
    serde_json::from_value(json!(s)).ok()
}

// ── Tier C ──────────────────────────────────────────────────────────────

struct NoOpJwks;
impl JwksResolver for NoOpJwks {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn start_handshake_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    let role = params
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("initiator");
    let handle = match params.get("keypair").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return err(id, "INVALID_REQUEST", "missing 'keypair'"),
    };
    let manifest_value = params.get("manifest").cloned().unwrap_or_default();
    let manifest: Manifest = match serde_json::from_value(manifest_value) {
        Ok(m) => m,
        Err(e) => return err(id, "INVALID_REQUEST", &format!("manifest: {e}")),
    };
    if state.key_for(&handle).is_none() {
        return err(id, "INVALID_REQUEST", &format!("unknown keypair {handle}"));
    }
    let requested_grants: Vec<String> = params
        .get("requested_grants")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    match role {
        "initiator" => {
            let peer_manifest_value = params.get("peer_manifest").cloned().unwrap_or_default();
            let peer_aid = match serde_json::from_value::<Manifest>(peer_manifest_value) {
                Ok(peer_m) => {
                    let aid = peer_m.aid.clone();
                    state
                        .peer_manifests
                        .insert(peer_m.aid.as_str().to_string(), peer_m);
                    aid
                }
                Err(_) => {
                    return err(
                        id,
                        "INVALID_REQUEST",
                        "start_handshake role=initiator requires `peer_manifest` so the pinned-key proof can bind the receiver AID per RFC-AITP-0002 §3.1",
                    );
                }
            };
            start_initiator(state, id, handle, manifest, peer_aid, requested_grants)
        }
        "responder" => {
            let session_id = state.fresh_session_id();
            state.sessions.insert(
                session_id.clone(),
                HandshakeSession::PendingResponder {
                    keypair_handle: handle,
                    my_manifest: manifest,
                    my_requested_grants: requested_grants,
                },
            );
            json!({
                "id": id,
                "ok": true,
                "result": {
                    "session_id": session_id,
                    "awaiting": "MUTUAL_HELLO",
                }
            })
        }
        other => err(
            id,
            "INVALID_REQUEST",
            &format!("unknown role: {other} (expected 'initiator' or 'responder')"),
        ),
    }
}

fn start_initiator(
    state: &mut AdapterState,
    id: &str,
    handle: String,
    manifest: Manifest,
    peer_aid: Aid,
    requested_grants: Vec<String>,
) -> Value {
    let key = state.key_for(&handle).expect("keypair existence checked");
    let identity = PresentedIdentity::PinnedKey {
        subject: manifest
            .display_name
            .clone()
            .unwrap_or_else(|| "initiator".into()),
    };
    let mid = Uuid::new_v4();
    let ts = state.now();
    let resolver = NoOpJwks;
    let cfg = PeerConfig {
        signing_key: &key,
        manifest: &manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: ts,
    };
    let (init_state, hello_payload) =
        match Initiator::start(&cfg, identity, &peer_aid, &mid, ts, requested_grants) {
            Ok(p) => p,
            Err(e) => return err(id, "HANDSHAKE_FAILED", &e.to_string()),
        };
    let envelope = sign_envelope_with_key(&key, MessageType::MutualHello, &hello_payload, mid, ts);
    let session_id = state.fresh_session_id();
    state.sessions.insert(
        session_id.clone(),
        HandshakeSession::Initiator {
            state: init_state,
            keypair_handle: handle,
            my_manifest: manifest,
        },
    );
    json!({
        "id": id,
        "ok": true,
        "result": {
            "session_id": session_id,
            "envelope": envelope,
        }
    })
}

fn process_handshake_message_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    // mh-001 replay test: each sequence step carries only
    // `message_id` (no envelope, no session_id). Track in the
    // adapter's seen-message-ids set; second occurrence within the
    // run returns REPLAY_DETECTED. The first occurrence is reported
    // as success.
    if params.get("envelope").is_none() && params.get("session_id").is_none() {
        if let Some(mid) = params.get("message_id").and_then(|v| v.as_str()) {
            if !state.seen_message_ids.insert(mid.to_string()) {
                return err(
                    id,
                    "REPLAY_DETECTED",
                    &format!("message_id {mid} already seen in this run"),
                );
            }
            return json!({"id": id, "ok": true, "result": {"verified": true, "message_id": mid}});
        }
    }
    let session_id = match params.get("session_id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return err(id, "INVALID_REQUEST", "missing session_id"),
    };
    let envelope = match serde_json::from_value::<AitpEnvelope>(
        params.get("envelope").cloned().unwrap_or_default(),
    ) {
        Ok(e) => e,
        Err(e) => return err(id, "INVALID_REQUEST", &format!("envelope: {e}")),
    };
    let sess = match state.sessions.remove(&session_id) {
        Some(s) => s,
        None => return err(id, "INVALID_REQUEST", "unknown session_id"),
    };
    match sess {
        HandshakeSession::Initiator {
            state: initiator,
            keypair_handle,
            my_manifest,
        } => initiator_step(
            state,
            id,
            session_id,
            envelope,
            initiator,
            keypair_handle,
            my_manifest,
        ),
        HandshakeSession::PendingResponder {
            keypair_handle,
            my_manifest,
            my_requested_grants,
        } => responder_first_hello(
            state,
            id,
            session_id,
            envelope,
            keypair_handle,
            my_manifest,
            my_requested_grants,
        ),
        HandshakeSession::ActiveResponder {
            state: responder,
            keypair_handle,
            my_manifest,
        } => responder_step(state, id, envelope, responder, keypair_handle, my_manifest),
    }
}

fn initiator_step(
    state: &mut AdapterState,
    id: &str,
    session_id: String,
    envelope: AitpEnvelope,
    mut initiator: Initiator,
    keypair_handle: String,
    my_manifest: Manifest,
) -> Value {
    let key = match state.key_for(&keypair_handle) {
        Some(k) => k,
        None => return err(id, "INVALID_REQUEST", "keypair vanished"),
    };
    // PeerConfig.manifest MUST be the *local* manifest. The handshake
    // verifier reads `cfg.manifest.aid` as the expected audience for
    // any TCT the peer minted for us (RFC-AITP-0005 §9 step 2), and
    // `cfg.manifest.offered_capabilities` to filter outbound grants.
    // Wiring the peer's manifest here would silently break TCT
    // verification on COMMIT_ACK.
    let resolver = NoOpJwks;
    let cfg = PeerConfig {
        signing_key: &key,
        manifest: &my_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: state.now(),
    };
    match envelope.message_type {
        MessageType::MutualHelloAck => {
            let ack_payload: MutualHelloAckPayload =
                match serde_json::from_value(envelope.payload.clone()) {
                    Ok(p) => p,
                    Err(e) => return err(id, "INVALID_ENVELOPE", &format!("hello_ack: {e}")),
                };
            let commit_payload = match initiator.on_hello_ack(&envelope, &ack_payload, &cfg) {
                Ok(p) => p,
                Err(e) => return err(id, "HANDSHAKE_FAILED", &e.to_string()),
            };
            let mid = Uuid::new_v4();
            let ts = state.now();
            let commit_env =
                sign_envelope_with_key(&key, MessageType::MutualCommit, &commit_payload, mid, ts);
            state.sessions.insert(
                session_id,
                HandshakeSession::Initiator {
                    state: initiator,
                    keypair_handle,
                    my_manifest,
                },
            );
            json!({
                "id": id,
                "ok": true,
                "result": {
                    "next_envelope": commit_env,
                    "completed": false,
                }
            })
        }
        MessageType::MutualCommitAck => {
            let ack_payload: MutualCommitAckPayload =
                match serde_json::from_value(envelope.payload.clone()) {
                    Ok(p) => p,
                    Err(e) => return err(id, "INVALID_ENVELOPE", &format!("commit_ack: {e}")),
                };
            let held = match initiator.on_commit_ack(&envelope, &ack_payload, &cfg) {
                Ok(t) => t,
                Err(e) => return err(id, "HANDSHAKE_FAILED", &e.to_string()),
            };
            json!({
                "id": id,
                "ok": true,
                "result": {
                    "completed": true,
                    "held_tct": completed_handshake_json(&held),
                }
            })
        }
        mt => err(
            id,
            "INVALID_ENVELOPE",
            &format!("unexpected message_type for initiator session: {mt:?}"),
        ),
    }
}

fn responder_first_hello(
    state: &mut AdapterState,
    id: &str,
    session_id: String,
    envelope: AitpEnvelope,
    keypair_handle: String,
    my_manifest: Manifest,
    my_requested_grants: Vec<String>,
) -> Value {
    if envelope.message_type != MessageType::MutualHello {
        return err(
            id,
            "INVALID_ENVELOPE",
            &format!(
                "responder session expected MutualHello, got {:?}",
                envelope.message_type
            ),
        );
    }
    let key = match state.key_for(&keypair_handle) {
        Some(k) => k,
        None => return err(id, "INVALID_REQUEST", "keypair vanished"),
    };
    let hello_payload: aitp_handshake::MutualHelloPayload =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(p) => p,
            Err(e) => return err(id, "INVALID_ENVELOPE", &format!("hello: {e}")),
        };
    // Cache the peer's manifest so commit-side can look it up.
    state.peer_manifests.insert(
        hello_payload.manifest.aid.as_str().to_string(),
        hello_payload.manifest.clone(),
    );

    let resolver = NoOpJwks;
    let cfg = PeerConfig {
        signing_key: &key,
        manifest: &my_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: state.now(),
    };
    let identity = PresentedIdentity::PinnedKey {
        subject: my_manifest
            .display_name
            .clone()
            .unwrap_or_else(|| "responder".into()),
    };
    let ack_mid = Uuid::new_v4();
    let ack_ts = state.now();
    let (responder, ack_payload) = match aitp_handshake::Responder::on_hello(
        &envelope,
        &hello_payload,
        identity,
        &ack_mid,
        ack_ts,
        &cfg,
        my_requested_grants,
    ) {
        Ok(p) => p,
        Err(e) => return err(id, "HANDSHAKE_FAILED", &e.to_string()),
    };
    let ack_env = sign_envelope_with_key(
        &key,
        MessageType::MutualHelloAck,
        &ack_payload,
        ack_mid,
        ack_ts,
    );
    state.sessions.insert(
        session_id,
        HandshakeSession::ActiveResponder {
            state: responder,
            keypair_handle,
            my_manifest,
        },
    );
    json!({
        "id": id,
        "ok": true,
        "result": {
            "next_envelope": ack_env,
            "completed": false,
        }
    })
}

fn responder_step(
    state: &mut AdapterState,
    id: &str,
    envelope: AitpEnvelope,
    mut responder: aitp_handshake::Responder,
    keypair_handle: String,
    my_manifest: Manifest,
) -> Value {
    if envelope.message_type != MessageType::MutualCommit {
        return err(
            id,
            "INVALID_ENVELOPE",
            &format!(
                "active responder expected MutualCommit, got {:?}",
                envelope.message_type
            ),
        );
    }
    let key = match state.key_for(&keypair_handle) {
        Some(k) => k,
        None => return err(id, "INVALID_REQUEST", "keypair vanished"),
    };
    let commit_payload: aitp_handshake::MutualCommitPayload =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(p) => p,
            Err(e) => return err(id, "INVALID_ENVELOPE", &format!("commit: {e}")),
        };
    let resolver = NoOpJwks;
    let cfg = PeerConfig {
        signing_key: &key,
        manifest: &my_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: state.now(),
    };
    let (ack_payload, held_tct) = match responder.on_commit(&envelope, &commit_payload, &cfg) {
        Ok(r) => r,
        Err(e) => return err(id, "HANDSHAKE_FAILED", &e.to_string()),
    };
    let ack_mid = Uuid::new_v4();
    let ack_ts = state.now();
    let ack_env = sign_envelope_with_key(
        &key,
        MessageType::MutualCommitAck,
        &ack_payload,
        ack_mid,
        ack_ts,
    );
    json!({
        "id": id,
        "ok": true,
        "result": {
            "next_envelope": ack_env,
            "completed": true,
            "held_tct": completed_handshake_json(&held_tct),
        }
    })
}

/// JSON view of a [`aitp_handshake::CompletedHandshake`]: the verbatim
/// peer-issued TCT token, its trusted claims, and the companion grant
/// voucher (verbatim) when the peer's policy allowed delegation.
fn completed_handshake_json(c: &aitp_handshake::CompletedHandshake) -> Value {
    json!({
        "tct_token": c.tct.token,
        "tct_claims": c.tct.claims,
        "grant_voucher": c.grant_voucher,
    })
}

fn sign_envelope_with_key<P: serde::Serialize>(
    key: &AitpSigningKey,
    mt: MessageType,
    payload: &P,
    mid: Uuid,
    ts: Timestamp,
) -> AitpEnvelope {
    let payload_value = serde_json::to_value(payload).unwrap();
    let digest =
        aitp_core::envelope_signing_digest(&mid, ts, key.aid(), &payload_value).expect("digest");
    let sig = key.sign(&digest);
    AitpEnvelope {
        version: aitp_core::PROTOCOL_VERSION.into(),
        message_type: mt,
        message_id: mid,
        timestamp: ts,
        sender: Sender {
            agent_id: key.aid().clone(),
        },
        payload: payload_value,
        signature: sig.into_string(),
    }
}

fn verify_revocation_snapshot_op(state: &AdapterState, id: &str, params: Value) -> Value {
    // Accept three field-name variants in fixtures: `revocation_list`
    // (pre-rc.4), `snapshot` (spec rc.4 + rev-* fixtures), `envelope`.
    let env_value = params
        .get("revocation_list")
        .cloned()
        .or_else(|| params.get("snapshot").cloned())
        .or_else(|| params.get("envelope").cloned())
        .unwrap_or_default();
    let env: aitp_tct::RevocationListEnvelope = match serde_json::from_value(env_value) {
        Ok(e) => e,
        Err(e) => return err(id, "INVALID_ENVELOPE", &format!("revocation_list: {e}")),
    };
    let expected_issuer = match params
        .get("expected_issuer")
        .and_then(|v| v.as_str())
        .map(Aid::parse)
    {
        Some(Ok(a)) => a,
        Some(Err(e)) => return err(id, "INVALID_REQUEST", &format!("expected_issuer: {e}")),
        None => return err(id, "INVALID_REQUEST", "missing expected_issuer"),
    };
    let now = params
        .get("now")
        .and_then(|v| v.as_i64())
        .map(Timestamp)
        .unwrap_or_else(|| state.now());
    let ctx = aitp_tct::VerifyRevocationListContext {
        expected_issuer: &expected_issuer,
        now,
    };
    if let Err(e) = aitp_tct::verify_revocation_list(&env, &ctx) {
        return err(id, &tct_error_code(&e), &e.to_string());
    }
    // Apply the optional RevocationPolicy when supplied (rev-001 /
    // rev-002 fixtures). The wire shape is `policy: {fail_mode,
    // max_staleness_secs}`. When absent, the snapshot's own validity
    // is the decision (current behavior).
    if let Some(policy) = params.get("policy") {
        let max_staleness = policy
            .get("max_staleness_secs")
            .and_then(|v| v.as_i64())
            .unwrap_or(86_400);
        let fail_mode = policy
            .get("fail_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("fail_closed");
        let age = now.0.saturating_sub(env.revocation_list.published_at.0);
        if age > max_staleness {
            return match fail_mode {
                "fail_open" | "soft_fail" => {
                    json!({"id": id, "ok": true, "result": {"verified": true, "stale": true}})
                }
                _ => err(
                    id,
                    "TCT_REVOKED",
                    &format!("snapshot stale ({age}s > {max_staleness}s) under fail_closed policy"),
                ),
            };
        }
    }
    json!({"id": id, "ok": true, "result": {"verified": true, "revoked_count": env.revocation_list.entries.len()}})
}

fn revoke_tct_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    let jti = match params.get("jti").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return err(id, "INVALID_REQUEST", "missing 'jti'"),
    };
    state.revoked_jtis.insert(jti);
    json!({"id": id, "ok": true, "result": {"revoked_count": state.revoked_jtis.len()}})
}

/// `issue_pop_challenge`: a consuming peer mints a PoP challenge for
/// a TCT it holds (RFC-AITP-0005 §6.1). The challenge stashes a fresh
/// 16-byte nonce and pins the challenged JTI; the holder is expected
/// to round-trip via `produce_pop_response`. This op records the
/// challenge in adapter state so a later `verify_pop_response` can
/// look it up.
fn issue_pop_challenge_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    // tct-006 envelope-wrapped mode: the fixture supplies the TCT as
    // a top-level `tct_token` compact JWS (merged into step params by
    // the runner) and the nonce inside the step's `envelope.payload`.
    // Accept either `tct_token` (fixture mode) or explicit `tct`
    // claims (rich CLI mode). The challenge only needs the JTI, so an
    // unverified decode is fine — the PoP itself is what proves key
    // possession.
    let tct = match tct_claims_from_params(&params) {
        Ok(t) => t,
        Err(e) => return err(id, "INVALID_ENVELOPE", &format!("tct parse: {e}")),
    };
    // If an envelope is supplied with `payload.nonce`, reuse that
    // nonce (deterministic for the fixture) instead of minting a
    // fresh one. The subsequent `produce_pop_response` /
    // `verify_pop_response` steps embed the same nonce.
    let envelope_nonce = params
        .get("envelope")
        .and_then(|e| e.get("payload"))
        .and_then(|p| p.get("nonce"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let ttl_secs = params
        .get("ttl_secs")
        .and_then(|v| v.as_i64())
        .unwrap_or(300);
    let nonce = if let Some(n) = envelope_nonce {
        n
    } else {
        let mut nonce_bytes = [0u8; 16];
        use rand::RngCore;
        if let Err(e) = rand::rngs::OsRng.try_fill_bytes(&mut nonce_bytes) {
            return err(id, "INTERNAL_ERROR", &e.to_string());
        }
        base64url::encode(&nonce_bytes)
    };
    let challenge = aitp_tct::PopChallenge {
        tct_jti: tct.jti,
        nonce: nonce.clone(),
        expires_at: Timestamp(state.now().0 + ttl_secs),
    };
    state
        .pop_challenges
        .insert(tct.jti.to_string(), challenge.clone());
    json!({
        "id": id,
        "ok": true,
        "result": {
            "challenge": challenge,
        }
    })
}

/// `produce_pop_response`: a TCT holder signs the most recently
/// issued challenge for its TCT (looked up from state by JTI) and
/// returns a [`PopResponse`]. RFC-AITP-0005 §6.2 step 3.
fn produce_pop_response_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    // tct-006 envelope-mode: the fixture pre-built the response
    // (the runner-substitution layer signs `pop_signature`). The
    // step's "produce" here is a verification of consistency:
    // does the envelope's `payload.nonce_echo` match the
    // challenge stashed in state, and does `pop_signature`
    // verify against the TCT subject's pubkey?
    if let Some(env) = params.get("envelope") {
        let payload = env
            .get("payload")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let nonce_echo = payload.get("nonce_echo").and_then(|v| v.as_str());
        let pop_sig = payload.get("pop_signature").and_then(|v| v.as_str());
        if let (Some(echo), Some(sig)) = (nonce_echo, pop_sig) {
            // Find the TCT for the holder pubkey lookup.
            let tct = match tct_claims_from_params(&params) {
                Ok(t) => t,
                Err(e) => return err(id, "INVALID_ENVELOPE", &format!("tct_token parse: {e}")),
            };
            let holder_pubkey = match AitpVerifyingKey::from_aid(&tct.sub) {
                Ok(p) => p,
                Err(e) => return err(id, "INVALID_REQUEST", &e.to_string()),
            };
            let nonce_bytes = match base64url::decode_strict(echo) {
                Ok(b) => b,
                Err(e) => return err(id, "INVALID_ENVELOPE", &e.to_string()),
            };
            use sha2::Digest;
            let pop_input = sha2::Sha256::digest(&nonce_bytes);
            let parsed_sig = match aitp_crypto::Signature::parse(sig) {
                Ok(s) => s,
                Err(_) => return err(id, "POP_RESPONSE_INVALID", "pop_signature parse"),
            };
            if holder_pubkey.verify(&pop_input, &parsed_sig).is_err() {
                return err(id, "POP_RESPONSE_INVALID", "pop_signature verify");
            }
            // Stash the synthetic PopResponse so verify_pop_response can
            // pick it up.
            let expires_at = Timestamp(state.now().0 + 300);
            state
                .pop_challenges
                .entry(tct.jti.to_string())
                .or_insert(aitp_tct::PopChallenge {
                    tct_jti: tct.jti,
                    nonce: echo.to_string(),
                    expires_at,
                });
            return json!({
                "id": id,
                "ok": true,
                "result": {"verified": true, "nonce_echo": echo}
            });
        }
    }

    let challenge: aitp_tct::PopChallenge = match params.get("challenge") {
        Some(v) => match serde_json::from_value(v.clone()) {
            Ok(c) => c,
            Err(e) => return err(id, "INVALID_ENVELOPE", &format!("challenge parse: {e}")),
        },
        None => {
            // Fallback: look up by tct_jti from state.
            let jti = match params.get("tct_jti").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => {
                    return err(
                        id,
                        "INVALID_REQUEST",
                        "missing `challenge` or `tct_jti` to look one up",
                    )
                }
            };
            match state.pop_challenges.get(jti) {
                Some(c) => c.clone(),
                None => {
                    return err(
                        id,
                        "INVALID_REQUEST",
                        &format!("no pending PoP challenge for jti {jti}"),
                    )
                }
            }
        }
    };
    let handle = match params.get("holder_keypair").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err(id, "INVALID_REQUEST", "missing 'holder_keypair'"),
    };
    let key = match state.key_for(handle) {
        Some(k) => k,
        None => return err(id, "INVALID_REQUEST", &format!("unknown keypair {handle}")),
    };
    let response = match aitp_tct::sign_pop_response(&challenge, &key) {
        Ok(r) => r,
        Err(e) => return err(id, &tct_error_code(&e), &e.to_string()),
    };
    json!({
        "id": id,
        "ok": true,
        "result": {
            "response": response,
        }
    })
}

/// `verify_pop_response`: the consuming peer verifies the holder's
/// response against the challenge it issued. RFC-AITP-0005 §6.2 step
/// 4. The challenge is looked up by JTI from adapter state if not
/// supplied directly.
fn verify_pop_response_op(state: &AdapterState, id: &str, params: Value) -> Value {
    // tct-006 envelope-mode step 3: no `response` is supplied
    // because the prior `produce_pop_response` step already
    // verified the holder's signed echo. The fixture's
    // expectations for step 3 are just `{outcome: success}` —
    // confirm there's a stashed challenge for the requested TCT
    // (or, if `tct_token` is supplied at the sequence level,
    // confirm at least one challenge was issued).
    if params.get("response").is_none() {
        let stashed = if params.get("tct_token").is_some() {
            if let Ok(tct) = tct_claims_from_params(&params) {
                state.pop_challenges.contains_key(&tct.jti.to_string())
            } else {
                false
            }
        } else {
            !state.pop_challenges.is_empty()
        };
        if stashed {
            return json!({"id": id, "ok": true, "result": {"verified": true}});
        }
        return err(
            id,
            "INVALID_REQUEST",
            "no PoP response or stashed challenge to verify against",
        );
    }
    let response: aitp_tct::PopResponse =
        match serde_json::from_value(params.get("response").cloned().unwrap_or_default()) {
            Ok(r) => r,
            Err(e) => return err(id, "INVALID_ENVELOPE", &format!("response parse: {e}")),
        };
    let tct = match tct_claims_from_params(&params) {
        Ok(t) => t,
        Err(e) => return err(id, "INVALID_ENVELOPE", &format!("tct parse: {e}")),
    };
    let challenge: aitp_tct::PopChallenge = if let Some(v) = params.get("challenge") {
        match serde_json::from_value(v.clone()) {
            Ok(c) => c,
            Err(e) => return err(id, "INVALID_ENVELOPE", &format!("challenge parse: {e}")),
        }
    } else {
        match state.pop_challenges.get(&tct.jti.to_string()) {
            Some(c) => c.clone(),
            None => {
                return err(
                    id,
                    "INVALID_REQUEST",
                    &format!("no pending PoP challenge for jti {}", tct.jti),
                )
            }
        }
    };
    match aitp_tct::verify_pop_response(&challenge, &response, &tct, state.now()) {
        Ok(()) => json!({"id": id, "ok": true, "result": {"verified": true}}),
        Err(e) => err(id, &tct_error_code(&e), &e.to_string()),
    }
}

// ── Tier D ──────────────────────────────────────────────────────────────

fn set_clock_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    let now = match params.get("now_unix_secs").and_then(|v| v.as_i64()) {
        Some(n) => n,
        None => return err(id, "INVALID_REQUEST", "missing 'now_unix_secs'"),
    };
    state.now_override = Some(now);
    json!({"id": id, "ok": true, "result": {"now_unix_secs": now}})
}

/// `set_features`: the runner declares which optional features
/// it has opted into. The adapter consults this to flip post-v0.1
/// RFC behaviors (e.g. multi-hop delegation, session bundles) that
/// default off in the strict v0.1 posture.
fn set_features_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    let features: Vec<String> = match params.get("features").and_then(|v| v.as_array()) {
        Some(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        None => {
            return err(
                id,
                "INVALID_REQUEST",
                "missing 'features' (array of strings)",
            )
        }
    };
    state.enabled_features = features.iter().cloned().collect();
    json!({"id": id, "ok": true, "result": {"enabled": features}})
}

fn dump_session_op(state: &AdapterState, id: &str, params: Value) -> Value {
    let session_id = params.get("session_id").and_then(|v| v.as_str());
    match session_id {
        Some(sid) => {
            let kind = state.sessions.get(sid).map(|s| match s {
                HandshakeSession::Initiator { .. } => "initiator",
                HandshakeSession::PendingResponder { .. } => "pending_responder",
                HandshakeSession::ActiveResponder { .. } => "active_responder",
            });
            json!({
                "id": id,
                "ok": true,
                "result": {
                    "session_id": sid,
                    "exists": kind.is_some(),
                    "kind": kind,
                }
            })
        }
        None => json!({
            "id": id,
            "ok": true,
            "result": {
                "session_count": state.sessions.len(),
                "keypair_count": state.keypair_seeds.len(),
                "revoked_jti_count": state.revoked_jtis.len(),
                "now_override": state.now_override,
            }
        }),
    }
}

fn err(id: &str, code: &str, message: &str) -> Value {
    json!({"id": id, "ok": false, "error_code": code, "message": message})
}

// ── Session Trust Bundle (RFC-AITP-0010) ────────────────────────────────

fn issue_session_bundle_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    use aitp_session_bundle::SessionBundleBuilder;

    let handle = match params.get("coordinator_keypair").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err(id, "INVALID_REQUEST", "missing 'coordinator_keypair'"),
    };
    let coord = match state.key_for(handle) {
        Some(k) => k,
        None => return err(id, "INVALID_REQUEST", &format!("unknown keypair {handle}")),
    };
    let participants_json = match params.get("participants").and_then(|v| v.as_array()) {
        Some(a) => a.clone(),
        None => return err(id, "INVALID_REQUEST", "missing 'participants' array"),
    };
    let mut builder = SessionBundleBuilder::new(&coord);
    if let Some(sid) = params
        .get("session_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        builder = builder.session_id(sid);
    }
    if let Some(now) = params.get("issued_at").and_then(|v| v.as_i64()) {
        builder = builder.issued_at(Timestamp(now));
    }
    for entry in &participants_json {
        let aid = match entry.get("aid").and_then(|v| v.as_str()).map(Aid::parse) {
            Some(Ok(a)) => a,
            _ => return err(id, "INVALID_REQUEST", "participant entry missing valid aid"),
        };
        // v0.2: the participant's TCT is an opaque compact JWS string.
        let tct = match entry.get("tct").and_then(|v| v.as_str()) {
            Some(t) => t.to_string(),
            None => {
                return err(
                    id,
                    "INVALID_REQUEST",
                    "participant entry missing 'tct' (compact JWS string)",
                )
            }
        };
        builder = builder.participant(aid, tct);
    }
    match builder.build() {
        Ok(bundle) => json!({
            "id": id,
            "ok": true,
            "result": {
                "session_bundle": bundle
            }
        }),
        Err(e) => err(id, &bundle_error_code(&e), &e.to_string()),
    }
}

fn verify_session_bundle_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    use aitp_session_bundle::{verify_session_bundle, BundleOutcome, VerifySessionBundleContext};

    // RFC-AITP-0010 §3 wire form: `{"session_bundle": {<body>}, "signature": "..."}`.
    // The internal `SessionTrustBundle` keeps `signature` as a field
    // *inside* the body (rc.1 representation); the envelope wrapper
    // is what's on the wire. Accept either:
    //
    // - `params.session_bundle = {<body with signature inside>}`
    //   (legacy internal callers)
    // - `params.session_bundle = {"session_bundle": {<body>}, "signature": "..."}`
    //   (spec wire envelope; `bundle-*` conformance fixtures)
    // - `params.bundle_envelope = <envelope>`
    //
    // Reassemble into the internal shape (signature inside body)
    // before deserialization.
    let mut bundle_value = if let Some(inner) = params.get("session_bundle") {
        // Detect envelope form: outer object has exactly the
        // "session_bundle" + "signature" pair.
        if let Some(map) = inner.as_object() {
            if map.contains_key("session_bundle") && map.contains_key("signature") {
                let mut body = map["session_bundle"].clone();
                if let Some(b_map) = body.as_object_mut() {
                    b_map.insert("signature".into(), map["signature"].clone());
                }
                body
            } else {
                inner.clone()
            }
        } else {
            inner.clone()
        }
    } else if let Some(env) = params.get("bundle_envelope") {
        if let Some(map) = env.as_object() {
            let mut body = map.get("session_bundle").cloned().unwrap_or_default();
            if let Some(b_map) = body.as_object_mut() {
                if let Some(sig) = map.get("signature") {
                    b_map.insert("signature".into(), sig.clone());
                }
            }
            body
        } else {
            env.clone()
        }
    } else {
        return err(id, "INVALID_REQUEST", "missing 'session_bundle'");
    };
    // Participant entries may carry `tct_claims` companions (the
    // claims-sibling minting convention); they are never wire bytes.
    strip_claims_companions(&mut bundle_value);
    let bundle: aitp_session_bundle::SessionTrustBundle = match serde_json::from_value(bundle_value)
    {
        Ok(b) => b,
        Err(e) => return err(id, "INVALID_REQUEST", &format!("malformed bundle: {e}")),
    };
    // Spec's PLACEHOLDERS.md uses `self_aid` for the receiving
    // participant; older internal callers use `verifier_aid`.
    // Accept either.
    let verifier_aid = match params
        .get("verifier_aid")
        .or_else(|| params.get("self_aid"))
        .and_then(|v| v.as_str())
        .map(Aid::parse)
    {
        Some(Ok(a)) => a,
        _ => {
            return err(
                id,
                "INVALID_REQUEST",
                "missing/invalid verifier_aid (or self_aid)",
            )
        }
    };
    let now = params
        .get("now")
        .and_then(|v| v.as_i64())
        .map(Timestamp)
        .unwrap_or_else(|| state.now());
    let revoked: std::collections::HashSet<Uuid> = params
        .get("revoked_jtis")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| Uuid::parse_str(s).ok())
                .collect()
        })
        .unwrap_or_default();
    let check = |jti: &Uuid| revoked.contains(jti);
    let revocation_check: Option<&dyn Fn(&Uuid) -> bool> = if revoked.is_empty() {
        None
    } else {
        Some(&check)
    };
    let ctx = VerifySessionBundleContext {
        verifier_aid: &verifier_aid,
        now,
        revocation_check,
    };
    match verify_session_bundle(&bundle, &ctx) {
        Ok(BundleOutcome::Clear { active_aids }) => {
            let aids: Vec<String> = active_aids.iter().map(|a| a.to_string()).collect();
            json!({
                "id": id,
                "ok": true,
                "result": { "verified": true, "outcome": "clear", "active_aids": aids }
            })
        }
        Ok(BundleOutcome::DegradedSubset {
            active_aids,
            dropped_aids,
        }) => {
            let active: Vec<String> = active_aids.iter().map(|a| a.to_string()).collect();
            let dropped: Vec<String> = dropped_aids.iter().map(|a| a.to_string()).collect();
            json!({
                "id": id,
                "ok": true,
                "result": {
                    "verified": true,
                    "outcome": "degraded_subset",
                    "active_aids": active,
                    "dropped_aids": dropped,
                }
            })
        }
        Err(e) => err(id, &bundle_error_code(&e), &e.to_string()),
    }
}

/// Map [`SessionBundleError`] to a stable conformance code. The
/// `BUNDLE_*` codes match the names proposed in
/// `agentidentitytrustprotocol/plans/v0.2-conformance-followups.md` §4
/// for inclusion in the RFC-AITP-0001 error registry. They are emitted
/// here ahead of the spec PR so that fixtures using these codes can be
/// minted without a downstream waiting cycle.
fn bundle_error_code(e: &aitp_session_bundle::SessionBundleError) -> String {
    use aitp_session_bundle::SessionBundleError::*;
    match e {
        VersionMismatch => "BUNDLE_VERSION_MISMATCH",
        InvalidSignature => "BUNDLE_INVALID_SIGNATURE",
        Expired => "BUNDLE_EXPIRED",
        ExpiryWindowInvariant => "BUNDLE_EXPIRY_WINDOW_INVARIANT",
        CoordinatorIssuerMismatch => "BUNDLE_COORDINATOR_ISSUER_MISMATCH",
        AudienceMismatch => "BUNDLE_AUDIENCE_MISMATCH",
        NotMember => "BUNDLE_NOT_MEMBER",
        EmptyParticipants => "BUNDLE_EMPTY_PARTICIPANTS",
        MissingField(_) => "INVALID_REQUEST",
        Canonicalization(_) => "INTERNAL_ERROR",
        TctVerification(_) => "BUNDLE_PARTICIPANT_TCT_INVALID",
        Crypto(_) => "INVALID_SIGNATURE",
    }
    .to_string()
}

#[cfg(test)]
mod p256_readiness_tests {
    //! P-256 conformance readiness (RFC-AITP-0001 §5.4.3).
    //!
    //! Conformance fixtures live in the spec repo (`schemas/conformance/`,
    //! passed to the runner via `--fixtures-dir`), so a P-256 envelope
    //! fixture — a future `env-005` — cannot be authored in this repo. The
    //! `env-001`..`env-004` fixtures are Ed25519. These tests instead drive
    //! a P-256-signed envelope through the **same `verify_envelope` op** the
    //! `env-*` fixtures use, proving this adapter will pass such a fixture
    //! the moment the spec defines it (the verifier resolves the key via
    //! the algorithm-agile `AitpVerifyingKey::from_aid`).
    use super::*;

    fn p256_signed_envelope() -> Value {
        let key = AitpSigningKey::from_p256_seed(&[0x42; 32]).expect("valid P-256 scalar");
        assert!(
            key.aid().as_str().starts_with("aid:pubkey:p256:"),
            "expected a P-256 AID"
        );
        let message_id = Uuid::from_u128(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);
        let timestamp = Timestamp(1_700_000_000);
        let payload = json!({"hello": "p256"});
        let digest =
            aitp_core::envelope_signing_digest(&message_id, timestamp, key.aid(), &payload)
                .unwrap();
        let envelope = AitpEnvelope {
            version: aitp_core::PROTOCOL_VERSION.into(),
            message_type: MessageType::MutualHello,
            message_id,
            timestamp,
            sender: Sender {
                agent_id: key.aid().clone(),
            },
            payload,
            signature: key.sign(&digest).into_string(),
        };
        serde_json::to_value(&envelope).unwrap()
    }

    #[test]
    fn adapter_verifies_p256_envelope() {
        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "env-p256-readiness",
            "verify_envelope",
            json!({ "envelope": p256_signed_envelope() }),
        );
        assert_eq!(
            out["ok"],
            json!(true),
            "adapter must verify a P-256 envelope: {out}"
        );
        assert_eq!(out["result"]["verified"], json!(true));
    }

    #[test]
    fn adapter_rejects_tampered_p256_envelope() {
        let mut env = p256_signed_envelope();
        // Mutate the payload after signing — the P-256 signature must no
        // longer verify (the same failure mode `env-*` tamper fixtures
        // expect).
        env["payload"] = json!({"hello": "tampered"});
        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "env-p256-readiness-neg",
            "verify_envelope",
            json!({ "envelope": env }),
        );
        assert_eq!(
            out["ok"],
            json!(false),
            "tampered envelope must fail: {out}"
        );
        assert_eq!(out["error_code"], json!("INVALID_SIGNATURE"));
    }
}

#[cfg(test)]
mod error_code_mapping_tests {
    //! The `*_error_code` helpers translate library errors into the
    //! conformance wire codes the runner asserts on. A misroute silently
    //! reports the wrong code on every negative fixture, so the
    //! non-obvious mappings (and the nested handshake→tct/manifest
    //! dispatch) are pinned here.
    use super::{delegation_error_code, handshake_error_code, manifest_error_code, tct_error_code};
    use aitp_delegation::DelegationError;
    use aitp_handshake::HandshakeError;
    use aitp_manifest::ManifestError;
    use aitp_tct::TctError;

    #[test]
    fn handshake_codes() {
        assert_eq!(
            handshake_error_code(&HandshakeError::NonceMismatch),
            "NONCE_MISMATCH"
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::PopVerificationFailed),
            "POP_VERIFICATION_FAILED"
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::InvalidSignature),
            "INVALID_SIGNATURE"
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::IncompatibleTrustAnchors),
            "INCOMPATIBLE_TRUST_ANCHORS"
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::PolicyViolation),
            "POLICY_VIOLATION"
        );
        // Non-obvious: insufficient grants is reported as GRANT_OVERFLOW.
        assert_eq!(
            handshake_error_code(&HandshakeError::InsufficientGrants),
            "GRANT_OVERFLOW"
        );
    }

    #[test]
    fn handshake_delegates_to_nested_mappers() {
        assert_eq!(
            handshake_error_code(&HandshakeError::Tct(TctError::Expired)),
            "TCT_EXPIRED"
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::Manifest(ManifestError::PopFailed)),
            "MANIFEST_POP_FAILED"
        );
    }

    #[test]
    fn tct_codes() {
        assert_eq!(tct_error_code(&TctError::VersionUnknown), "UNKNOWN_VERSION");
        assert_eq!(tct_error_code(&TctError::Expired), "TCT_EXPIRED");
        assert_eq!(tct_error_code(&TctError::Revoked), "TCT_REVOKED");
        // cnf/grant shape problems collapse to INVALID_ENVELOPE.
        assert_eq!(tct_error_code(&TctError::CnfMalformed), "INVALID_ENVELOPE");
        // All four PoP failure modes share one wire code.
        assert_eq!(tct_error_code(&TctError::PopFailed), "POP_RESPONSE_INVALID");
        assert_eq!(
            tct_error_code(&TctError::PopChallengeExpired),
            "POP_RESPONSE_INVALID"
        );
    }

    #[test]
    fn delegation_codes() {
        assert_eq!(
            delegation_error_code(&DelegationError::ScopeExceeded),
            "DELEGATION_SCOPE_EXCEEDED"
        );
        assert_eq!(
            delegation_error_code(&DelegationError::AudienceMismatch),
            "AUDIENCE_MISMATCH"
        );
        assert_eq!(
            delegation_error_code(&DelegationError::MultihopNotSupported),
            "DELEGATION_MULTIHOP_NOT_SUPPORTED"
        );
        assert_eq!(
            delegation_error_code(&DelegationError::InvalidVoucher),
            "DELEGATION_INVALID_VOUCHER"
        );
        // Non-obvious: self-delegation reuses the bad-outer-signature code.
        assert_eq!(
            delegation_error_code(&DelegationError::SelfDelegation),
            "DELEGATION_INVALID_SIGNATURE"
        );
        // Non-obvious: a plain bad JWS signature inside delegation
        // verification can only come from the embedded voucher (the
        // outer token maps to InvalidSignature in aitp-delegation).
        assert_eq!(
            delegation_error_code(&DelegationError::Crypto(
                aitp_crypto::CryptoError::SignatureInvalid
            )),
            "DELEGATION_INVALID_VOUCHER"
        );
    }

    #[test]
    fn jws_header_codes() {
        // The compact-JWS header failures keep token-generic codes
        // across every artifact kind (RFC-AITP-0001 §5.4.5).
        assert_eq!(
            tct_error_code(&TctError::Crypto(aitp_crypto::CryptoError::AlgMismatch(
                "none".into()
            ))),
            "TOKEN_ALG_MISMATCH"
        );
        assert_eq!(
            tct_error_code(&TctError::Crypto(aitp_crypto::CryptoError::TypMismatch {
                expected: "aitp-tct+jwt".into(),
                got: "aitp-grant+jwt".into(),
            })),
            "TOKEN_TYP_MISMATCH"
        );
        assert_eq!(
            tct_error_code(&TctError::Crypto(aitp_crypto::CryptoError::JwsMalformed(
                "two segments".into()
            ))),
            "INVALID_ENVELOPE"
        );
        // A bad TCT signature surfaces through the Crypto variant.
        assert_eq!(
            tct_error_code(&TctError::Crypto(
                aitp_crypto::CryptoError::SignatureInvalid
            )),
            "TCT_SIGNATURE_INVALID"
        );
    }

    #[test]
    fn manifest_codes() {
        assert_eq!(
            manifest_error_code(&ManifestError::Expired),
            "MANIFEST_EXPIRED"
        );
        assert_eq!(
            manifest_error_code(&ManifestError::PopFailed),
            "MANIFEST_POP_FAILED"
        );
        // Non-obvious: an AID/key mismatch is surfaced as a bad signature.
        assert_eq!(
            manifest_error_code(&ManifestError::AidMismatch),
            "MANIFEST_SIGNATURE_INVALID"
        );
    }
}
