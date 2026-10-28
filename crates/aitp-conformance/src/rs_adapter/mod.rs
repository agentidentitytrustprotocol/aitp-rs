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

use aitp::core::{base64url, jcs, Aid, AitpEnvelope, CheckedJson, MessageType, Timestamp};
use aitp::crypto::{jws, AitpSigningKey, AitpVerifyingKey, CryptoError, Signature};
use aitp::delegation::DelegationBuilder;
use aitp::handshake::{
    IdentityKind, Initiator, JwkKeyMaterial, JwkPublicKey, JwksResolver, JwsAlgorithm,
    MutualCommitAckPayload, MutualHelloAckPayload, PeerConfig, PinnedKeyEntry, PresentedIdentity,
    ResolveError, StaticPinnedKeyStore,
};
use aitp::manifest::{IdentityHint, Manifest, ManifestBuilder, ManifestEnvelope};
use aitp::tct::{TctBuilder, TctClaims};
use aitp_experimental::spiffe::{SpiffeBundleStore, SpiffeVerifier};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

mod admission;
mod renewal;

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
    pop_challenges: HashMap<String, aitp::tct::PopChallenge>,
    /// Message-IDs the adapter has accepted in the current run.
    /// Used by env-* replay-test fixtures: a second
    /// `verify_envelope` call carrying the same `message_id`
    /// must return REPLAY_DETECTED. Single-set (no TTL) since
    /// fixture runs are short-lived.
    seen_message_ids: HashSet<String>,
    /// Feature flags the runner has told us are enabled. The
    /// adapter consults this when deciding whether to opt into
    /// post-v0.1 RFC behavior. Examples:
    ///   `experimental-multihop-delegation` → delegations verify with
    ///       `aitp_experimental::delegation` instead of the strict
    ///       single-hop `aitp::delegation::verify_delegation`.
    ///   `experimental-session-bundle` → bundle ops accept work.
    enabled_features: HashSet<String>,
    /// PoP-enforcement state for the `tct-007` capability-invocation
    /// sequence (RFC-AITP-0005 §6.2). `authorize_capability_invocation`
    /// sets it: `Some(true)` when the invoked grant was marked
    /// PoP-required (a `pop_challenge` was issued), `Some(false)` when
    /// it was not. `expect_pop_challenge_issued` and
    /// `withhold_pop_response` read it.
    pop_enforcement: Option<bool>,
    /// The pinned-admission verifier of the current fixture
    /// ([`admission`]). Built by its first admission step, dropped by
    /// `begin_fixture`.
    admission: Option<admission::AdmissionHarness>,
    /// The issuer's renewal replay guard (RFC-AITP-0013 §4 step 5) for
    /// the current fixture: `renew_tct` steps share it, `begin_fixture`
    /// drops it.
    renewal_nonces: Option<aitp::core::nonce_store::InMemoryNonceStore>,
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
            .map(AitpSigningKey::from_ed25519_seed)
    }
}

/// In-progress handshake session.
///
/// Responder sessions land in `PendingResponder` at `start_handshake`
/// and transition to `ActiveResponder` on the first
/// `process_handshake_message` carrying a HELLO envelope. The lazy
/// construction matches the `aitp::handshake::Responder` API, which has
/// no empty constructor.
#[allow(clippy::large_enum_variant)] // size delta between PendingResponder and Active variants is acceptable here
enum HandshakeSession {
    Initiator {
        state: Initiator,
        keypair_handle: String,
        /// The initiator's own manifest. Required so that
        /// `process_handshake_message` can construct a `PeerConfig`
        /// where `cfg.manifest.aid` is the initiator's AID — the TCT
        /// verifier in `aitp::handshake` uses it as the expected
        /// audience for incoming TCTs (RFC-AITP-0005 §9 step 2).
        my_manifest: Manifest,
        /// Pinned-key trust for the HELLO_ACK (RFC-AITP-0002 §3.2 step 3).
        trusted: StaticPinnedKeyStore,
    },
    PendingResponder {
        keypair_handle: String,
        my_manifest: Manifest,
        my_requested_grants: Vec<String>,
        /// Pinned-key trust for the HELLO. `None` = the harness default,
        /// see [`harness_pinned_trust`].
        trusted: Option<StaticPinnedKeyStore>,
    },
    ActiveResponder {
        state: aitp::handshake::Responder,
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
        "verify_tct_as_issuer" => verify_tct_as_issuer_op(state, id, params),
        "authorize_capability_invocation" => authorize_capability_invocation_op(state, id, params),
        "expect_pop_challenge_issued" => expect_pop_challenge_issued_op(state, id, params),
        "withhold_pop_response" => withhold_pop_response_op(state, id, params),

        // Pinned-key admission (RFC-AITP-0002 §3.4) and self-attestation
        // (RFC-AITP-0005 §5.3)
        "verify_identity_presentation" => {
            admission::verify_identity_presentation_op(state, id, params)
        }
        "issue_presentation_challenge" => {
            admission::issue_presentation_challenge_op(state, id, params)
        }
        "verify_attestation" => admission::verify_attestation_op(state, id, params),

        // TCT renewal (RFC-AITP-0013)
        "renew_tct" => renewal::renew_tct_op(state, id, params),
        "verify_renewal_response" => renewal::verify_renewal_response_op(state, id, params),

        // Tier D
        "set_clock" => set_clock_op(state, id, params),
        "set_features" => set_features_op(state, id, params),
        "begin_fixture" => begin_fixture_op(state, id),
        "inject_revocation" => revoke_tct_op(state, id, params),
        "dump_session" => dump_session_op(state, id, params),

        other => err(
            id,
            "OP_NOT_SUPPORTED",
            &format!("op {other} not implemented"),
        ),
    }
}

/// Revocation source for the handshake ops. The conformance harness
/// supplies revocation status only to `verify_tct` (tct-024/025); its
/// handshake fixtures and cross-impl peers carry no `ListRevoked` input,
/// so the handshake ops run `fail_open` explicitly.
const HARNESS_REVOCATION: aitp::tct::RevocationSource<'static> =
    aitp::tct::RevocationSource::FailOpen;

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
        "verify_tct_as_issuer",
        "authorize_capability_invocation",
        "expect_pop_challenge_issued",
        "withhold_pop_response",
        "verify_identity_presentation",
        "issue_presentation_challenge",
        "verify_attestation",
        "renew_tct",
        "verify_renewal_response",
        // Tier D
        "set_clock",
        "set_features",
        "begin_fixture",
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
            "repository": env!("CARGO_PKG_REPOSITORY"),
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
        // Our own signing backend failed: a local fault, never the peer's.
        CryptoError::Signer(_) => "INTERNAL_ERROR".to_string(),
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
    let thumbprint = aitp::crypto::compute_jwk_thumbprint_ed25519_sha256(&buf);
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

    let envelope_value = params.get("envelope").cloned().unwrap_or_default();
    // RFC-AITP-0001 §5.5 timestamp window, when the fixture supplies
    // `tolerance_seconds`, relative to the verifier's clock (or the
    // fixture's explicit `now`). It runs on the raw JSON before the §5.4
    // checks below (RFC-AITP-0009 §3.1, RFC-AITP-0001 §5.4): an envelope
    // that is both stale and malformed, or stale with an unknown
    // `version`, is TIMESTAMP_EXPIRED. A `timestamp` that is missing or
    // not an integer skips the window and fails the structural step.
    if let Some(tolerance) = params
        .get("tolerance_seconds")
        .and_then(|v| v.as_i64())
        .map(|t| std::time::Duration::from_secs(t.max(0).unsigned_abs()))
    {
        let now = params
            .get("now")
            .and_then(|v| v.as_i64())
            .map(Timestamp)
            .unwrap_or_else(|| state.now());
        if let Some(ts) = envelope_value
            .get("timestamp")
            .and_then(|v| v.as_i64())
            .map(Timestamp)
        {
            if !ts.is_within_tolerance_of(now, tolerance) {
                return err(
                    id,
                    "TIMESTAMP_EXPIRED",
                    &format!(
                        "envelope timestamp outside the {}s window",
                        tolerance.as_secs()
                    ),
                );
            }
        }
    }
    // RFC-AITP-0001 §5.4 check order: `parse_envelope_wire` runs steps 1
    // (`version`, UNKNOWN_VERSION) and 2 (member set and structure);
    // step 3, the signature, follows.
    let envelope = match aitp::core::parse_envelope_wire(&checked(&envelope_value)) {
        Ok(e) => e,
        Err(e) => {
            return err(
                id,
                &envelope_parse_error_code(&e),
                &format!("envelope parse: {e}"),
            )
        }
    };
    let pk = match AitpVerifyingKey::from_aid(&envelope.sender.agent_id) {
        Ok(p) => p,
        Err(e) => return err(id, "KEY_RESOLUTION_FAILED", &e.to_string()),
    };
    let digest = match aitp::core::envelope_signing_digest(&envelope) {
        Ok(d) => d,
        Err(e) => return err(id, "INTERNAL_ERROR", &e.to_string()),
    };
    let sig = match Signature::parse(&envelope.signature) {
        Ok(s) => s,
        Err(_) => return err(id, "INVALID_SIGNATURE", "signature parse"),
    };
    match pk.verify_jcs(&aitp::crypto::Digest32::from(digest), &sig) {
        Ok(()) => json!({"id": id, "ok": true, "result": {"verified": true}}),
        Err(_) => err(id, "INVALID_SIGNATURE", "envelope signature invalid"),
    }
}

fn envelope_parse_error_code(e: &aitp::core::EnvelopeParseError) -> String {
    use aitp::core::EnvelopeParseError::*;
    match e {
        UnknownVersion(_) => "UNKNOWN_VERSION",
        UnknownField(_) => "UNKNOWN_FIELD",
        Malformed(_) => "INVALID_ENVELOPE",
        _ => "INVALID_ENVELOPE",
    }
    .to_string()
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
/// The identity type a fixture names by its RFC-AITP-0002 wire string.
fn identity_kind(v: &Value) -> Option<aitp::handshake::IdentityKind> {
    serde_json::from_value(v.clone()).ok()
}

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

    // RFC-AITP-0001 §5.4 check order, steps 1 (`version`) and 2 (member
    // set and structure); the envelope signature (step 3) runs below at
    // the RFC-AITP-0004 §5.1 position for its message type.
    let envelope_value = params.get("envelope").cloned().unwrap_or_default();
    let mut envelope = match aitp::core::parse_envelope_wire(&checked(&envelope_value)) {
        Ok(e) => e,
        Err(e) => {
            return err(
                id,
                &envelope_parse_error_code(&e),
                &format!("envelope parse: {e}"),
            )
        }
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
    let self_key = AitpSigningKey::from_ed25519_seed(&self_seed);

    // RFC-AITP-0002 §6.2: a `spiffe` fixture's
    // `trust_anchors_config.spiffe_bundles` is the verifier's whole
    // bundle store. The verifier accepts `spiffe` only with the
    // feature on (§6.6; PLACEHOLDERS.md `id-*` row): then it attaches a
    // `SpiffeVerifier`, over an empty store when the fixture has none.
    let spiffe_enabled = state.has_feature("experimental-spiffe-identity");
    let spiffe_store = if spiffe_enabled {
        match params
            .get("trust_anchors_config")
            .and_then(|c| c.get("spiffe_bundles"))
        {
            Some(bundles) => match SpiffeBundleStore::from_config(bundles) {
                Ok(store) => Some(store),
                Err(e) => return err(id, "IDENTITY_FAILED", &format!("spiffe_bundles: {e}")),
            },
            None => Some(SpiffeBundleStore::new()),
        }
    } else {
        None
    };
    let spiffe_verifier = spiffe_store.as_ref().map(SpiffeVerifier::new);

    // `self_trust_anchors` is the receiver's OIDC `trust_anchors` when the
    // fixture states it. When it is absent the receiver trusts exactly the
    // runner-minted OIDC test issuer (README, "Receiver policy inputs").
    let cfg_anchors: Vec<aitp::core::RawUrl> =
        match params.get("self_trust_anchors").and_then(|v| v.as_array()) {
            Some(anchors) => anchors
                .iter()
                .filter_map(|a| a.as_str()?.parse().ok())
                .collect(),
            None => vec!["https://auth.openai.com".parse().unwrap()],
        };
    // Synthesize a minimal verifier-side Manifest. Most fields are
    // throwaway; what bootstrap_verify_peer reads out of `cfg.manifest`
    // is `aid` (audience for OIDC) and `required_peer_capabilities`.
    let self_manifest = ManifestBuilder::new(&self_key)
        .display_name("conformance-verifier")
        .handshake_endpoint(
            "https://verifier.example.com/aitp/handshake"
                .parse()
                .unwrap(),
        )
        .identity_hint(
            IdentityHint::new(IdentityKind::PinnedKey, "verifier").with_public_key(
                aitp::core::base64url::encode(
                    &self_key
                        .verifying_key()
                        .try_to_ed25519_bytes()
                        .expect("key was constructed as Ed25519, never P-256"),
                ),
            ),
        );
    let self_manifest = cfg_anchors
        .iter()
        .fold(self_manifest, |m, a| m.accept_trust_anchor_raw(a.clone()));
    // RFC-AITP-0004 §5.1 step 8: an `mh-*` fixture states the receiver's
    // own `accepted_identity_types` as `self_accepted_identity_types`, and
    // the runner fills in the default `["oidc"]` when it is absent. An
    // `id-*` fixture stops at step 6 and states none, so the verifier
    // accepts every type it supports (PLACEHOLDERS.md `id-*` row).
    let self_manifest = match params
        .get("self_accepted_identity_types")
        .and_then(|v| v.as_array())
    {
        Some(types) if types.is_empty() => self_manifest.accept_no_identity_types(),
        Some(types) => {
            let mut b = self_manifest;
            for t in types {
                match identity_kind(t) {
                    Some(kind) => b = b.accept_identity_type(kind),
                    None => {
                        return err(
                            id,
                            "INVALID_REQUEST",
                            "unknown self_accepted_identity_types entry",
                        )
                    }
                }
            }
            b
        }
        None => {
            let b = self_manifest
                .accept_identity_type(aitp::handshake::IdentityKind::PinnedKey)
                .accept_identity_type(aitp::handshake::IdentityKind::Oidc);
            if spiffe_enabled {
                b.accept_identity_type(aitp::handshake::IdentityKind::Spiffe)
            } else {
                b
            }
        }
    };
    let self_manifest = match self_manifest
        .ttl(std::time::Duration::from_secs(3600))
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
        let digest =
            aitp::core::envelope_signing_digest(envelope).map_err(|e| format!("digest: {e}"))?;
        let sig = Signature::parse(&envelope.signature).map_err(|e| format!("sig: {e}"))?;
        pk.verify_jcs(&aitp::crypto::Digest32::from(digest), &sig)
            .map_err(|_| "verify".to_string())
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
    let resolver = OidcTestIssuerResolver;
    // RFC-AITP-0002 §3.2 step 3: the pinned-key trust store is
    // required. Fixtures that exercise it (e.g. id-007) supply
    // `trust_store` as a list of AID strings (Ed25519 or P-256).
    let trust_store = harness_pinned_trust(&params, &envelope.sender.agent_id);
    let mut cfg = PeerConfig::new(
        &self_key,
        &self_manifest,
        &resolver,
        &trust_store,
        HARNESS_REVOCATION,
        envelope.timestamp,
    )
    .with_trust_anchors(&cfg_anchors);
    if let Some(verifier) = &spiffe_verifier {
        cfg = cfg.with_identity_verifier(verifier);
    }

    use aitp::__private::{apply_peer_policy, bootstrap_verify_peer};
    use aitp::__private::{check_members, from_serde_error};
    use aitp::handshake::HandshakeError;
    use aitp::handshake::{
        MutualCommitAckPayload, MutualHelloAckPayload, MutualHelloPayload,
        MUTUAL_COMMIT_ACK_PAYLOAD_MEMBERS, MUTUAL_HELLO_ACK_PAYLOAD_MEMBERS,
        MUTUAL_HELLO_PAYLOAD_MEMBERS,
    };

    let hello_family = matches!(
        envelope.message_type,
        MessageType::MutualHello | MessageType::MutualHelloAck
    );
    // The identity a HELLO-family peer presented, for the step 8 policy
    // check once the envelope signature (step 7) passes.
    let mut peer_identity = None;
    let result = match envelope.message_type {
        MessageType::MutualHello => {
            if let Err(e) = check_members(
                "MutualHelloPayload",
                &envelope.payload,
                MUTUAL_HELLO_PAYLOAD_MEMBERS,
            ) {
                return err(
                    id,
                    &handshake_error_code(&HandshakeError::UnknownField(e.field)),
                    "unknown field in MUTUAL_HELLO payload",
                );
            }
            let p: MutualHelloPayload = match serde_json::from_value(envelope.payload.clone()) {
                Ok(p) => p,
                Err(e) => {
                    return if let Some(field) = from_serde_error(&e) {
                        err(
                            id,
                            &handshake_error_code(&HandshakeError::UnknownField(field)),
                            &format!("hello payload: {e}"),
                        )
                    } else {
                        err(id, "INVALID_ENVELOPE", &format!("hello payload: {e}"))
                    }
                }
            };
            let r = bootstrap_verify_peer(&envelope, &p.manifest, &p.identity, &p.pop_nonce, &cfg)
                .map(|_| ());
            peer_identity = Some(p.identity);
            r
        }
        MessageType::MutualHelloAck => {
            if let Err(e) = check_members(
                "MutualHelloAckPayload",
                &envelope.payload,
                MUTUAL_HELLO_ACK_PAYLOAD_MEMBERS,
            ) {
                return err(
                    id,
                    &handshake_error_code(&HandshakeError::UnknownField(e.field)),
                    "unknown field in MUTUAL_HELLO_ACK payload",
                );
            }
            let p: MutualHelloAckPayload = match serde_json::from_value(envelope.payload.clone()) {
                Ok(p) => p,
                Err(e) => {
                    return if let Some(field) = from_serde_error(&e) {
                        err(
                            id,
                            &handshake_error_code(&HandshakeError::UnknownField(field)),
                            &format!("hello_ack payload: {e}"),
                        )
                    } else {
                        err(id, "INVALID_ENVELOPE", &format!("hello_ack payload: {e}"))
                    }
                }
            };
            // RFC-AITP-0004 §5.2 step 3 (`mh-015`): `peer_aid` is the AID
            // the initiator addressed. The HELLO_ACK sender must be that
            // peer, checked before any Manifest step. The initiator state
            // machine (`Initiator::on_hello_ack`) applies the same check.
            if let Some(peer_aid) = params.get("peer_aid").and_then(|v| v.as_str()) {
                if envelope.sender.agent_id.as_str() != peer_aid {
                    return err(
                        id,
                        &handshake_error_code(&HandshakeError::PeerMismatch),
                        "HELLO_ACK sender is not the intended peer",
                    );
                }
            }
            // mh-005 supplies `sent_pop_nonce` — the nonce the
            // receiver sent in its prior HELLO. The receiver MUST
            // check that the HELLO_ACK's `pop_nonce_echo` matches.
            // This is normally tracked by the Initiator session
            // state in `aitp::handshake`; the conformance fixture
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
            let r = bootstrap_verify_peer(&envelope, &p.manifest, &p.identity, &p.pop_nonce, &cfg)
                .map(|_| ());
            peer_identity = Some(p.identity);
            r
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
            // `MutualCommitPayload` and `MutualCommitAckPayload` declare
            // the same member set on the wire (RFC-AITP-0001 §7), so a
            // single member-set check covers both message types here.
            if let Err(e) = check_members(
                "MutualCommitAckPayload",
                &envelope.payload,
                MUTUAL_COMMIT_ACK_PAYLOAD_MEMBERS,
            ) {
                return err(
                    id,
                    &handshake_error_code(&HandshakeError::UnknownField(e.field)),
                    "unknown field in MUTUAL_COMMIT/MUTUAL_COMMIT_ACK payload",
                );
            }
            let p: MutualCommitAckPayload = match serde_json::from_value(envelope.payload.clone())
            {
                Ok(p) => p,
                Err(e) => {
                    return if let Some(field) = from_serde_error(&e) {
                        err(
                            id,
                            &handshake_error_code(&HandshakeError::UnknownField(field)),
                            &format!("commit_ack payload: {e}"),
                        )
                    } else {
                        err(id, "INVALID_ENVELOPE", &format!("commit_ack payload: {e}"))
                    }
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
        // RFC-AITP-0004 §5.1 step 8 / §5.2, after steps 6 and 7.
        if let Some(identity) = &peer_identity {
            if let Err(e) = apply_peer_policy(identity, &cfg) {
                return err(id, &handshake_error_code(&e), &e.to_string());
            }
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
    now: aitp::core::Timestamp,
) -> Value {
    fn verify_one(
        peer: &Value,
        now: aitp::core::Timestamp,
    ) -> Result<Vec<String>, aitp::handshake::HandshakeError> {
        use aitp::handshake::HandshakeError;
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
        let payload: aitp::handshake::MutualCommitAckPayload =
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
        Ok(verified.into_parts().claims.grants)
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
/// machine in `aitp::handshake` requires an AwaitingCommitAck state
/// (because the receiving peer needs to remember the pop_nonce it
/// sent in HELLO and the peer manifest's expiry). The conformance
/// fixtures don't carry that state — they pre-build a single
/// envelope and assert the receiver rejects it with a specific
/// terminal error. This helper does the audience / grant /
/// pop-signature checks the spec mandates without the session
/// state.
fn verify_commit_ack_stateless(
    payload: &aitp::handshake::MutualCommitAckPayload,
    sender_aid: &Aid,
    self_aid: &Aid,
    now: aitp::core::Timestamp,
    issuer_offered_capabilities: Option<&[String]>,
    expected_pop_nonce: Option<&str>,
) -> Result<aitp::tct::VerifiedTct, aitp::handshake::HandshakeError> {
    use aitp::handshake::HandshakeError;
    use aitp::tct::{verify_tct, TctVerifyContext};

    // Peek the (unverified) claims for the policy-level checks; the
    // full cryptographic verification runs last so the policy errors
    // surface with their specific codes even when the fixture's
    // pinned clock makes time-based checks ambiguous.
    let claims_bytes =
        jws::decode_payload_unverified(&payload.tct).map_err(HandshakeError::Crypto)?;
    let claims: TctClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|e| HandshakeError::Tct(aitp::tct::TctError::ClaimsMalformed(e.to_string())))?;

    // RFC-AITP-0005 §2: the TCT's `aud` MUST equal the receiving
    // peer's AID. Check first because that's the most specific
    // identity-level error the receiver can produce.
    if &claims.aud != self_aid {
        return Err(HandshakeError::Tct(aitp::tct::TctError::AudienceMismatch));
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
        let nonce_bytes = aitp::core::base64url::decode_strict(expected_nonce)
            .map_err(|_| HandshakeError::Identity("pop_nonce not base64url".into()))?;
        let pop_input = aitp::crypto::Digest32::sha256(&nonce_bytes);
        let sig = aitp::crypto::Signature::parse(&payload.pop_signature)
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
            .verify_jcs(&pop_input, &sig)
            .map_err(|_| HandshakeError::PopVerificationFailed)?;
    } else if payload.pop_nonce_echo.is_empty() {
        return Err(HandshakeError::NonceMismatch);
    }

    // TCT signature + expiry last. mh-007 deliberately uses an
    // unexpired TCT (relative to the runner's pinned clock) and
    // depends on this check happening AFTER grant-overflow.
    let ctx = TctVerifyContext::builder().expected_audience(self_aid).issuer(sender_aid).now(now)
        // Handshake-payload conformance op: no revocation source or
        // issuer Manifest is wired for this synthetic check.
        .revocation(aitp::tct::RevocationSource::FailOpen)
        .skip_manifest_expiry_cap_dangerous()
        .build()
        .expect("both verify decisions are made above");
    let verified = verify_tct(&payload.tct, &ctx).map_err(HandshakeError::Tct)?;
    Ok(verified)
}

/// The spec's OIDC test-issuer keys (`known-answer/oidc-test-issuers.json`),
/// vendored at the pinned spec commit. The runner (`aitp-conformance`)
/// signs the corpus's JWTs with keys from the same file.
const OIDC_TEST_ISSUERS: &str =
    include_str!("../../../../tests/schemas/known-answer/oidc-test-issuers.json");

/// The trusted test issuer (kat-oidc-issuer-001, `role: "trusted"`):
/// its issuer URL and Ed25519 seed. The untrusted vector is never read.
fn oidc_test_issuer() -> (String, [u8; 32]) {
    let doc: serde_json::Value =
        serde_json::from_str(OIDC_TEST_ISSUERS).expect("oidc-test-issuers.json parses");
    let v = doc["vectors"]
        .as_array()
        .and_then(|v| v.iter().find(|v| v["id"] == "kat-oidc-issuer-001"))
        .expect("oidc-test-issuers.json has kat-oidc-issuer-001");
    assert_eq!(
        v["role"], "trusted",
        "kat-oidc-issuer-001 must be the trusted issuer"
    );
    let issuer = v["issuer"]
        .as_str()
        .expect("kat-oidc-issuer-001 has an issuer")
        .to_owned();
    let seed = v["seed_hex"]
        .as_str()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| b.try_into().ok())
        .expect("kat-oidc-issuer-001: seed_hex is 32 bytes of hex");
    (issuer, seed)
}

/// Resolves the single OIDC test issuer's JWK for
/// `verify_handshake_payload_op`; every other issuer stays untrusted
/// (empty candidate list), matching the prior always-empty
/// `NoOpResolver` for any fixture that never reaches key resolution
/// (see the Phase 5 plan's per-fixture trace table).
struct OidcTestIssuerResolver;
impl JwksResolver for OidcTestIssuerResolver {
    fn resolve(&self, issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        // Compare parsed `Url`s, not raw strings: `Url::parse` adds a
        // trailing slash to a bare-domain URL, so a string compare
        // against the issuer string would silently never match.
        let (test_issuer, seed) = oidc_test_issuer();
        let Ok(test_issuer) = url::Url::parse(&test_issuer) else {
            return Ok(vec![]);
        };
        if issuer != &test_issuer {
            return Ok(vec![]);
        }
        let key = AitpSigningKey::from_ed25519_seed(&seed);
        let Some(x) = key.verifying_key().try_to_ed25519_bytes() else {
            return Ok(vec![]);
        };
        Ok(vec![
            JwkPublicKey::new(JwkKeyMaterial::Ed25519 { x }).with_alg(JwsAlgorithm::EdDSA)
        ])
    }
}

fn handshake_error_code(e: &aitp::handshake::HandshakeError) -> String {
    use aitp::handshake::HandshakeError::*;
    match e {
        Identity(_) => "IDENTITY_FAILED".to_string(),
        KeyResolutionFailed { .. } => "KEY_RESOLUTION_FAILED".to_string(),
        Manifest(m) => manifest_error_code(m),
        Tct(t) => tct_error_code(t),
        InvalidEnvelope(_) => "INVALID_ENVELOPE".to_string(),
        InvalidSignature => "INVALID_SIGNATURE".to_string(),
        IncompatibleTrustAnchors => "INCOMPATIBLE_TRUST_ANCHORS".to_string(),
        NonceMismatch => "NONCE_MISMATCH".to_string(),
        PeerMismatch => "PEER_MISMATCH".to_string(),
        PopVerificationFailed => "POP_VERIFICATION_FAILED".to_string(),
        State(_) => "INVALID_STATE".to_string(),
        InsufficientGrants | GrantOverflow => "GRANT_OVERFLOW".to_string(),
        PolicyViolation => "POLICY_VIOLATION".to_string(),
        Crypto(c) => crypto_error_code(c, "INVALID_SIGNATURE"),
        Rng(_) => "INTERNAL_ERROR".to_string(),
        Canonicalization(_) => "INTERNAL_ERROR".to_string(),
        // RFC-AITP-0001 §7 / issue #140 Phase 7a: a dedicated core code,
        // never left to the `_ => INTERNAL_ERROR` catch-all below. No
        // fixture covers this mapper (the spec's `mh-*` pack doesn't
        // exercise §7 for handshake payloads), so the direct
        // `error_code_mapping_tests::handshake_codes` assertion is the
        // only thing that would catch a missing/misplaced arm.
        UnknownField(_) => "UNKNOWN_FIELD".to_string(),
        IdentityVerifier(_) | GrantPolicy(_) => e.error_code().as_str().to_string(),
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
    let manifest = match aitp::manifest::parse_manifest_wire(&checked(&manifest_value)) {
        Ok(m) => m,
        Err(e) => {
            return err(
                id,
                &manifest_error_code(&e),
                &format!("manifest parse: {e}"),
            )
        }
    };
    let now = params
        .get("now")
        .and_then(|v| v.as_i64())
        .map(Timestamp)
        .unwrap_or_else(|| state.now());
    match aitp::manifest::verify_manifest(
        &manifest,
        &aitp::manifest::ManifestVerifyContext::at(now),
    ) {
        Ok(_) => json!({"id": id, "ok": true, "result": {"verified": true}}),
        Err(e) => err(id, &manifest_error_code(&e), &e.to_string()),
    }
}

fn manifest_error_code(e: &aitp::manifest::ManifestError) -> String {
    use aitp::manifest::ManifestError::*;
    match e {
        Expired => "MANIFEST_EXPIRED",
        SignatureInvalid => "MANIFEST_SIGNATURE_INVALID",
        PopFailed => "MANIFEST_POP_FAILED",
        VersionUnknown => "MANIFEST_VERSION_UNKNOWN",
        IdentityHintMalformed(_) => "MANIFEST_INVALID",
        IncompatibleIdentityType(_) => "INCOMPATIBLE_IDENTITY_TYPE",
        AidMismatch => "MANIFEST_SIGNATURE_INVALID",
        MissingField(_) => "INVALID_ENVELOPE",
        Canonicalization(_) => "INTERNAL_ERROR",
        // Our own signing backend failed: a local fault, never the peer's.
        Crypto(CryptoError::Signer(_)) => "INTERNAL_ERROR",
        Crypto(_) => "INVALID_SIGNATURE",
        Rng(_) => "INTERNAL_ERROR",
        // RFC-AITP-0001 §7 / issue #140: a top-level or nested member
        // outside the schema-declared member set, found by
        // `parse_manifest_wire` before any expiry/PoP/signature check.
        // Explicit arm so a future variant added to the (non_exhaustive)
        // `ManifestError` enum without a matching arm here fails loudly
        // (as INTERNAL_ERROR) rather than THIS variant silently losing
        // its dedicated code if the match were ever reordered.
        UnknownField(_) => "UNKNOWN_FIELD",
        Malformed(_) => "MANIFEST_INVALID",
        NotFound => "MANIFEST_NOT_FOUND",
        _ => "INTERNAL_ERROR",
    }
    .to_string()
}

fn verify_tct_op(state: &AdapterState, id: &str, params: Value) -> Value {
    use std::sync::atomic::{AtomicBool, Ordering};
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
    // the TCT's issuer (the per-issuing-peer model) before honoring;
    // older callers may supply a bare `revoked_jtis` array.
    let mut revoked_jtis = state.revoked_jtis.clone();
    // Set when the supplied snapshot was discarded: the issuer's
    // revocation status is then unknown and `snapshot_mode` decides.
    let mut snapshot_mode: Option<SnapshotPolicyMode> = None;
    // Why the issuer's revocation status is unknown, for the
    // `RevocationUnavailable` detail (tct-024: it must read differently
    // from a listed `jti`, though both are TCT_REVOKED).
    let mut absent_reason = String::new();
    if let Some(list) = params.get("issuer_revocation_list") {
        // tct-024 / tct-025: `available: false` says no snapshot can be
        // obtained for `issuer`. Absent, so the policy decides, and with
        // no mode named the default `fail_closed` applies.
        if list.get("available").and_then(|v| v.as_bool()) == Some(false) {
            let policy = match snapshot_policy(&params, Some(list)) {
                Ok(p) => p,
                Err(msg) => return err(id, "INVALID_REQUEST", &msg),
            };
            let named = list
                .get("issuer")
                .and_then(|v| v.as_str())
                .unwrap_or(issuer.as_str());
            absent_reason = format!("no revocation snapshot available for issuer {named}");
            snapshot_mode = Some(policy.mode);
        }
        if let Some(jtis) = list.get("revoked_jtis").and_then(|v| v.as_array()) {
            for j in jtis {
                if let Some(s) = j.as_str() {
                    revoked_jtis.insert(s.to_string());
                }
            }
        }
        if let Some(snapshot) = list.get("snapshot") {
            let policy = match snapshot_policy(&params, Some(list)) {
                Ok(p) => p,
                Err(msg) => return err(id, "INVALID_REQUEST", &msg),
            };
            // Issue #271, RFC-AITP-0008 §1.5 / §3.1 (0.3.1-draft): a
            // snapshot discarded for any reason (structure, unknown
            // member, version, signature, expiry, issuer, staleness) is
            // absent. It never reads as "nothing is revoked"; the policy
            // mode decides, and under `fail_closed` (the default) the TCT
            // is rejected with TCT_REVOKED. That decision is taken inside
            // the revocation check, so it still runs only after the TCT's
            // own signature verifies (RFC-AITP-0008 §3.3, rev-004).
            match accepted_snapshot(snapshot, &issuer, now, policy.max_staleness_secs) {
                Ok(env) => {
                    for entry in &env.revocation_list.entries {
                        revoked_jtis.insert(entry.jti.to_string());
                    }
                }
                Err((_code, reason)) => {
                    absent_reason = format!("revocation snapshot discarded: {reason}");
                    snapshot_mode = Some(policy.mode);
                }
            }
        }
    }
    let absent_is_revoked = snapshot_mode
        .as_ref()
        .is_some_and(SnapshotPolicyMode::absent_is_revoked);
    // rev-004 instrumentation: record whether the revocation source
    // was consulted at all, to pin the RFC-AITP-0008 §3.3 ordering
    // (signature verification MUST precede any revocation lookup).
    let lookup_called = AtomicBool::new(false);
    let check = |q: &aitp::tct::RevocationQuery<'_>| {
        use aitp::tct::RevocationStatus;
        lookup_called.store(true, Ordering::Relaxed);
        if absent_is_revoked {
            return Err(aitp::tct::RevocationUnavailable::new(absent_reason.clone()));
        }
        if revoked_jtis.contains(&q.jti.to_string()) {
            return Ok(RevocationStatus::Revoked);
        }
        // soft_fail with a safe subset: the snapshot was discarded, so
        // the verifier narrows the grants to that subset (RFC-AITP-0008
        // §3.1); an empty intersection is SafeSubsetEmpty.
        Ok(match &snapshot_mode {
            Some(SnapshotPolicyMode::SoftFail(safe)) => {
                RevocationStatus::soft_fail_safe_subset(safe.clone())
            }
            _ => RevocationStatus::Clear,
        })
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
        let b = aitp::tct::TctVerifyContext::builder()
            .expected_audience(&expected_audience)
            .issuer(&issuer)
            .now(now)
            .revocation(aitp::tct::RevocationSource::Check(&check));
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
    match aitp::tct::verify_tct(&token, &ctx) {
        Ok(v) => {
            let mut result = json!({"verified": true, "grants": v.effective_grants()});
            if instrumented {
                result["side_effects"] = json!({
                    "revocation_lookup_called": lookup_called.load(Ordering::Relaxed),
                    "network_fetch_called": false,
                });
            }
            json!({"id": id, "ok": true, "result": result})
        }
        Err(e) => err(id, &tct_error_code(&e), &e.to_string()),
    }
}

fn tct_error_code(e: &aitp::tct::TctError) -> String {
    use aitp::tct::TctError::*;
    match e {
        VersionUnknown => "UNKNOWN_VERSION",
        SignatureInvalid => "TCT_SIGNATURE_INVALID",
        // The issuer pin failed: the token's `iss` is not the peer
        // whose key it verifies under — same trust failure class as
        // a bad signature.
        IssuerMismatch => "TCT_SIGNATURE_INVALID",
        AudienceMismatch => "AUDIENCE_MISMATCH",
        // Proposal #72 Item 6b: a non-v4 `jti` uses the artifact's
        // structural-rejection code.
        JtiNotV4(_) => "TCT_SIGNATURE_INVALID",
        // Proposal #72 Item 5: a self-issued TCT, or the attestation
        // marker, in a grant context (owner decision 2026-10-16).
        SelfIssued | AttestationMarker => "TCT_SIGNATURE_INVALID",
        NotAttestation | AttestationStatementMissing(_) => "TCT_SIGNATURE_INVALID",
        Expired => "TCT_EXPIRED",
        ExpiresAfterManifest => "TCT_EXPIRES_AFTER_MANIFEST",
        Revoked | RevocationUnavailable(_) => "TCT_REVOKED",
        SafeSubsetEmpty => "POLICY_VIOLATION",
        EmptyGrants => "INVALID_ENVELOPE",
        GrantWhitespace(_) => "INVALID_ENVELOPE",
        CnfMalformed => "INVALID_ENVELOPE",
        ClaimsMalformed(_) => "INVALID_ENVELOPE",
        MissingField(_) => "INVALID_ENVELOPE",
        Canonicalization(_) => "INTERNAL_ERROR",
        // RFC-AITP-0005 §6.2: a stale challenge is the challenge's fault;
        // every other PoP failure is the response's.
        PopChallengeExpired => "POP_CHALLENGE_INVALID",
        PopNonceMismatch | PopFailed | PopJtiMismatch => "POP_RESPONSE_INVALID",
        Crypto(c) => return crypto_error_code(c, "TCT_SIGNATURE_INVALID"),
        // RFC-AITP-0001 §7 / issue #140: a JSON member outside the
        // artifact's declared member set (revocation snapshot envelope or
        // body, RFC-AITP-0008 §1.5) is a distinct structural-rejection
        // class from a malformed envelope — it must not fall into
        // `ClaimsMalformed`'s `INVALID_ENVELOPE` bucket above, nor into
        // the `_` catch-all below.
        UnknownField(_) => "UNKNOWN_FIELD",
        _ => "INTERNAL_ERROR",
    }
    .to_string()
}

/// Like `tct_error_code`, but for a revocation *snapshot* rather than a
/// TCT's own JWS (RFC-AITP-0008 §1.5 / registry §"Revocation codes").
/// `tct_error_code` stays untouched and shared with real `tct-*`
/// fixtures; this sibling overrides only the structural/signature arms a
/// revocation snapshot needs its own codes for.
///
/// An unknown `revocation_list.version` is `REVOCATION_SNAPSHOT_INVALID`,
/// not `UNKNOWN_VERSION` (issue #265): spec VERSIONING.md gives each
/// artifact its own unknown-version code, and a snapshot's is its
/// schema-failure code (the schema pins `version` to `aitp/0.3`).
/// `verify_revocation_list` checks `version` before the signature, so a
/// validly signed snapshot whose `version` is changed afterwards
/// (rev-010-version-unknown) reports this code, not a signature failure.
/// `IssuerMismatch` deliberately falls through to `TCT_SIGNATURE_INVALID`
/// via `tct_error_code` — same treatment as `ManifestError::AidMismatch`
/// in `manifest_error_code`, not a registry gap.
fn revocation_error_code(e: &aitp::tct::TctError) -> String {
    use aitp::tct::TctError::*;
    match e {
        // A non-v4 `entries[].jti` is a malformed snapshot, not a TCT.
        ClaimsMalformed(_) | JtiNotV4(_) | VersionUnknown => {
            "REVOCATION_SNAPSHOT_INVALID".to_string()
        }
        SignatureInvalid => "REVOCATION_SNAPSHOT_SIGNATURE_INVALID".to_string(),
        other => tct_error_code(other),
    }
}

/// `revocation_policy.mode` (RFC-AITP-0008 §3.1) for a request that
/// supplies a revocation snapshot to `verify_tct` or
/// `verify_delegation_token`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SnapshotPolicyMode {
    FailClosed,
    FailOpen,
    /// `soft_fail` with its configured safe-grant subset. An empty subset
    /// fails closed, as `aitp::transport::RevocationFailMode::SoftFail`
    /// does.
    SoftFail(Vec<String>),
}

impl SnapshotPolicyMode {
    /// Whether a TCT whose issuer's snapshot is absent counts as revoked.
    /// `soft_fail` with a non-empty subset does not: the caller narrows
    /// the grants instead.
    fn absent_is_revoked(&self) -> bool {
        match self {
            Self::FailClosed => true,
            Self::FailOpen => false,
            Self::SoftFail(safe) => safe.is_empty(),
        }
    }
}

/// The revocation policy a snapshot-consuming op applies when the
/// snapshot it was given is discarded.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotPolicy {
    mode: SnapshotPolicyMode,
    /// RFC-AITP-0008 §3.2. `None`: no staleness bound beyond the
    /// snapshot's own `expires_at`.
    max_staleness_secs: Option<i64>,
}

/// Read the revocation policy from a request. Fixtures spell it three
/// ways: `fail_mode` beside the snapshot (`tct-004`'s
/// `issuer_revocation_list`), `policy: {fail_mode, max_staleness_secs}`
/// (the `rev-*` fixtures) and the RFC-AITP-0008 §3 shape
/// `revocation_policy: {mode, max_staleness_secs}`. The first one that
/// names a mode wins. With none, the mode is `fail_closed`, the schema
/// default (RFC-AITP-0008 §3.1). An unrecognised mode is a malformed
/// request, never a reason to pick a mode.
fn snapshot_policy(
    params: &Value,
    beside_snapshot: Option<&Value>,
) -> Result<SnapshotPolicy, String> {
    let sources = [
        beside_snapshot,
        params.get("revocation_policy"),
        params.get("policy"),
    ];
    let mode_of = |s: &Value| s.get("fail_mode").or_else(|| s.get("mode")).cloned();
    let source = sources.into_iter().flatten().find(|s| mode_of(s).is_some());
    let mode_value = source.and_then(mode_of);
    let mode_str = match &mode_value {
        None => "fail_closed",
        Some(Value::String(s)) => s.as_str(),
        Some(_) => return Err("revocation policy mode must be a string".into()),
    };
    let mode = match mode_str {
        "fail_closed" => SnapshotPolicyMode::FailClosed,
        "fail_open" => SnapshotPolicyMode::FailOpen,
        "soft_fail" => SnapshotPolicyMode::SoftFail(
            source
                .and_then(|s| s.get("safe_grants"))
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|g| g.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        ),
        other => return Err(format!("unknown revocation policy mode {other:?}")),
    };
    let max_staleness_secs = sources
        .into_iter()
        .flatten()
        .find_map(|s| s.get("max_staleness_secs").and_then(|v| v.as_i64()));
    Ok(SnapshotPolicy {
        mode,
        max_staleness_secs,
    })
}

/// Parse and verify a fixture-supplied revocation snapshot for
/// `expected_issuer`. `Err` is `(error_code, message)` saying why the
/// snapshot was discarded: structure, unknown member, version,
/// signature, expiry, issuer or staleness.
///
/// For a hop issuer's (or a TCT issuer's) snapshot, RFC-AITP-0008 §1.5
/// (0.3.1-draft: for every discard reason) makes a discarded snapshot
/// *absent*, and the caller applies the policy mode (§3.1). It must never
/// read as "nothing is revoked" (issue #271). The code matters only for
/// the verifier's own deny list, which surfaces it as an error.
fn accepted_snapshot(
    snapshot: &Value,
    expected_issuer: &Aid,
    now: Timestamp,
    max_staleness_secs: Option<i64>,
) -> Result<aitp::tct::RevocationListEnvelope, (String, String)> {
    let env = aitp::tct::parse_revocation_snapshot_wire(&checked(snapshot))
        .map_err(|e| (revocation_error_code(&e), e.to_string()))?;
    let ctx = aitp::tct::RevocationListVerifyContext::new(expected_issuer, now);
    aitp::tct::verify_revocation_list(&env, &ctx).map_err(|e| {
        let code = match e {
            // No dedicated registry code: an expired snapshot is not one
            // the verifier may use, and one signed by another issuer does
            // not validate under the expected issuer's key.
            aitp::tct::TctError::Expired => "REVOCATION_SNAPSHOT_INVALID".to_string(),
            aitp::tct::TctError::IssuerMismatch => {
                "REVOCATION_SNAPSHOT_SIGNATURE_INVALID".to_string()
            }
            ref other => revocation_error_code(other),
        };
        (code, e.to_string())
    })?;
    if let Some(max) = max_staleness_secs {
        let age = now.0.saturating_sub(env.revocation_list.published_at.0);
        if age > max {
            return Err((
                "REVOCATION_SNAPSHOT_INVALID".to_string(),
                format!("snapshot stale ({age}s > {max}s)"),
            ));
        }
    }
    Ok(env)
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
    let claims = match aitp::tct::verify_voucher(token, &verifier_aid) {
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
fn voucher_error_code(e: &aitp::tct::TctError) -> String {
    use aitp::tct::TctError::*;
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
    // Hop issuers whose snapshot was discarded under a policy that
    // treats unknown status as revoked: every hop they issued is
    // revoked (DELEGATION_SOURCE_TCT_REVOKED). `soft_fail` has no
    // safe-subset model for a delegation chain, so only `fail_open`
    // lets such a hop through.
    let mut absent_issuers: HashSet<Aid> = HashSet::new();
    if let Some(arr) = params
        .get("revocation_snapshots")
        .and_then(|v| v.as_array())
    {
        for entry in arr {
            let policy = match snapshot_policy(&params, Some(entry)) {
                Ok(p) => p,
                Err(msg) => return err(id, "INVALID_REQUEST", &msg),
            };
            // An entry that cannot be attributed to an issuer is a
            // malformed request; skipping it would silently drop a
            // supplied snapshot (issue #271).
            let Some(issuer_str) = entry.get("issuer_aid").and_then(|v| v.as_str()) else {
                return err(
                    id,
                    "INVALID_REQUEST",
                    "revocation_snapshots[] entry is missing issuer_aid",
                );
            };
            let issuer_aid = match Aid::parse(issuer_str) {
                Ok(a) => a,
                Err(e) => {
                    return err(
                        id,
                        "INVALID_REQUEST",
                        &format!("revocation_snapshots[].issuer_aid: {e}"),
                    )
                }
            };
            let Some(snapshot) = entry.get("snapshot") else {
                return err(
                    id,
                    "INVALID_REQUEST",
                    "revocation_snapshots[] entry is missing snapshot",
                );
            };
            let env = match accepted_snapshot(snapshot, &issuer_aid, now, policy.max_staleness_secs)
            {
                Ok(env) => env,
                // The verifier's own deny list (RFC-AITP-0006 §4 step 7)
                // is local state, not a fetched snapshot, so the
                // revocation policy does not govern it: one it cannot
                // trust is an error, never "nothing is revoked" (issue
                // #140 hazard 4, issue #271).
                Err((code, msg)) if issuer_aid == verifier_aid => {
                    return err(
                        id,
                        &code,
                        &format!("revocation_snapshots[].snapshot: {msg}"),
                    )
                }
                // A hop issuer's snapshot (RFC-AITP-0011 §6) discarded for
                // any reason is absent (RFC-AITP-0008 §1.5 / §3.1,
                // 0.3.1-draft) and the policy mode decides below.
                Err(_) => {
                    if policy.mode != SnapshotPolicyMode::FailOpen {
                        absent_issuers.insert(issuer_aid);
                    }
                    continue;
                }
            };
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
    // An empty deny list is an explicit "nothing revoked" here: the
    // harness supplied every snapshot it has, and absent hop issuers are
    // already folded into `absent_issuers` by policy.
    let status = |revoked: bool| {
        Ok(if revoked {
            aitp::tct::RevocationStatus::Revoked
        } else {
            aitp::tct::RevocationStatus::Clear
        })
    };
    let revocation_check_closure =
        |q: &aitp::tct::RevocationQuery<'_>| status(own_denied.contains(q.jti));
    let hop_revocation_closure = |q: &aitp::tct::RevocationQuery<'_>| {
        status(
            absent_issuers.contains(q.issuer)
                || deny_lists.get(q.issuer).is_some_and(|s| s.contains(q.jti)),
        )
    };

    let issuer_manifests = match delegation_issuer_manifests(&params) {
        Ok(m) => m,
        Err((code, msg)) => return err(id, &code, &msg),
    };
    let revocation = aitp::tct::RevocationSource::Check(&revocation_check_closure);
    // Multi-hop opt-in. Per RFC-AITP-0006 §4 the default MUST reject any
    // chain-bearing token; the runner enables RFC-AITP-0011 semantics by
    // sending `set_features` with `experimental-multihop-delegation`.
    let scope = if state.has_feature("experimental-multihop-delegation") {
        let ctx =
            aitp_experimental::delegation::ChainVerifyContext::new(&verifier_aid, now, revocation)
                .with_issuer_manifests(&issuer_manifests)
                .with_hop_revocation_check(&hop_revocation_closure);
        aitp_experimental::delegation::verify_chained_delegation(&token, &ctx)
            .map(|v| v.effective_grants)
            .map_err(|e| (chained_delegation_error_code(&e), e.to_string()))
    } else {
        let ctx = aitp::delegation::DelegationVerifyContext::new(&verifier_aid, now, revocation)
            .with_issuer_manifests(&issuer_manifests);
        aitp::delegation::verify_delegation(&token, &ctx)
            .map(|v| v.into_parts().effective_grants)
            .map_err(|e| (delegation_error_code(&e), e.to_string()))
    };
    match scope {
        Ok(scope) => json!({
            "id": id,
            "ok": true,
            "result": {"verified": true, "grants": scope}
        }),
        Err((code, msg)) => err(id, &code, &msg),
    }
}

/// The Manifest source for delegation verification: the single-hop
/// token (RFC-AITP-0006 §4 step 1) and every multi-hop hop
/// (RFC-AITP-0011 §3 step 1) verify under the key resolved from the
/// issuer's Manifest.
///
/// The request's `issuer_manifests` (each a Manifest or a
/// `{"manifest": …}` envelope, parsed with the §7 member check) is the
/// verifier's whole Manifest source: no key is derived from an issuer
/// AID and no Manifest is synthesized, so an issuer without one here
/// fails with `KEY_RESOLUTION_FAILED` (conformance README, "Manifest
/// inputs").
fn delegation_issuer_manifests(params: &Value) -> Result<Vec<Manifest>, (String, String)> {
    let mut manifests = Vec::new();
    for v in params
        .get("issuer_manifests")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let m = v.get("manifest").unwrap_or(v);
        let parsed = aitp::manifest::parse_manifest_wire(&checked(m))
            .map_err(|e| (manifest_error_code(&e), format!("issuer_manifests[]: {e}")))?;
        manifests.push(parsed);
    }
    Ok(manifests)
}

fn delegation_error_code(e: &aitp::delegation::DelegationError) -> String {
    use aitp::delegation::DelegationError::*;
    match e {
        Expired => "DELEGATION_EXPIRED",
        InvalidSignature => "DELEGATION_INVALID_SIGNATURE",
        ScopeExceeded => "DELEGATION_SCOPE_EXCEEDED",
        InvalidVoucher => "DELEGATION_INVALID_VOUCHER",
        SourceTctRevoked | RevocationUnavailable(_) => "DELEGATION_SOURCE_TCT_REVOKED",
        SafeSubsetEmpty => "POLICY_VIOLATION",
        AudienceMismatch => "AUDIENCE_MISMATCH",
        PopFailed => "POP_RESPONSE_INVALID",
        MultihopNotSupported => "DELEGATION_MULTIHOP_NOT_SUPPORTED",
        VersionUnknown => "UNKNOWN_VERSION",
        // RFC-AITP-0006 §4 step 10: self-delegation maps to
        // DELEGATION_INVALID_SIGNATURE (same code as a bad outer sig).
        SelfDelegation => "DELEGATION_INVALID_SIGNATURE",
        EmptyScope | CnfMalformed | MissingField(_) | ClaimsMalformed(_) => "INVALID_ENVELOPE",
        // Crypto errors surface from JWS-layer verification. A plain
        // bad signature here can only come from the embedded voucher
        // (the outer token's bad signature maps to InvalidSignature
        // in `aitp::delegation`) — hence DELEGATION_INVALID_VOUCHER.
        Crypto(c) => return crypto_error_code(c, "DELEGATION_INVALID_VOUCHER"),
        UnknownField(_) => "UNKNOWN_FIELD",
        // RFC-AITP-0006 §4 step 1 / RFC-AITP-0011 §3 step 1 +
        // RFC-AITP-0007 §1: the delegation (or hop) issuer's Manifest
        // could not be obtained, did not verify, or does not designate
        // the issuer's AID.
        KeyResolutionFailed { .. } => "KEY_RESOLUTION_FAILED",
        _ => "INTERNAL_ERROR",
    }
    .to_string()
}

fn chained_delegation_error_code(
    e: &aitp_experimental::delegation::ChainedDelegationError,
) -> String {
    use aitp_experimental::delegation::ChainedDelegationError::*;
    match e {
        Delegation(d) => return delegation_error_code(d),
        HopLimitExceeded => "DELEGATION_HOP_LIMIT_EXCEEDED",
        ChainHashMismatch => "DELEGATION_CHAIN_HASH_MISMATCH",
        // Spec PR C: a non-v4 hop `jti` is a signature-class reject.
        JtiNotV4(_) => "DELEGATION_INVALID_SIGNATURE",
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
        use rand::TryRng;
        match rand::rngs::SysRng.try_fill_bytes(&mut s) {
            Ok(()) => {}
            Err(e) => return err(id, "INTERNAL_ERROR", &e.to_string()),
        }
        s
    };
    let key = AitpSigningKey::from_ed25519_seed(&seed);
    let aid = key.aid().as_str().to_string();
    let pubkey = base64url::encode(
        &key.verifying_key()
            .try_to_ed25519_bytes()
            .expect("key was constructed as Ed25519, never P-256"),
    );
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
    let trust_anchors: Vec<aitp::core::RawUrl> = params
        .get("accepted_trust_anchors")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(aitp::core::RawUrl::from))
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
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);

    let mut b = ManifestBuilder::new(key)
        .handshake_endpoint(endpoint)
        .identity_hint(identity_hint)
        .ttl(std::time::Duration::from_secs(ttl))
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
    // Absent leaves the field off the Manifest, which means `["oidc"]`
    // (RFC-AITP-0003 §3.2).
    if let Some(types) = params
        .get("accepted_identity_types")
        .and_then(|v| v.as_array())
    {
        for t in types {
            match identity_kind(t) {
                Some(kind) => b = b.accept_identity_type(kind),
                None => {
                    return err(
                        id,
                        "INVALID_REQUEST",
                        "unknown accepted_identity_types entry",
                    )
                }
            }
        }
    }
    let manifest = match b.build() {
        Ok(m) => m,
        Err(e) => return err(id, "INTERNAL_ERROR", &e.to_string()),
    };
    let env = ManifestEnvelope::new(manifest);
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
            Ok(IdentityHint::new(IdentityKind::Oidc, subject).with_issuer(issuer))
        }
        "pinned_key" => {
            let pk = v
                .get("public_key")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "pinned_key identity_hint.public_key missing".to_string())?
                .to_string();
            Ok(IdentityHint::new(IdentityKind::PinnedKey, subject).with_public_key(pk))
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
    let subject_pubkey = match AitpVerifyingKey::from_ed25519_bytes(&buf) {
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
        .and_then(|v| v.as_u64())
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
        .ttl(std::time::Duration::from_secs(ttl))
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
            "tct_token": issued.token(),
            "tct_claims": issued.claims(),
            "grant_voucher": issued.voucher(),
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
        .and_then(|v| v.as_u64())
        .unwrap_or(1800);

    // Single-hop: the delegator presents the grant voucher its TCT
    // issuer minted for it (`voucher` / `grant_voucher`, a compact
    // JWS). Multi-hop extension: `prior_token` is the delegation the
    // delegator received and is extending; it and a per-hop `jti` are
    // RFC-AITP-0011 and mint with `aitp_experimental::delegation`.
    let voucher = params
        .get("voucher")
        .or_else(|| params.get("grant_voucher"))
        .or_else(|| params.get("voucher_token"))
        .and_then(|v| v.as_str());
    let prior = params.get("prior_token").and_then(|v| v.as_str());
    let jti = params
        .get("jti")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());
    let now = state.now();
    use aitp_experimental::delegation::ChainedDelegationBuilder;
    let chained = |builder: Result<ChainedDelegationBuilder<'_>, _>| {
        builder
            .and_then(|b| {
                let b = b
                    .delegatee(delegatee.clone())
                    .scope(scope.clone())
                    .ttl(std::time::Duration::from_secs(ttl))
                    .now(now);
                match jti {
                    Some(jti) => b.jti(jti),
                    None => b,
                }
                .build()
            })
            .map_err(|e| (chained_delegation_error_code(&e), e.to_string()))
    };
    let token = match (voucher, prior) {
        (Some(voucher), _) if jti.is_none() => DelegationBuilder::new(delegator, voucher)
            .and_then(|b| {
                b.delegatee(delegatee)
                    .scope(scope)
                    .ttl(std::time::Duration::from_secs(ttl))
                    .now(now)
                    .build()
            })
            .map(|issued| issued.into_parts().token)
            .map_err(|e| (delegation_error_code(&e), e.to_string())),
        (Some(voucher), _) => chained(ChainedDelegationBuilder::new(delegator, voucher)),
        (None, Some(prior)) => chained(ChainedDelegationBuilder::extending(delegator, prior)),
        (None, None) => {
            return err(
                id,
                "INVALID_REQUEST",
                "missing 'voucher' (single-hop) or 'prior_token' (multi-hop extension)",
            )
        }
    };
    match token {
        Ok(token) => json!({"id": id, "ok": true, "result": {"delegation_token": token}}),
        Err((code, msg)) => err(id, &code, &msg),
    }
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
    let env = AitpEnvelope::unsigned(key.aid().clone(), mt, payload, message_id, timestamp);
    let env = match sign_unsigned_envelope(key, env) {
        Ok(env) => env,
        Err(e) => return err(id, "INTERNAL_ERROR", &e.to_string()),
    };
    json!({"id": id, "ok": true, "result": {"envelope": env}})
}

/// Set `envelope.signature` over the RFC-AITP-0001 §5.4 digest of the
/// whole envelope minus `signature` (`aitp-envelope-v2` input).
fn sign_unsigned_envelope(
    key: &AitpSigningKey,
    mut envelope: AitpEnvelope,
) -> Result<AitpEnvelope, aitp::core::jcs::JcsError> {
    let digest = aitp::core::envelope_signing_digest(&envelope)?;
    envelope.signature = key
        .sign_jcs(&aitp::crypto::Digest32::from(digest))
        .into_string();
    Ok(envelope)
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
            let trusted = harness_pinned_trust(&params, &peer_aid);
            start_initiator(
                state,
                id,
                handle,
                manifest,
                peer_aid,
                requested_grants,
                trusted,
            )
        }
        "responder" => {
            let session_id = state.fresh_session_id();
            state.sessions.insert(
                session_id.clone(),
                HandshakeSession::PendingResponder {
                    keypair_handle: handle,
                    my_manifest: manifest,
                    my_requested_grants: requested_grants,
                    trusted: trust_store_param(&params),
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

/// The fixture's explicit pinned-key trust store: `params.trust_store`,
/// a list whose entries are AID strings (Ed25519 or P-256) or
/// trust-anchors `pinned_keys` objects (`{subject, public_key,
/// algorithm?}`). Entries that do not parse are skipped, so a fixture can
/// list a deliberately malformed key.
fn trust_store_param(params: &Value) -> Option<StaticPinnedKeyStore> {
    let entries = params.get("trust_store")?.as_array()?;
    Some(
        entries
            .iter()
            .filter_map(|v| match v {
                Value::String(aid) => Aid::parse(aid)
                    .ok()
                    .and_then(|aid| AitpVerifyingKey::from_aid(&aid).ok()),
                Value::Object(_) => serde_json::from_value::<PinnedKeyEntry>(v.clone())
                    .ok()
                    .and_then(|e| e.verifying_key().ok()),
                _ => None,
            })
            .collect(),
    )
}

/// Conformance-harness trust policy. The library has no possession-only
/// mode (RFC-AITP-0002 §3.2 step 3), so every handshake the adapter
/// drives has a store. A fixture that supplies `trust_store` gets exactly
/// that. A fixture that does not is taken to declare its peer
/// (`declared_peer`: the peer manifest for an initiator, the HELLO
/// sender for a responder or a bootstrap vector) as pinned. This is
/// harness configuration standing in for an operator's `pinned_keys`,
/// not library behaviour.
fn harness_pinned_trust(params: &Value, declared_peer: &Aid) -> StaticPinnedKeyStore {
    trust_store_param(params).unwrap_or_else(|| {
        AitpVerifyingKey::from_aid(declared_peer)
            .map(|k| StaticPinnedKeyStore::new([k]))
            .unwrap_or_default()
    })
}

fn start_initiator(
    state: &mut AdapterState,
    id: &str,
    handle: String,
    manifest: Manifest,
    peer_aid: Aid,
    requested_grants: Vec<String>,
    trusted: StaticPinnedKeyStore,
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
    let cfg = PeerConfig::new(&key, &manifest, &resolver, &trusted, HARNESS_REVOCATION, ts);
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
            trusted,
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
            trusted,
        } => initiator_step(
            state,
            id,
            session_id,
            envelope,
            initiator,
            keypair_handle,
            my_manifest,
            trusted,
        ),
        HandshakeSession::PendingResponder {
            keypair_handle,
            my_manifest,
            my_requested_grants,
            trusted,
        } => responder_first_hello(
            state,
            id,
            session_id,
            envelope,
            keypair_handle,
            my_manifest,
            my_requested_grants,
            trusted,
        ),
        HandshakeSession::ActiveResponder {
            state: responder,
            keypair_handle,
            my_manifest,
        } => responder_step(state, id, envelope, responder, keypair_handle, my_manifest),
    }
}

// One parameter per field of the `HandshakeSession` variant it consumes.
#[allow(clippy::too_many_arguments)]
fn initiator_step(
    state: &mut AdapterState,
    id: &str,
    session_id: String,
    envelope: AitpEnvelope,
    mut initiator: Initiator,
    keypair_handle: String,
    my_manifest: Manifest,
    trusted: StaticPinnedKeyStore,
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
    let cfg = PeerConfig::new(
        &key,
        &my_manifest,
        &resolver,
        &trusted,
        HARNESS_REVOCATION,
        state.now(),
    );
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
                    trusted,
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

// One parameter per field of the `HandshakeSession` variant it consumes.
#[allow(clippy::too_many_arguments)]
fn responder_first_hello(
    state: &mut AdapterState,
    id: &str,
    session_id: String,
    envelope: AitpEnvelope,
    keypair_handle: String,
    my_manifest: Manifest,
    my_requested_grants: Vec<String>,
    trusted: Option<StaticPinnedKeyStore>,
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
    let hello_payload: aitp::handshake::MutualHelloPayload =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(p) => p,
            Err(e) => return err(id, "INVALID_ENVELOPE", &format!("hello: {e}")),
        };
    // Cache the peer's manifest so commit-side can look it up.
    state.peer_manifests.insert(
        hello_payload.manifest.aid.as_str().to_string(),
        hello_payload.manifest.clone(),
    );

    let trusted =
        trusted.unwrap_or_else(|| harness_pinned_trust(&Value::Null, &hello_payload.manifest.aid));
    let resolver = NoOpJwks;
    let cfg = PeerConfig::new(
        &key,
        &my_manifest,
        &resolver,
        &trusted,
        HARNESS_REVOCATION,
        state.now(),
    );
    let identity = PresentedIdentity::PinnedKey {
        subject: my_manifest
            .display_name
            .clone()
            .unwrap_or_else(|| "responder".into()),
    };
    let ack_mid = Uuid::new_v4();
    let ack_ts = state.now();
    let (responder, ack_payload) = match aitp::handshake::Responder::on_hello(
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
    mut responder: aitp::handshake::Responder,
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
    let commit_payload: aitp::handshake::MutualCommitPayload =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(p) => p,
            Err(e) => return err(id, "INVALID_ENVELOPE", &format!("commit: {e}")),
        };
    let resolver = NoOpJwks;
    let cfg = PeerConfig::new(
        &key,
        &my_manifest,
        &resolver,
        &aitp::handshake::NoPinnedKeys,
        HARNESS_REVOCATION,
        state.now(),
    );
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

/// JSON view of a [`aitp::handshake::CompletedHandshake`]: the verbatim
/// peer-issued TCT token, its trusted claims, and the companion grant
/// voucher (verbatim) when the peer's policy allowed delegation.
fn completed_handshake_json(c: &aitp::handshake::CompletedHandshake) -> Value {
    json!({
        "tct_token": c.tct().token(),
        "tct_claims": c.tct().claims(),
        "grant_voucher": c.grant_voucher(),
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
    let envelope = AitpEnvelope::unsigned(key.aid().clone(), mt, payload_value, mid, ts);
    sign_unsigned_envelope(key, envelope).expect("digest")
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
    let env: aitp::tct::RevocationListEnvelope =
        match aitp::tct::parse_revocation_snapshot_wire(&checked(&env_value)) {
            Ok(e) => e,
            Err(e) => {
                return err(
                    id,
                    &revocation_error_code(&e),
                    &format!("revocation_list: {e}"),
                )
            }
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
    let ctx = aitp::tct::RevocationListVerifyContext::new(&expected_issuer, now);
    if let Err(e) = aitp::tct::verify_revocation_list(&env, &ctx) {
        return err(id, &revocation_error_code(&e), &e.to_string());
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
        use rand::TryRng;
        if let Err(e) = rand::rngs::SysRng.try_fill_bytes(&mut nonce_bytes) {
            return err(id, "INTERNAL_ERROR", &e.to_string());
        }
        base64url::encode(&nonce_bytes)
    };
    let challenge =
        aitp::tct::PopChallenge::new(tct.jti, nonce.clone(), Timestamp(state.now().0 + ttl_secs));
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
            let pop_input = aitp::crypto::Digest32::sha256(&nonce_bytes);
            let parsed_sig = match aitp::crypto::Signature::parse(sig) {
                Ok(s) => s,
                Err(_) => return err(id, "POP_RESPONSE_INVALID", "pop_signature parse"),
            };
            if holder_pubkey.verify_jcs(&pop_input, &parsed_sig).is_err() {
                return err(id, "POP_RESPONSE_INVALID", "pop_signature verify");
            }
            // Stash the synthetic PopResponse so verify_pop_response can
            // pick it up.
            let expires_at = Timestamp(state.now().0 + 300);
            state.pop_challenges.entry(tct.jti.to_string()).or_insert(
                aitp::tct::PopChallenge::new(tct.jti, echo.to_string(), expires_at),
            );
            return json!({
                "id": id,
                "ok": true,
                "result": {"verified": true, "nonce_echo": echo}
            });
        }
    }

    let challenge: aitp::tct::PopChallenge = match params.get("challenge") {
        Some(v) => match serde_json::from_value(v.clone()) {
            Ok(c) => c,
            Err(e) => {
                return err(
                    id,
                    "POP_CHALLENGE_INVALID",
                    &format!("challenge parse: {e}"),
                )
            }
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
    let response = match aitp::tct::sign_pop_response(&challenge, &key) {
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
    let response: aitp::tct::PopResponse =
        match serde_json::from_value(params.get("response").cloned().unwrap_or_default()) {
            Ok(r) => r,
            Err(e) => return err(id, "POP_RESPONSE_INVALID", &format!("response parse: {e}")),
        };
    let tct = match tct_claims_from_params(&params) {
        Ok(t) => t,
        Err(e) => return err(id, "INVALID_ENVELOPE", &format!("tct parse: {e}")),
    };
    let challenge: aitp::tct::PopChallenge = if let Some(v) = params.get("challenge") {
        match serde_json::from_value(v.clone()) {
            Ok(c) => c,
            Err(e) => {
                return err(
                    id,
                    "POP_CHALLENGE_INVALID",
                    &format!("challenge parse: {e}"),
                )
            }
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
    match aitp::tct::verify_pop_response(&challenge, &response, &tct, state.now()) {
        Ok(()) => json!({"id": id, "ok": true, "result": {"verified": true}}),
        Err(e) => err(id, &tct_error_code(&e), &e.to_string()),
    }
}

/// `verify_tct_as_issuer`: the issuer receives back a TCT it issued,
/// with one `pop_response` envelope answering a challenge it issued
/// (RFC-AITP-0005 §10.5, `tct-027` to `tct-029`). The presenter AID
/// comes only from the PoP: there is no channel binding here, and no
/// `expected_audience` input (item 5).
fn verify_tct_as_issuer_op(state: &AdapterState, id: &str, params: Value) -> Value {
    let self_aid: Aid = match params
        .get("self_aid")
        .map(|v| serde_json::from_value(v.clone()))
    {
        Some(Ok(a)) => a,
        Some(Err(e)) => return err(id, "INVALID_REQUEST", &format!("self_aid: {e}")),
        None => return err(id, "INVALID_REQUEST", "missing 'self_aid'"),
    };
    let token = match params.get("tct_token").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return err(id, "INVALID_REQUEST", "missing 'tct_token'"),
    };
    let now = state.now();

    // Items 1 and 2: §7.2 with the verifier as issuer and its own key.
    // The audience is read from the issuer's side, `aud` == `sub`; item
    // 3 then proves `sub` is the presenter, so this compares `aud` with
    // the PoP-proven AID, never with a value the token alone vouches for.
    // Revocation is deferred to item 6.
    let Some(sub) = peek_token_aid_claim(token, "sub") else {
        return err(id, "TCT_SIGNATURE_INVALID", "TCT has no decodable sub");
    };
    let ctx = aitp::tct::TctVerifyContext::builder()
        .expected_audience(&sub)
        .issuer(&self_aid)
        .now(now)
        .skip_manifest_expiry_cap_dangerous()
        .revocation(aitp::tct::RevocationSource::FailOpen)
        .build()
        .expect("both verify decisions are made above");
    let claims = match aitp::tct::verify_tct(token, &ctx) {
        Ok(v) => v.into_parts().claims,
        // An `aud` other than `sub` is the issuer-side audience failure.
        Err(aitp::tct::TctError::AudienceMismatch) => {
            return err(id, "TCT_SIGNATURE_INVALID", "aud differs from sub")
        }
        Err(e) => return err(id, &tct_error_code(&e), &e.to_string()),
    };

    // Item 3: downstream PoP over a challenge this verifier issued for
    // the token's `jti`. No response, or any §6.2 failure, is
    // POP_RESPONSE_INVALID; a stale or malformed challenge is
    // POP_CHALLENGE_INVALID.
    let Some(envelope_value) = params.get("envelope") else {
        return err(id, "POP_RESPONSE_INVALID", "no pop_response");
    };
    let mut envelope = match aitp::core::parse_envelope_wire(&checked(envelope_value)) {
        Ok(e) => e,
        Err(e) => return err(id, "POP_RESPONSE_INVALID", &format!("envelope parse: {e}")),
    };
    strip_claims_companions(&mut envelope.payload);
    if envelope.message_type != MessageType::PopResponse {
        return err(id, "POP_RESPONSE_INVALID", "envelope is not a pop_response");
    }
    let envelope_verified = AitpVerifyingKey::from_aid(&envelope.sender.agent_id)
        .ok()
        .zip(aitp::core::envelope_signing_digest(&envelope).ok())
        .zip(Signature::parse(&envelope.signature).ok())
        .is_some_and(|((pk, digest), sig)| {
            pk.verify_jcs(&aitp::crypto::Digest32::from(digest), &sig)
                .is_ok()
        });
    if !envelope_verified {
        return err(
            id,
            "POP_RESPONSE_INVALID",
            "pop_response envelope signature",
        );
    }
    let response: aitp::tct::PopResponse = match serde_json::from_value(envelope.payload.clone()) {
        Ok(r) => r,
        Err(e) => return err(id, "POP_RESPONSE_INVALID", &format!("pop_response: {e}")),
    };
    let mut challenge = None;
    for entry in params
        .get("outstanding_pop_challenges")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        match serde_json::from_value::<aitp::tct::PopChallenge>(entry.clone()) {
            Ok(c) if c.tct_jti == claims.jti => challenge = Some(c),
            Ok(_) => {}
            Err(e) => return err(id, "POP_CHALLENGE_INVALID", &format!("challenge: {e}")),
        }
    }
    let Some(challenge) = challenge else {
        return err(
            id,
            "POP_RESPONSE_INVALID",
            &format!("no outstanding PoP challenge for jti {}", claims.jti),
        );
    };
    if let Err(e) = aitp::tct::verify_pop_response(&challenge, &response, &claims, now) {
        return err(id, &tct_error_code(&e), &e.to_string());
    }

    // Item 4: presenter AID == `sub` == `aud`. The PoP signature verified
    // under the `sub` key, and the envelope must come from that AID too.
    let presenter = &claims.sub;
    if envelope.sender.agent_id != *presenter || claims.aud != *presenter {
        return err(
            id,
            "POP_RESPONSE_INVALID",
            "pop_response sender is not the TCT subject",
        );
    }

    // Item 6: revocation against the issuer's own deny list, last.
    if state.revoked_jtis.contains(&claims.jti.to_string()) {
        return err(id, "TCT_REVOKED", &format!("jti {} is revoked", claims.jti));
    }
    json!({
        "id": id,
        "ok": true,
        "result": {
            "verified": true,
            "presenter_aid": presenter,
            "grants": claims.grants,
            "side_effects": {"capability_authorized": true},
        }
    })
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

/// `begin_fixture`: the runner starts a new fixture. Drops state that a
/// fixture's sequence carries across its steps (the pinned-admission
/// verifier), so one fixture's consumed nonces and recorded
/// `message_id`s never leak into the next.
fn begin_fixture_op(state: &mut AdapterState, id: &str) -> Value {
    state.admission = None;
    state.renewal_nonces = None;
    json!({"id": id, "ok": true, "result": {}})
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

/// Re-enter a request sub-value as a [`CheckedJson`] for the
/// `parse_*_wire` functions.
///
/// The adapter's dispatch navigates (and occasionally edits) a `Value`
/// built from one NDJSON request line, and `main.rs` already ran the
/// RFC-AITP-0001 §5.4.5 duplicate-key check on that line's raw bytes
/// before the `Value` existed. A sub-tree of a checked document carries
/// no duplicate key, so re-serializing it and parsing it back through
/// [`CheckedJson`]'s only constructor cannot fail on that ground; it keeps
/// the parsers' input type honest instead of adding an unchecked
/// `Value -> CheckedJson` escape hatch to `aitp::core`.
pub(crate) fn checked(v: &Value) -> CheckedJson {
    v.to_string()
        .parse()
        .expect("a serialized serde_json::Value is valid JSON with no duplicate key")
}

fn err(id: &str, code: &str, message: &str) -> Value {
    json!({"id": id, "ok": false, "error_code": code, "message": message})
}

// ── Session Trust Bundle (RFC-AITP-0010) ────────────────────────────────

fn issue_session_bundle_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    use aitp_experimental::session_bundle::SessionBundleBuilder;

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
    use aitp_experimental::session_bundle::{
        verify_session_bundle, BundleOutcome, CoordinatorKeySource, SessionBundleVerifyContext,
    };

    // RFC-AITP-0010 §3 wire form: `{"session_bundle": {<body>}}`, where
    // `signature` is a member of the inner body (spec commit 45b5ef978e13
    // corrected the schema and all `bundle-*` fixtures to this shape).
    // `parse_session_bundle_wire` unwraps the transport envelope and
    // rejects any sibling member beside `session_bundle` as
    // `WireFormInvalid` — notably the pre-erratum shape where `signature`
    // sat OUTSIDE the wrapped body (`bundle-004-signature-sibling-rejected`).
    // An unknown member of the inner body itself is a separate class,
    // `UnknownField` (RFC-AITP-0001 §7, `bundle-006-unknown-field-rejected`).
    // Accept either:
    //
    // - `params.session_bundle = {<body with signature inside>}`
    //   (legacy internal callers, no envelope)
    // - `params.session_bundle = {"session_bundle": {<body with signature
    //   inside>}}` (spec wire envelope; `bundle-*` conformance fixtures)
    // - `params.bundle_envelope = <envelope>` (same shape, alternate key)
    let mut wire_value = if let Some(inner) = params.get("session_bundle") {
        inner.clone()
    } else if let Some(env) = params.get("bundle_envelope") {
        env.clone()
    } else {
        return err(id, "INVALID_REQUEST", "missing 'session_bundle'");
    };
    // Participant entries may carry `tct_claims` companions (the
    // claims-sibling minting convention); they are never wire bytes. Must
    // run BEFORE parsing: it mutates the raw wire value (stripping a
    // per-participant key), not the deserialized bundle.
    strip_claims_companions(&mut wire_value);
    let bundle =
        match aitp_experimental::session_bundle::parse_session_bundle_wire(&checked(&wire_value)) {
            Ok(b) => b,
            Err(e) => return err(id, &bundle_error_code(&e), &e.to_string()),
        };
    // RFC-AITP-0010 §5 step 5: the coordinator's key is resolved from
    // the coordinator's own verified Manifest (bare body or
    // `{"manifest": …}` envelope). There is no AID-only fallback here:
    // without a Manifest no key can be resolved, which is
    // KEY_RESOLUTION_FAILED (RFC-AITP-0007 §1), as is a Manifest that
    // designates another AID (`bundle-007`, mapped in `bundle_error_code`).
    let coordinator_manifest = match params.get("coordinator_manifest") {
        Some(v) => match aitp::manifest::parse_manifest_wire(&checked(v)) {
            Ok(m) => m,
            Err(e) => return err(id, &manifest_error_code(&e), &e.to_string()),
        },
        None => {
            return err(
                id,
                "KEY_RESOLUTION_FAILED",
                "missing 'coordinator_manifest': the coordinator key is resolved from its Manifest (RFC-AITP-0010 §5 step 5)",
            )
        }
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
    let ctx = SessionBundleVerifyContext {
        verifier_aid: &verifier_aid,
        now,
        revocation_check,
        coordinator_key: CoordinatorKeySource::Manifest(&coordinator_manifest),
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
fn bundle_error_code(e: &aitp_experimental::session_bundle::SessionBundleError) -> String {
    use aitp_experimental::session_bundle::SessionBundleError::*;
    match e {
        VersionMismatch => "BUNDLE_VERSION_MISMATCH",
        InvalidSignature => "BUNDLE_INVALID_SIGNATURE",
        Expired => "BUNDLE_EXPIRED",
        ExpiryWindowInvariant => "BUNDLE_EXPIRY_WINDOW_INVARIANT",
        CoordinatorIssuerMismatch => "BUNDLE_COORDINATOR_ISSUER_MISMATCH",
        AudienceMismatch => "BUNDLE_AUDIENCE_MISMATCH",
        NotMember => "BUNDLE_NOT_MEMBER",
        EmptyParticipants => "BUNDLE_EMPTY_PARTICIPANTS",
        CoordinatorManifest(e) => return manifest_error_code(e),
        // The Manifest does not designate the coordinator, so the
        // coordinator's key cannot be resolved (RFC-AITP-0010 §5 step 5,
        // RFC-AITP-0007 §1; `bundle-007`).
        CoordinatorManifestMismatch => "KEY_RESOLUTION_FAILED",
        MissingField(_) => "INVALID_REQUEST",
        Canonicalization(_) => "INTERNAL_ERROR",
        TctVerification(_) => "BUNDLE_PARTICIPANT_TCT_INVALID",
        // Our own signing backend failed: a local fault, never the peer's.
        Crypto(CryptoError::Signer(_)) => "INTERNAL_ERROR",
        Crypto(_) => "INVALID_SIGNATURE",
        WireFormInvalid(_) => "SESSION_BUNDLE_INVALID",
        UnknownField(_) => "UNKNOWN_FIELD",
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
        let message_id = Uuid::from_u128(0x0102_0304_0506_4708_890a_0b0c_0d0e_0f10);
        let timestamp = Timestamp(1_700_000_000);
        let payload = json!({"hello": "p256"});
        let envelope = AitpEnvelope::unsigned(
            key.aid().clone(),
            MessageType::MutualHello,
            payload,
            message_id,
            timestamp,
        );
        let envelope = sign_unsigned_envelope(&key, envelope).unwrap();
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

    fn verify_code(env: Value) -> Value {
        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "env-check-order",
            "verify_envelope",
            json!({ "envelope": env }),
        );
        assert_eq!(out["ok"], json!(false), "got: {out}");
        out["error_code"].clone()
    }

    /// RFC-AITP-0001 §5.4 check order (env-008..env-011 shapes):
    /// `version` → member set → signature. A changed `message_type` or
    /// `extensions` under a known version is INVALID_SIGNATURE (both are
    /// signed); an unknown version wins over an unknown member and a bad
    /// signature; a correctly signed `aitp/0.2` envelope is
    /// UNKNOWN_VERSION (strict cutover).
    #[test]
    fn adapter_envelope_check_order() {
        let mut mt = p256_signed_envelope();
        mt["message_type"] = json!("mutual_hello_ack");
        assert_eq!(verify_code(mt), json!("INVALID_SIGNATURE"));

        let mut ext = p256_signed_envelope();
        ext["extensions"] = json!({"com.example.debug_trace": "x"});
        assert_eq!(verify_code(ext), json!("INVALID_SIGNATURE"));

        let mut ver = p256_signed_envelope();
        ver["version"] = json!("aitp/9.9");
        ver["trace_id"] = json!("rogue");
        assert_eq!(verify_code(ver), json!("UNKNOWN_VERSION"));

        let key = AitpSigningKey::from_p256_seed(&[0x42; 32]).unwrap();
        let mut prev: AitpEnvelope = serde_json::from_value(p256_signed_envelope()).unwrap();
        prev.version = "aitp/0.2".into();
        let prev = sign_unsigned_envelope(&key, prev).unwrap();
        assert_eq!(
            verify_code(serde_json::to_value(prev).unwrap()),
            json!("UNKNOWN_VERSION")
        );

        let mut field = p256_signed_envelope();
        field["trace_id"] = json!("rogue");
        field["signature"] = json!("A".repeat(86));
        assert_eq!(verify_code(field), json!("UNKNOWN_FIELD"));
    }

    /// Issue #255, RFC-AITP-0009 §3.1: the timestamp window runs before
    /// the §5.4 checks, so a stale envelope with an unknown or absent
    /// `version` or an unknown member is TIMESTAMP_EXPIRED. An unreadable
    /// `timestamp` skips the window and fails the structural step.
    #[test]
    fn adapter_timestamp_window_precedes_envelope_checks() {
        let code = |env: Value, now: i64| {
            let mut state = AdapterState::default();
            let out = handle(
                &mut state,
                "env-window-order",
                "verify_envelope",
                json!({ "envelope": env, "tolerance_seconds": 300, "now": now }),
            );
            out["error_code"].clone()
        };
        // p256_signed_envelope() is stamped 1_700_000_000.
        let stale = 1_700_000_000 + 301;

        let mut ver = p256_signed_envelope();
        ver["version"] = json!("aitp/9.9");
        assert_eq!(code(ver, stale), json!("TIMESTAMP_EXPIRED"));
        let mut no_ver = p256_signed_envelope();
        no_ver.as_object_mut().unwrap().remove("version");
        assert_eq!(code(no_ver.clone(), stale), json!("TIMESTAMP_EXPIRED"));
        let mut field = p256_signed_envelope();
        field["trace_id"] = json!("rogue");
        assert_eq!(code(field, stale), json!("TIMESTAMP_EXPIRED"));

        // In the window, the §5.4 order applies.
        assert_eq!(code(no_ver, 1_700_000_000), json!("UNKNOWN_VERSION"));
        let mut str_ts = p256_signed_envelope();
        str_ts["timestamp"] = json!("1700000000");
        assert_eq!(code(str_ts, stale), json!("INVALID_ENVELOPE"));
    }
}

#[cfg(test)]
mod error_code_mapping_tests {
    //! The `*_error_code` helpers translate library errors into the
    //! conformance wire codes the runner asserts on. A misroute silently
    //! reports the wrong code on every negative fixture, so the
    //! non-obvious mappings (and the nested handshake→tct/manifest
    //! dispatch) are pinned here.
    use super::{
        bundle_error_code, delegation_error_code, handshake_error_code, manifest_error_code,
        revocation_error_code, tct_error_code, voucher_error_code,
    };
    use aitp::delegation::DelegationError;
    use aitp::handshake::HandshakeError;
    use aitp::manifest::ManifestError;
    use aitp::tct::TctError;

    #[test]
    fn handshake_codes() {
        assert_eq!(
            handshake_error_code(&HandshakeError::NonceMismatch),
            "NONCE_MISMATCH"
        );
        assert_eq!(
            handshake_error_code(&HandshakeError::PeerMismatch),
            "PEER_MISMATCH"
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
        // Unresolvable issuer keys are distinct from a bad proof
        // (RFC-AITP-0001 §5.4.3 / RFC-AITP-0007 §3): retryable
        // KEY_RESOLUTION_FAILED, not IDENTITY_FAILED.
        assert_eq!(
            handshake_error_code(&HandshakeError::KeyResolutionFailed {
                issuer: "https://idp.example.com".into(),
                reason: "jwks fetch failed".into(),
            }),
            "KEY_RESOLUTION_FAILED"
        );
        // RFC-AITP-0001 §7 / issue #140 Phase 7a (AC2): UnknownField MUST
        // have its own explicit arm, never fall through the
        // `_ => "INTERNAL_ERROR"` catch-all. Asserted directly here so the
        // arm cannot be quietly deleted without a red test — no fixture
        // covers this mapper.
        assert_eq!(
            handshake_error_code(&HandshakeError::UnknownField("rogue".into())),
            "UNKNOWN_FIELD"
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
        // A stale challenge is POP_CHALLENGE_INVALID; every other PoP
        // failure is POP_RESPONSE_INVALID (RFC-AITP-0005 §6.2).
        assert_eq!(
            tct_error_code(&TctError::PopChallengeExpired),
            "POP_CHALLENGE_INVALID"
        );
        for e in [
            TctError::PopFailed,
            TctError::PopNonceMismatch,
            TctError::PopJtiMismatch,
        ] {
            assert_eq!(tct_error_code(&e), "POP_RESPONSE_INVALID");
        }
    }

    /// RFC-AITP-0001 §7 / issue #140 Phase 6a (AC6): `voucher_error_code`
    /// has no explicit `UnknownField` arm of its own — it MUST fall
    /// through its `other => tct_error_code(other)` arm to reach
    /// `tct_error_code`'s explicit `UnknownField(_) => "UNKNOWN_FIELD"`
    /// arm. Pinned directly (not only via the vch/tct fixtures) so a
    /// future edit that adds an `UnknownField` case to
    /// `voucher_error_code`'s bundled
    /// `EmptyGrants | ClaimsMalformed(_) | MissingField(_)` arm — which
    /// would silently capture it before the fall-through — turns this
    /// test red.
    #[test]
    fn voucher_error_code_falls_through_to_tct_unknown_field() {
        assert_eq!(
            voucher_error_code(&TctError::UnknownField("rogue".into())),
            "UNKNOWN_FIELD"
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
        // outer token maps to InvalidSignature in `aitp::delegation`).
        assert_eq!(
            delegation_error_code(&DelegationError::Crypto(
                aitp::crypto::CryptoError::SignatureInvalid
            )),
            "DELEGATION_INVALID_VOUCHER"
        );
        // §7 unknown-member rejection: a dedicated core code, not merged
        // into ClaimsMalformed's INVALID_ENVELOPE and not left to the
        // `_ => INTERNAL_ERROR` catch-all. No fixture covers this
        // mapper, so this direct assertion is the only thing that would
        // catch a missing/misplaced arm.
        assert_eq!(
            delegation_error_code(&DelegationError::UnknownField("rogue".into())),
            "UNKNOWN_FIELD"
        );
        // RFC-AITP-0011 §3 step 1: a hop issuer's Manifest is unavailable
        // or does not designate its key — no fixture covers this.
        assert_eq!(
            delegation_error_code(&DelegationError::KeyResolutionFailed {
                issuer: aitp::core::Aid::parse(
                    "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
                )
                .unwrap(),
                source: ManifestError::NotFound,
            }),
            "KEY_RESOLUTION_FAILED"
        );
    }

    #[test]
    fn local_signer_failure_maps_to_internal_error() {
        // A failure of our own signing backend (KMS/HSM) is a local
        // fault: INTERNAL_ERROR, never a peer-blamed signature code.
        let signer =
            || aitp::crypto::CryptoError::Signer(aitp::crypto::SignerError::VerificationFailed);
        assert_eq!(
            tct_error_code(&TctError::Crypto(signer())),
            "INTERNAL_ERROR"
        );
        assert_eq!(
            manifest_error_code(&aitp::manifest::ManifestError::Crypto(signer())),
            "INTERNAL_ERROR"
        );
        assert_eq!(
            bundle_error_code(
                &aitp_experimental::session_bundle::SessionBundleError::Crypto(signer())
            ),
            "INTERNAL_ERROR"
        );
    }

    #[test]
    fn coordinator_manifest_mismatch_is_key_resolution_failed() {
        // RFC-AITP-0010 §5 step 5 / RFC-AITP-0007 §1 (bundle-007, #238).
        assert_eq!(
            bundle_error_code(
                &aitp_experimental::session_bundle::SessionBundleError::CoordinatorManifestMismatch
            ),
            "KEY_RESOLUTION_FAILED"
        );
    }

    #[test]
    fn jws_header_codes() {
        // The compact-JWS header failures keep token-generic codes
        // across every artifact kind (RFC-AITP-0001 §5.4.5).
        assert_eq!(
            tct_error_code(&TctError::Crypto(aitp::crypto::CryptoError::AlgMismatch(
                "none".into()
            ))),
            "TOKEN_ALG_MISMATCH"
        );
        assert_eq!(
            tct_error_code(&TctError::Crypto(aitp::crypto::CryptoError::TypMismatch {
                expected: "aitp-tct+jwt".into(),
                got: "aitp-grant+jwt".into(),
            })),
            "TOKEN_TYP_MISMATCH"
        );
        assert_eq!(
            tct_error_code(&TctError::Crypto(aitp::crypto::CryptoError::JwsMalformed(
                "two segments".into()
            ))),
            "INVALID_ENVELOPE"
        );
        // A bad TCT signature surfaces through the Crypto variant.
        assert_eq!(
            tct_error_code(&TctError::Crypto(
                aitp::crypto::CryptoError::SignatureInvalid
            )),
            "TCT_SIGNATURE_INVALID"
        );
        // Regression (issue #140 Phase 6a, AC7): the protected JWS
        // header's own strictness (RFC-AITP-0001 §5.4.5, `deny_unknown_fields`
        // on `alg`+`typ`) is orthogonal to the new claim-set check and MUST
        // NOT be relabeled UNKNOWN_FIELD — `voucher_error_code` keeps the
        // same token-generic codes as `tct_error_code` for header failures.
        assert_eq!(
            voucher_error_code(&TctError::Crypto(aitp::crypto::CryptoError::AlgMismatch(
                "none".into()
            ))),
            "TOKEN_ALG_MISMATCH"
        );
        assert_eq!(
            voucher_error_code(&TctError::Crypto(aitp::crypto::CryptoError::JwsMalformed(
                "protected header: unknown field `kid`".into()
            ))),
            "INVALID_ENVELOPE"
        );
        assert_ne!(
            voucher_error_code(&TctError::Crypto(aitp::crypto::CryptoError::JwsMalformed(
                "protected header: unknown field `kid`".into()
            ))),
            "UNKNOWN_FIELD"
        );
    }

    #[test]
    fn revocation_codes() {
        // The two overridden arms: a revocation snapshot's own
        // structural/signature defects get their own codes, distinct
        // from a TCT's own JWS.
        assert_eq!(
            revocation_error_code(&TctError::ClaimsMalformed(
                "missing required field `published_at`".into()
            )),
            "REVOCATION_SNAPSHOT_INVALID"
        );
        assert_eq!(
            revocation_error_code(&TctError::SignatureInvalid),
            "REVOCATION_SNAPSHOT_SIGNATURE_INVALID"
        );
        // Everything else falls through to tct_error_code unchanged.
        // IssuerMismatch in particular is a deliberate non-change (same
        // treatment as ManifestError::AidMismatch in Phase 2) — pinned
        // directly so it can't silently drift.
        assert_eq!(
            revocation_error_code(&TctError::IssuerMismatch),
            "TCT_SIGNATURE_INVALID"
        );
        assert_eq!(
            revocation_error_code(&TctError::UnknownField("rogue".into())),
            "UNKNOWN_FIELD"
        );
        assert_eq!(revocation_error_code(&TctError::Revoked), "TCT_REVOKED");
        // #265: a snapshot's unknown-version code is its schema-failure
        // code (VERSIONING.md), unlike a TCT's `ver` (UNKNOWN_VERSION).
        assert_eq!(
            revocation_error_code(&TctError::VersionUnknown),
            "REVOCATION_SNAPSHOT_INVALID"
        );
        assert_eq!(tct_error_code(&TctError::VersionUnknown), "UNKNOWN_VERSION");
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
        // RFC-AITP-0001 §7 / issue #140 (AC5): UnknownField MUST have its
        // own explicit arm, never fall through the `_ => "INTERNAL_ERROR"`
        // catch-all. Asserted directly here so the arm cannot be quietly
        // deleted without a red test, independent of the man-004 fixture.
        assert_eq!(
            manifest_error_code(&ManifestError::UnknownField("deployment_region".into())),
            "UNKNOWN_FIELD"
        );
        // Issue #144: a structurally-invalid manifest (missing required
        // member, wrong type) must report MANIFEST_INVALID, not the
        // borrowed INVALID_ENVELOPE code. Asserted directly here so the
        // arm cannot be quietly reverted without a red test, independent
        // of the man-006 fixture.
        assert_eq!(
            manifest_error_code(&ManifestError::Malformed(
                "missing required field `handshake_endpoint`".into()
            )),
            "MANIFEST_INVALID"
        );
    }
}

#[cfg(test)]
mod manifest_unknown_field_tests {
    //! Adapter-level (not just library-level) coverage for RFC-AITP-0001
    //! §7 on the Manifest `verify_manifest` op — mirrors the man-004 /
    //! man-002 conformance fixtures and the member-check-before-signature
    //! ordering, but drives the actual JSON-RPC `handle` dispatch rather
    //! than calling `aitp::manifest::parse_manifest_wire` directly, so a
    //! regression in the adapter's own wiring (not just the library) would
    //! be caught here too.
    use super::*;

    fn signed_manifest_value() -> (Value, aitp::crypto::AitpSigningKey) {
        let key = aitp::crypto::AitpSigningKey::from_ed25519_seed(&[9u8; 32]);
        let manifest = ManifestBuilder::new(&key)
            .handshake_endpoint("https://b.example.com/handshake".parse().unwrap())
            .identity_hint(
                IdentityHint::new(IdentityKind::Oidc, "agent-b")
                    .with_issuer("https://idp.example.com".parse().unwrap()),
            )
            .accept_trust_anchor("https://idp.example.com".parse().unwrap())
            .offer("demo.echo")
            .published_at(Timestamp(1_711_900_000))
            .ttl(std::time::Duration::from_secs(86_400))
            .build()
            .unwrap();
        (serde_json::to_value(&manifest).unwrap(), key)
    }

    /// man-004 shape: an unrecognized sibling member outside `extensions`
    /// is rejected as UNKNOWN_FIELD via the real `verify_manifest` op.
    #[test]
    fn adapter_rejects_unknown_sibling_field() {
        let (mut manifest, _key) = signed_manifest_value();
        manifest
            .as_object_mut()
            .unwrap()
            .insert("deployment_region".into(), json!("us-east-1"));
        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "man-004-like",
            "verify_manifest",
            json!({ "manifest": manifest, "now": 1_711_900_100 }),
        );
        assert_eq!(out["ok"], json!(false), "got: {out}");
        assert_eq!(out["error_code"], json!("UNKNOWN_FIELD"));
    }

    /// Ordering gate via the adapter: an unknown member AND a corrupted
    /// signature together must still report UNKNOWN_FIELD, proving the
    /// member-set check the adapter now performs via `parse_manifest_wire`
    /// runs before the signature is ever checked.
    #[test]
    fn adapter_reports_unknown_field_even_with_a_corrupt_signature() {
        let (mut manifest, _key) = signed_manifest_value();
        let obj = manifest.as_object_mut().unwrap();
        obj.insert("deployment_region".into(), json!("us-east-1"));
        let mut sig = obj.get("signature").unwrap().as_str().unwrap().to_string();
        let last = sig.pop().unwrap();
        sig.push(if last == 'A' { 'B' } else { 'A' });
        obj.insert("signature".into(), json!(sig));
        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "man-ordering",
            "verify_manifest",
            json!({ "manifest": manifest, "now": 1_711_900_100 }),
        );
        assert_eq!(out["ok"], json!(false), "got: {out}");
        assert_eq!(
            out["error_code"],
            json!("UNKNOWN_FIELD"),
            "member-set check must precede signature verification"
        );
    }

    /// man-002 regression, at the adapter level: an unknown *value* for
    /// the known `version` member is MANIFEST_VERSION_UNKNOWN, never
    /// UNKNOWN_FIELD.
    #[test]
    fn adapter_reports_version_unknown_not_unknown_field() {
        let (mut manifest, _key) = signed_manifest_value();
        manifest["version"] = json!("aitp/9.9");
        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "man-002-like",
            "verify_manifest",
            json!({ "manifest": manifest, "now": 1_711_900_100 }),
        );
        assert_eq!(out["ok"], json!(false), "got: {out}");
        assert_eq!(out["error_code"], json!("MANIFEST_VERSION_UNKNOWN"));
    }

    /// man-005 shape: a vendor-namespaced key inside `extensions` is
    /// ignored and the manifest still verifies.
    #[test]
    fn adapter_accepts_unknown_key_inside_extensions() {
        let (mut manifest, key) = signed_manifest_value();
        // Re-sign over a body that includes "extensions" so the outer
        // signature covers it, mirroring what a real issuer would do.
        let obj = manifest.as_object_mut().unwrap();
        obj.insert(
            "extensions".into(),
            json!({"com.example.debug_trace": {"build_id": "worker-7"}}),
        );
        obj.remove("signature");
        let canonical = aitp::core::jcs::canonicalize(&manifest).unwrap();
        let signature = key
            .sign_jcs(&aitp::crypto::Digest32::sha256(&canonical))
            .into_string();
        manifest
            .as_object_mut()
            .unwrap()
            .insert("signature".into(), json!(signature));

        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "man-005-like",
            "verify_manifest",
            json!({ "manifest": manifest, "now": 1_711_900_100 }),
        );
        assert_eq!(out["ok"], json!(true), "got: {out}");
    }
}

#[cfg(test)]
mod revocation_unknown_field_tests {
    //! Issue #140 / Phase 4: RFC-AITP-0001 §7 for the revocation snapshot
    //! (RFC-AITP-0008 §1.5), driven through the real adapter dispatch —
    //! mirrors `manifest_unknown_field_tests` above, but also covers the
    //! two previously-silent-swallow call sites (`verify_tct`'s
    //! `issuer_revocation_list.snapshot` and `verify_delegation_token`'s
    //! `revocation_snapshots[]`), which must now surface an error rather
    //! than silently treating an unparseable snapshot as "nothing is
    //! revoked" (a fail-open hazard under a permissive revocation policy).
    use super::*;

    fn issuer() -> AitpSigningKey {
        AitpSigningKey::from_ed25519_seed(&[0xE1; 32])
    }

    fn signed_snapshot_value(issuer_key: &AitpSigningKey) -> Value {
        let env = aitp::tct::sign_revocation_list(
            aitp::tct::RevocationList::new(
                issuer_key.aid().clone(),
                Timestamp(1_700_000_000),
                Timestamp(1_700_003_600),
                vec![],
            ),
            issuer_key,
        )
        .unwrap();
        serde_json::to_value(&env).unwrap()
    }

    /// rev-005 shape, via the real `verify_revocation_snapshot` op: an
    /// unrecognized member of the inner `revocation_list` body is
    /// rejected as `UNKNOWN_FIELD`.
    #[test]
    fn verify_revocation_snapshot_rejects_unknown_body_member() {
        let key = issuer();
        let mut snapshot = signed_snapshot_value(&key);
        snapshot["revocation_list"]
            .as_object_mut()
            .unwrap()
            .insert("list_owner".into(), json!("team-trust"));

        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "rev-005-like",
            "verify_revocation_snapshot",
            json!({
                "snapshot": snapshot,
                "expected_issuer": key.aid().as_str(),
                "now": 1_700_000_100,
            }),
        );
        assert_eq!(out["ok"], json!(false), "got: {out}");
        assert_eq!(out["error_code"], json!("UNKNOWN_FIELD"));
    }

    /// issue #144 regression, sibling of the unknown-member test above: a
    /// snapshot missing a required inner member (`published_at`) — member
    /// set intact, nothing extra — must report `REVOCATION_SNAPSHOT_INVALID`
    /// via the real `verify_revocation_snapshot` op, exercising
    /// `revocation_error_code`'s `ClaimsMalformed` arm end-to-end rather
    /// than only via the hand-built mapping test.
    #[test]
    fn verify_revocation_snapshot_rejects_missing_required_field() {
        let key = issuer();
        let mut snapshot = signed_snapshot_value(&key);
        snapshot["revocation_list"]
            .as_object_mut()
            .unwrap()
            .remove("published_at");

        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "man-006-like",
            "verify_revocation_snapshot",
            json!({
                "snapshot": snapshot,
                "expected_issuer": key.aid().as_str(),
                "now": 1_700_000_100,
            }),
        );
        assert_eq!(out["ok"], json!(false), "got: {out}");
        assert_eq!(out["error_code"], json!("REVOCATION_SNAPSHOT_INVALID"));
    }

    /// rev-010-version-unknown shape (#265): a validly signed snapshot
    /// whose `version` is changed afterwards to `aitp/9.9`. The signature
    /// no longer verifies either, so this also pins that `version` is
    /// checked first and reported with the snapshot's own code.
    #[test]
    fn verify_revocation_snapshot_unknown_version_is_snapshot_invalid() {
        let key = issuer();
        let mut snapshot = signed_snapshot_value(&key);
        snapshot["revocation_list"]["version"] = json!("aitp/9.9");

        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "rev-010-like",
            "verify_revocation_snapshot",
            json!({
                "snapshot": snapshot,
                "expected_issuer": key.aid().as_str(),
                "now": 1_700_000_100,
            }),
        );
        assert_eq!(out["ok"], json!(false), "got: {out}");
        assert_eq!(out["error_code"], json!("REVOCATION_SNAPSHOT_INVALID"));
    }

    /// rev-006 shape: a snapshot carrying a legitimate `extensions` member
    /// still verifies.
    #[test]
    fn verify_revocation_snapshot_accepts_extensions() {
        let key = issuer();
        let env = aitp::tct::sign_revocation_list(
            {
                let mut list = aitp::tct::RevocationList::new(
                    key.aid().clone(),
                    Timestamp(1_700_000_000),
                    Timestamp(1_700_003_600),
                    vec![],
                );
                list.extensions = Some({
                    let mut ext = aitp::core::ExtensionsMap::new();
                    ext.insert("com.example.debug_trace", json!({"generator": "svc"}));
                    ext
                });
                list
            },
            &key,
        )
        .unwrap();
        let snapshot = serde_json::to_value(&env).unwrap();

        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "rev-006-like",
            "verify_revocation_snapshot",
            json!({
                "snapshot": snapshot,
                "expected_issuer": key.aid().as_str(),
                "now": 1_700_000_100,
            }),
        );
        assert_eq!(out["ok"], json!(true), "got: {out}");
    }

    /// rev-004 shape stays unaffected: a tampered signature reports the
    /// crypto failure, not `UNKNOWN_FIELD`.
    #[test]
    fn verify_revocation_snapshot_tampered_signature_is_not_unknown_field() {
        let key = issuer();
        let mut snapshot = signed_snapshot_value(&key);
        snapshot["signature"] = json!(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );

        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "rev-004-like",
            "verify_revocation_snapshot",
            json!({
                "snapshot": snapshot,
                "expected_issuer": key.aid().as_str(),
                "now": 1_700_000_100,
            }),
        );
        assert_eq!(out["ok"], json!(false), "got: {out}");
        assert_ne!(out["error_code"], json!("UNKNOWN_FIELD"));
        // Issue #144: a revocation snapshot's own signature failure now
        // reports REVOCATION_SNAPSHOT_SIGNATURE_INVALID, distinct from a
        // TCT's own JWS signature failure.
        assert_eq!(
            out["error_code"],
            json!("REVOCATION_SNAPSHOT_SIGNATURE_INVALID")
        );
    }

    /// `tct_error_code` has an explicit `UnknownField` arm reporting
    /// `UNKNOWN_FIELD`, asserted directly rather than only via the
    /// `verify_revocation_snapshot` fixture-shaped test above.
    #[test]
    fn tct_error_code_maps_item_5_and_6b_rejections_to_signature_family() {
        use aitp::tct::TctError as E;
        for e in [
            E::JtiNotV4(aitp::core::ids::V4Error::Version),
            E::SelfIssued,
            E::AttestationMarker,
            E::NotAttestation,
            E::AttestationStatementMissing("k".into()),
        ] {
            assert_eq!(tct_error_code(&e), "TCT_SIGNATURE_INVALID", "{e:?}");
        }
    }

    #[test]
    fn tct_error_code_maps_unknown_field_directly() {
        assert_eq!(
            tct_error_code(&aitp::tct::TctError::UnknownField("rogue".into())),
            "UNKNOWN_FIELD"
        );
    }

    /// Hazard 4, first silent-swallow site (`verify_tct`'s
    /// `issuer_revocation_list.snapshot`): before this phase, a snapshot
    /// that failed to deserialize — including for an unknown member — was
    /// discarded with `if let Ok(...) = ...`, so the surrounding
    /// `verify_tct` call would still succeed as if the issuer had
    /// published no revocations at all. That is a fail-open hazard for
    /// any deployment that does not run this check under a strict
    /// `fail_closed` policy. This test proves the snapshot's defect now
    /// surfaces as an error instead.
    #[test]
    fn verify_tct_surfaces_unparseable_issuer_revocation_snapshot_instead_of_ignoring_it() {
        let issuer_key = issuer();
        let subject_key = AitpSigningKey::from_ed25519_seed(&[0xE2; 32]);
        let issued = TctBuilder::new(&issuer_key)
            .subject(subject_key.aid().clone())
            .audience(subject_key.aid().clone())
            .grants(["demo.echo"])
            .ttl(std::time::Duration::from_secs(3600))
            .subject_pubkey(subject_key.verifying_key())
            .issued_at(Timestamp(1_700_000_000))
            .build()
            .unwrap();

        let mut snapshot = signed_snapshot_value(&issuer_key);
        snapshot["revocation_list"]
            .as_object_mut()
            .unwrap()
            .insert("list_owner".into(), json!("team-trust"));

        let mut state = AdapterState::default();
        // Sanity check: with NO revocation snapshot supplied at all, this
        // exact TCT verifies (the fixture is otherwise well-formed).
        let baseline = handle(
            &mut state,
            "rev-swallow-1-baseline",
            "verify_tct",
            json!({
                "tct_token": issued.token(),
                "issuer": issuer_key.aid().as_str(),
                "expected_audience": subject_key.aid().as_str(),
                "now": 1_700_000_100,
            }),
        );
        assert_eq!(baseline["ok"], json!(true), "got: {baseline}");

        // Under the OLD (silently-swallowing) behavior this would ALSO
        // report ok:true — the malformed snapshot was quietly ignored and
        // treated as "the issuer has revoked nothing". Since issue #271
        // (RFC-AITP-0008 §1.5 / §3.1, 0.3.1-draft) the discarded snapshot
        // is absent and the default `fail_closed` mode rejects the TCT
        // as TCT_REVOKED.
        let out = handle(
            &mut state,
            "rev-swallow-1",
            "verify_tct",
            json!({
                "tct_token": issued.token(),
                "issuer": issuer_key.aid().as_str(),
                "expected_audience": subject_key.aid().as_str(),
                "now": 1_700_000_100,
                "issuer_revocation_list": { "snapshot": snapshot },
            }),
        );
        assert_eq!(
            out["ok"],
            json!(false),
            "an unparseable revocation snapshot must not silently read as \
             'nothing is revoked': {out}"
        );
        assert_eq!(out["error_code"], json!("TCT_REVOKED"));
    }

    /// Hazard 4, second silent-swallow site (`verify_delegation_token`'s
    /// `revocation_snapshots[]`, the multi-hop path): an entry whose
    /// snapshot fails to deserialize was previously skipped with
    /// `Err(_) => continue`, silently excluding it from the per-issuer
    /// deny list rather than surfacing the defect.
    #[test]
    fn verify_delegation_surfaces_unparseable_revocation_snapshot_instead_of_skipping_it() {
        let a = AitpSigningKey::from_ed25519_seed(&[0xE3; 32]);
        let b = AitpSigningKey::from_ed25519_seed(&[0xE4; 32]);
        let c = AitpSigningKey::from_ed25519_seed(&[0xE5; 32]);

        let voucher = TctBuilder::new(&a)
            .subject(b.aid().clone())
            .audience(b.aid().clone())
            .grants(["read_data"])
            .ttl(std::time::Duration::from_secs(7200))
            .subject_pubkey(b.verifying_key())
            .issued_at(Timestamp(1_700_000_000))
            .build()
            .unwrap()
            .into_parts()
            .voucher
            .unwrap();
        let token = aitp::delegation::DelegationBuilder::new(&b, &voucher)
            .unwrap()
            .delegatee(c.aid().clone())
            .scope(["read_data"])
            .ttl(std::time::Duration::from_secs(3600))
            .now(Timestamp(1_700_000_000))
            .build()
            .unwrap()
            .into_parts()
            .token;

        let mut snapshot = signed_snapshot_value(&a);
        snapshot["revocation_list"]
            .as_object_mut()
            .unwrap()
            .insert("list_owner".into(), json!("team-trust"));

        // B's Manifest: the delegation's issuer key source
        // (RFC-AITP-0006 §4 step 1).
        let b_manifest = ManifestBuilder::new(&b)
            .handshake_endpoint("https://b.example.com/aitp/handshake".parse().unwrap())
            .identity_hint(
                IdentityHint::new(IdentityKind::Oidc, "b")
                    .with_issuer("https://idp.example.com".parse().unwrap()),
            )
            .accept_trust_anchor("https://idp.example.com".parse().unwrap())
            .published_at(Timestamp(1_700_000_000))
            .ttl(std::time::Duration::from_secs(3600))
            .build()
            .unwrap();

        let mut state = AdapterState::default();
        // Baseline: with no `revocation_snapshots` supplied, this
        // delegation token verifies.
        let baseline = handle(
            &mut state,
            "rev-swallow-2-baseline",
            "verify_delegation_token",
            json!({
                "delegation_token": token,
                "verifier_aid": a.aid().as_str(),
                "issuer_manifests": [b_manifest],
                "now": 1_700_000_100,
            }),
        );
        assert_eq!(baseline["ok"], json!(true), "got: {baseline}");

        let out = handle(
            &mut state,
            "rev-swallow-2",
            "verify_delegation_token",
            json!({
                "delegation_token": token,
                "verifier_aid": a.aid().as_str(),
                "issuer_manifests": [b_manifest],
                "now": 1_700_000_100,
                "revocation_snapshots": [
                    { "issuer_aid": a.aid().as_str(), "snapshot": snapshot }
                ],
            }),
        );
        assert_eq!(
            out["ok"],
            json!(false),
            "an unparseable revocation snapshot entry must not silently be \
             skipped as if it carried no revocations: {out}"
        );
        assert_eq!(out["error_code"], json!("UNKNOWN_FIELD"));
    }
}

#[cfg(test)]
mod discarded_snapshot_policy_tests {
    //! Issue #271: a revocation snapshot that `verify_tct` or a multi-hop
    //! `verify_delegation_token` cannot use is *absent*, and the
    //! revocation policy mode decides (RFC-AITP-0008 §1.5 / §3.1,
    //! 0.3.1-draft): `fail_closed` rejects as revoked, `fail_open`
    //! accepts. It never reads as "nothing is revoked".
    use super::*;

    const NOW: i64 = 1_700_000_100;

    fn key(seed: u8) -> AitpSigningKey {
        AitpSigningKey::from_ed25519_seed(&[seed; 32])
    }

    fn snapshot(issuer_key: &AitpSigningKey, revoked: &[Uuid]) -> Value {
        let env = aitp::tct::sign_revocation_list(
            aitp::tct::RevocationList::new(
                issuer_key.aid().clone(),
                Timestamp(1_700_000_000),
                Timestamp(1_700_003_600),
                revoked
                    .iter()
                    .map(|jti| aitp::tct::RevocationEntry::new(*jti, Timestamp(1_700_000_000)))
                    .collect(),
            ),
            issuer_key,
        )
        .unwrap();
        serde_json::to_value(&env).unwrap()
    }

    /// A snapshot whose body changed after signing: structurally valid,
    /// signature invalid (REVOCATION_SNAPSHOT_SIGNATURE_INVALID on its own).
    fn tampered(issuer_key: &AitpSigningKey) -> Value {
        let mut s = snapshot(issuer_key, &[]);
        s["revocation_list"]["published_at"] = json!(1_700_000_001);
        s
    }

    struct Tct {
        issuer: AitpSigningKey,
        subject: AitpSigningKey,
        token: String,
    }

    fn tct() -> Tct {
        let issuer = key(0xA1);
        let subject = key(0xA2);
        let token = TctBuilder::new(&issuer)
            .subject(subject.aid().clone())
            .audience(subject.aid().clone())
            .grants(["demo.echo", "demo.read"])
            .ttl(std::time::Duration::from_secs(3600))
            .subject_pubkey(subject.verifying_key())
            .issued_at(Timestamp(1_700_000_000))
            .build()
            .unwrap()
            .into_parts()
            .token;
        Tct {
            issuer,
            subject,
            token,
        }
    }

    fn verify_tct_with(t: &Tct, token: &str, list: Value, extra: Value) -> Value {
        let mut params = json!({
            "tct_token": token,
            "issuer": t.issuer.aid().as_str(),
            "expected_audience": t.subject.aid().as_str(),
            "now": NOW,
            "issuer_revocation_list": list,
        });
        if let Value::Object(m) = extra {
            params.as_object_mut().unwrap().extend(m);
        }
        handle(&mut AdapterState::default(), "t", "verify_tct", params)
    }

    #[test]
    fn valid_snapshot_still_decides() {
        let t = tct();
        let ok = verify_tct_with(
            &t,
            &t.token,
            json!({"snapshot": snapshot(&t.issuer, &[Uuid::new_v4()])}),
            json!({}),
        );
        assert_eq!(ok["ok"], json!(true), "{ok}");
    }

    #[test]
    fn invalid_signature_snapshot_fails_closed_by_default() {
        let t = tct();
        let out = verify_tct_with(
            &t,
            &t.token,
            json!({"snapshot": tampered(&t.issuer)}),
            json!({}),
        );
        assert_eq!(out["ok"], json!(false), "{out}");
        assert_eq!(out["error_code"], json!("TCT_REVOKED"));
    }

    #[test]
    fn invalid_snapshot_policy_mode_decides() {
        let t = tct();
        let snap = tampered(&t.issuer);
        // tct-004 shape: `fail_mode` beside the snapshot.
        let closed = verify_tct_with(
            &t,
            &t.token,
            json!({"snapshot": snap, "fail_mode": "fail_closed"}),
            json!({}),
        );
        assert_eq!(closed["error_code"], json!("TCT_REVOKED"), "{closed}");
        let open = verify_tct_with(
            &t,
            &t.token,
            json!({"snapshot": snap, "fail_mode": "fail_open"}),
            json!({}),
        );
        assert_eq!(open["ok"], json!(true), "{open}");
        assert_eq!(open["result"]["grants"], json!(["demo.echo", "demo.read"]));
        // RFC-AITP-0008 §3 shape: `revocation_policy.mode`.
        let open = verify_tct_with(
            &t,
            &t.token,
            json!({"snapshot": snap}),
            json!({"revocation_policy": {"mode": "fail_open"}}),
        );
        assert_eq!(open["ok"], json!(true), "{open}");
        let bogus = verify_tct_with(
            &t,
            &t.token,
            json!({"snapshot": snap, "fail_mode": "maybe"}),
            json!({}),
        );
        assert_eq!(bogus["error_code"], json!("INVALID_REQUEST"), "{bogus}");
    }

    #[test]
    fn soft_fail_narrows_to_the_safe_subset_or_fails_closed() {
        let t = tct();
        let snap = tampered(&t.issuer);
        let narrowed = verify_tct_with(
            &t,
            &t.token,
            json!({"snapshot": snap}),
            json!({"revocation_policy": {"mode": "soft_fail", "safe_grants": ["demo.read"]}}),
        );
        assert_eq!(narrowed["ok"], json!(true), "{narrowed}");
        assert_eq!(narrowed["result"]["grants"], json!(["demo.read"]));
        let disjoint = verify_tct_with(
            &t,
            &t.token,
            json!({"snapshot": snap}),
            json!({"revocation_policy": {"mode": "soft_fail", "safe_grants": ["other"]}}),
        );
        assert_eq!(
            disjoint["error_code"],
            json!("POLICY_VIOLATION"),
            "{disjoint}"
        );
        let no_subset = verify_tct_with(
            &t,
            &t.token,
            json!({"snapshot": snap, "fail_mode": "soft_fail"}),
            json!({}),
        );
        assert_eq!(no_subset["error_code"], json!("TCT_REVOKED"), "{no_subset}");
    }

    #[test]
    fn every_discard_reason_is_absent() {
        let t = tct();
        let mut schema_invalid = snapshot(&t.issuer, &[]);
        schema_invalid["revocation_list"]
            .as_object_mut()
            .unwrap()
            .remove("published_at");
        let mut version = snapshot(&t.issuer, &[]);
        version["revocation_list"]["version"] = json!("aitp/9.9");
        let cases = [
            ("schema", schema_invalid, json!({})),
            ("version", version, json!({})),
            // Signed by someone other than the TCT's issuer.
            ("issuer", snapshot(&key(0xA9), &[]), json!({})),
            // Fresh by `expires_at`, too old for the policy (rev-001).
            (
                "stale",
                snapshot(&t.issuer, &[]),
                json!({"policy": {"fail_mode": "fail_closed", "max_staleness_secs": 10}}),
            ),
        ];
        for (name, snap, extra) in cases {
            let out = verify_tct_with(&t, &t.token, json!({"snapshot": snap}), extra);
            assert_eq!(out["error_code"], json!("TCT_REVOKED"), "{name}: {out}");
        }
    }

    /// RFC-AITP-0008 §3.3 / rev-004: the fail-closed decision is taken in
    /// the revocation check, so a TCT whose own signature is bad still
    /// fails as TCT_SIGNATURE_INVALID with no revocation lookup.
    #[test]
    fn signature_check_still_precedes_the_policy_decision() {
        let t = tct();
        let mut parts: Vec<String> = t.token.split('.').map(str::to_string).collect();
        let other = TctBuilder::new(&key(0xA7))
            .subject(t.subject.aid().clone())
            .audience(t.subject.aid().clone())
            .grants(["demo.echo"])
            .ttl(std::time::Duration::from_secs(3600))
            .subject_pubkey(t.subject.verifying_key())
            .issued_at(Timestamp(1_700_000_000))
            .build()
            .unwrap()
            .into_parts()
            .token;
        parts[2] = other.rsplit('.').next().unwrap().to_string();
        let forged = parts.join(".");
        let out = verify_tct_with(
            &t,
            &forged,
            json!({"snapshot": tampered(&t.issuer)}),
            json!({"revocation_instrumented": true}),
        );
        assert_eq!(out["error_code"], json!("TCT_SIGNATURE_INVALID"), "{out}");
    }

    fn manifest(k: &AitpSigningKey, name: &str) -> Value {
        let m = ManifestBuilder::new(k)
            .handshake_endpoint(
                format!("https://{name}.example.com/aitp/handshake")
                    .parse()
                    .unwrap(),
            )
            .identity_hint(
                IdentityHint::new(IdentityKind::Oidc, name)
                    .with_issuer("https://idp.example.com".parse().unwrap()),
            )
            .accept_trust_anchor("https://idp.example.com".parse().unwrap())
            .published_at(Timestamp(1_700_000_000))
            .ttl(std::time::Duration::from_secs(3600))
            .build()
            .unwrap();
        serde_json::to_value(m).unwrap()
    }

    /// A (verifier) → voucher → B delegates to C → C extends to D.
    /// Hops: chain[0] issued by B, outer token issued by C.
    struct Chain {
        a: AitpSigningKey,
        b: AitpSigningKey,
        c: AitpSigningKey,
        single_hop: String,
        two_hop: String,
    }

    fn chain() -> Chain {
        let (a, b, c, d) = (key(0xB1), key(0xB2), key(0xB3), key(0xB4));
        let voucher = TctBuilder::new(&a)
            .subject(b.aid().clone())
            .audience(b.aid().clone())
            .grants(["read_data"])
            .ttl(std::time::Duration::from_secs(7200))
            .subject_pubkey(b.verifying_key())
            .issued_at(Timestamp(1_700_000_000))
            .build()
            .unwrap()
            .into_parts()
            .voucher
            .unwrap();
        let single_hop = aitp_experimental::delegation::ChainedDelegationBuilder::new(&b, &voucher)
            .unwrap()
            .delegatee(c.aid().clone())
            .scope(["read_data"])
            .ttl(std::time::Duration::from_secs(3600))
            .now(Timestamp(1_700_000_000))
            .jti(Uuid::new_v4())
            .build()
            .unwrap();
        let two_hop =
            aitp_experimental::delegation::ChainedDelegationBuilder::extending(&c, &single_hop)
                .unwrap()
                .delegatee(d.aid().clone())
                .scope(["read_data"])
                .ttl(std::time::Duration::from_secs(1800))
                .now(Timestamp(1_700_000_000))
                .build()
                .unwrap();
        Chain {
            a,
            b,
            c,
            single_hop,
            two_hop,
        }
    }

    fn verify_delegation_with(ch: &Chain, token: &str, snapshots: Value, extra: Value) -> Value {
        let mut state = AdapterState::default();
        let f = handle(
            &mut state,
            "f",
            "set_features",
            json!({"features": ["experimental-multihop-delegation"]}),
        );
        assert_eq!(f["ok"], json!(true), "{f}");
        let mut params = json!({
            "delegation_token": token,
            "verifier_aid": ch.a.aid().as_str(),
            "issuer_manifests": [manifest(&ch.b, "b"), manifest(&ch.c, "c")],
            "now": NOW,
            "revocation_snapshots": snapshots,
        });
        if let Value::Object(m) = extra {
            params.as_object_mut().unwrap().extend(m);
        }
        handle(&mut state, "d", "verify_delegation_token", params)
    }

    #[test]
    fn multihop_invalid_hop_snapshot_policy_mode_decides() {
        let ch = chain();
        let b = ch.b.aid().as_str();
        let valid = verify_delegation_with(
            &ch,
            &ch.two_hop,
            json!([{"issuer_aid": b, "snapshot": snapshot(&ch.b, &[])}]),
            json!({}),
        );
        assert_eq!(valid["ok"], json!(true), "{valid}");

        let bad = json!([{"issuer_aid": b, "snapshot": tampered(&ch.b)}]);
        let default = verify_delegation_with(&ch, &ch.two_hop, bad.clone(), json!({}));
        assert_eq!(
            default["error_code"],
            json!("DELEGATION_SOURCE_TCT_REVOKED"),
            "{default}"
        );
        let open = verify_delegation_with(
            &ch,
            &ch.two_hop,
            bad.clone(),
            json!({"revocation_policy": {"mode": "fail_open"}}),
        );
        assert_eq!(open["ok"], json!(true), "{open}");
        // Per-entry mode, and soft_fail has no chain safe-subset model.
        let soft = verify_delegation_with(
            &ch,
            &ch.two_hop,
            json!([{"issuer_aid": b, "snapshot": tampered(&ch.b), "fail_mode": "soft_fail"}]),
            json!({}),
        );
        assert_eq!(
            soft["error_code"],
            json!("DELEGATION_SOURCE_TCT_REVOKED"),
            "{soft}"
        );
        // A snapshot listed under B but signed by C is B's absent one.
        let wrong = verify_delegation_with(
            &ch,
            &ch.two_hop,
            json!([{"issuer_aid": b, "snapshot": snapshot(&ch.c, &[])}]),
            json!({}),
        );
        assert_eq!(
            wrong["error_code"],
            json!("DELEGATION_SOURCE_TCT_REVOKED"),
            "{wrong}"
        );
    }

    /// RFC-AITP-0006 §4 step 7 checks the verifier's own local deny list,
    /// which the revocation policy does not govern: one it cannot trust
    /// is an error carrying the snapshot's own code.
    #[test]
    fn verifier_own_snapshot_that_fails_verification_is_an_error() {
        let ch = chain();
        let out = verify_delegation_with(
            &ch,
            &ch.single_hop,
            json!([{"issuer_aid": ch.a.aid().as_str(), "snapshot": tampered(&ch.a)}]),
            json!({"revocation_policy": {"mode": "fail_open"}}),
        );
        assert_eq!(
            out["error_code"],
            json!("REVOCATION_SNAPSHOT_SIGNATURE_INVALID"),
            "{out}"
        );
    }

    #[test]
    fn unattributable_snapshot_entry_is_a_bad_request() {
        let ch = chain();
        for entry in [
            json!({"snapshot": snapshot(&ch.b, &[])}),
            json!({"issuer_aid": "not-an-aid", "snapshot": snapshot(&ch.b, &[])}),
            json!({"issuer_aid": ch.b.aid().as_str()}),
        ] {
            let out = verify_delegation_with(&ch, &ch.two_hop, json!([entry]), json!({}));
            assert_eq!(out["error_code"], json!("INVALID_REQUEST"), "{out}");
        }
    }
}

#[cfg(test)]
mod handshake_unknown_field_tests {
    //! Issue #140 Phase 7a: RFC-AITP-0001 §7 for the four Mutual
    //! Handshake payload types, driven through the real
    //! `verify_handshake_payload` op dispatch — mirrors
    //! `manifest_unknown_field_tests` / `revocation_unknown_field_tests`
    //! above. No conformance fixture covers this surface (the spec's
    //! `mh-*` pack doesn't exercise §7 for handshake payloads), so this
    //! is the only thing that would catch a wiring regression in the
    //! adapter itself (as opposed to the library-level tests in
    //! `aitp::handshake`).
    use super::*;

    /// One of the three kat-keypair AIDs `kat_seed_for_aid` resolves —
    /// used as the default receiver identity when a fixture/test omits
    /// `self_aid`.
    const KAT_KEYPAIR_001_AID: &str = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";

    fn dummy_envelope(message_type: MessageType, payload: Value) -> Value {
        json!({
            "version": aitp::core::PROTOCOL_VERSION,
            "message_type": message_type,
            "message_id": Uuid::new_v4(),
            "timestamp": 1_700_000_000,
            "sender": {"agent_id": KAT_KEYPAIR_001_AID},
            "payload": payload,
            "signature": "A".repeat(86),
        })
    }

    /// Real Ed25519-signed envelope, needed for the MUTUAL_COMMIT /
    /// MUTUAL_COMMIT_ACK branch: `verify_handshake_payload_op` verifies
    /// the envelope signature BEFORE the member-set check for those two
    /// message types (unlike HELLO/HELLO_ACK, checked only after a
    /// successful result), so a dummy signature would surface
    /// INVALID_SIGNATURE before ever reaching UNKNOWN_FIELD.
    fn signed_envelope(message_type: MessageType, payload: Value) -> Value {
        let key = AitpSigningKey::from_ed25519_seed(&[0x11; 32]);
        let message_id = Uuid::new_v4();
        let timestamp = Timestamp(1_700_000_000);
        let envelope = AitpEnvelope::unsigned(
            key.aid().clone(),
            message_type,
            payload,
            message_id,
            timestamp,
        );
        let envelope = sign_unsigned_envelope(&key, envelope).unwrap();
        serde_json::to_value(&envelope).unwrap()
    }

    /// Acceptance criterion 2: an unknown sibling member on a
    /// MUTUAL_HELLO payload is rejected as UNKNOWN_FIELD before any
    /// identity/manifest verification runs.
    #[test]
    fn adapter_rejects_unknown_sibling_on_mutual_hello() {
        let payload = json!({
            "identity": {
                "type": "pinned_key",
                "subject": "x",
                "proof": "A".repeat(86),
                "public_key": "A".repeat(43),
            },
            "manifest": {},
            "requested_grants": [],
            "pop_nonce": "A".repeat(22),
            "rogue": 1,
        });
        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "mh-unknown-field-hello",
            "verify_handshake_payload",
            json!({ "envelope": dummy_envelope(MessageType::MutualHello, payload) }),
        );
        assert_eq!(out["ok"], json!(false), "got: {out}");
        assert_eq!(out["error_code"], json!("UNKNOWN_FIELD"));
    }

    /// RFC-AITP-0001 §5.4 check order on the handshake path: an
    /// `aitp/0.2` envelope is UNKNOWN_VERSION before its unknown
    /// envelope-level member (UNKNOWN_FIELD) is looked at.
    #[test]
    fn handshake_payload_checks_envelope_version_first() {
        let mut env = dummy_envelope(MessageType::MutualHello, json!({}));
        env["trace_id"] = json!("rogue");
        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "mh-version-first",
            "verify_handshake_payload",
            json!({ "envelope": env.clone() }),
        );
        assert_eq!(out["error_code"], json!("UNKNOWN_FIELD"), "got: {out}");
        env["version"] = json!("aitp/0.2");
        let out = handle(
            &mut state,
            "mh-version-first",
            "verify_handshake_payload",
            json!({ "envelope": env }),
        );
        assert_eq!(out["error_code"], json!("UNKNOWN_VERSION"), "got: {out}");
    }

    /// Same check on MUTUAL_HELLO_ACK.
    #[test]
    fn adapter_rejects_unknown_sibling_on_mutual_hello_ack() {
        let payload = json!({
            "identity": {
                "type": "pinned_key",
                "subject": "x",
                "proof": "A".repeat(86),
                "public_key": "A".repeat(43),
            },
            "manifest": {},
            "requested_grants": [],
            "pop_nonce": "A".repeat(22),
            "pop_nonce_echo": "A".repeat(22),
            "rogue": 1,
        });
        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "mh-unknown-field-hello-ack",
            "verify_handshake_payload",
            json!({ "envelope": dummy_envelope(MessageType::MutualHelloAck, payload) }),
        );
        assert_eq!(out["ok"], json!(false), "got: {out}");
        assert_eq!(out["error_code"], json!("UNKNOWN_FIELD"));
    }

    /// Same check on MUTUAL_COMMIT_ACK (shares its member-set check and
    /// parse path with MUTUAL_COMMIT in `verify_handshake_payload_op`).
    #[test]
    fn adapter_rejects_unknown_sibling_on_mutual_commit_ack() {
        let payload = json!({
            "tct": "aaaa.bbbb.cccc",
            "pop_signature": "A".repeat(86),
            "pop_nonce_echo": "A".repeat(22),
            "rogue": 1,
        });
        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "mh-unknown-field-commit-ack",
            "verify_handshake_payload",
            json!({ "envelope": signed_envelope(MessageType::MutualCommitAck, payload) }),
        );
        assert_eq!(out["ok"], json!(false), "got: {out}");
        assert_eq!(out["error_code"], json!("UNKNOWN_FIELD"));
    }

    /// Acceptance criterion 3, via the real op: an unknown member nested
    /// inside `identity` is also rejected as UNKNOWN_FIELD, through the
    /// `from_serde_error` recovery path (not `check_members`, which only
    /// inspects the payload's own top-level keys).
    #[test]
    fn adapter_rejects_unknown_field_inside_nested_identity() {
        let payload = json!({
            "identity": {
                "type": "pinned_key",
                "subject": "x",
                "proof": "A".repeat(86),
                "public_key": "A".repeat(43),
                "rogue": 1,
            },
            "manifest": {},
            "requested_grants": [],
            "pop_nonce": "A".repeat(22),
        });
        let mut state = AdapterState::default();
        let out = handle(
            &mut state,
            "mh-unknown-field-nested-identity",
            "verify_handshake_payload",
            json!({ "envelope": dummy_envelope(MessageType::MutualHello, payload) }),
        );
        assert_eq!(out["ok"], json!(false), "got: {out}");
        assert_eq!(out["error_code"], json!("UNKNOWN_FIELD"));
    }
}

#[cfg(test)]
mod oidc_test_issuer_tests {
    //! Issue #144 Phase 5, acceptance criterion 3: `OidcTestIssuerResolver`
    //! (the real resolver `verify_handshake_payload_op` now uses in place
    //! of `NoOpResolver`) must actually resolve a key that makes
    //! `verify_oidc` accept a JWT from the test issuer — proven here at
    //! the `verify_oidc` layer directly, independent of the full
    //! MUTUAL_HELLO envelope/fixture machinery
    //! (`crates/aitp-conformance/src/fixture/placeholder.rs`'s
    //! `mint_oidc_jwt` mints the same shape with the same
    //! `oidc-test-issuers.json` key, exercised end-to-end by the `id-009`
    //! conformance fixture instead).
    use super::*;
    use aitp::handshake::{verify_oidc, IdentityDescriptor, OidcVerifyContext};

    /// Mint a JWT with the OIDC-profile claims `verify_oidc` requires
    /// (`identity_oidc.rs`'s full check order), signed by the test
    /// issuer's key. Deliberately independent of
    /// `aitp-conformance`'s `mint_oidc_jwt` (that crate depends on this
    /// one, not the reverse) — same recipe, ported the same way that
    /// function was: header/payload/sig, no `kid` (the resolver returns
    /// exactly one candidate key).
    fn mint_test_issuer_jwt(sub: &str, aud: &Aid, nonce: &str, cnf_jkt: &str, now: i64) -> String {
        let (issuer, seed) = oidc_test_issuer();
        let key = AitpSigningKey::from_ed25519_seed(&seed);
        let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
        let claims = json!({
            "iss": issuer,
            "sub": sub,
            "aud": aud.as_str(),
            "iat": now,
            "exp": now + 3600,
            "nonce": nonce,
            "cnf": { "jkt": cnf_jkt },
        });
        let header_b64 = base64url::encode(header.as_bytes());
        let payload_b64 = base64url::encode(claims.to_string().as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = base64url::encode(key.sign_raw(signing_input.as_bytes()).as_bytes());
        format!("{signing_input}.{sig}")
    }

    /// The resolver trusts exactly kat-oidc-issuer-001's published key,
    /// for its issuer only, and never kat-oidc-issuer-002-unknown's.
    #[test]
    fn resolver_returns_only_the_trusted_kat_key() {
        let doc: serde_json::Value = serde_json::from_str(OIDC_TEST_ISSUERS).unwrap();
        let vector = |id: &str| {
            doc["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["id"] == id)
                .unwrap()
                .clone()
        };
        let pubkey = |v: &serde_json::Value| {
            base64url::decode_strict(v["pubkey_b64url"].as_str().unwrap()).unwrap()
        };
        let trusted = vector("kat-oidc-issuer-001");
        let untrusted = vector("kat-oidc-issuer-002-unknown");

        let issuer: url::Url = trusted["issuer"].as_str().unwrap().parse().unwrap();
        let keys = OidcTestIssuerResolver.resolve(&issuer).unwrap();
        assert_eq!(keys.len(), 1);
        let JwkKeyMaterial::Ed25519 { x } = &keys[0].key else {
            panic!("not Ed25519")
        };
        assert_eq!(
            x.to_vec(),
            pubkey(&trusted),
            "resolved key is not the published one"
        );
        assert_ne!(x.to_vec(), pubkey(&untrusted));

        let other: url::Url = "https://idp.example.com".parse().unwrap();
        assert!(OidcTestIssuerResolver.resolve(&other).unwrap().is_empty());
    }

    #[test]
    fn oidc_test_issuer_resolver_makes_verify_oidc_accept() {
        let subject_key = AitpSigningKey::from_ed25519_seed(&[0x61; 32]);
        let audience_key = AitpSigningKey::from_ed25519_seed(&[0x62; 32]);
        let cnf_jkt = AitpVerifyingKey::from_aid(subject_key.aid())
            .unwrap()
            .to_jwk_thumbprint_sha256()
            .unwrap();
        let now = 1_711_900_000_i64;
        let now_ts = aitp::core::Timestamp(now);
        let nonce = "test-nonce-oidc-resolver";

        let jwt =
            mint_test_issuer_jwt("agent-under-test", audience_key.aid(), nonce, &cnf_jkt, now);

        let descriptor = IdentityDescriptor::oidc(
            oidc_test_issuer().0.parse().unwrap(),
            "agent-under-test",
            jwt,
        );
        let anchors: Vec<aitp::core::RawUrl> = vec![oidc_test_issuer().0.parse().unwrap()];
        let resolver = OidcTestIssuerResolver;
        let ctx = OidcVerifyContext::builder()
            .expected_audience(audience_key.aid())
            .expected_nonce(nonce)
            .trust_anchors(&anchors)
            .jwks_resolver(&resolver)
            .subject_aid(subject_key.aid())
            .iat_tolerance(std::time::Duration::from_secs(300))
            .now(now_ts)
            .build()
            .expect("every required input is set");
        let result = verify_oidc(&descriptor, &ctx);
        assert!(
            result.is_ok(),
            "expected verify_oidc to accept, got {result:?}"
        );
    }

    #[test]
    fn oidc_test_issuer_resolver_returns_no_keys_for_other_issuers() {
        let resolver = OidcTestIssuerResolver;
        let other: url::Url = "https://not-the-test-issuer.example.com".parse().unwrap();
        let keys = resolver
            .resolve(&other)
            .expect("resolve must not hard-error");
        assert!(
            keys.is_empty(),
            "resolver must not hand out the test issuer's key for a different issuer"
        );
    }
}
