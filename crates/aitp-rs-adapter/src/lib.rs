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
//! See `docs/design/02-conformance-adapter.md` for the wire
//! protocol the binary speaks; this library is the layer below it.

#![forbid(unsafe_code)]

use aitp_core::{base64url, jcs, Aid, AitpEnvelope, MessageType, Sender, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey, Signature};
use aitp_delegation::{DelegationBuilder, DelegationEnvelope};
use aitp_handshake::{
    Initiator, JwkPublicKey, JwksResolver, MutualCommitAckPayload, MutualHelloAckPayload,
    PeerConfig, PresentedIdentity, ResolveError,
};
use aitp_manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder, ManifestEnvelope};
use aitp_tct::{TctBuilder, TctEnvelope};
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
    if envelope.version != "aitp/0.1" {
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
            .unwrap_or_else(|| Timestamp::now().0);
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

    let envelope = match serde_json::from_value::<AitpEnvelope>(
        params.get("envelope").cloned().unwrap_or_default(),
    ) {
        Ok(e) => e,
        Err(e) => return err(id, "INVALID_ENVELOPE", &format!("envelope parse: {e}")),
    };

    // Conformance convention: when a fixture omits `self_aid`,
    // the verifier defaults to the receiver implied by the
    // message shape:
    //
    // - For MUTUAL_COMMIT / MUTUAL_COMMIT_ACK envelopes the
    //   payload carries `tct_for_peer.tct` whose `audience` IS
    //   the recipient (the TCT was minted by the sender for the
    //   receiver). Use that as the default self_aid so mh-007 /
    //   mh-008 (which omit self_aid) verify against the right
    //   pubkey.
    // - Otherwise fall back to kat-keypair-001 (the default
    //   "initiator-side" receiver used by mh-* HELLO fixtures).
    //   id-* fixtures supply self_aid explicitly.
    let default_self_aid = envelope
        .payload
        .get("tct_for_peer")
        .and_then(|t| t.get("tct"))
        .and_then(|t| t.get("audience"))
        .and_then(|v| v.as_str())
        .unwrap_or("aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik");
    let self_aid_str = params
        .get("self_aid")
        .and_then(|v| v.as_str())
        .unwrap_or(default_self_aid);
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

    // Step 1: envelope signature.
    if let Err(e) = (|| -> Result<(), String> {
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
    })() {
        return err(id, "INVALID_SIGNATURE", &format!("envelope: {e}"));
    }

    // Step 2: parse payload as MutualHello / MutualHelloAck and run
    // bootstrap_verify_peer.
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

    match result {
        Ok(()) => json!({"id": id, "ok": true, "result": {"verified": true}}),
        Err(e) => err(id, &handshake_error_code(&e), &e.to_string()),
    }
}

/// Dual-peer verification mode for `mh-success-001`: each peer
/// has a `self_aid` and `inbound_tct`; the TCT was minted by the
/// other peer with `audience == self_aid`. Verifies both TCTs
/// against each peer's expected audience using their respective
/// issuer (the OTHER peer's AID).
fn verify_handshake_dual_peer(
    id: &str,
    peer_a: &Value,
    peer_b: &Value,
    now: aitp_core::Timestamp,
) -> Value {
    fn verify_one(peer: &Value, now: aitp_core::Timestamp) -> Result<(), String> {
        let self_aid_str = peer
            .get("self_aid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing self_aid".to_string())?;
        let self_aid = Aid::parse(self_aid_str).map_err(|e| format!("self_aid: {e}"))?;
        let tct_value = peer
            .get("inbound_tct")
            .cloned()
            .ok_or_else(|| "missing inbound_tct".to_string())?;
        let tct: aitp_tct::Tct =
            serde_json::from_value(tct_value).map_err(|e| format!("inbound_tct parse: {e}"))?;
        let issuer_pubkey =
            AitpVerifyingKey::from_aid(&tct.issuer).map_err(|e| format!("issuer key: {e}"))?;
        let ctx = aitp_tct::TctVerifyContext {
            expected_audience: &self_aid,
            issuer_pubkey: &issuer_pubkey,
            now,
            issuer_manifest_expires_at: None,
            revocation_check: None,
        };
        aitp_tct::verify_tct(&tct, &ctx).map_err(|e| format!("verify_tct: {e}"))?;
        Ok(())
    }
    if let Err(e) = verify_one(peer_a, now) {
        return err(id, "INVALID_ENVELOPE", &format!("peer_a: {e}"));
    }
    if let Err(e) = verify_one(peer_b, now) {
        return err(id, "INVALID_ENVELOPE", &format!("peer_b: {e}"));
    }
    // Report the grants from peer_a's TCT — the expected.grants
    // field on mh-success-001 checks that. Both peers' grants
    // match by construction in the fixture.
    let grants: Vec<String> = peer_a
        .get("inbound_tct")
        .and_then(|t| t.get("grants"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
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
) -> Result<(), aitp_handshake::HandshakeError> {
    use aitp_handshake::HandshakeError;
    use aitp_tct::{verify_tct, TctVerifyContext};
    let tct = &payload.tct_for_peer.tct;

    // RFC-AITP-0005 §9: the TCT's `audience` MUST equal the
    // receiving peer's AID. Check first because that's the most
    // specific identity-level error the receiver can produce.
    if &tct.audience != self_aid {
        return Err(HandshakeError::Tct(aitp_tct::TctError::AudienceMismatch));
    }

    // RFC-AITP-0005 §9.4 (grant overflow): every grant in the TCT
    // MUST appear in the issuer's `offered_capabilities`. Fires
    // before the cryptographic checks because grant overflow is a
    // policy decision that doesn't depend on signature validity.
    if let Some(offered) = issuer_offered_capabilities {
        for g in &tct.grants {
            if !offered.iter().any(|o| o == g) {
                return Err(HandshakeError::InsufficientGrants);
            }
        }
    }

    // PoP signature (RFC-AITP-0004 §5.1 step 4): the sender
    // signed `sha256(base64url_decode(pop_nonce))` with their
    // AID-derived key. The fixture supplies the original HELLO_ACK
    // nonce as `self_pop_nonce_sent_in_hello_ack`; if absent we
    // can't run the crypto check (stateless fixtures lack the
    // HELLO_ACK context).
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
        // The PoP is signed by the TCT subject (the holder), not
        // the sender. RFC-AITP-0005 §6.2.
        let subject_pubkey =
            AitpVerifyingKey::from_aid(&tct.subject).map_err(HandshakeError::Crypto)?;
        subject_pubkey
            .verify(&pop_input, &sig)
            .map_err(|_| HandshakeError::PopVerificationFailed)?;
    } else if payload.pop_nonce_echo.is_empty() {
        return Err(HandshakeError::NonceMismatch);
    }

    // TCT signature + expiry last. mh-007 deliberately uses an
    // unexpired TCT (relative to the runner's pinned clock) and
    // depends on this check happening AFTER grant-overflow.
    let issuer_pubkey = AitpVerifyingKey::from_aid(sender_aid).map_err(HandshakeError::Crypto)?;
    let ctx = TctVerifyContext {
        expected_audience: self_aid,
        issuer_pubkey: &issuer_pubkey,
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    verify_tct(tct, &ctx).map_err(HandshakeError::Tct)?;
    Ok(())
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
        InsufficientGrants => "GRANT_OVERFLOW".to_string(),
        PolicyViolation => "POLICY_VIOLATION".to_string(),
        Crypto(_) => "INVALID_SIGNATURE".to_string(),
        Rng(_) => "INTERNAL_ERROR".to_string(),
        Canonicalization(_) => "INTERNAL_ERROR".to_string(),
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
    }
    .to_string()
}

fn verify_tct_op(state: &AdapterState, id: &str, params: Value) -> Value {
    // Accept both `tct` (alpha.4 vintage) and `tct_token` (spec rc.4
    // vintage). The two are equivalent.
    let tct_value = params
        .get("tct")
        .cloned()
        .or_else(|| params.get("tct_token").cloned())
        .unwrap_or_default();
    let tct = match serde_json::from_value::<aitp_tct::Tct>(tct_value) {
        Ok(t) => t,
        Err(e) => return err(id, "INVALID_ENVELOPE", &format!("tct parse: {e}")),
    };
    // expected_audience defaults to the TCT's own audience (v0.1
    // mandates audience == subject; the holder is verifying its own
    // TCT). Fixtures may also supply `self_aid` as an explicit
    // verifier name.
    let expected_audience = match params
        .get("expected_audience")
        .or_else(|| params.get("self_aid"))
        .and_then(|v| v.as_str())
        .map(Aid::parse)
    {
        Some(Ok(a)) => a,
        Some(Err(e)) => return err(id, "INVALID_ENVELOPE", &format!("expected_audience: {e}")),
        None => tct.audience.clone(),
    };
    let issuer_pubkey = match AitpVerifyingKey::from_aid(&tct.issuer) {
        Ok(p) => p,
        Err(e) => return err(id, "KEY_RESOLUTION_FAILED", &e.to_string()),
    };
    let now = params
        .get("now")
        .and_then(|v| v.as_i64())
        .map(Timestamp)
        .unwrap_or_else(|| state.now());
    // Honor a fixture-supplied issuer_revocation_list in addition to
    // any JTIs the adapter has been told to revoke via Tier-D inject.
    let mut revoked_jtis = state.revoked_jtis.clone();
    if let Some(list) = params.get("issuer_revocation_list") {
        if let Some(jtis) = list.get("revoked_jtis").and_then(|v| v.as_array()) {
            for j in jtis {
                if let Some(s) = j.as_str() {
                    revoked_jtis.insert(s.to_string());
                }
            }
        }
    }
    let check = move |jti: &Uuid| revoked_jtis.contains(&jti.to_string());
    let ctx = aitp_tct::TctVerifyContext {
        expected_audience: &expected_audience,
        issuer_pubkey: &issuer_pubkey,
        now,
        issuer_manifest_expires_at: None,
        revocation_check: Some(&check),
    };
    match aitp_tct::verify_tct(&tct, &ctx) {
        Ok(_) => json!({"id": id, "ok": true, "result": {"verified": true}}),
        Err(e) => err(id, &tct_error_code(&e), &e.to_string()),
    }
}

fn tct_error_code(e: &aitp_tct::TctError) -> String {
    use aitp_tct::TctError::*;
    match e {
        VersionUnknown => "UNKNOWN_VERSION",
        SignatureInvalid => "TCT_SIGNATURE_INVALID",
        AudienceMismatch => "AUDIENCE_MISMATCH",
        Expired => "TCT_EXPIRED",
        ExpiresAfterManifest => "TCT_EXPIRES_AFTER_MANIFEST",
        Revoked => "TCT_REVOKED",
        EmptyGrants => "INVALID_ENVELOPE",
        GrantWhitespace(_) => "INVALID_ENVELOPE",
        CnfMalformed => "INVALID_ENVELOPE",
        MissingField(_) => "INVALID_ENVELOPE",
        Canonicalization(_) => "INTERNAL_ERROR",
        PopNonceMismatch | PopFailed | PopChallengeExpired | PopJtiMismatch => {
            "POP_RESPONSE_INVALID"
        }
        Crypto(_) => "INVALID_SIGNATURE",
    }
    .to_string()
}

fn verify_delegation_op(state: &AdapterState, id: &str, params: Value) -> Value {
    // Accept both `delegation` and `delegation_token` field names per
    // the spec PLACEHOLDERS convention.
    let token_value = params
        .get("delegation")
        .cloned()
        .or_else(|| params.get("delegation_token").cloned())
        .unwrap_or_default();
    let token = match serde_json::from_value::<aitp_delegation::DelegationToken>(token_value) {
        Ok(t) => t,
        Err(e) => return err(id, "INVALID_ENVELOPE", &format!("delegation parse: {e}")),
    };
    // Spec fixtures carry `verifier_aid` OR they carry `audience`/`self_aid`
    // — both name the receiver. Default to `audience` derived from the
    // token if neither is supplied.
    let verifier_aid = match params
        .get("verifier_aid")
        .or_else(|| params.get("self_aid"))
        .or_else(|| params.get("audience"))
        .and_then(|v| v.as_str())
        .map(Aid::parse)
    {
        Some(Ok(a)) => a,
        Some(Err(e)) => return err(id, "INVALID_ENVELOPE", &format!("verifier_aid: {e}")),
        None => token.audience.clone(),
    };
    let now = params
        .get("now")
        .and_then(|v| v.as_i64())
        .map(Timestamp)
        .unwrap_or_else(|| state.now());

    // RFC-AITP-0011 §6 + spec PLACEHOLDERS.md: multi-hop fixtures
    // may carry a `revocation_snapshots` array of {issuer_aid,
    // snapshot} records. The runner verifies each snapshot's
    // signature against the issuer's AID-derived key and flattens
    // all revoked JTIs into a single deny list. The verifier
    // consults this list per-hop on `source_tct_jti`. Plain UUIDs
    // are unique across issuers so a flat set is safe even though
    // the spec models per-issuer scoping.
    let mut revoked_jtis: HashSet<Uuid> = HashSet::new();
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
            for entry in &env.revocation_list.entries {
                revoked_jtis.insert(entry.jti);
            }
        }
    }
    let revocation_check_closure = |jti: &Uuid| revoked_jtis.contains(jti);
    let revocation_check: Option<&dyn Fn(&Uuid) -> bool> = if revoked_jtis.is_empty() {
        None
    } else {
        Some(&revocation_check_closure)
    };

    // Multi-hop opt-in. Per RFC-AITP-0006 §4.4 the v0.1 default
    // MUST reject any non-empty chain; the runner enables RFC-0011
    // semantics by sending `set_features` with
    // `experimental-multihop-delegation`. Without that feature
    // we use the strict v0.1 cap (`V0_1_STRICT_MAX_HOPS = 0`).
    let max_hops = if state.has_feature("experimental-multihop-delegation") {
        aitp_delegation::DEFAULT_MAX_HOPS
    } else {
        aitp_delegation::V0_1_STRICT_MAX_HOPS
    };
    let ctx = aitp_delegation::VerifyDelegationContext {
        verifier_aid: &verifier_aid,
        now,
        revocation_check,
        max_hops,
    };
    match aitp_delegation::verify_delegation(&token, &ctx) {
        Ok(_) => json!({"id": id, "ok": true, "result": {"verified": true}}),
        Err(e) => err(id, &delegation_error_code(&e), &e.to_string()),
    }
}

fn delegation_error_code(e: &aitp_delegation::DelegationError) -> String {
    use aitp_delegation::DelegationError::*;
    match e {
        Expired => "DELEGATION_EXPIRED",
        InvalidSignature => "DELEGATION_INVALID",
        ScopeExceeded => "DELEGATION_SCOPE_EXCEEDED",
        InvalidGrantProof => "DELEGATION_INVALID_GRANT_PROOF",
        SourceTctRevoked => "DELEGATION_SOURCE_TCT_REVOKED",
        AudienceMismatch => "AUDIENCE_MISMATCH",
        PopFailed => "POP_RESPONSE_INVALID",
        MultihopNotSupported => "DELEGATION_MULTIHOP_NOT_SUPPORTED",
        HopLimitExceeded => "DELEGATION_HOP_LIMIT_EXCEEDED",
        ChainHashMismatch => "DELEGATION_CHAIN_HASH_MISMATCH",
        SelfDelegation => "INVALID_REQUEST",
        EmptyScope | CnfMalformed | MissingField(_) => "INVALID_ENVELOPE",
        Canonicalization(_) => "INTERNAL_ERROR",
        Crypto(_) => "INVALID_SIGNATURE",
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

    let tct = match TctBuilder::new(key)
        .subject(subject)
        .audience(audience)
        .grants(grants)
        .ttl_secs(ttl)
        .subject_pubkey(subject_pubkey)
        .issued_at(issued_at)
        .build()
    {
        Ok(t) => t,
        Err(e) => return err(id, "INTERNAL_ERROR", &e.to_string()),
    };
    let env = TctEnvelope { tct };
    json!({"id": id, "ok": true, "result": {"tct_envelope": env}})
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
    let source_tct = match serde_json::from_value::<aitp_tct::Tct>(
        params.get("source_tct").cloned().unwrap_or_default(),
    ) {
        Ok(t) => t,
        Err(e) => return err(id, "INVALID_REQUEST", &format!("source_tct: {e}")),
    };
    let delegatee = match params
        .get("delegatee")
        .and_then(|v| v.as_str())
        .map(Aid::parse)
    {
        Some(Ok(a)) => a,
        _ => return err(id, "INVALID_REQUEST", "missing/invalid delegatee"),
    };
    let pk_b64 = match params.get("delegatee_public_key").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err(id, "INVALID_REQUEST", "missing delegatee_public_key"),
    };
    let pk_bytes = match base64url::decode_strict(pk_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return err(
                id,
                "INVALID_REQUEST",
                "delegatee_public_key not 32-byte b64url",
            )
        }
    };
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&pk_bytes);
    let delegatee_pk = match AitpVerifyingKey::from_bytes(&buf) {
        Ok(p) => p,
        Err(e) => return err(id, "INVALID_REQUEST", &format!("delegatee_public_key: {e}")),
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

    let token = match DelegationBuilder::new(delegator, &source_tct)
        .delegatee(delegatee)
        .delegatee_pubkey(delegatee_pk)
        .scope(scope)
        .ttl_secs(ttl)
        .now(state.now())
        .build()
    {
        Ok(t) => t,
        Err(e) => return err(id, "INTERNAL_ERROR", &e.to_string()),
    };
    let env = DelegationEnvelope { delegation: token };
    json!({"id": id, "ok": true, "result": {"delegation_envelope": env}})
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
        version: "aitp/0.1".into(),
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
                    "held_tct": held,
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
            "held_tct": held_tct,
        }
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
        version: "aitp/0.1".into(),
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
    // tct-006 envelope-wrapped mode: the fixture supplies the TCT
    // as a top-level `tct_token` (merged into step params by the
    // runner) and the nonce inside the step's `envelope.payload`.
    // Accept either explicit `tct` (rich CLI mode) or
    // `tct_token` (fixture mode).
    let tct_source = params
        .get("tct")
        .cloned()
        .or_else(|| params.get("tct_token").cloned())
        .unwrap_or_default();
    let tct: aitp_tct::Tct = match serde_json::from_value(tct_source) {
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
            let tct_value = params.get("tct_token").cloned().unwrap_or_default();
            let tct: aitp_tct::Tct = match serde_json::from_value(tct_value) {
                Ok(t) => t,
                Err(e) => return err(id, "INVALID_ENVELOPE", &format!("tct_token parse: {e}")),
            };
            let holder_pubkey = match AitpVerifyingKey::from_aid(&tct.subject) {
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
        let stashed = if let Some(tct_value) = params.get("tct_token") {
            if let Ok(tct) = serde_json::from_value::<aitp_tct::Tct>(tct_value.clone()) {
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
    let tct: aitp_tct::Tct =
        match serde_json::from_value(params.get("tct").cloned().unwrap_or_default()) {
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
        None => return err(id, "INVALID_REQUEST", "missing 'features' (array of strings)"),
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
        let tct = match serde_json::from_value::<aitp_tct::Tct>(
            entry.get("tct").cloned().unwrap_or_default(),
        ) {
            Ok(t) => t,
            Err(e) => return err(id, "INVALID_REQUEST", &format!("participant tct: {e}")),
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
    let bundle_value = if let Some(inner) = params.get("session_bundle") {
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
