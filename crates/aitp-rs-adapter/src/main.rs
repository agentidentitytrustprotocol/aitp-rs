//! Subprocess conformance adapter for `aitp-rs`.
//!
//! Reads NDJSON requests from stdin, dispatches to the appropriate
//! `aitp-*` crate, writes NDJSON responses to stdout. See
//! `docs/design/02-conformance-adapter.md` for the protocol.

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
use std::io::{BufRead, Write};
use uuid::Uuid;

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut state = AdapterState::default();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("aitp-rs-adapter: stdin read error: {e}");
                return;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let resp = json!({
                    "id": "unknown",
                    "ok": false,
                    "error_code": "MALFORMED_REQUEST",
                    "message": e.to_string(),
                });
                writeln!(out, "{resp}").ok();
                continue;
            }
        };
        let id = request
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let op = request.get("op").and_then(|v| v.as_str()).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or_default();

        let response = handle(&mut state, id, op, params);
        writeln!(out, "{response}").ok();
        out.flush().ok();
        if op == "shutdown" {
            return;
        }
    }
}

#[derive(Default)]
struct AdapterState {
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

fn handle(state: &mut AdapterState, id: &str, op: &str, params: Value) -> Value {
    match op {
        "init" => init(id),
        "shutdown" => json!({"id": id, "ok": true}),

        // Tier A
        "verify_jcs" => verify_jcs(id, params),
        "compute_jwk_thumbprint" => compute_jwk_thumbprint(id, params),
        "verify_envelope" => verify_envelope_op(id, params),
        "verify_manifest" => verify_manifest_op(state, id, params),
        "verify_tct" => verify_tct_op(state, id, params),
        "verify_delegation_token" => verify_delegation_op(state, id, params),

        // Tier B
        "generate_keypair" => generate_keypair(state, id, params),
        "issue_manifest" => issue_manifest_op(state, id, params),
        "issue_tct" => issue_tct_op(state, id, params),
        "issue_delegation_token" => issue_delegation_op(state, id, params),
        "sign_envelope" => sign_envelope_op(state, id, params),

        // Tier C
        "start_handshake" => start_handshake_op(state, id, params),
        "process_handshake_message" => process_handshake_message_op(state, id, params),
        "revoke_tct" => revoke_tct_op(state, id, params),
        "verify_revocation_snapshot" => verify_revocation_snapshot_op(state, id, params),

        // Tier D
        "set_clock" => set_clock_op(state, id, params),
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
        // Tier B
        "generate_keypair",
        "issue_manifest",
        "issue_tct",
        "issue_delegation_token",
        "sign_envelope",
        // Tier C
        "start_handshake",
        "process_handshake_message",
        "revoke_tct",
        "verify_revocation_snapshot",
        // Tier D
        "set_clock",
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

fn verify_envelope_op(id: &str, params: Value) -> Value {
    let envelope = match serde_json::from_value::<AitpEnvelope>(
        params.get("envelope").cloned().unwrap_or_default(),
    ) {
        Ok(e) => e,
        Err(e) => return err(id, "INVALID_ENVELOPE", &format!("envelope parse: {e}")),
    };
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
        AidMismatch => "MANIFEST_SIGNATURE_INVALID",
        MissingField(_) => "INVALID_ENVELOPE",
        Canonicalization(_) => "INTERNAL_ERROR",
        Crypto(_) => "INVALID_SIGNATURE",
        Rng(_) => "INTERNAL_ERROR",
    }
    .to_string()
}

fn verify_tct_op(state: &AdapterState, id: &str, params: Value) -> Value {
    let tct = match serde_json::from_value::<aitp_tct::Tct>(
        params.get("tct").cloned().unwrap_or_default(),
    ) {
        Ok(t) => t,
        Err(e) => return err(id, "INVALID_ENVELOPE", &format!("tct parse: {e}")),
    };
    let expected_audience = match params
        .get("expected_audience")
        .and_then(|v| v.as_str())
        .map(Aid::parse)
    {
        Some(Ok(a)) => a,
        Some(Err(e)) => return err(id, "INVALID_ENVELOPE", &format!("expected_audience: {e}")),
        None => return err(id, "INVALID_ENVELOPE", "missing expected_audience"),
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
    let revoked_jtis = state.revoked_jtis.clone();
    let check = move |jti: &Uuid| revoked_jtis.contains(&jti.to_string());
    let ctx = aitp_tct::TctVerifyContext {
        expected_audience: &expected_audience,
        issuer_pubkey: &issuer_pubkey,
        now,
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
        Revoked => "TCT_REVOKED",
        EmptyGrants => "INVALID_ENVELOPE",
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
    let token = match serde_json::from_value::<aitp_delegation::DelegationToken>(
        params.get("delegation").cloned().unwrap_or_default(),
    ) {
        Ok(t) => t,
        Err(e) => return err(id, "INVALID_ENVELOPE", &format!("delegation parse: {e}")),
    };
    let verifier_aid = match params
        .get("verifier_aid")
        .and_then(|v| v.as_str())
        .map(Aid::parse)
    {
        Some(Ok(a)) => a,
        Some(Err(e)) => return err(id, "INVALID_ENVELOPE", &format!("verifier_aid: {e}")),
        None => return err(id, "INVALID_ENVELOPE", "missing verifier_aid"),
    };
    let now = params
        .get("now")
        .and_then(|v| v.as_i64())
        .map(Timestamp)
        .unwrap_or_else(|| state.now());
    let ctx = aitp_delegation::VerifyDelegationContext {
        verifier_aid: &verifier_aid,
        now,
        revocation_check: None,
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
        SourceTctRevoked => "SOURCE_TCT_REVOKED",
        AudienceMismatch => "AUDIENCE_MISMATCH",
        PopFailed => "POP_RESPONSE_INVALID",
        MultihopNotSupported => "MULTIHOP_NOT_SUPPORTED",
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
    let trust_anchors: Vec<url::Url> = params
        .get("accepted_trust_anchors")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()?.parse().ok()).collect())
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
        b = b.accept_trust_anchor(anchor);
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
            if let Ok(peer_m) = serde_json::from_value::<Manifest>(peer_manifest_value) {
                state
                    .peer_manifests
                    .insert(peer_m.aid.as_str().to_string(), peer_m);
            }
            start_initiator(state, id, handle, manifest, requested_grants)
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
        now: ts,
    };
    let (init_state, hello_payload) =
        match Initiator::start(&cfg, identity, &mid, ts, requested_grants) {
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
    let env: aitp_tct::RevocationListEnvelope =
        match serde_json::from_value(params.get("revocation_list").cloned().unwrap_or_default()) {
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
    match aitp_tct::verify_revocation_list(&env, &ctx) {
        Ok(()) => {
            json!({"id": id, "ok": true, "result": {"verified": true, "revoked_count": env.revocation_list.entries.len()}})
        }
        Err(e) => err(id, &tct_error_code(&e), &e.to_string()),
    }
}

fn revoke_tct_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    let jti = match params.get("jti").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return err(id, "INVALID_REQUEST", "missing 'jti'"),
    };
    state.revoked_jtis.insert(jti);
    json!({"id": id, "ok": true, "result": {"revoked_count": state.revoked_jtis.len()}})
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
