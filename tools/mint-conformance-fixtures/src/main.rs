//! Mint real signed values into the spec's 22 conformance fixtures.
//!
//! Walks each `*.json` under `${AITP_SPEC_DIR}/schemas/conformance/`,
//! applies the normative substitution rules from PLACEHOLDERS.md, and
//! writes the result back. Closes PHASE-B-FIXTURE-PR /
//! BLOCKED-SPEC-FIXTURE-MIGRATION.
//!
//! Substitution order:
//! 1. AID role placeholders (string-walk; per the spec's role table)
//! 2. Time placeholders (`__NOW__`, `__NOW_MINUS_3600__`)
//! 3. Operation key (added per fixture-id prefix)
//! 4. Nonce placeholders (`__VALID_NONCE__`, `__VALID_NONCE_ECHO__`)
//! 5. JWT placeholders (`__VALID_JWT__`, `__JWT_*`)
//! 6. Per-fixture mint pass: signs/tampers/captures as needed
//!
//! Output is byte-stable for the same KAT seeds + reference clock.

use aitp_core::{base64url, jcs, Aid, Timestamp};
use aitp_crypto::AitpSigningKey;
use jsonwebtoken::{EncodingKey, Header};
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

// ── Pinned KAT inputs ────────────────────────────────────────────────────

const KAT_001_SEED_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const KAT_002_SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const KAT_003_SEED_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
// Fixture-only attacker (NOT in spec keypairs.json).
const KAT_ATTACKER_SEED_HEX: &str =
    "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead";
// Fixture-only "some other agent" (the wrong-audience peer in mh-006 etc).
const KAT_SOMEOTHER_SEED_HEX: &str =
    "abababababababababababababababababababababababababababababababab";
// Fixture-only OIDC issuer (RSA or HMAC; using HS256 for simplicity).
const OIDC_ISSUER_HMAC_SECRET: &[u8] = b"aitp-conformance-trusted-oidc-issuer-secret-001";
const OIDC_UNTRUSTED_HMAC_SECRET: &[u8] = b"aitp-conformance-untrusted-oidc-issuer-secret-002";

// PLACEHOLDERS.md § "Reference clock for byte-stable minting"
const FIXED_NOW: i64 = 1_711_900_000;
const NOW_MINUS_3600: i64 = FIXED_NOW - 3600;

fn key_from_hex(seed_hex: &str) -> AitpSigningKey {
    let bytes = hex::decode(seed_hex).expect("hex");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    AitpSigningKey::from_seed(&seed)
}

fn aid_for_role(role: &str) -> String {
    match role {
        "agentA" | "issuingPeer" | "verifier" | "victim" | "peerA" | "initiator" => {
            key_from_hex(KAT_001_SEED_HEX).aid().as_str().to_string()
        }
        "agentB" | "worker" | "peerB" => key_from_hex(KAT_002_SEED_HEX).aid().as_str().to_string(),
        "agentC" | "delegatee" | "targetX" | "workerA" => {
            key_from_hex(KAT_003_SEED_HEX).aid().as_str().to_string()
        }
        "attacker" => key_from_hex(KAT_ATTACKER_SEED_HEX)
            .aid()
            .as_str()
            .to_string(),
        "someOtherAgent" => key_from_hex(KAT_SOMEOTHER_SEED_HEX)
            .aid()
            .as_str()
            .to_string(),
        other => panic!("unknown role: {other}"),
    }
}

fn aid_role_substitution_table() -> Vec<(&'static str, String)> {
    // Sorted longest-first to avoid prefix collisions.
    let mut t = vec![
        // workerA / workerB → kat-keypair-003 (delegatee role)
        (
            "aid:pubkey:workerA_pubkey_AID_v01_placeholder_aaaaaaaa",
            aid_for_role("workerA"),
        ),
        (
            "aid:pubkey:targetX_pubkey_AID_v01_placeholder_xxxxxxxx",
            aid_for_role("targetX"),
        ),
        (
            "aid:pubkey:victim_pubkey_AID_v01_placeholder_vvvvvvvvv",
            aid_for_role("victim"),
        ),
        (
            "aid:pubkey:verifier_pubkey_AID_v01_placeholder_vvvvvvv",
            aid_for_role("verifier"),
        ),
        (
            "aid:pubkey:attacker_pubkey_AID_v01_placeholder_XXXXXXX",
            aid_for_role("attacker"),
        ),
        (
            "aid:pubkey:worker_pubkey_AID_v01_placeholder_wwwwwwwww",
            aid_for_role("worker"),
        ),
        (
            "aid:pubkey:peerA_pubkey_AID_v01_placeholder_aaaaaaaaaa",
            aid_for_role("peerA"),
        ),
        (
            "aid:pubkey:peerB_pubkey_AID_v01_placeholder_bbbbbbbbbb",
            aid_for_role("peerB"),
        ),
        (
            "aid:pubkey:initiator_pubkey_AID_v01_placeholder_iiiiii",
            aid_for_role("initiator"),
        ),
        (
            "aid:pubkey:someOtherAgent_pubkey_AID_v01_placeholderoo",
            aid_for_role("someOtherAgent"),
        ),
        // Bare pubkey forms used as binding.cnf etc.
        (
            "initiator_pubkey_AID_v01_placeholder_iiiiii",
            base64url::encode(&key_from_hex(KAT_001_SEED_HEX).verifying_key().to_bytes()),
        ),
        (
            "peerA_pubkey_AID_v01_placeholder_aaaaaaaaaa",
            base64url::encode(&key_from_hex(KAT_001_SEED_HEX).verifying_key().to_bytes()),
        ),
        (
            "peerB_pubkey_AID_v01_placeholder_bbbbbbbbbb",
            base64url::encode(&key_from_hex(KAT_002_SEED_HEX).verifying_key().to_bytes()),
        ),
        (
            "aid:pubkey:agentA_pubkey_AID_v01_placeholder_AAAAAAAAA",
            aid_for_role("agentA"),
        ),
        (
            "aid:pubkey:agentB_pubkey_AID_v01_placeholder_BBBBBBBBB",
            aid_for_role("agentB"),
        ),
        (
            "aid:pubkey:agentC_pubkey_AID_v01_placeholder_CCCCCCCCC",
            aid_for_role("agentC"),
        ),
        (
            "aid:pubkey:issuingPeer_pubkey_AID_v01_placeholderPPPPP",
            aid_for_role("agentA"),
        ),
        // Bare pubkey placeholders (used as `identity_hint.public_key`,
        // `binding.cnf`, etc.):
        (
            "workerA_pubkey_AID_v01_placeholder_aaaaaaaa",
            base64url::encode(&key_from_hex(KAT_003_SEED_HEX).verifying_key().to_bytes()),
        ),
        (
            "agentA_pubkey_AID_v01_placeholder_AAAAAAAAA",
            base64url::encode(&key_from_hex(KAT_001_SEED_HEX).verifying_key().to_bytes()),
        ),
        (
            "agentB_pubkey_AID_v01_placeholder_BBBBBBBBB",
            base64url::encode(&key_from_hex(KAT_002_SEED_HEX).verifying_key().to_bytes()),
        ),
        (
            "agentC_pubkey_AID_v01_placeholder_CCCCCCCCC",
            base64url::encode(&key_from_hex(KAT_003_SEED_HEX).verifying_key().to_bytes()),
        ),
    ];
    // Sort longest-first so prefix matches don't collide.
    t.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    t
}

/// Walk every string in the value tree and apply substitutions.
fn substitute_strings(value: &mut Value, subs: &[(String, String)]) {
    match value {
        Value::String(s) => {
            for (from, to) in subs {
                if s.contains(from) {
                    *s = s.replace(from, to);
                }
            }
        }
        Value::Object(m) => {
            for (_, v) in m.iter_mut() {
                substitute_strings(v, subs);
            }
        }
        Value::Array(a) => {
            for v in a.iter_mut() {
                substitute_strings(v, subs);
            }
        }
        _ => {}
    }
}

/// Walk and substitute time placeholders. `__NOW__` and `__NOW_MINUS_3600__`
/// can appear as JSON strings in the fixtures even though the schema
/// expects integers — replace the string with an integer JSON value.
fn substitute_times(value: &mut Value) {
    match value {
        Value::String(s) => {
            if s == "__NOW__" {
                *value = json!(FIXED_NOW);
            } else if s == "__NOW_MINUS_3600__" {
                *value = json!(NOW_MINUS_3600);
            }
        }
        Value::Object(m) => {
            for (_, v) in m.iter_mut() {
                substitute_times(v);
            }
        }
        Value::Array(a) => {
            for v in a.iter_mut() {
                substitute_times(v);
            }
        }
        _ => {}
    }
}

/// Substitute deterministic nonce placeholders. Per-fixture seed makes
/// re-mints byte-stable.
fn substitute_nonces(value: &mut Value, fixture_id: &str) {
    let nonce = deterministic_nonce(fixture_id);
    let nonce_echo = deterministic_nonce(&format!("{fixture_id}-echo"));
    fn walk(value: &mut Value, nonce: &str, nonce_echo: &str) {
        match value {
            Value::String(s) => {
                if s == "__VALID_NONCE__" {
                    *s = nonce.to_string();
                } else if s == "__VALID_NONCE_ECHO__" {
                    *s = nonce_echo.to_string();
                }
            }
            Value::Object(m) => {
                for (_, v) in m.iter_mut() {
                    walk(v, nonce, nonce_echo);
                }
            }
            Value::Array(a) => {
                for v in a.iter_mut() {
                    walk(v, nonce, nonce_echo);
                }
            }
            _ => {}
        }
    }
    walk(value, &nonce, &nonce_echo);
}

fn deterministic_nonce(seed: &str) -> String {
    let h = Sha256::digest(seed.as_bytes());
    base64url::encode(&h[..16])
}

/// Add `input.operation` per the PLACEHOLDERS.md operation registry.
fn add_operation_key(value: &mut Value, fixture_id: &str) {
    let op = if fixture_id.starts_with("env-") {
        "verify_envelope"
    } else if fixture_id.starts_with("man-") {
        "verify_manifest"
    } else if fixture_id.starts_with("tct-") {
        "verify_tct"
    } else if fixture_id.starts_with("del-") {
        "verify_delegation_token"
    } else if fixture_id.starts_with("id-") || fixture_id.starts_with("mh-") {
        if value.get("input").and_then(|i| i.get("sequence")).is_some() {
            // multi-step; per-step operation handled below
            return;
        }
        "verify_handshake_payload"
    } else {
        return;
    };
    if let Some(input) = value.get_mut("input").and_then(|v| v.as_object_mut()) {
        input.insert("operation".into(), json!(op));
    }
}

// ── Signing helpers ──────────────────────────────────────────────────────

fn key_for_aid(aid: &str) -> Option<AitpSigningKey> {
    for seed in [
        KAT_001_SEED_HEX,
        KAT_002_SEED_HEX,
        KAT_003_SEED_HEX,
        KAT_ATTACKER_SEED_HEX,
    ] {
        let k = key_from_hex(seed);
        if k.aid().as_str() == aid {
            return Some(k);
        }
    }
    None
}

fn jcs_sign(view: &impl Serialize, key: &AitpSigningKey) -> String {
    let canonical = jcs::canonicalize_serializable(view).expect("canon");
    let digest = Sha256::digest(&canonical);
    key.sign(&digest).into_string()
}

/// Apply LSB-flip-of-last-byte tamper to a base64url signature.
fn tamper_signature(sig: &str) -> String {
    let mut bytes = base64url::decode_strict(sig).expect("valid base64url sig");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    base64url::encode(&bytes)
}

/// Sign an object that has a `signature: "<placeholder>"` field, by
/// hashing JCS over the object minus signature and signing with `key`.
fn sign_inplace(obj: &mut Map<String, Value>, key: &AitpSigningKey) {
    obj.remove("signature");
    let view = Value::Object(obj.clone());
    let sig = jcs_sign(&view, key);
    obj.insert("signature".into(), json!(sig));
}

/// Sign the `proof_of_possession.signature` over sha256(challenge.as_bytes())
/// per RFC-AITP-0003 §3.1.
///
/// Also normalizes the challenge to a 22-char base64url string (the
/// schema requires exactly 22 chars / 16 raw bytes; some fixtures
/// pre-date that constraint and use longer literal strings).
fn sign_pop_inplace(pop: &mut Map<String, Value>, key: &AitpSigningKey) {
    let original = pop
        .get("challenge")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_default();
    let challenge = if original.len() == 22 && original.chars().all(is_base64url_char) {
        original
    } else {
        // Derive a deterministic 22-char base64url challenge from the
        // original string (so re-mints reproduce).
        deterministic_nonce(&format!("manifest-pop-{original}"))
    };
    let digest = Sha256::digest(challenge.as_bytes());
    let sig = key.sign(&digest).into_string();
    pop.insert("challenge".into(), json!(challenge));
    pop.insert("signature".into(), json!(sig));
}

fn is_base64url_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Add a `binding.cnf` field to a TCT object using the subject's
/// AID (= subject's pubkey, base64url). Required by the spec wire form
/// even when the fixture omits it.
fn ensure_tct_binding(tct: &mut Map<String, Value>) {
    if !tct.contains_key("binding") {
        let subject_aid = tct
            .get("subject")
            .and_then(|v| v.as_str())
            .expect("tct.subject");
        let cnf = subject_aid
            .strip_prefix("aid:pubkey:")
            .expect("aid:pubkey")
            .to_string();
        tct.insert("binding".into(), json!({"cnf": cnf}));
    }
    // Ensure issued_at — the schema requires it and some fixtures omit it.
    if !tct.contains_key("issued_at") {
        let derived = tct
            .get("expires_at")
            .and_then(|v| v.as_i64())
            .map(|e| e - 3600)
            .unwrap_or(FIXED_NOW);
        tct.insert("issued_at".into(), json!(derived));
    }
}

// ── Per-fixture mint dispatch ────────────────────────────────────────────

fn mint_fixture(value: &mut Value) {
    let id = value["id"].as_str().unwrap().to_string();

    // 1. AID role substitution (string walk).
    let table = aid_role_substitution_table();
    let owned: Vec<(String, String)> = table.into_iter().map(|(k, v)| (k.into(), v)).collect();
    substitute_strings(value, &owned);

    // 2. Time placeholders.
    substitute_times(value);

    // 3. operation key.
    add_operation_key(value, &id);

    // 4. Nonces.
    substitute_nonces(value, &id);

    // 5. Per-fixture pass.
    match id.as_str() {
        "env-001" => mint_env_001(value),
        "env-002" => mint_env_002(value),
        "env-003" => {} // self-contained
        "id-001" => mint_id_001(value),
        "id-002" => mint_id_002(value),
        "id-003" => mint_id_003(value),
        "id-004" => mint_id_004(value),
        "man-001" | "man-002" => mint_man(value),
        "mh-001" => {} // self-contained sequence
        "mh-002" => mint_mh_002(value),
        "mh-003" => mint_mh_003(value),
        "mh-004" => mint_mh_004(value),
        "mh-005" => mint_mh_005(value),
        "mh-006" => mint_mh_006(value),
        "mh-007" => mint_mh_007(value),
        "mh-008" => mint_mh_008(value),
        "mh-success-001" => mint_mh_success_001(value),
        "tct-002" | "tct-004" => mint_tct_simple(value),
        "tct-003" => mint_tct_003(value),
        "del-003" => mint_del_003(value),
        other => eprintln!("WARN: unhandled fixture id {other}"),
    }
}

// ── Per-fixture handlers ─────────────────────────────────────────────────

fn mint_env_001(value: &mut Value) {
    // Sender = peerA = kat-keypair-001. Sign envelope.
    let key = key_from_hex(KAT_001_SEED_HEX);
    let env = value
        .get_mut("input")
        .unwrap()
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap();
    sign_aitp_envelope(env, &key);
}

fn sign_aitp_envelope(env: &mut Map<String, Value>, key: &AitpSigningKey) {
    use uuid::Uuid;
    let mid_str = env.get("message_id").and_then(|v| v.as_str()).unwrap();
    let mid = Uuid::parse_str(mid_str).unwrap();
    let ts_int = env.get("timestamp").and_then(|v| v.as_i64()).unwrap();
    let ts = Timestamp(ts_int);
    let sender_aid = env
        .get("sender")
        .and_then(|s| s.get("agent_id"))
        .and_then(|v| v.as_str())
        .unwrap();
    let aid = Aid::parse(sender_aid).unwrap();
    let payload = env.get("payload").cloned().unwrap_or(json!({}));
    let digest = aitp_core::envelope_signing_digest(&mid, ts, &aid, &payload).unwrap();
    let sig = key.sign(&digest).into_string();
    env.insert("signature".into(), json!(sig));
}

fn sign_manifest_inplace(manifest: &mut Map<String, Value>) {
    // The manifest's aid drives the signing key.
    let aid = manifest.get("aid").and_then(|v| v.as_str()).unwrap();
    let key = key_for_aid(aid).unwrap_or_else(|| panic!("no key for manifest aid {aid}"));
    if let Some(pop) = manifest
        .get_mut("proof_of_possession")
        .and_then(|v| v.as_object_mut())
    {
        sign_pop_inplace(pop, &key);
    }
    sign_inplace(manifest, &key);
}

fn sign_tct_inplace(tct: &mut Map<String, Value>) {
    ensure_tct_binding(tct);
    let issuer_aid = tct.get("issuer").and_then(|v| v.as_str()).unwrap();
    let key =
        key_for_aid(issuer_aid).unwrap_or_else(|| panic!("no key for tct issuer {issuer_aid}"));
    sign_inplace(tct, &key);
}

fn mint_env_002(value: &mut Value) {
    // active_tct.signature = __VALID_TCT_SIG__
    let tct = value
        .get_mut("input")
        .unwrap()
        .get_mut("active_tct")
        .unwrap()
        .as_object_mut()
        .unwrap();
    sign_tct_inplace(tct);
}

fn mint_man(value: &mut Value) {
    let manifest = value
        .get_mut("input")
        .unwrap()
        .get_mut("manifest")
        .unwrap()
        .as_object_mut()
        .unwrap();
    sign_manifest_inplace(manifest);
}

fn mint_tct_simple(value: &mut Value) {
    let tct = value
        .get_mut("input")
        .unwrap()
        .get_mut("tct_token")
        .unwrap()
        .as_object_mut()
        .unwrap();
    sign_tct_inplace(tct);
}

fn mint_tct_003(value: &mut Value) {
    // Sign properly, then tamper the signature LSB.
    let tct = value
        .get_mut("input")
        .unwrap()
        .get_mut("tct_token")
        .unwrap()
        .as_object_mut()
        .unwrap();
    sign_tct_inplace(tct);
    let sig = tct
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    tct.insert("signature".into(), json!(tamper_signature(&sig)));
}

// ── OIDC JWT minting ─────────────────────────────────────────────────────

fn mint_jwt(claims: &Value, secret: &[u8]) -> String {
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(secret);
    jsonwebtoken::encode(&header, claims, &key).expect("encode jwt")
}

/// Mint a "valid" identity JWT for an OIDC peer. The PLACEHOLDERS.md
/// rules require the JWT carry sub, iat, exp, nonce, cnf.jkt, aud.
fn mint_valid_jwt(
    subject: &str,
    audience_aid: &str,
    nonce: &str,
    sender_pubkey_b64: &str,
    secret: &[u8],
) -> String {
    // cnf.jkt is the SHA-256 thumbprint of the canonical JWK form per
    // RFC-AITP-0002 §2.2.1 (matches aitp_crypto::compute_jwk_thumbprint).
    let pubkey_bytes = base64url::decode_strict(sender_pubkey_b64).unwrap();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&pubkey_bytes);
    let jkt = aitp_crypto::compute_jwk_thumbprint(&buf);
    let claims = json!({
        "sub": subject,
        "iat": FIXED_NOW,
        "exp": FIXED_NOW + 3600,
        "nonce": nonce,
        "aud": audience_aid,
        "cnf": {"jkt": jkt},
    });
    mint_jwt(&claims, secret)
}

fn mint_jwt_missing_aud(
    subject: &str,
    nonce: &str,
    sender_pubkey_b64: &str,
    secret: &[u8],
) -> String {
    let pubkey_bytes = base64url::decode_strict(sender_pubkey_b64).unwrap();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&pubkey_bytes);
    let jkt = aitp_crypto::compute_jwk_thumbprint(&buf);
    let claims = json!({
        "sub": subject,
        "iat": FIXED_NOW,
        "exp": FIXED_NOW + 3600,
        "nonce": nonce,
        "cnf": {"jkt": jkt},
    });
    mint_jwt(&claims, secret)
}

fn mint_jwt_wrong_aud(
    subject: &str,
    nonce: &str,
    sender_pubkey_b64: &str,
    secret: &[u8],
) -> String {
    let pubkey_bytes = base64url::decode_strict(sender_pubkey_b64).unwrap();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&pubkey_bytes);
    let jkt = aitp_crypto::compute_jwk_thumbprint(&buf);
    // Audience targets a DIFFERENT peer than the one verifying.
    let wrong = key_from_hex(KAT_003_SEED_HEX).aid().as_str().to_string();
    let claims = json!({
        "sub": subject,
        "iat": FIXED_NOW,
        "exp": FIXED_NOW + 3600,
        "nonce": nonce,
        "aud": wrong,
        "cnf": {"jkt": jkt},
    });
    mint_jwt(&claims, secret)
}

fn mint_jwt_missing_cnf_jkt(
    subject: &str,
    audience_aid: &str,
    nonce: &str,
    secret: &[u8],
) -> String {
    let claims = json!({
        "sub": subject,
        "iat": FIXED_NOW,
        "exp": FIXED_NOW + 3600,
        "nonce": nonce,
        "aud": audience_aid,
    });
    mint_jwt(&claims, secret)
}

// ── Identity-fixture (id-*) handlers ─────────────────────────────────────

/// Common machinery for id-001, id-002, id-003 — they all carry an
/// inline MUTUAL_HELLO envelope where:
///   - manifest needs to be re-signed (sigs over real AID)
///   - identity.proof needs a JWT minted with a specific defect
///   - envelope needs to be re-signed
fn mint_id_jwt_fixture(value: &mut Value, jwt_kind: JwtDefect) {
    // Pull receiver first (immutable read) so the later mutable borrow
    // of `envelope` doesn't conflict.
    let receiver_aid = value
        .get("input")
        .and_then(|i| i.get("self_aid"))
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let envelope = value
        .get_mut("input")
        .unwrap()
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap();
    let sender_aid = envelope
        .get("sender")
        .and_then(|s| s.get("agent_id"))
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let sender_key = key_for_aid(&sender_aid).unwrap();
    let sender_pubkey_b64 = base64url::encode(&sender_key.verifying_key().to_bytes());

    // 1. Re-sign manifest (PoP + outer signature).
    let manifest = envelope
        .get_mut("payload")
        .unwrap()
        .get_mut("manifest")
        .unwrap()
        .as_object_mut()
        .unwrap();
    sign_manifest_inplace(manifest);

    // 2. Mint JWT with the requested defect.
    let payload = envelope.get_mut("payload").unwrap();
    let nonce = payload
        .get("pop_nonce")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let identity = payload
        .get_mut("identity")
        .unwrap()
        .as_object_mut()
        .unwrap();
    let subject = identity
        .get("subject")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let jwt = match jwt_kind {
        JwtDefect::Valid => mint_valid_jwt(
            &subject,
            &receiver_aid,
            &nonce,
            &sender_pubkey_b64,
            OIDC_ISSUER_HMAC_SECRET,
        ),
        JwtDefect::MissingAud => mint_jwt_missing_aud(
            &subject,
            &nonce,
            &sender_pubkey_b64,
            OIDC_ISSUER_HMAC_SECRET,
        ),
        JwtDefect::WrongAud => mint_jwt_wrong_aud(
            &subject,
            &nonce,
            &sender_pubkey_b64,
            OIDC_ISSUER_HMAC_SECRET,
        ),
        JwtDefect::MissingCnfJkt => {
            mint_jwt_missing_cnf_jkt(&subject, &receiver_aid, &nonce, OIDC_ISSUER_HMAC_SECRET)
        }
        JwtDefect::FromUnknownIssuer => mint_valid_jwt(
            &subject,
            &receiver_aid,
            &nonce,
            &sender_pubkey_b64,
            OIDC_UNTRUSTED_HMAC_SECRET,
        ),
    };
    identity.insert("proof".into(), json!(jwt));

    // 3. Re-sign envelope.
    sign_aitp_envelope(envelope, &sender_key);
}

#[derive(Copy, Clone)]
enum JwtDefect {
    Valid,
    MissingAud,
    WrongAud,
    MissingCnfJkt,
    FromUnknownIssuer,
}

fn mint_id_001(value: &mut Value) {
    mint_id_jwt_fixture(value, JwtDefect::MissingAud);
}
fn mint_id_002(value: &mut Value) {
    mint_id_jwt_fixture(value, JwtDefect::WrongAud);
}
fn mint_id_003(value: &mut Value) {
    mint_id_jwt_fixture(value, JwtDefect::MissingCnfJkt);
}

fn mint_id_004(value: &mut Value) {
    // Pinned-key cross-peer replay: mint a proof against the
    // ORIGINAL captured-context tuple, embed that signature, then
    // re-sign the envelope with the current message_id/timestamp/nonce.
    // The captured proof is tied to the wrong tuple, so verify fails.
    use uuid::Uuid;
    let captured = value
        .get("input")
        .and_then(|i| i.get("captured_proof_context"))
        .cloned()
        .unwrap();
    let original_sender = captured["original_sender_aid"]
        .as_str()
        .unwrap()
        .to_string();
    let original_receiver = captured["original_receiver_aid"]
        .as_str()
        .unwrap()
        .to_string();
    let original_mid = Uuid::parse_str(captured["original_message_id"].as_str().unwrap()).unwrap();
    let original_ts = Timestamp(captured["original_timestamp"].as_i64().unwrap());
    let original_nonce = captured["original_pop_nonce"].as_str().unwrap().to_string();

    let sender_key = key_for_aid(&original_sender).unwrap();

    // Build the ORIGINAL pinned-key proof input per RFC-AITP-0002 §3.1:
    //   sender_aid || 0x00 || receiver_aid || 0x00 || message_id || 0x00 ||
    //   timestamp || 0x00 || pop_nonce_decoded_bytes
    let mut input_bytes = Vec::new();
    input_bytes.extend_from_slice(original_sender.as_bytes());
    input_bytes.push(0);
    input_bytes.extend_from_slice(original_receiver.as_bytes());
    input_bytes.push(0);
    input_bytes.extend_from_slice(original_mid.to_string().as_bytes());
    input_bytes.push(0);
    input_bytes.extend_from_slice(original_ts.0.to_string().as_bytes());
    input_bytes.push(0);
    input_bytes.extend_from_slice(&base64url::decode_strict(&original_nonce).unwrap());
    let digest = Sha256::digest(&input_bytes);
    let captured_proof = sender_key.sign(&digest).into_string();

    // Embed into the envelope's identity.proof, then re-sign envelope.
    let envelope = value
        .get_mut("input")
        .unwrap()
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap();
    envelope
        .get_mut("payload")
        .unwrap()
        .get_mut("identity")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("proof".into(), json!(captured_proof));
    // Sign manifest (inline manifest needs its own sigs).
    let manifest = envelope
        .get_mut("payload")
        .unwrap()
        .get_mut("manifest")
        .unwrap()
        .as_object_mut()
        .unwrap();
    sign_manifest_inplace(manifest);
    sign_aitp_envelope(envelope, &sender_key);
}

// ── Mutual-handshake fixtures ────────────────────────────────────────────

/// Generic mh-* helper: re-signs the inline manifest (and PoP), mints an
/// OIDC JWT for the identity, and signs the envelope. Returns nothing.
fn mint_mh_oidc_envelope(value: &mut Value, jwt_defect: JwtDefect, tamper_manifest_sig: bool) {
    let envelope = value
        .get_mut("input")
        .unwrap()
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap();
    let sender_aid = envelope
        .get("sender")
        .and_then(|s| s.get("agent_id"))
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let sender_key = key_for_aid(&sender_aid).unwrap();
    let sender_pubkey_b64 = base64url::encode(&sender_key.verifying_key().to_bytes());

    // Receiver: use kat-001 (verifier role) by convention.
    let receiver_aid = key_from_hex(KAT_001_SEED_HEX).aid().as_str().to_string();

    let manifest = envelope
        .get_mut("payload")
        .unwrap()
        .get_mut("manifest")
        .unwrap()
        .as_object_mut()
        .unwrap();
    sign_manifest_inplace(manifest);
    if tamper_manifest_sig {
        let sig = manifest
            .get("signature")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        manifest.insert("signature".into(), json!(tamper_signature(&sig)));
    }

    // JWT
    let payload = envelope.get_mut("payload").unwrap();
    let nonce = payload
        .get("pop_nonce")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let identity = payload
        .get_mut("identity")
        .unwrap()
        .as_object_mut()
        .unwrap();
    let subject = identity
        .get("subject")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let secret = match jwt_defect {
        JwtDefect::FromUnknownIssuer => OIDC_UNTRUSTED_HMAC_SECRET,
        _ => OIDC_ISSUER_HMAC_SECRET,
    };
    let jwt = match jwt_defect {
        JwtDefect::Valid | JwtDefect::FromUnknownIssuer => {
            mint_valid_jwt(&subject, &receiver_aid, &nonce, &sender_pubkey_b64, secret)
        }
        JwtDefect::MissingAud => mint_jwt_missing_aud(&subject, &nonce, &sender_pubkey_b64, secret),
        JwtDefect::WrongAud => mint_jwt_wrong_aud(&subject, &nonce, &sender_pubkey_b64, secret),
        JwtDefect::MissingCnfJkt => {
            mint_jwt_missing_cnf_jkt(&subject, &receiver_aid, &nonce, secret)
        }
    };
    identity.insert("proof".into(), json!(jwt));

    sign_aitp_envelope(envelope, &sender_key);
}

fn mint_mh_002(value: &mut Value) {
    // Manifest signature is tampered.
    mint_mh_oidc_envelope(value, JwtDefect::Valid, true);
}

fn mint_mh_003(value: &mut Value) {
    // Manifest PoP is invalid. Mint normally then mutate the PoP sig.
    mint_mh_oidc_envelope(value, JwtDefect::Valid, false);
    // Tamper the manifest's PoP signature.
    let envelope = value
        .get_mut("input")
        .unwrap()
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap();
    let pop = envelope
        .get_mut("payload")
        .unwrap()
        .get_mut("manifest")
        .unwrap()
        .get_mut("proof_of_possession")
        .unwrap()
        .as_object_mut()
        .unwrap();
    let sig = pop
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    pop.insert("signature".into(), json!(tamper_signature(&sig)));
    // Re-sign envelope since manifest changed.
    let sender_aid = envelope
        .get("sender")
        .and_then(|s| s.get("agent_id"))
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let sender_key = key_for_aid(&sender_aid).unwrap();
    sign_aitp_envelope(envelope, &sender_key);
}

fn mint_mh_004(value: &mut Value) {
    mint_mh_oidc_envelope(value, JwtDefect::FromUnknownIssuer, false);
}

fn mint_mh_005(value: &mut Value) {
    // Nonce mismatch tested somewhere in the payload — sign normally;
    // expected outcome is NONCE_MISMATCH which the runner triggers
    // based on payload content.
    mint_mh_oidc_envelope(value, JwtDefect::Valid, false);
}

fn mint_mh_006(value: &mut Value) {
    // mh-006 has TCT in COMMIT context.
    mint_mh_pinned_key_envelope_with_tct(value, false);
}

fn mint_mh_007(value: &mut Value) {
    mint_mh_pinned_key_envelope_with_tct(value, false);
}

fn mint_mh_008(value: &mut Value) {
    // POP signature is over the wrong nonce.
    mint_mh_pinned_key_envelope_with_tct(value, true);
}

fn mint_mh_pinned_key_envelope_with_tct(value: &mut Value, invalid_pop: bool) {
    // mh-006/007/008: COMMIT_ACK or COMMIT containing a TCT plus a
    // handshake-level pop_signature. Sign manifest (if present), TCT,
    // pop_signature (over decoded(pop_nonce_echo)), then envelope.
    let envelope = value
        .get_mut("input")
        .unwrap()
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap();
    let sender_aid = envelope
        .get("sender")
        .and_then(|s| s.get("agent_id"))
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let sender_key = key_for_aid(&sender_aid).unwrap();

    let payload = envelope
        .get_mut("payload")
        .unwrap()
        .as_object_mut()
        .unwrap();
    if let Some(m) = payload.get_mut("manifest").and_then(|v| v.as_object_mut()) {
        sign_manifest_inplace(m);
    }
    if let Some(env_tct) = payload
        .get_mut("tct_for_peer")
        .and_then(|v| v.as_object_mut())
    {
        if let Some(tct) = env_tct.get_mut("tct").and_then(|v| v.as_object_mut()) {
            sign_tct_inplace(tct);
        }
    }
    // Mint pop_signature (handshake-level, RFC-AITP-0005 §6.2 rc.4):
    // sign sha256(decoded(pop_nonce_echo)) — or, for the invalid-pop
    // case, sign over a different nonce so verify fails.
    if let Some(echo) = payload.get("pop_nonce_echo").and_then(|v| v.as_str()) {
        let nonce_to_sign_over = if invalid_pop {
            deterministic_nonce("mh-008-wrong-nonce")
        } else {
            echo.to_string()
        };
        let decoded = base64url::decode_strict(&nonce_to_sign_over)
            .expect("pop_nonce_echo is valid base64url");
        let digest = Sha256::digest(&decoded);
        let sig = sender_key.sign(&digest).into_string();
        payload.insert("pop_signature".into(), json!(sig));
    } else if invalid_pop {
        // mh-008 may not carry pop_nonce_echo at the payload top level;
        // sign over an arbitrary "wrong" nonce.
        let decoded =
            base64url::decode_strict(&deterministic_nonce("mh-008-wrong")).expect("nonce");
        let digest = Sha256::digest(&decoded);
        let sig = sender_key.sign(&digest).into_string();
        payload.insert("pop_signature".into(), json!(sig));
    }
    sign_aitp_envelope(envelope, &sender_key);
}

fn mint_mh_success_001(value: &mut Value) {
    // mh-success-001 has a non-sequence shape: input.peer_a.inbound_tct
    // and input.peer_b.inbound_tct, each with its own __VALID_*_SIG__.
    let input = value.get_mut("input").unwrap().as_object_mut().unwrap();
    for peer_key in &["peer_a", "peer_b"] {
        if let Some(peer) = input.get_mut(*peer_key).and_then(|v| v.as_object_mut()) {
            if let Some(tct) = peer.get_mut("inbound_tct").and_then(|v| v.as_object_mut()) {
                sign_tct_inplace(tct);
            }
        }
    }
}

fn mint_del_003(value: &mut Value) {
    // del-003 carries a delegation token under one of two field names
    // depending on the fixture's vintage.
    let input = value.get_mut("input").unwrap();
    let key_name = if input.get("delegation_token").is_some() {
        "delegation_token"
    } else {
        "delegation"
    };
    let token = input.get_mut(key_name).unwrap().as_object_mut().unwrap();
    sign_delegation_inplace(token);
}

fn sign_delegation_inplace(token: &mut Map<String, Value>) {
    // grant_proof.signature is the source TCT signature (issuing peer's).
    // delegation.signature is B's signature over the body excluding sig.
    let issued_by = token
        .get("issued_by")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let b_key = key_for_aid(&issued_by).expect("B key");
    if let Some(gp) = token.get_mut("grant_proof").and_then(|v| v.as_object_mut()) {
        let original_issuer = gp
            .get("issuer")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let issuing_key = key_for_aid(&original_issuer).expect("A key");
        // Reconstruct source TCT and sign it.
        let jti = gp
            .get("source_tct_jti")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let subject = gp
            .get("subject")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let issued_at = gp
            .get("issued_at")
            .and_then(|v| v.as_i64())
            .unwrap_or(FIXED_NOW);
        let expires_at = gp
            .get("expires_at")
            .and_then(|v| v.as_i64())
            .unwrap_or(FIXED_NOW + 3600);
        let capabilities = gp.get("capabilities").cloned().unwrap_or(json!([]));
        let subject_pubkey = subject.strip_prefix("aid:pubkey:").unwrap();
        let source_view = json!({
            "version": "aitp/0.1",
            "jti": jti,
            "issuer": original_issuer,
            "subject": subject,
            "audience": subject,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "grants": capabilities,
            "binding": {"cnf": subject_pubkey},
        });
        let source_canon = jcs::canonicalize(&source_view).unwrap();
        let digest = Sha256::digest(&source_canon);
        let source_sig = issuing_key.sign(&digest).into_string();
        gp.insert("signature".into(), json!(source_sig));
    }
    // Now sign the delegation body.
    sign_inplace(token, &b_key);
}

// ── Driver ───────────────────────────────────────────────────────────────

fn fixtures_dir() -> PathBuf {
    let base =
        std::env::var("AITP_SPEC_DIR").unwrap_or_else(|_| "../agentidentitytrustprotocol".into());
    PathBuf::from(base).join("schemas/conformance")
}

fn write_pretty(path: &PathBuf, value: &Value) {
    let s = serde_json::to_string_pretty(value).expect("serialize");
    std::fs::write(path, s + "\n").expect("write");
}

fn main() {
    let dir = fixtures_dir();
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension().is_some_and(|e| e == "json")
                && p.parent()
                    .is_some_and(|d| d.file_name().is_some_and(|n| n == "conformance"))
        })
        .collect();
    paths.sort();
    println!("minting {} fixtures from {}", paths.len(), dir.display());

    for path in &paths {
        let mut value: Value = serde_json::from_slice(&std::fs::read(path).unwrap())
            .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        let id = value["id"].as_str().unwrap_or("(no id)").to_string();
        mint_fixture(&mut value);
        write_pretty(path, &value);
        println!("  ✓ {}", id);
    }
    println!("done.");
}
