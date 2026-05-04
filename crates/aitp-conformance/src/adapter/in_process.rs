//! In-process adapter for the Rust reference implementation.
//!
//! Calls the AITP crates directly, no IPC overhead. Used during local
//! development; CI uses the subprocess adapter against the same code via
//! `aitp-rs-adapter` so that the subprocess protocol itself is exercised.
//!
//! Only Tier-A (stateless verification) ops are implemented today. Tier
//! B/C/D require persistent keypair/session state which lives in the
//! subprocess adapter (`aitp-rs-adapter`) — duplicating it here would
//! re-implement most of that binary. Use the subprocess path for those.

use crate::adapter::{Adapter, AdapterError, AdapterInfo, OpResult};
use serde_json::{json, Value};

/// In-process adapter wrapping the `aitp-rs` crates directly.
pub struct InProcessRustAdapter;

impl InProcessRustAdapter {
    /// Construct a fresh adapter.
    pub fn new() -> Self {
        Self
    }
}

impl Default for InProcessRustAdapter {
    fn default() -> Self {
        Self::new()
    }
}

const SUPPORTED_OPS: &[&str] = &[
    "init",
    "shutdown",
    "verify_jcs",
    "compute_jwk_thumbprint",
    "verify_envelope",
    "verify_manifest",
    "verify_tct",
    "verify_delegation_token",
];

impl Adapter for InProcessRustAdapter {
    fn init(&mut self) -> Result<AdapterInfo, AdapterError> {
        Ok(AdapterInfo {
            implementation: "aitp-rs (in-process, Tier-A only)".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            supported_ops: SUPPORTED_OPS.iter().map(|s| (*s).to_string()).collect(),
            supported_features: ["pinned_key_identity"]
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        })
    }

    fn execute(&mut self, op: &str, params: Value) -> Result<OpResult, AdapterError> {
        Ok(match op {
            "verify_jcs" => verify_jcs(params),
            "compute_jwk_thumbprint" => compute_jwk_thumbprint(params),
            "verify_envelope" => verify_envelope(params),
            "verify_manifest" => verify_manifest_op(params),
            "verify_tct" => verify_tct_op(params),
            "verify_delegation_token" => verify_delegation_token_op(params),
            _ => return Err(AdapterError::OpNotSupported(op.to_string())),
        })
    }

    fn shutdown(&mut self) -> Result<(), AdapterError> {
        Ok(())
    }
}

fn ok(result: Value) -> OpResult {
    OpResult::Ok { ok: true, result }
}
fn err(code: &str, msg: &str) -> OpResult {
    OpResult::Err {
        ok: false,
        error_code: code.to_string(),
        message: msg.to_string(),
    }
}

fn verify_jcs(params: Value) -> OpResult {
    let input = match params.get("input") {
        Some(v) => v.clone(),
        None => return err("INVALID_REQUEST", "missing 'input'"),
    };
    match aitp_core::jcs::canonicalize(&input) {
        Ok(bytes) => ok(json!({
            "canonical_utf8": std::str::from_utf8(&bytes).unwrap_or(""),
        })),
        Err(e) => err("JCS_ERROR", &e.to_string()),
    }
}

fn compute_jwk_thumbprint(params: Value) -> OpResult {
    let pubkey_b64 = match params.get("public_key").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err("INVALID_REQUEST", "missing 'public_key'"),
    };
    let bytes = match aitp_core::base64url::decode_strict(pubkey_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => return err("INVALID_REQUEST", "public_key must be 32-byte base64url"),
    };
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    ok(json!({"thumbprint": aitp_crypto::compute_jwk_thumbprint(&buf)}))
}

fn verify_envelope(params: Value) -> OpResult {
    let env: aitp_core::AitpEnvelope =
        match serde_json::from_value(params.get("envelope").cloned().unwrap_or_default()) {
            Ok(e) => e,
            Err(e) => return err("INVALID_ENVELOPE", &format!("envelope parse: {e}")),
        };
    let pk = match aitp_crypto::AitpVerifyingKey::from_aid(&env.sender.agent_id) {
        Ok(p) => p,
        Err(e) => return err("KEY_RESOLUTION_FAILED", &e.to_string()),
    };
    let digest = match aitp_core::envelope_signing_digest(
        &env.message_id,
        env.timestamp,
        &env.sender.agent_id,
        &env.payload,
    ) {
        Ok(d) => d,
        Err(e) => return err("INTERNAL_ERROR", &e.to_string()),
    };
    let sig = match aitp_crypto::Signature::parse(&env.signature) {
        Ok(s) => s,
        Err(_) => return err("INVALID_SIGNATURE", "signature parse"),
    };
    match pk.verify(&digest, &sig) {
        Ok(()) => ok(json!({"verified": true})),
        Err(_) => err("INVALID_SIGNATURE", "envelope signature invalid"),
    }
}

fn verify_manifest_op(params: Value) -> OpResult {
    let m: aitp_manifest::Manifest =
        match serde_json::from_value(params.get("manifest").cloned().unwrap_or_default()) {
            Ok(m) => m,
            Err(e) => return err("INVALID_ENVELOPE", &format!("manifest parse: {e}")),
        };
    let now = params
        .get("now")
        .and_then(|v| v.as_i64())
        .map(aitp_core::Timestamp)
        .unwrap_or_else(aitp_core::Timestamp::now);
    match aitp_manifest::verify_manifest(&m, &aitp_manifest::VerifyManifestContext { now }) {
        Ok(()) => ok(json!({"verified": true})),
        Err(e) => err("MANIFEST_SIGNATURE_INVALID", &e.to_string()),
    }
}

fn verify_tct_op(params: Value) -> OpResult {
    let tct: aitp_tct::Tct =
        match serde_json::from_value(params.get("tct").cloned().unwrap_or_default()) {
            Ok(t) => t,
            Err(e) => return err("INVALID_ENVELOPE", &format!("tct parse: {e}")),
        };
    let expected_audience = match params
        .get("expected_audience")
        .and_then(|v| v.as_str())
        .map(aitp_core::Aid::parse)
    {
        Some(Ok(a)) => a,
        _ => return err("INVALID_REQUEST", "missing/invalid expected_audience"),
    };
    let issuer_pubkey = match aitp_crypto::AitpVerifyingKey::from_aid(&tct.issuer) {
        Ok(p) => p,
        Err(e) => return err("KEY_RESOLUTION_FAILED", &e.to_string()),
    };
    let now = params
        .get("now")
        .and_then(|v| v.as_i64())
        .map(aitp_core::Timestamp)
        .unwrap_or_else(aitp_core::Timestamp::now);
    let ctx = aitp_tct::TctVerifyContext {
        expected_audience: &expected_audience,
        issuer_pubkey: &issuer_pubkey,
        now,
        revocation_check: None,
    };
    match aitp_tct::verify_tct(&tct, &ctx) {
        Ok(_) => ok(json!({"verified": true})),
        Err(e) => err("TCT_SIGNATURE_INVALID", &e.to_string()),
    }
}

fn verify_delegation_token_op(params: Value) -> OpResult {
    let token: aitp_delegation::DelegationToken =
        match serde_json::from_value(params.get("delegation").cloned().unwrap_or_default()) {
            Ok(t) => t,
            Err(e) => return err("INVALID_ENVELOPE", &format!("delegation parse: {e}")),
        };
    let verifier_aid = match params
        .get("verifier_aid")
        .and_then(|v| v.as_str())
        .map(aitp_core::Aid::parse)
    {
        Some(Ok(a)) => a,
        _ => return err("INVALID_REQUEST", "missing/invalid verifier_aid"),
    };
    let now = params
        .get("now")
        .and_then(|v| v.as_i64())
        .map(aitp_core::Timestamp)
        .unwrap_or_else(aitp_core::Timestamp::now);
    let ctx = aitp_delegation::VerifyDelegationContext {
        verifier_aid: &verifier_aid,
        now,
        revocation_check: None,
    };
    match aitp_delegation::verify_delegation(&token, &ctx) {
        Ok(_) => ok(json!({"verified": true})),
        Err(e) => err("DELEGATION_INVALID", &e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_returns_supported_ops() {
        let mut a = InProcessRustAdapter::new();
        let info = a.init().unwrap();
        assert!(info.supported_ops.contains("verify_jcs"));
        assert!(info.supported_ops.contains("verify_tct"));
        assert!(!info.supported_ops.contains("issue_tct"));
    }

    #[test]
    fn unsupported_op_returns_op_not_supported() {
        let mut a = InProcessRustAdapter::new();
        let result = a.execute("issue_tct", json!({}));
        assert!(matches!(
            result,
            Err(AdapterError::OpNotSupported(ref op)) if op == "issue_tct"
        ));
    }

    #[test]
    fn jcs_round_trip() {
        let mut a = InProcessRustAdapter::new();
        let r = a
            .execute("verify_jcs", json!({"input": {"b": 2, "a": 1}}))
            .unwrap();
        match r {
            OpResult::Ok { result, .. } => {
                assert_eq!(result["canonical_utf8"], json!("{\"a\":1,\"b\":2}"));
            }
            OpResult::Err { error_code, .. } => panic!("expected ok, got err: {error_code}"),
        }
    }

    #[test]
    fn jwk_thumbprint_matches_kat_001() {
        // KAT vector kat-jwk-thumb-001: pubkey for kat-keypair-001 -> jkt.
        let mut a = InProcessRustAdapter::new();
        let r = a
            .execute(
                "compute_jwk_thumbprint",
                json!({"public_key": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"}),
            )
            .unwrap();
        match r {
            OpResult::Ok { result, .. } => {
                assert_eq!(
                    result["thumbprint"],
                    json!("9ZP03Nu8GrXPAUkbKNxHOKBzxPX83SShgFkRNK-f2lw")
                );
            }
            OpResult::Err { error_code, .. } => panic!("expected ok, got err: {error_code}"),
        }
    }
}
