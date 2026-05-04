//! In-process adapter for the Rust reference implementation.
//!
//! Calls directly into [`aitp_rs_adapter`]'s library API, so the
//! subprocess and in-process adapters share one dispatch
//! implementation — every Tier A/B/C/D op the subprocess binary
//! supports is also reachable here, with no IPC overhead. Used for
//! fast local development; CI uses the subprocess adapter against
//! the same library so the NDJSON wire protocol is exercised on
//! every PR.

use crate::adapter::{Adapter, AdapterError, AdapterInfo, OpResult};
use serde_json::{json, Value};

/// In-process adapter wrapping the `aitp-rs-adapter` library directly.
pub struct InProcessRustAdapter {
    state: aitp_rs_adapter::AdapterState,
}

impl InProcessRustAdapter {
    /// Construct a fresh adapter with a clean session/keypair store.
    pub fn new() -> Self {
        Self {
            state: aitp_rs_adapter::AdapterState::default(),
        }
    }
}

impl Default for InProcessRustAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for InProcessRustAdapter {
    fn init(&mut self) -> Result<AdapterInfo, AdapterError> {
        // Run the canonical `init` op against the same dispatcher the
        // subprocess binary uses — that way the supported_ops /
        // supported_features list stays in sync automatically.
        let resp = aitp_rs_adapter::handle(&mut self.state, "init", "init", json!({}));
        let result = resp.get("result").cloned().unwrap_or_default();
        let supported_ops = result
            .get("supported_ops")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        let supported_features = result
            .get("supported_features")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        Ok(AdapterInfo {
            implementation: format!(
                "{} (in-process)",
                result
                    .get("implementation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("aitp-rs")
            ),
            version: result
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .to_string(),
            supported_ops,
            supported_features,
        })
    }

    fn execute(&mut self, op: &str, params: Value) -> Result<OpResult, AdapterError> {
        let resp = aitp_rs_adapter::handle(&mut self.state, "exec", op, params);
        let ok = resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        if ok {
            Ok(OpResult::Ok {
                ok: true,
                result: resp.get("result").cloned().unwrap_or_default(),
            })
        } else {
            let error_code = resp
                .get("error_code")
                .and_then(|v| v.as_str())
                .unwrap_or("INTERNAL_ERROR")
                .to_string();
            // Translate OP_NOT_SUPPORTED to AdapterError so the
            // runner's skip path triggers, mirroring how the
            // subprocess adapter behaves.
            if error_code == "OP_NOT_SUPPORTED" {
                return Err(AdapterError::OpNotSupported(op.to_string()));
            }
            Ok(OpResult::Err {
                ok: false,
                error_code,
                message: resp
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
        }
    }

    fn shutdown(&mut self) -> Result<(), AdapterError> {
        Ok(())
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
        // After the rc.1 refactor the in-process adapter shares its
        // dispatch with the subprocess binary, so it now supports
        // Tier B/C/D ops too.
        assert!(info.supported_ops.contains("issue_tct"));
        assert!(info.supported_ops.contains("generate_keypair"));
        assert!(info.supported_ops.contains("start_handshake"));
    }

    #[test]
    fn unsupported_op_returns_op_not_supported() {
        let mut a = InProcessRustAdapter::new();
        let result = a.execute("nonexistent_op", json!({}));
        assert!(matches!(
            result,
            Err(AdapterError::OpNotSupported(ref op)) if op == "nonexistent_op"
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

    /// Round-trip a Tier-B issuance pipeline through the in-process
    /// adapter: generate a keypair, mint a Manifest, mint a TCT for
    /// the same pubkey, then verify the TCT. Pre-rc.1 the in-process
    /// adapter returned `OP_NOT_SUPPORTED` for these ops.
    #[test]
    fn tier_b_round_trip_through_in_process() {
        let mut a = InProcessRustAdapter::new();
        // 1. Generate a keypair from kat-keypair-001's seed (zeros).
        let kp = match a
            .execute(
                "generate_keypair",
                json!({"seed": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
            )
            .unwrap()
        {
            OpResult::Ok { result, .. } => result,
            OpResult::Err {
                error_code,
                message,
                ..
            } => panic!("generate_keypair failed: {error_code} {message}"),
        };
        let issuer_handle = kp["handle"].as_str().unwrap().to_string();
        let issuer_aid = kp["aid"].as_str().unwrap().to_string();
        let issuer_pubkey = kp["public_key"].as_str().unwrap().to_string();

        // 2. Issue a Manifest using that keypair.
        let manifest = match a
            .execute(
                "issue_manifest",
                json!({
                    "keypair": issuer_handle,
                    "ttl_secs": 3600,
                    "handshake_endpoint": "https://example.com/aitp/handshake",
                    "identity_hint": {
                        "type": "pinned_key",
                        "subject": "x",
                        "public_key": issuer_pubkey,
                    },
                    "accepted_trust_anchors": ["https://idp.example.com"],
                    "offered_capabilities": ["demo.echo"],
                }),
            )
            .unwrap()
        {
            OpResult::Ok { result, .. } => result,
            OpResult::Err {
                error_code,
                message,
                ..
            } => panic!("issue_manifest failed: {error_code} {message}"),
        };
        assert!(manifest["manifest_envelope"]["manifest"].is_object());

        // 3. Issue a TCT under the same keypair, audience == issuer.
        let tct = match a
            .execute(
                "issue_tct",
                json!({
                    "issuer_keypair": issuer_handle,
                    "subject": issuer_aid,
                    "audience": issuer_aid,
                    "subject_public_key": issuer_pubkey,
                    "grants": ["demo.echo"],
                    "ttl_secs": 600,
                }),
            )
            .unwrap()
        {
            OpResult::Ok { result, .. } => result,
            OpResult::Err {
                error_code,
                message,
                ..
            } => panic!("issue_tct failed: {error_code} {message}"),
        };
        assert!(tct["tct_envelope"]["tct"].is_object());

        // 4. Verify the TCT round-trips through the same adapter.
        let verify = match a
            .execute(
                "verify_tct",
                json!({
                    "tct": tct["tct_envelope"]["tct"].clone(),
                    "expected_audience": issuer_aid,
                }),
            )
            .unwrap()
        {
            OpResult::Ok { result, .. } => result,
            OpResult::Err {
                error_code,
                message,
                ..
            } => panic!("verify_tct failed: {error_code} {message}"),
        };
        assert!(verify
            .get("verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false));
    }
}
