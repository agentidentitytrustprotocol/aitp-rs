//! TCT renewal ops (RFC-AITP-0013, Draft; `aitp_experimental::renewal`).
//!
//! `renew_tct` runs the issuer side (§4) and returns the signed response
//! envelope (§6) as `response_envelope`, from which the runner reads the
//! renewed TCT. `verify_renewal_response` runs the holder side (§6.1).

use super::admission::ready;
use super::{checked, envelope_parse_error_code, err, kat_seed_for_aid, AdapterState};
use aitp::core::nonce_store::InMemoryNonceStore;
use aitp::core::{Aid, ErrorCode, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp_experimental::renewal::{
    parse_renewal_request, process_renewal_request, renewal_response_envelope,
    verify_renewal_response, RenewalContext, RenewalError, RenewalResponseContext,
};
use serde_json::{json, Value};
use std::collections::HashSet;
use uuid::Uuid;

/// The registered string of `code`.
fn code_str(code: ErrorCode) -> String {
    code.as_str().to_owned()
}

fn step_now(state: &AdapterState, params: &Value) -> Timestamp {
    params
        .get("now")
        .and_then(Value::as_i64)
        .map(Timestamp)
        .unwrap_or_else(|| state.now())
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// `renew_tct`: this adapter is the issuer `self_aid`, with the Manifest
/// `issuer_manifest`, the policy `issuer_policy` and the deny list
/// `issuer_deny_list`. The replay guard lives for the fixture.
pub(super) fn renew_tct_op(state: &mut AdapterState, id: &str, params: Value) -> Value {
    let Some(self_aid) = params.get("self_aid").and_then(Value::as_str) else {
        return err(id, "INVALID_REQUEST", "missing self_aid");
    };
    let Some(seed) = kat_seed_for_aid(self_aid) else {
        return err(id, "OP_NOT_SUPPORTED", "self_aid is not a KAT keypair");
    };
    let issuer = AitpSigningKey::from_seed(&seed);
    let now = step_now(state, &params);
    let manifest = params
        .get("issuer_manifest")
        .cloned()
        .unwrap_or(Value::Null);
    let Some(manifest_exp) = manifest.get("expires_at").and_then(Value::as_i64) else {
        return err(id, "INVALID_REQUEST", "missing issuer_manifest.expires_at");
    };
    let offered = strings(manifest.get("offered_capabilities"));
    let policy = params.get("issuer_policy").cloned().unwrap_or(Value::Null);
    let deny: HashSet<String> = strings(params.get("issuer_deny_list"))
        .into_iter()
        .collect();
    let revocation_check = move |q: &aitp::tct::RevocationQuery<'_>| {
        Ok(if deny.contains(&q.jti.to_string()) {
            aitp::tct::RevocationStatus::Revoked
        } else {
            aitp::tct::RevocationStatus::Clear
        })
    };
    let Some(body) = params.get("renewal_request") else {
        return err(id, "INVALID_REQUEST", "missing renewal_request");
    };

    let request = match parse_renewal_request(body.to_string().as_bytes()) {
        Ok(r) => r,
        Err(e) => return err(id, &code_str(e.error_code()), &e.to_string()),
    };
    let store = state
        .renewal_nonces
        .get_or_insert_with(InMemoryNonceStore::default);
    let mut ctx = RenewalContext::new(
        Timestamp(manifest_exp),
        &offered,
        aitp::tct::RevocationSource::Check(&revocation_check),
        &*store,
        now,
    );
    if let Some(ttl) = policy.get("renewal_ttl_secs").and_then(Value::as_i64) {
        ctx = ctx.ttl_secs(ttl);
    }
    if policy.get("mint_grant_voucher").and_then(Value::as_bool) == Some(false) {
        ctx = ctx.without_voucher();
    }
    let renewed = match ready(process_renewal_request(&request, &issuer, &ctx)) {
        Ok(r) => r,
        Err(RenewalError::NonceStore(e)) => return err(id, "INTERNAL_ERROR", &e.to_string()),
        Err(e) => return err(id, &code_str(e.error_code()), &e.to_string()),
    };
    match renewal_response_envelope(&issuer, &renewed, &request.pop_nonce, Uuid::new_v4(), now) {
        Ok(envelope) => json!({
            "id": id,
            "ok": true,
            "result": {"response_envelope": envelope},
        }),
        Err(e) => err(id, "INTERNAL_ERROR", &e.to_string()),
    }
}

/// `verify_renewal_response`: this adapter is the holder `self_aid`,
/// which presented `current_tct` with `sent_pop_nonce` and received
/// `envelope`.
pub(super) fn verify_renewal_response_op(
    state: &mut AdapterState,
    id: &str,
    params: Value,
) -> Value {
    let Some(self_aid) = params.get("self_aid").and_then(Value::as_str) else {
        return err(id, "INVALID_REQUEST", "missing self_aid");
    };
    let Ok(self_aid) = Aid::parse(self_aid) else {
        return err(id, "INVALID_REQUEST", "self_aid is not an AID");
    };
    let (Some(current_tct), Some(sent_pop_nonce), Some(envelope)) = (
        params.get("current_tct").and_then(Value::as_str),
        params.get("sent_pop_nonce").and_then(Value::as_str),
        params.get("envelope"),
    ) else {
        return err(
            id,
            "INVALID_REQUEST",
            "missing current_tct, sent_pop_nonce or envelope",
        );
    };
    let now = step_now(state, &params);
    let envelope = match aitp::core::parse_envelope_wire(&checked(envelope)) {
        Ok(e) => e,
        Err(e) => return err(id, &envelope_parse_error_code(&e), &e.to_string()),
    };
    let ctx = RenewalResponseContext::new(&self_aid, current_tct, sent_pop_nonce, now);
    match verify_renewal_response(&envelope, &ctx) {
        Ok(renewed) => {
            // RFC-AITP-0001 §5.5: a message_id seen before is a replay.
            if !state
                .seen_message_ids
                .insert(envelope.message_id.to_string())
            {
                return err(id, "REPLAY_DETECTED", "message_id already seen in this run");
            }
            json!({
                "id": id,
                "ok": true,
                "result": {
                    "verified": true,
                    "renewed_jti": renewed.tct.claims().jti.to_string(),
                },
            })
        }
        Err(e) => err(id, &code_str(e.error_code()), &e.to_string()),
    }
}
