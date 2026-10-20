//! Envelope signing *and verification* bindings (issue #256).
//!
//! Until 0.17.0 the bindings exposed envelope types but no way to check an
//! envelope's outer signature: only the HTTP server and the `aitp` facade
//! did, so a binding caller receiving an envelope outside a session had to
//! trust it unverified or hand-roll the `aitp/0.3` signing input.
//!
//! Both halves wrap the Rust implementation — [`wire::envelope`] for the
//! first two steps of the RFC-AITP-0001 §5.4 check order and
//! [`aitp_envelope::verify_envelope_signature`] /
//! [`aitp_envelope::sign_prepared_envelope`] for the signature — so the
//! binding cannot drift from the server.

use aitp_core::{
    Aid, AitpEnvelope, ExtensionsMap, MessageType, Sender, Timestamp, PROTOCOL_VERSION,
};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use uuid::Uuid;

use crate::throw_with_code;
use crate::wire::{self, WireError};

/// The registered wire code for a check-order step 1 or 2 failure.
fn wire_code(err: &WireError) -> &'static str {
    match err {
        WireError::UnknownVersion(_) => "UNKNOWN_VERSION",
        WireError::UnknownField(_) => "UNKNOWN_FIELD",
        WireError::Malformed(_) => "INVALID_ENVELOPE",
    }
}

/// Verify an `AitpEnvelope` JSON string sent by `expectedSenderAid`.
///
/// Returns on success; on failure throws an `Error` whose **`code`** is the
/// registered RFC-AITP-0001 §5.7 code of the first failing step of the §5.4
/// check order:
///
/// 1. `version` absent or not `aitp/0.3` → `UNKNOWN_VERSION` (no
///    dual-accept: `aitp/0.2` is as unknown as `aitp/9.9`);
/// 2. a member outside the schema and outside `extensions` →
///    `UNKNOWN_FIELD`; any other structural defect (a duplicate key,
///    RFC-AITP-0001 §5.4.5, a missing member, an unregistered
///    `message_type`, a non-v4 `message_id`, a non-object `payload`, a
///    negative `timestamp`, a `signature` outside the schema pattern) →
///    `INVALID_ENVELOPE`;
/// 3. a signature that does not verify over `sig_input_v2` under the
///    expected sender's key → `INVALID_SIGNATURE`. An envelope whose
///    `sender.agent_id` is not `expectedSenderAid` fails here too: it is
///    not signed by the key the caller trusts.
///
/// Branch on `error.code`, never on `error.message`.
///
/// The key comes from `expectedSenderAid` (every AID encodes its public
/// key), as `verifyRevocationList` takes its pinned issuer. A malformed
/// `expectedSenderAid` is the caller's error and throws an `Error` with no
/// verification code.
///
/// Establishes **authenticity and structure only**. Replay and freshness
/// (RFC-AITP-0001 §5.5: the timestamp window and `message_id`
/// deduplication) are not checked; they belong to the receiving endpoint's
/// RFC-AITP-0009 §3.1 order, which the caller owns.
#[napi(js_name = "verifyEnvelope")]
pub fn verify_envelope_js(
    env: Env,
    envelope_json: String,
    expected_sender_aid: String,
) -> Result<()> {
    let envelope = wire::envelope(&envelope_json)
        .map_err(|e| throw_with_code(env, wire_code(&e), format!("invalid envelope JSON: {e}")))?;
    // A bad AID is the caller's error, not the envelope's — do not report
    // it as a verification cause.
    let expected = Aid::parse(&expected_sender_aid)
        .map_err(|e| Error::from_reason(format!("invalid expectedSenderAid: {e}")))?;
    let key = AitpVerifyingKey::from_aid(&expected)
        .map_err(|e| Error::from_reason(format!("invalid expectedSenderAid: {e}")))?;
    if envelope.sender.agent_id != expected {
        return Err(throw_with_code(
            env,
            "INVALID_SIGNATURE",
            format!(
                "envelope sender `{}` is not the expected sender `{}`",
                envelope.sender.agent_id, expected
            ),
        ));
    }
    aitp_envelope::verify_envelope_signature(&envelope, &key).map_err(|e| {
        throw_with_code(
            env,
            "INVALID_SIGNATURE",
            format!("envelope signature invalid: {e}"),
        )
    })
}

/// Options for `AitpAgent.signEnvelope`.
#[napi(object)]
pub struct SignEnvelopeOpts {
    /// JSON object for the envelope's `extensions` member, covered by the
    /// signature like every other member. Omitted when absent.
    pub extensions_json: Option<String>,
    /// UUID v4. Defaults to a fresh one.
    pub message_id: Option<String>,
    /// Unix seconds. Defaults to now.
    pub timestamp: Option<i64>,
}

/// Sign an envelope with `key` (RFC-AITP-0001 §5.4) and return its JSON.
pub fn sign_envelope_js(
    key: &AitpSigningKey,
    message_type: &str,
    payload_json: &str,
    opts: Option<SignEnvelopeOpts>,
) -> Result<String> {
    let opts = opts.unwrap_or(SignEnvelopeOpts {
        extensions_json: None,
        message_id: None,
        timestamp: None,
    });
    let message_type: MessageType =
        serde_json::from_value(serde_json::Value::String(message_type.to_string()))
            .map_err(|_| Error::from_reason(format!("unknown messageType '{message_type}'")))?;
    let payload: serde_json::Value = serde_json::from_str(payload_json)
        .map_err(|e| Error::from_reason(format!("invalid payload JSON: {e}")))?;
    if !payload.is_object() {
        return Err(Error::from_reason("payload must be a JSON object"));
    }
    let extensions = opts
        .extensions_json
        .as_deref()
        .map(serde_json::from_str::<ExtensionsMap>)
        .transpose()
        .map_err(|e| Error::from_reason(format!("invalid extensions JSON: {e}")))?;
    let message_id = match opts.message_id.as_deref() {
        Some(s) => {
            Uuid::parse_str(s).map_err(|e| Error::from_reason(format!("invalid uuid: {e}")))?
        }
        None => Uuid::new_v4(),
    };
    let envelope = AitpEnvelope {
        version: PROTOCOL_VERSION.into(),
        message_type,
        message_id,
        timestamp: opts.timestamp.map(Timestamp).unwrap_or_else(Timestamp::now),
        sender: Sender {
            agent_id: key.aid().clone(),
        },
        payload,
        extensions,
        signature: String::new(),
    };
    // Refuses a non-v4 `message_id` and a negative `timestamp` before
    // signing: whatever a verifier rejects is not signed.
    let signed = aitp_envelope::sign_prepared_envelope(key, envelope)
        .map_err(|e| Error::from_reason(format!("signEnvelope failed: {e}")))?;
    serde_json::to_string(&signed).map_err(|e| Error::from_reason(e.to_string()))
}
