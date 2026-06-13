//! AITP envelope signing and verification.
//!
//! These helpers wrap a payload in a signed [`AitpEnvelope`] and verify
//! an envelope's outer signature. They depend only on `aitp-core` (wire
//! types, canonicalization) and `aitp-crypto` (Ed25519) — no HTTP, no
//! async, no I/O — so they can be reused by language bindings and other
//! sync consumers without inheriting a transport stack.
//!
//! `aitp-transport-http::common` keeps thin wrappers over these
//! functions, so existing callers that imported `sign_envelope*` /
//! `verify_envelope_signature` from the transport crate keep compiling
//! unchanged.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use aitp_core::{envelope_signing_digest, AitpEnvelope, MessageType, Sender, Timestamp};
use aitp_crypto::AitpSigningKey;
use uuid::Uuid;

/// Sign and wrap a payload as an [`AitpEnvelope`] with caller-provided
/// `message_id` and `timestamp`.
///
/// **Use this** whenever the payload contains a pinned-key identity proof
/// (the proof is signed over `<message_id>|<timestamp>` and the receiver
/// reconstructs the same string from `envelope.message_id` /
/// `envelope.timestamp`). Caller MUST pass the same `(mid, ts)` it used
/// to build the identity proof inside `payload`.
pub fn sign_envelope_with(
    signing_key: &AitpSigningKey,
    message_type: MessageType,
    payload: serde_json::Value,
    message_id: Uuid,
    timestamp: Timestamp,
) -> Result<AitpEnvelope, String> {
    let digest = envelope_signing_digest(&message_id, timestamp, signing_key.aid(), &payload)
        .map_err(|e| e.to_string())?;
    let signature = signing_key.sign(&digest).into_string();
    Ok(AitpEnvelope {
        version: "aitp/0.2".into(),
        message_type,
        message_id,
        timestamp,
        sender: Sender {
            agent_id: signing_key.aid().clone(),
        },
        payload,
        signature,
    })
}

/// Convenience: sign with a freshly generated `message_id` and
/// `timestamp`. **Do not use** for envelopes whose payload carries a
/// pinned-key identity proof — see [`sign_envelope_with`].
pub fn sign_envelope(
    signing_key: &AitpSigningKey,
    message_type: MessageType,
    payload: serde_json::Value,
) -> Result<AitpEnvelope, String> {
    sign_envelope_with(
        signing_key,
        message_type,
        payload,
        Uuid::new_v4(),
        Timestamp::now(),
    )
}

/// Verify an envelope's outer signature given the sender's verifying key.
pub fn verify_envelope_signature(
    envelope: &AitpEnvelope,
    sender_pubkey: &aitp_crypto::AitpVerifyingKey,
) -> Result<(), aitp_crypto::CryptoError> {
    let digest = envelope_signing_digest(
        &envelope.message_id,
        envelope.timestamp,
        &envelope.sender.agent_id,
        &envelope.payload,
    )
    .map_err(|e| aitp_crypto::CryptoError::SignatureMalformed(e.to_string()))?;
    let sig = aitp_crypto::Signature::parse(&envelope.signature)?;
    sender_pubkey.verify(&digest, &sig)
}
