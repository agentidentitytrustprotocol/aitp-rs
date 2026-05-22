//! Shared client/server helpers.
//!
//! Envelope signing/verification is implemented in the `aitp-envelope`
//! crate (no HTTP, no async) so language bindings and other sync
//! consumers can reuse it without a transport stack. The thin wrappers
//! below delegate to it while keeping the `aitp_transport_http::common`
//! API surface stable for existing callers.

use aitp_core::{AitpEnvelope, MessageType, Timestamp};
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
    aitp_envelope::sign_envelope_with(signing_key, message_type, payload, message_id, timestamp)
}

/// Convenience: sign with a freshly generated `message_id` and
/// `timestamp`. **Do not use** for envelopes whose payload carries a
/// pinned-key identity proof — see [`sign_envelope_with`].
pub fn sign_envelope(
    signing_key: &AitpSigningKey,
    message_type: MessageType,
    payload: serde_json::Value,
) -> Result<AitpEnvelope, String> {
    aitp_envelope::sign_envelope(signing_key, message_type, payload)
}

/// Verify an envelope's outer signature given the sender's verifying key.
pub fn verify_envelope_signature(
    envelope: &AitpEnvelope,
    sender_pubkey: &aitp_crypto::AitpVerifyingKey,
) -> Result<(), aitp_crypto::CryptoError> {
    aitp_envelope::verify_envelope_signature(envelope, sender_pubkey)
}
