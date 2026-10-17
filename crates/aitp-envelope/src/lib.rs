//! AITP envelope signing and verification.
//!
//! These helpers wrap a payload in a signed [`AitpEnvelope`] and verify
//! an envelope's outer signature. They depend only on `aitp-core` (wire
//! types, canonicalization) and `aitp-crypto` (signing) — no HTTP, no
//! runtime, no I/O — so they can be reused by language bindings and other
//! sync consumers without inheriting a transport stack.
//!
//! [`sign_envelope_async`] and [`sign_envelope_with_async`] take an async
//! signing backend ([`DynAsyncAitpSigner`], e.g. a cloud KMS client). They
//! validate, frame and assemble exactly as the sync functions do; only the
//! backend call is awaited.
//!
//! `aitp-transport-http::common` keeps thin wrappers over these
//! functions, so existing callers that imported `sign_envelope*` /
//! `verify_envelope_signature` from the transport crate keep compiling
//! unchanged.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use aitp_core::{envelope_signing_digest, Aid, AitpEnvelope, MessageType, Sender, Timestamp};
use aitp_crypto::{AitpSigner, Digest32, DynAsyncAitpSigner};
use uuid::Uuid;

/// Sign and wrap a payload as an [`AitpEnvelope`] with caller-provided
/// `message_id` and `timestamp`.
///
/// **Use this** whenever the payload contains a pinned-key identity proof
/// (the proof is signed over `<message_id>|<timestamp>` and the receiver
/// reconstructs the same string from `envelope.message_id` /
/// `envelope.timestamp`). Caller MUST pass the same `(mid, ts)` it used
/// to build the identity proof inside `payload`.
///
/// `message_id` MUST be in the UUID v4 layout (random, or derived per
/// [`aitp_core::ids::derived_v4`]); anything else is refused before the
/// backend is called.
///
/// Accepts any [`AitpSigner`] (in-process key, KMS, HSM); a backend
/// failure is returned as `Err("signing backend failed: ...")`.
pub fn sign_envelope_with(
    signing_key: &dyn AitpSigner,
    message_type: MessageType,
    payload: serde_json::Value,
    message_id: Uuid,
    timestamp: Timestamp,
) -> Result<AitpEnvelope, String> {
    let digest = envelope_digest(signing_key.aid(), &payload, &message_id, timestamp)?;
    let signature = aitp_crypto::sign_jcs(signing_key, &digest).map_err(backend_failed)?;
    Ok(assemble(
        signing_key.aid(),
        message_type,
        payload,
        message_id,
        timestamp,
        signature,
    ))
}

/// As [`sign_envelope_with`], signed by an async backend (KMS, HSM,
/// remote signer). Validation, digest and output are identical to the
/// sync function; the returned future is `Send`.
///
/// A backend failure is returned as `Err("signing backend failed: ...")`.
pub async fn sign_envelope_with_async(
    signing_key: &dyn DynAsyncAitpSigner,
    message_type: MessageType,
    payload: serde_json::Value,
    message_id: Uuid,
    timestamp: Timestamp,
) -> Result<AitpEnvelope, String> {
    let digest = envelope_digest(signing_key.aid(), &payload, &message_id, timestamp)?;
    let signature = aitp_crypto::sign_jcs_async(signing_key, &digest)
        .await
        .map_err(backend_failed)?;
    Ok(assemble(
        signing_key.aid(),
        message_type,
        payload,
        message_id,
        timestamp,
        signature,
    ))
}

/// The digest the envelope signature covers (RFC-AITP-0001 §5.4).
fn envelope_digest(
    sender: &Aid,
    payload: &serde_json::Value,
    message_id: &Uuid,
    timestamp: Timestamp,
) -> Result<Digest32, String> {
    // Proposal #72 Item 6b: every verifier rejects a non-v4 message_id,
    // so refuse to sign one.
    aitp_core::ids::check_v4(message_id).map_err(|e| format!("message_id: {e}"))?;
    envelope_signing_digest(message_id, timestamp, sender, payload)
        .map(Digest32::from)
        .map_err(|e| e.to_string())
}

fn backend_failed(e: aitp_crypto::SignerError) -> String {
    format!("signing backend failed: {e}")
}

/// Assemble the signed envelope; shared by the sync and async paths.
fn assemble(
    sender: &Aid,
    message_type: MessageType,
    payload: serde_json::Value,
    message_id: Uuid,
    timestamp: Timestamp,
    signature: aitp_crypto::Signature,
) -> AitpEnvelope {
    AitpEnvelope {
        version: "aitp/0.2".into(),
        message_type,
        message_id,
        timestamp,
        sender: Sender {
            agent_id: sender.clone(),
        },
        payload,
        extensions: None,
        signature: signature.into_string(),
    }
}

/// Convenience: sign with a freshly generated `message_id` and
/// `timestamp`. **Do not use** for envelopes whose payload carries a
/// pinned-key identity proof — see [`sign_envelope_with`].
///
/// Accepts any [`AitpSigner`] (in-process key, KMS, HSM); a backend
/// failure is returned as `Err("signing backend failed: ...")`.
pub fn sign_envelope(
    signing_key: &dyn AitpSigner,
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

/// As [`sign_envelope`], signed by an async backend: a fresh
/// `message_id` and `timestamp`, then [`sign_envelope_with_async`].
/// **Do not use** for envelopes whose payload carries a pinned-key
/// identity proof. The returned future is `Send`.
///
/// A backend failure is returned as `Err("signing backend failed: ...")`.
pub async fn sign_envelope_async(
    signing_key: &dyn DynAsyncAitpSigner,
    message_type: MessageType,
    payload: serde_json::Value,
) -> Result<AitpEnvelope, String> {
    sign_envelope_with_async(
        signing_key,
        message_type,
        payload,
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .await
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
    sender_pubkey.verify_jcs(&aitp_crypto::Digest32::from(digest), &sig)
}
