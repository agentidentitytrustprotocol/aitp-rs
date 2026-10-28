//! AITP envelope signing and verification.
//!
//! **No stability promise.** This crate is published so the AITP bindings
//! and tools can build on it; its API can change in any release. Depend
//! on the [`aitp`](https://docs.rs/aitp) facade crate instead.
//!
//! These helpers wrap a payload in a signed [`AitpEnvelope`] and verify
//! an envelope's outer signature. They depend only on `aitp::core` (wire
//! types, canonicalization) and `aitp::crypto` (signing) — no HTTP, no
//! runtime, no I/O — so they can be reused by language bindings and other
//! sync consumers without inheriting a transport stack.
//!
//! [`sign_envelope_async`] and [`sign_envelope_with_async`] take an async
//! signing backend ([`DynAsyncAitpSigner`], e.g. a cloud KMS client). They
//! validate, frame and assemble exactly as the sync functions do; only the
//! backend call is awaited.
//!
//! `aitp::transport::common` keeps thin wrappers over these
//! functions, so existing callers that imported `sign_envelope*` /
//! `verify_envelope_signature` from the transport crate keep compiling
//! unchanged.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use crate::core::{envelope_signing_digest, Aid, AitpEnvelope, MessageType, Timestamp};
use crate::crypto::{AitpSigner, Digest32, DynAsyncAitpSigner};
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
/// [`crate::core::ids::derived_v4`]); anything else is refused before the
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
) -> Result<AitpEnvelope, EnvelopeError> {
    sign_prepared_envelope(
        signing_key,
        unsigned(
            signing_key.aid(),
            message_type,
            payload,
            message_id,
            timestamp,
        ),
    )
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
) -> Result<AitpEnvelope, EnvelopeError> {
    sign_prepared_envelope_async(
        signing_key,
        unsigned(
            signing_key.aid(),
            message_type,
            payload,
            message_id,
            timestamp,
        ),
    )
    .await
}

/// Sign an envelope the caller assembled, e.g. one carrying an
/// `extensions` map, and return it with `signature` set.
///
/// The signature covers every member except `signature`
/// (RFC-AITP-0001 §5.4, `aitp/0.3`), so `extensions` MUST be attached
/// **before** this call; changing any member afterwards invalidates the
/// signature. Whatever `envelope.signature` holds on input is ignored and
/// replaced.
///
/// Refuses, before the backend is called: a `version` other than
/// [`crate::core::PROTOCOL_VERSION`], a non-v4 `message_id`, a `payload`
/// that is not a JSON object, a negative `timestamp`, and a
/// `sender.agent_id` that is not the signer's AID. The `signature` it
/// writes always matches the schema pattern, so the result passes
/// [`crate::core::check_envelope_structure`].
pub fn sign_prepared_envelope(
    signing_key: &dyn AitpSigner,
    mut envelope: AitpEnvelope,
) -> Result<AitpEnvelope, EnvelopeError> {
    let digest = envelope_digest(signing_key.aid(), &envelope)?;
    envelope.signature = crate::crypto::sign_jcs(signing_key, &digest)
        .map_err(EnvelopeError::Signer)?
        .into_string();
    Ok(envelope)
}

/// As [`sign_prepared_envelope`], signed by an async backend. The
/// returned future is `Send`.
pub async fn sign_prepared_envelope_async(
    signing_key: &dyn DynAsyncAitpSigner,
    mut envelope: AitpEnvelope,
) -> Result<AitpEnvelope, EnvelopeError> {
    let digest = envelope_digest(signing_key.aid(), &envelope)?;
    envelope.signature = crate::crypto::sign_jcs_async(signing_key, &digest)
        .await
        .map_err(EnvelopeError::Signer)?
        .into_string();
    Ok(envelope)
}

/// Validate an envelope about to be signed and return the digest its
/// signature covers: `sha256("aitp-envelope-v2" || 0x00 ||
/// JCS(envelope minus signature))` (RFC-AITP-0001 §5.4).
fn envelope_digest(signer: &Aid, envelope: &AitpEnvelope) -> Result<Digest32, EnvelopeError> {
    if envelope.version != crate::core::PROTOCOL_VERSION {
        return Err(EnvelopeError::UnsupportedVersion(envelope.version.clone()));
    }
    // Proposal #72 Item 6b: every verifier rejects a non-v4 message_id,
    // so refuse to sign one.
    crate::core::ids::check_v4(&envelope.message_id).map_err(EnvelopeError::MessageId)?;
    // Issue #261: every verifier rejects a non-object `payload` and a
    // negative `timestamp` as INVALID_ENVELOPE, so refuse to sign them.
    crate::core::check_unsigned_envelope_structure(envelope).map_err(EnvelopeError::Structure)?;
    if &envelope.sender.agent_id != signer {
        return Err(EnvelopeError::SenderMismatch {
            sender: envelope.sender.agent_id.clone(),
            signer: signer.clone(),
        });
    }
    envelope_signing_digest(envelope)
        .map(Digest32::from)
        .map_err(EnvelopeError::Canonicalization)
}

/// Why an envelope could not be signed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// `version` is not [`crate::core::PROTOCOL_VERSION`].
    #[error("version: `{0}` is not `{v}`", v = crate::core::PROTOCOL_VERSION)]
    UnsupportedVersion(String),
    /// `message_id` is not a UUID v4.
    #[error("message_id: {0}")]
    MessageId(#[source] crate::core::ids::V4Error),
    /// A member breaks a schema rule.
    #[error("{0}")]
    Structure(#[source] crate::core::EnvelopeStructureError),
    /// `sender.agent_id` is not the signer's AID.
    #[error("sender.agent_id `{}` is not the signer's AID `{}`", sender.as_str(), signer.as_str())]
    SenderMismatch {
        /// The envelope's `sender.agent_id`.
        sender: Aid,
        /// The signer's AID.
        signer: Aid,
    },
    /// The envelope could not be canonicalized (RFC 8785).
    #[error("canonicalization: {0}")]
    Canonicalization(#[source] crate::core::jcs::JcsError),
    /// The signing backend failed.
    #[error("signing backend failed: {0}")]
    Signer(#[source] crate::crypto::SignerError),
}

/// The envelope the plain `sign_envelope*` functions sign: no
/// `extensions`, empty `signature`.
fn unsigned(
    sender: &Aid,
    message_type: MessageType,
    payload: serde_json::Value,
    message_id: Uuid,
    timestamp: Timestamp,
) -> AitpEnvelope {
    AitpEnvelope::unsigned(sender.clone(), message_type, payload, message_id, timestamp)
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
) -> Result<AitpEnvelope, EnvelopeError> {
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
) -> Result<AitpEnvelope, EnvelopeError> {
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
///
/// The digest is re-computed over the whole envelope minus `signature`
/// (RFC-AITP-0001 §5.4), so a change to any member, `extensions`
/// included, fails verification.
pub fn verify_envelope_signature(
    envelope: &AitpEnvelope,
    sender_pubkey: &crate::crypto::AitpVerifyingKey,
) -> Result<(), crate::crypto::CryptoError> {
    let digest = envelope_signing_digest(envelope)
        .map_err(|e| crate::crypto::CryptoError::SignatureMalformed(e.to_string()))?;
    let sig = crate::crypto::Signature::parse(&envelope.signature)?;
    sender_pubkey.verify_jcs(&crate::crypto::Digest32::from(digest), &sig)
}
