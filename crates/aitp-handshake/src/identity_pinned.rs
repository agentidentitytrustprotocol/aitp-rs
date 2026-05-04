//! Pinned-key identity verification (RFC-AITP-0002 §3).
//!
//! The pinned-key proof input is exactly:
//!
//! ```text
//! proof_input = message_id + "|" + timestamp_string
//! proof       = base64url(sign(agent_priv, sha256(proof_input)))
//! ```
//!
//! `verify_pinned_key` reconstructs `proof_input` from the **envelope's**
//! `message_id` and `timestamp` (passed in via [`PinnedKeyVerifyContext`])
//! and checks the signature against the public key encoded in
//! `descriptor.public_key`. The verifier also enforces that
//! `descriptor.public_key` decodes to the same 32 bytes as
//! `ctx.sender_aid` — preventing a sender from claiming an AID it
//! doesn't control the key for.

use crate::error::HandshakeError;
use crate::identity::IdentityDescriptor;
use aitp_core::{base64url, Aid, Timestamp};
use aitp_crypto::{AitpVerifyingKey, Signature};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Inputs for verifying a pinned-key identity proof.
pub struct PinnedKeyVerifyContext<'a> {
    /// The sender's AID (per `envelope.sender.agent_id`).
    pub sender_aid: &'a Aid,
    /// The envelope's `message_id`.
    pub message_id: &'a Uuid,
    /// The envelope's `timestamp`.
    pub timestamp: Timestamp,
}

/// Verify a pinned-key identity proof.
///
/// Steps (RFC-AITP-0002 §3.2):
///
/// 1. Decode `descriptor.public_key` (43-char base64url) → 32 bytes.
/// 2. Confirm those 32 bytes equal the public key encoded in
///    `ctx.sender_aid`.
/// 3. Reconstruct `proof_input = message_id || "|" || timestamp_string`.
/// 4. Verify `descriptor.proof` over `sha256(proof_input)`.
pub fn verify_pinned_key(
    descriptor: &IdentityDescriptor,
    ctx: &PinnedKeyVerifyContext<'_>,
) -> Result<(), HandshakeError> {
    let public_key = descriptor
        .public_key
        .as_ref()
        .ok_or_else(|| HandshakeError::Identity("pinned_key missing public_key".into()))?;
    let pk_bytes = base64url::decode_strict(public_key)
        .map_err(|_| HandshakeError::Identity("public_key malformed base64url".into()))?;
    if pk_bytes.len() != 32 {
        return Err(HandshakeError::Identity(
            "public_key must decode to 32 bytes".into(),
        ));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&pk_bytes);
    if buf != ctx.sender_aid.to_ed25519_bytes() {
        return Err(HandshakeError::Identity(
            "public_key does not match sender AID".into(),
        ));
    }

    let pk = AitpVerifyingKey::from_bytes(&buf)
        .map_err(|_| HandshakeError::Identity("public_key not Ed25519".into()))?;
    let proof_input = format!("{}|{}", ctx.message_id, ctx.timestamp.0);
    let digest = Sha256::digest(proof_input.as_bytes());
    let sig = Signature::parse(&descriptor.proof)
        .map_err(|_| HandshakeError::Identity("proof malformed".into()))?;
    pk.verify(&digest, &sig)
        .map_err(|_| HandshakeError::Identity("pinned_key signature invalid".into()))?;
    Ok(())
}

/// Sign a pinned-key identity proof — helper for the issuing side.
pub fn sign_pinned_key_proof(
    signing_key: &aitp_crypto::AitpSigningKey,
    message_id: &Uuid,
    timestamp: Timestamp,
) -> String {
    let proof_input = format!("{}|{}", message_id, timestamp.0);
    let digest = Sha256::digest(proof_input.as_bytes());
    signing_key.sign(&digest).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdentityKind;
    use aitp_crypto::AitpSigningKey;

    #[test]
    fn round_trip() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let mid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let ts = Timestamp(1_700_000_000);
        let proof = sign_pinned_key_proof(&key, &mid, ts);
        let descriptor = IdentityDescriptor {
            kind: IdentityKind::PinnedKey,
            issuer: None,
            subject: "agent-x".into(),
            proof,
            public_key: Some(base64url::encode(&key.verifying_key().to_bytes())),
        };
        verify_pinned_key(
            &descriptor,
            &PinnedKeyVerifyContext {
                sender_aid: key.aid(),
                message_id: &mid,
                timestamp: ts,
            },
        )
        .unwrap();
    }

    #[test]
    fn pubkey_aid_mismatch_rejected() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let other = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::nil();
        let ts = Timestamp(1);
        let proof = sign_pinned_key_proof(&key, &mid, ts);
        let descriptor = IdentityDescriptor {
            kind: IdentityKind::PinnedKey,
            issuer: None,
            subject: "x".into(),
            proof,
            // Lie about which key signed.
            public_key: Some(base64url::encode(&other.verifying_key().to_bytes())),
        };
        let err = verify_pinned_key(
            &descriptor,
            &PinnedKeyVerifyContext {
                sender_aid: other.aid(),
                message_id: &mid,
                timestamp: ts,
            },
        )
        .unwrap_err();
        assert!(matches!(err, HandshakeError::Identity(_)));
    }
}
