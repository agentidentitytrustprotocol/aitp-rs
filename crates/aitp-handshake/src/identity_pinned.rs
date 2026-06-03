//! Pinned-key identity verification (RFC-AITP-0002 §3).
//!
//! The pinned-key proof input is exactly:
//!
//! ```text
//! proof_input =
//!     b"aitp-pinned-key-v1\0"
//!     || sender_aid_bytes       || b"\0"
//!     || receiver_aid_bytes     || b"\0"
//!     || message_id_bytes       || b"\0"
//!     || timestamp_be_8_bytes   || b"\0"
//!     || pop_nonce_decoded_bytes
//! proof = base64url(sign(agent_priv, sha256(proof_input)))
//! ```
//!
//! Where:
//! - `sender_aid_bytes` = UTF-8 bytes of the full `aid:pubkey:...` string
//! - `receiver_aid_bytes` = UTF-8 bytes of the verifying peer's own AID
//! - `message_id_bytes` = UTF-8 bytes of the UUID in canonical lowercase form
//! - `timestamp_be_8_bytes` = envelope timestamp as signed big-endian i64
//! - `pop_nonce_decoded_bytes` = raw bytes from base64url-decoding the
//!   `pop_nonce` (NOT the ASCII string)
//! - `\0` = single null byte separator between every field
//!
//! Binding all five fields prevents a captured proof from being replayed
//! against a different sender, receiver, message, timestamp, or
//! handshake nonce.

use crate::error::HandshakeError;
use crate::identity::IdentityDescriptor;
use aitp_core::{base64url, Aid, Timestamp};
use aitp_crypto::{AitpVerifyingKey, Signature};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Domain-separation prefix for the pinned-key proof input. Prevents
/// a signature minted under one AITP version from being replayed
/// against a future version with a different proof-input layout.
pub const PINNED_KEY_PROOF_DOMAIN: &[u8] = b"aitp-pinned-key-v1\0";

/// Build the canonical pinned-key proof input bytes.
///
/// See module-level docs for the exact byte layout. This is the
/// pre-hash input — both signer and verifier MUST produce identical
/// bytes here for the signature check to succeed.
pub fn pinned_key_proof_input(
    sender_aid: &Aid,
    receiver_aid: &Aid,
    message_id: &Uuid,
    timestamp: Timestamp,
    pop_nonce: &str,
) -> Result<Vec<u8>, HandshakeError> {
    let pop_nonce_bytes = base64url::decode_strict(pop_nonce)
        .map_err(|_| HandshakeError::Identity("pop_nonce is not valid base64url".into()))?;
    let ts_bytes = timestamp.0.to_be_bytes();
    let mut input = Vec::with_capacity(
        PINNED_KEY_PROOF_DOMAIN.len()
            + sender_aid.as_str().len()
            + 1
            + receiver_aid.as_str().len()
            + 1
            + 36 // UUID canonical form
            + 1
            + ts_bytes.len()
            + 1
            + pop_nonce_bytes.len(),
    );
    input.extend_from_slice(PINNED_KEY_PROOF_DOMAIN);
    input.extend_from_slice(sender_aid.as_str().as_bytes());
    input.push(0);
    input.extend_from_slice(receiver_aid.as_str().as_bytes());
    input.push(0);
    input.extend_from_slice(message_id.to_string().as_bytes());
    input.push(0);
    input.extend_from_slice(&ts_bytes);
    input.push(0);
    input.extend_from_slice(&pop_nonce_bytes);
    Ok(input)
}

/// Inputs for verifying a pinned-key identity proof.
pub struct PinnedKeyVerifyContext<'a> {
    /// The sender's AID (per `envelope.sender.agent_id`).
    pub sender_aid: &'a Aid,
    /// The verifying peer's own AID — required by RFC-AITP-0002 §3.1
    /// to bind the proof to *this* receiver and defend against
    /// cross-peer replay.
    pub receiver_aid: &'a Aid,
    /// The envelope's `message_id`.
    pub message_id: &'a Uuid,
    /// The envelope's `timestamp`.
    pub timestamp: Timestamp,
    /// The handshake's `pop_nonce` (the base64url string from the
    /// surrounding HELLO/HELLO_ACK payload).
    pub pop_nonce: &'a str,
}

/// Verify a pinned-key identity proof.
///
/// Steps (RFC-AITP-0002 §3.2):
///
/// 1. Decode `descriptor.public_key` (43-char base64url) → 32 bytes.
/// 2. Confirm those 32 bytes equal the public key encoded in
///    `ctx.sender_aid`.
/// 3. Reconstruct `proof_input` per [`pinned_key_proof_input`].
/// 4. Verify `descriptor.proof` over `sha256(proof_input)`.
pub fn verify_pinned_key(
    descriptor: &IdentityDescriptor,
    ctx: &PinnedKeyVerifyContext<'_>,
) -> Result<(), HandshakeError> {
    // The `pinned_key` mechanism is Ed25519-only in v0.1. The sender AID
    // is attacker-controlled (from the peer's Manifest), and since the
    // v0.2 P-256 work it may legitimately be a P-256 AID — guard the
    // algorithm before the Ed25519-only decode below, which would
    // otherwise panic on a non-Ed25519 AID.
    let sender_ed25519 = ctx.sender_aid.try_to_ed25519_bytes().ok_or_else(|| {
        HandshakeError::Identity("pinned_key requires an Ed25519 sender AID".into())
    })?;
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
    if buf != sender_ed25519 {
        return Err(HandshakeError::Identity(
            "public_key does not match sender AID".into(),
        ));
    }

    let pk = AitpVerifyingKey::from_bytes(&buf)
        .map_err(|_| HandshakeError::Identity("public_key not Ed25519".into()))?;
    let input = pinned_key_proof_input(
        ctx.sender_aid,
        ctx.receiver_aid,
        ctx.message_id,
        ctx.timestamp,
        ctx.pop_nonce,
    )?;
    let digest = Sha256::digest(&input);
    let sig = Signature::parse(&descriptor.proof)
        .map_err(|_| HandshakeError::Identity("proof malformed".into()))?;
    pk.verify(&digest, &sig)
        .map_err(|_| HandshakeError::Identity("pinned_key signature invalid".into()))?;
    Ok(())
}

/// Sign a pinned-key identity proof — helper for the issuing side.
///
/// All five fields MUST match what the verifying peer will reconstruct
/// from the surrounding envelope (sender AID, receiver AID, message_id,
/// timestamp, pop_nonce). A captured signature is bound to that exact
/// tuple and cannot be replayed.
pub fn sign_pinned_key_proof(
    signing_key: &aitp_crypto::AitpSigningKey,
    sender_aid: &Aid,
    receiver_aid: &Aid,
    message_id: &Uuid,
    timestamp: Timestamp,
    pop_nonce: &str,
) -> Result<String, HandshakeError> {
    let input = pinned_key_proof_input(sender_aid, receiver_aid, message_id, timestamp, pop_nonce)?;
    let digest = Sha256::digest(&input);
    Ok(signing_key.sign(&digest).into_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdentityKind;
    use aitp_crypto::AitpSigningKey;

    fn fixed_nonce() -> &'static str {
        // 16 bytes → 22 char base64url (matches the on-wire format).
        "AAECAwQFBgcICQoLDA0ODw"
    }

    fn descriptor_for(
        signer: &AitpSigningKey,
        sender: &Aid,
        receiver: &Aid,
        mid: &Uuid,
        ts: Timestamp,
        nonce: &str,
    ) -> IdentityDescriptor {
        let proof = sign_pinned_key_proof(signer, sender, receiver, mid, ts, nonce).unwrap();
        IdentityDescriptor {
            kind: IdentityKind::PinnedKey,
            issuer: None,
            subject: "agent-x".into(),
            proof,
            public_key: Some(base64url::encode(&signer.verifying_key().to_bytes())),
        }
    }

    #[test]
    fn round_trip_full_context() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let ts = Timestamp(1_700_000_000);
        let nonce = fixed_nonce();
        let desc = descriptor_for(&key, key.aid(), receiver.aid(), &mid, ts, nonce);
        verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: key.aid(),
                receiver_aid: receiver.aid(),
                message_id: &mid,
                timestamp: ts,
                pop_nonce: nonce,
            },
        )
        .expect("proof verifies under the same five-tuple");
    }

    #[test]
    fn p256_sender_aid_rejected_without_panic() {
        // Regression: a P-256 sender AID must be rejected with a clean
        // error, not panic. `Aid::to_ed25519_bytes()` asserts on a
        // non-Ed25519 AID; `verify_pinned_key` guards the algorithm
        // first. Attacker-reachable from MUTUAL_HELLO / HELLO_ACK.
        let p256 = AitpSigningKey::generate_p256();
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::nil();
        let ts = Timestamp(1);
        let desc = IdentityDescriptor {
            kind: IdentityKind::PinnedKey,
            issuer: None,
            subject: "agent-x".into(),
            // Any 32-byte value — the algorithm guard fires before this
            // is even compared.
            proof: base64url::encode(&[0u8; 64]),
            public_key: Some(base64url::encode(&[0u8; 32])),
        };
        let err = verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: p256.aid(),
                receiver_aid: receiver.aid(),
                message_id: &mid,
                timestamp: ts,
                pop_nonce: fixed_nonce(),
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, HandshakeError::Identity(ref s) if s.contains("Ed25519")),
            "got {err:?}"
        );
    }

    #[test]
    fn changing_receiver_aid_rejects() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let other_receiver = AitpSigningKey::from_seed(&[5u8; 32]);
        let mid = Uuid::nil();
        let ts = Timestamp(1);
        let desc = descriptor_for(&key, key.aid(), receiver.aid(), &mid, ts, fixed_nonce());
        let err = verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: key.aid(),
                receiver_aid: other_receiver.aid(),
                message_id: &mid,
                timestamp: ts,
                pop_nonce: fixed_nonce(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, HandshakeError::Identity(_)));
    }

    #[test]
    fn changing_sender_aid_rejects() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let other = AitpSigningKey::from_seed(&[6u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::nil();
        let ts = Timestamp(1);
        // Sign claiming to be `key`, but the verifier reconstructs with `other` as sender.
        let desc = descriptor_for(&key, key.aid(), receiver.aid(), &mid, ts, fixed_nonce());
        let err = verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: other.aid(),
                receiver_aid: receiver.aid(),
                message_id: &mid,
                timestamp: ts,
                pop_nonce: fixed_nonce(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, HandshakeError::Identity(_)));
    }

    #[test]
    fn changing_message_id_rejects() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid_a = Uuid::nil();
        let mid_b = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let ts = Timestamp(1);
        let desc = descriptor_for(&key, key.aid(), receiver.aid(), &mid_a, ts, fixed_nonce());
        let err = verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: key.aid(),
                receiver_aid: receiver.aid(),
                message_id: &mid_b,
                timestamp: ts,
                pop_nonce: fixed_nonce(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, HandshakeError::Identity(_)));
    }

    #[test]
    fn changing_timestamp_rejects() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::nil();
        let ts_a = Timestamp(1);
        let ts_b = Timestamp(2);
        let desc = descriptor_for(&key, key.aid(), receiver.aid(), &mid, ts_a, fixed_nonce());
        let err = verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: key.aid(),
                receiver_aid: receiver.aid(),
                message_id: &mid,
                timestamp: ts_b,
                pop_nonce: fixed_nonce(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, HandshakeError::Identity(_)));
    }

    #[test]
    fn changing_pop_nonce_rejects() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::nil();
        let ts = Timestamp(1);
        let nonce_a = "AAECAwQFBgcICQoLDA0ODw";
        let nonce_b = "DwAAAAAAAAAAAAAAAAAAAA";
        let desc = descriptor_for(&key, key.aid(), receiver.aid(), &mid, ts, nonce_a);
        let err = verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: key.aid(),
                receiver_aid: receiver.aid(),
                message_id: &mid,
                timestamp: ts,
                pop_nonce: nonce_b,
            },
        )
        .unwrap_err();
        assert!(matches!(err, HandshakeError::Identity(_)));
    }

    #[test]
    fn malformed_pop_nonce_returns_error_not_panic() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let result = sign_pinned_key_proof(
            &key,
            key.aid(),
            receiver.aid(),
            &Uuid::nil(),
            Timestamp(1),
            "not!valid!base64url!",
        );
        assert!(matches!(result, Err(HandshakeError::Identity(_))));
    }

    #[test]
    fn legacy_two_field_proof_fails_under_new_verifier() {
        // Manually mint a signature using the old `message_id|timestamp`
        // layout — the v0.1 verifier MUST reject it.
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let ts = Timestamp(1_700_000_000);
        let legacy_input = format!("{}|{}", mid, ts.0);
        let legacy_digest = Sha256::digest(legacy_input.as_bytes());
        let legacy_proof = key.sign(&legacy_digest).into_string();
        let desc = IdentityDescriptor {
            kind: IdentityKind::PinnedKey,
            issuer: None,
            subject: "agent-x".into(),
            proof: legacy_proof,
            public_key: Some(base64url::encode(&key.verifying_key().to_bytes())),
        };
        let err = verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: key.aid(),
                receiver_aid: receiver.aid(),
                message_id: &mid,
                timestamp: ts,
                pop_nonce: fixed_nonce(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, HandshakeError::Identity(_)));
    }
}
