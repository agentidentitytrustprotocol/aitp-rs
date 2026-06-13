//! AITP message envelope (RFC-AITP-0001 §5).
//!
//! Every AITP protocol message — handshake, TCT delivery, PoP exchange,
//! errors — is wrapped in an [`AitpEnvelope`]. The envelope provides
//! sender identity, replay protection (`message_id`, `timestamp`), and
//! end-to-end Ed25519 signing.
//!
//! ## Signing input (RFC-AITP-0001 §5.4)
//!
//! The envelope signature is **not** computed by JCS-canonicalizing the whole
//! envelope. Instead:
//!
//! ```text
//! payload_hash = sha256(JCS(payload))
//! sig_input    = message_id + "|" + timestamp_string + "|" + sender.agent_id + "|" + hex(payload_hash)
//! signature    = base64url(sign(private_key, sha256(sig_input)))
//! ```
//!
//! [`envelope_signing_input`] computes `sig_input` for a partially-built
//! envelope; [`envelope_signing_digest`] returns the SHA-256 of that input —
//! the actual 32 bytes that get fed into Ed25519.

use crate::jcs;
use crate::{Aid, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The standard AITP message envelope (RFC-AITP-0001 §5.1).
///
/// `payload` is kept as raw JSON so that protocol-specific crates
/// (`aitp-handshake`, `aitp-tct`, etc.) can parse it into their own typed
/// payload structs. The envelope crate does not need to know every payload
/// type.
///
/// The schema is `additionalProperties: false` — the envelope has no
/// `extensions` slot. Forward compatibility happens inside `payload` per
/// RFC-AITP-0012.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AitpEnvelope {
    /// Protocol version. MUST be `"aitp/0.2"`.
    pub version: String,

    /// Wire-level message type.
    pub message_type: MessageType,

    /// UUID v4 (hyphenated lowercase). Used for replay-prevention
    /// deduplication.
    pub message_id: Uuid,

    /// Unix timestamp in seconds.
    pub timestamp: Timestamp,

    /// Identifier of the sending agent.
    pub sender: Sender,

    /// Type-specific payload, kept as raw JSON until parsed by a protocol
    /// crate.
    pub payload: serde_json::Value,

    /// base64url-unpadded Ed25519 signature over
    /// `sha256(message_id|ts|sender|hex(sha256(jcs(payload))))`.
    pub signature: String,
}

/// Sender identification block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Sender {
    /// AID of the sending agent.
    pub agent_id: Aid,
}

/// Wire-level message type discriminant.
///
/// Marked `#[non_exhaustive]` so future protocol extensions (new
/// envelope message types added in RFC-AITP minor revisions) do not
/// break downstream `match` arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MessageType {
    /// Initiating peer's handshake opener (RFC-AITP-0004).
    MutualHello,
    /// Responding peer's reply to MutualHello.
    MutualHelloAck,
    /// Initiating peer's TCT + PoP delivery.
    MutualCommit,
    /// Responding peer's TCT + PoP delivery (handshake complete).
    MutualCommitAck,
    /// A standalone TCT delivery (for renewal flows).
    Tct,
    /// Downstream PoP challenge (RFC-AITP-0005 §6).
    PopChallenge,
    /// Downstream PoP response.
    PopResponse,
    /// Error envelope.
    Error,
}

impl MessageType {
    /// The wire string for this message type (snake_case).
    pub fn as_wire_str(&self) -> &'static str {
        match self {
            Self::MutualHello => "mutual_hello",
            Self::MutualHelloAck => "mutual_hello_ack",
            Self::MutualCommit => "mutual_commit",
            Self::MutualCommitAck => "mutual_commit_ack",
            Self::Tct => "tct",
            Self::PopChallenge => "pop_challenge",
            Self::PopResponse => "pop_response",
            Self::Error => "error",
        }
    }
}

/// Compute the envelope signing input per RFC-AITP-0001 §5.4.
///
/// Returns the bytes that will be SHA-256'd before signing. Produced as:
///
/// ```text
/// message_id + "|" + timestamp + "|" + sender.agent_id + "|" + hex(sha256(JCS(payload)))
/// ```
pub fn envelope_signing_input(
    message_id: &Uuid,
    timestamp: Timestamp,
    sender_aid: &Aid,
    payload: &serde_json::Value,
) -> Result<Vec<u8>, jcs::JcsError> {
    use sha2::{Digest, Sha256};
    let canonical = jcs::canonicalize(payload)?;
    let payload_hash = Sha256::digest(&canonical);
    let mut hex_buf = [0u8; 64];
    hex::encode_to_slice(payload_hash, &mut hex_buf)
        .expect("64-byte buffer fits 32-byte digest hex-encoded");
    let payload_hex = std::str::from_utf8(&hex_buf).expect("hex output is always ASCII");
    Ok(format!(
        "{}|{}|{}|{}",
        message_id,
        timestamp.0,
        sender_aid.as_str(),
        payload_hex
    )
    .into_bytes())
}

/// Compute the 32-byte SHA-256 digest of [`envelope_signing_input`].
///
/// This is the value the issuer Ed25519-signs, and the value verifiers
/// re-compute from a received envelope before checking the signature.
pub fn envelope_signing_digest(
    message_id: &Uuid,
    timestamp: Timestamp,
    sender_aid: &Aid,
    payload: &serde_json::Value,
) -> Result<[u8; 32], jcs::JcsError> {
    use sha2::{Digest, Sha256};
    let input = envelope_signing_input(message_id, timestamp, sender_aid, payload)?;
    Ok(Sha256::digest(&input).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_aid() -> Aid {
        Aid::from_ed25519(&[0u8; 32])
    }

    fn sample_envelope(mt: MessageType) -> AitpEnvelope {
        AitpEnvelope {
            version: "aitp/0.2".into(),
            message_type: mt,
            message_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            timestamp: Timestamp(1_711_900_000),
            sender: Sender {
                agent_id: sample_aid(),
            },
            payload: json!({"x": 1}),
            signature: "A".repeat(86),
        }
    }

    #[test]
    fn round_trip_each_message_type() {
        for mt in [
            MessageType::MutualHello,
            MessageType::MutualHelloAck,
            MessageType::MutualCommit,
            MessageType::MutualCommitAck,
            MessageType::Tct,
            MessageType::PopChallenge,
            MessageType::PopResponse,
            MessageType::Error,
        ] {
            let env = sample_envelope(mt);
            let s = serde_json::to_string(&env).unwrap();
            let parsed: AitpEnvelope = serde_json::from_str(&s).unwrap();
            assert_eq!(parsed, env, "round-trip for {:?}", mt);
        }
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let mut v = serde_json::to_value(sample_envelope(MessageType::MutualHello)).unwrap();
        v.as_object_mut().unwrap().insert("rogue".into(), json!(1));
        let s = serde_json::to_string(&v).unwrap();
        let err = serde_json::from_str::<AitpEnvelope>(&s).unwrap_err();
        assert!(err.to_string().contains("rogue"), "got: {}", err);
    }

    #[test]
    fn rejects_unknown_sender_field() {
        let bad = json!({
            "version": "aitp/0.2",
            "message_type": "tct",
            "message_id": "550e8400-e29b-41d4-a716-446655440000",
            "timestamp": 1711900000,
            "sender": {"agent_id": sample_aid().as_str(), "rogue": 1},
            "payload": {},
            "signature": "A".repeat(86),
        });
        let err = serde_json::from_value::<AitpEnvelope>(bad).unwrap_err();
        assert!(err.to_string().contains("rogue"), "got: {}", err);
    }

    #[test]
    fn rejects_extensions_field() {
        // Schema is additionalProperties:false — no top-level `extensions`.
        let mut v = serde_json::to_value(sample_envelope(MessageType::Tct)).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("extensions".into(), json!({}));
        let err = serde_json::from_str::<AitpEnvelope>(&v.to_string()).unwrap_err();
        assert!(err.to_string().contains("extensions"), "got: {}", err);
    }

    #[test]
    fn signing_input_is_pipe_formatted() {
        let mid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let aid = sample_aid();
        let input =
            envelope_signing_input(&mid, Timestamp(1_700_000_000), &aid, &json!({})).unwrap();
        let s = String::from_utf8(input).unwrap();
        // Three pipes between four components.
        assert_eq!(s.matches('|').count(), 3);
        assert!(s.starts_with("550e8400-e29b-41d4-a716-446655440000|1700000000|"));
        // Last component is hex of sha256("{}") which is sha256 of canonical empty obj.
        let parts: Vec<&str> = s.split('|').collect();
        assert_eq!(parts[3].len(), 64);
        assert!(parts[3].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn signing_digest_is_deterministic() {
        let mid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let aid = sample_aid();
        let payload = json!({"foo": "bar", "n": 1});
        let d1 = envelope_signing_digest(&mid, Timestamp(1), &aid, &payload).unwrap();
        let d2 = envelope_signing_digest(&mid, Timestamp(1), &aid, &payload).unwrap();
        assert_eq!(d1, d2);
        // Reordering JSON keys should not change the digest (JCS).
        let payload2 = json!({"n": 1, "foo": "bar"});
        let d3 = envelope_signing_digest(&mid, Timestamp(1), &aid, &payload2).unwrap();
        assert_eq!(d1, d3);
    }

    #[test]
    fn message_type_wire_strings() {
        let cases = [
            (MessageType::MutualHello, "mutual_hello"),
            (MessageType::MutualHelloAck, "mutual_hello_ack"),
            (MessageType::MutualCommit, "mutual_commit"),
            (MessageType::MutualCommitAck, "mutual_commit_ack"),
            (MessageType::Tct, "tct"),
            (MessageType::PopChallenge, "pop_challenge"),
            (MessageType::PopResponse, "pop_response"),
            (MessageType::Error, "error"),
        ];
        for (mt, wire) in cases {
            assert_eq!(mt.as_wire_str(), wire);
            // Also verify serde produces the same wire string.
            let v = serde_json::to_value(mt).unwrap();
            assert_eq!(v.as_str().unwrap(), wire);
        }
    }
}
