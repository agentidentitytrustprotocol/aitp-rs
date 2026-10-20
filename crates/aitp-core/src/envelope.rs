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
use crate::unknown_field::{check_members, from_serde_error, CheckedJson};
use crate::{Aid, ExtensionsMap, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The standard AITP message envelope (RFC-AITP-0001 §5.1).
///
/// `payload` is kept as raw JSON so that protocol-specific crates
/// (`aitp-handshake`, `aitp-tct`, etc.) can parse it into their own typed
/// payload structs. The envelope crate does not need to know every payload
/// type.
///
/// The schema is `additionalProperties: false`, with an explicit
/// `extensions` slot reserved per RFC-AITP-0001 §7.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AitpEnvelope {
    /// Protocol version. MUST be `"aitp/0.3"`.
    pub version: String,

    /// Wire-level message type.
    pub message_type: MessageType,

    /// UUID v4 (hyphenated lowercase). Used for replay-prevention
    /// deduplication. Deserialization enforces the strict v4 wire form
    /// (proposal #72 Item 6b); anything else is a malformed envelope
    /// (`INVALID_ENVELOPE`). It MAY be derived per
    /// [`crate::ids::derived_v4`].
    #[serde(with = "crate::ids::serde_v4")]
    pub message_id: Uuid,

    /// Unix timestamp in seconds.
    pub timestamp: Timestamp,

    /// Identifier of the sending agent.
    pub sender: Sender,

    /// Type-specific payload, kept as raw JSON until parsed by a protocol
    /// crate.
    pub payload: serde_json::Value,

    /// Forward-compatible extension namespace (RFC-AITP-0001 §7).
    ///
    /// **Presence-sensitive**, deliberately modeled as `Option<ExtensionsMap>`
    /// rather than a defaulted empty map with `skip_serializing_if =
    /// "is_empty"`. Under RFC 8785 canonicalization, absent (`None`) emits
    /// no `extensions` key at all, while present-but-empty
    /// (`Some(ExtensionsMap::new())`) emits `"extensions":{}` — different
    /// bytes, different digest, different signature. Silently normalizing
    /// one into the other would change the signing input and break
    /// verification against a conformant peer (RFC-AITP-0001 §5.4.1). Note
    /// that for this particular struct the point is moot for
    /// [`envelope_signing_input`], which never canonicalizes the whole
    /// envelope — see the module docs — but the field is modeled the same
    /// way as every other signed AITP object for consistency and because a
    /// future signing-input revision must not have to fix this again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionsMap>,

    /// base64url-unpadded Ed25519 signature over
    /// `sha256(message_id|ts|sender|hex(sha256(jcs(payload))))`.
    pub signature: String,
}

/// Full set of top-level members `aitp-envelope.schema.json` declares,
/// including the `extensions` namespace key itself. Used by
/// [`parse_envelope_wire`]'s member-set check (RFC-AITP-0001 §7).
///
/// Anchored to the vendored schema by
/// `crates/aitp-core/tests/schema.rs`, which asserts this list equals the
/// schema's `properties` keys — so this cannot silently drift from the
/// spec.
pub const AITP_ENVELOPE_MEMBERS: &[&str] = &[
    "version",
    "message_type",
    "message_id",
    "timestamp",
    "sender",
    "payload",
    "extensions",
    "signature",
];

/// Error from [`parse_envelope_wire`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeParseError {
    /// A top-level or nested member outside the schema-declared member
    /// set (RFC-AITP-0001 §7). Carries the offending field name.
    #[error("unknown field `{0}`")]
    UnknownField(String),
    /// Any other parse failure (missing required field, wrong type,
    /// etc.).
    #[error("malformed envelope: {0}")]
    Malformed(String),
}

/// Parse a raw wire-form JSON value into an [`AitpEnvelope`], enforcing
/// RFC-AITP-0001 §7's member-set check before typed deserialization.
///
/// Takes a [`CheckedJson`], so the RFC-AITP-0001 §5.4.5 duplicate-key
/// check has necessarily already run on the original bytes.
///
/// Order of operations:
/// 1. [`check_members`] against [`AITP_ENVELOPE_MEMBERS`] — rejects any
///    top-level member the schema does not declare, before anything else
///    runs.
/// 2. `serde_json::from_value` into [`AitpEnvelope`].
/// 3. On a residual serde error (which, now that the top-level check has
///    already passed, can only come from the nested `Sender` object's own
///    `deny_unknown_fields`), [`from_serde_error`] recovers the offending
///    field name so the caller can still report `UnknownField` rather
///    than a generic parse failure.
pub fn parse_envelope_wire(value: &CheckedJson) -> Result<AitpEnvelope, EnvelopeParseError> {
    let value = value.as_value();
    check_members("AitpEnvelope", value, AITP_ENVELOPE_MEMBERS)
        .map_err(|e| EnvelopeParseError::UnknownField(e.field))?;
    serde_json::from_value(value.clone()).map_err(|e| {
        if let Some(field) = from_serde_error(&e) {
            EnvelopeParseError::UnknownField(field)
        } else {
            EnvelopeParseError::Malformed(e.to_string())
        }
    })
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
    /// One-way pinned-key admission presentation (RFC-AITP-0002 §3.4,
    /// proposal agentidentitytrustprotocol#72 Item 5): payload
    /// `{identity, pop_nonce}`.
    IdentityPresentation,
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
            Self::IdentityPresentation => "identity_presentation",
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

    /// Re-enter an in-memory `Value` through `CheckedJson`'s text-only
    /// constructor (a `Value` has no duplicate key, so this cannot fail).
    fn checked(v: &serde_json::Value) -> crate::CheckedJson {
        v.to_string().parse().expect("valid JSON")
    }

    fn sample_aid() -> Aid {
        Aid::from_ed25519(&[0u8; 32])
    }

    fn sample_envelope(mt: MessageType) -> AitpEnvelope {
        AitpEnvelope {
            version: "aitp/0.3".into(),
            message_type: mt,
            message_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            timestamp: Timestamp(1_711_900_000),
            sender: Sender {
                agent_id: sample_aid(),
            },
            payload: json!({"x": 1}),
            extensions: None,
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
            MessageType::IdentityPresentation,
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
            "version": "aitp/0.3",
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
    fn accepts_extensions_field() {
        // aitp-envelope.schema.json declares a top-level `extensions`
        // slot (RFC-AITP-0001 §7) — a vendor-namespaced key inside it
        // must round-trip, not be rejected.
        let mut v = serde_json::to_value(sample_envelope(MessageType::Tct)).unwrap();
        let mut ext = ExtensionsMap::new();
        ext.insert("com.example/junk", json!({"anything": true}));
        v.as_object_mut()
            .unwrap()
            .insert("extensions".into(), serde_json::to_value(&ext).unwrap());
        let parsed: AitpEnvelope = serde_json::from_str(&v.to_string()).unwrap();
        assert_eq!(parsed.extensions, Some(ext));
    }

    #[test]
    fn parse_envelope_wire_rejects_unknown_top_level_sibling() {
        let mut v = serde_json::to_value(sample_envelope(MessageType::MutualHello)).unwrap();
        v.as_object_mut().unwrap().insert("rogue".into(), json!(1));
        let err = parse_envelope_wire(&checked(&v)).unwrap_err();
        assert_eq!(err, EnvelopeParseError::UnknownField("rogue".into()));
    }

    #[test]
    fn parse_envelope_wire_ignores_junk_key_inside_extensions() {
        let mut v = serde_json::to_value(sample_envelope(MessageType::MutualHello)).unwrap();
        v.as_object_mut().unwrap().insert(
            "extensions".into(),
            json!({"junk_key_of_any_shape": {"deeply": {"nested": true}}}),
        );
        let env =
            parse_envelope_wire(&checked(&v)).expect("junk inside extensions must be ignored");
        assert!(env.extensions.is_some());
    }

    #[test]
    fn parse_envelope_wire_reports_unknown_field_from_nested_sender() {
        let bad = json!({
            "version": "aitp/0.3",
            "message_type": "tct",
            "message_id": "550e8400-e29b-41d4-a716-446655440000",
            "timestamp": 1711900000,
            "sender": {"agent_id": sample_aid().as_str(), "rogue": 1},
            "payload": {},
            "signature": "A".repeat(86),
        });
        let err = parse_envelope_wire(&checked(&bad)).unwrap_err();
        assert_eq!(err, EnvelopeParseError::UnknownField("rogue".into()));
    }

    #[test]
    fn parse_envelope_wire_reports_malformed_for_non_unknown_field_errors() {
        let bad = json!({
            "version": "aitp/0.3",
            "message_type": "tct",
            // message_id missing entirely.
            "timestamp": 1711900000,
            "sender": {"agent_id": sample_aid().as_str()},
            "payload": {},
            "signature": "A".repeat(86),
        });
        let err = parse_envelope_wire(&checked(&bad)).unwrap_err();
        assert!(
            matches!(err, EnvelopeParseError::Malformed(_)),
            "got: {err:?}"
        );
    }

    /// RFC-AITP-0001 §5.4.5 / issues #140, #146: a `Value` cannot
    /// represent a duplicate key, so `parse_envelope_wire` takes a
    /// [`CheckedJson`], whose only constructors run the raw-bytes
    /// duplicate-key guard. A body with a duplicate top-level `version`
    /// never becomes a `CheckedJson`, so it cannot reach the parser.
    #[test]
    fn a_duplicate_key_never_reaches_parse_envelope_wire() {
        let env = sample_envelope(MessageType::Tct);
        let good = serde_json::to_string(&env).unwrap();
        let needle = "\"version\":\"aitp/0.3\",";
        assert!(good.contains(needle), "fixture shape changed: {good}");
        let dup_bytes = good.replacen(needle, &format!("{needle}{needle}"), 1);

        let err = CheckedJson::from_slice(dup_bytes.as_bytes()).unwrap_err();
        assert!(
            err.to_string().contains("duplicate field `version`"),
            "got: {err}"
        );
        // The same bytes without the duplicate do parse.
        let clean: CheckedJson = good.parse().unwrap();
        assert!(parse_envelope_wire(&checked(&clean)).is_ok());
    }

    #[test]
    fn extensions_round_trip_absent_vs_empty() {
        // Absent: no `extensions` key on the wire at all.
        let absent = sample_envelope(MessageType::MutualHello);
        let s = serde_json::to_value(&absent).unwrap();
        assert!(!s.as_object().unwrap().contains_key("extensions"));

        // Present-but-empty: `"extensions":{}` must appear on the wire.
        let mut present = sample_envelope(MessageType::MutualHello);
        present.extensions = Some(ExtensionsMap::new());
        let s = serde_json::to_value(&present).unwrap();
        assert_eq!(s.get("extensions"), Some(&json!({})));

        // And it round-trips back to `Some(empty)`, not `None`.
        let parsed: AitpEnvelope = serde_json::from_value(s).unwrap();
        assert_eq!(parsed.extensions, Some(ExtensionsMap::new()));
    }

    #[test]
    fn signing_input_is_identical_with_and_without_extensions() {
        // envelope_signing_input takes explicit scalar arguments and never
        // sees the AitpEnvelope struct or its `extensions` field, so this
        // is necessarily a compile-time/type-level guarantee rather than a
        // runtime one — there is no way to vary `extensions` through this
        // function's own signature, which is what makes the invariant
        // hold. `aitp-envelope`'s
        // `attaching_extensions_after_signing_does_not_invalidate_the_signature`
        // exercises the real end-to-end path instead: sign a full
        // envelope, attach a populated `extensions` map afterward, and
        // confirm the outer signature still verifies.
        let mid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let aid = sample_aid();
        let payload = json!({"hello": true});

        let mut without = sample_envelope(MessageType::MutualHello);
        without.message_id = mid;
        without.sender.agent_id = aid.clone();
        without.payload = payload.clone();
        without.extensions = None;

        let mut with = without.clone();
        let mut ext = ExtensionsMap::new();
        ext.insert("com.example/debug_trace", json!({"request_id": "abc"}));
        with.extensions = Some(ext);

        let input_without =
            envelope_signing_input(&mid, without.timestamp, &aid, &without.payload).unwrap();
        let input_with = envelope_signing_input(&mid, with.timestamp, &aid, &with.payload).unwrap();
        assert_eq!(
            input_without, input_with,
            "envelope_signing_input must be byte-identical regardless of `extensions`"
        );
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
    fn non_v4_message_id_is_malformed() {
        let good = serde_json::to_value(sample_envelope(MessageType::Tct)).unwrap();
        assert!(parse_envelope_wire(&checked(&good)).is_ok());
        for bad in [
            "01890a5d-ac96-774b-bcce-b302099a8057",
            "770e8400-e29b-41d4-c716-446655440702",
            "770E8400-E29B-41D4-A716-446655440702",
            "770e8400e29b41d4a716446655440702",
        ] {
            let mut v = good.clone();
            v["message_id"] = serde_json::json!(bad);
            assert!(
                matches!(
                    parse_envelope_wire(&checked(&v)),
                    Err(EnvelopeParseError::Malformed(_))
                ),
                "{bad}"
            );
        }
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
            (MessageType::IdentityPresentation, "identity_presentation"),
        ];
        for (mt, wire) in cases {
            assert_eq!(mt.as_wire_str(), wire);
            // Also verify serde produces the same wire string.
            let v = serde_json::to_value(mt).unwrap();
            assert_eq!(v.as_str().unwrap(), wire);
        }
    }
}
