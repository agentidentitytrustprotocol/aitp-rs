//! AITP message envelope (RFC-AITP-0001 §5).
//!
//! Every AITP protocol message — handshake, TCT delivery, PoP exchange,
//! errors — is wrapped in an [`AitpEnvelope`]. The envelope provides
//! sender identity, replay protection (`message_id`, `timestamp`), and
//! end-to-end signing.
//!
//! ## Signing input (RFC-AITP-0001 §5.4, `aitp/0.3`)
//!
//! The envelope signature covers the whole envelope except `signature`,
//! behind a domain tag:
//!
//! ```text
//! sig_input_v2 = "aitp-envelope-v2" || 0x00 || JCS(envelope_without_signature)
//! d            = sha256(sig_input_v2)
//! signature    = base64url(SIGN_alg(private_key, d))   ; §5.4.6
//! ```
//!
//! Every other member (`version`, `message_type`, `message_id`,
//! `timestamp`, `sender`, `payload`, and `extensions` when present) is
//! therefore sender-authenticated. [`envelope_signing_input`] computes
//! `sig_input_v2` for an envelope (its `signature` member is ignored);
//! [`envelope_signing_digest`] returns `d`, the 32 bytes handed to
//! `SIGN_alg`. The `aitp/0.2` pipe-composed input
//! (`message_id|timestamp|sender.agent_id|hex(sha256(JCS(payload)))`) is
//! retired and no longer computed anywhere.

use crate::core::jcs;
use crate::core::unknown_field::{check_members, from_serde_error, CheckedJson};
use crate::core::{Aid, ExtensionsMap, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The standard AITP message envelope (RFC-AITP-0001 §5.1).
///
/// `payload` is kept as raw JSON so that protocol-specific crates
/// (`aitp::handshake`, `aitp::tct`, etc.) can parse it into their own typed
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
    /// [`crate::core::ids::derived_v4`].
    #[serde(with = "crate::core::ids::serde_v4")]
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
    /// verification against a conformant peer (RFC-AITP-0001 §5.4.1). Since
    /// `aitp/0.3` the envelope signing input is the JCS form of the whole
    /// envelope minus `signature` (see the module docs), so `extensions` is
    /// authenticated and this distinction is load-bearing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionsMap>,

    /// base64url-unpadded (optionally algorithm-tagged, RFC-AITP-0001
    /// §5.4.3) signature over [`envelope_signing_digest`]: `sha256` of
    /// `"aitp-envelope-v2" || 0x00 || JCS(envelope without signature)`.
    pub signature: String,
}

/// Full set of top-level members `aitp-envelope.schema.json` declares,
/// including the `extensions` namespace key itself. Used by
/// [`parse_envelope_wire`]'s member-set check (RFC-AITP-0001 §7).
///
/// Anchored to the vendored schema by
/// `crates/aitp/tests/core_schema.rs`, which asserts this list equals the
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
    /// `version` is absent, not a string, or not the revision this
    /// implementation speaks ([`crate::core::PROTOCOL_VERSION`]). Checked first
    /// (RFC-AITP-0001 §5.4 envelope check order, §7). Carries the
    /// offending value as JSON text, or `<absent>`.
    #[error("unknown protocol version {0}")]
    UnknownVersion(String),
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
/// the first two steps of the RFC-AITP-0001 §5.4 envelope check order
/// before typed deserialization. The caller runs step 3 (the signature,
/// `INVALID_SIGNATURE`) on the returned envelope.
///
/// Takes a [`CheckedJson`], so the RFC-AITP-0001 §5.4.5 duplicate-key
/// check has necessarily already run on the original bytes.
///
/// Order of operations:
/// 1. `version`: absent, non-string or any value other than
///    [`crate::core::PROTOCOL_VERSION`] is [`EnvelopeParseError::UnknownVersion`]
///    (`UNKNOWN_VERSION`), before the member set is looked at. A
///    non-object value has no `version` and is `Malformed`. There is no
///    dual-accept: `aitp/0.2` is as unknown as `aitp/9.9`.
/// 2. [`check_members`] against [`AITP_ENVELOPE_MEMBERS`] — rejects any
///    top-level member the schema does not declare.
/// 3. `extensions`, when present, must be an object. `null` is
///    `Malformed` rather than read as absent: absent and present are
///    different signing inputs, so folding `null` into absent would let a
///    relay add the member without breaking the signature.
/// 4. `serde_json::from_value` into [`AitpEnvelope`].
/// 5. On a residual serde error (which, now that the top-level check has
///    already passed, can only come from the nested `Sender` object's own
///    `deny_unknown_fields`), [`from_serde_error`] recovers the offending
///    field name so the caller can still report `UnknownField` rather
///    than a generic parse failure.
/// 6. [`check_envelope_structure`]: the `aitp-envelope.schema.json` rules
///    the typed envelope does not carry (`payload` an object, `timestamp`
///    `>= 0`, the `signature` pattern). A failure is `Malformed`
///    (`INVALID_ENVELOPE`), still ahead of the signature step.
pub fn parse_envelope_wire(value: &CheckedJson) -> Result<AitpEnvelope, EnvelopeParseError> {
    let value = value.as_value();
    let obj = value
        .as_object()
        .ok_or_else(|| EnvelopeParseError::Malformed("envelope is not a JSON object".into()))?;
    match obj.get("version") {
        Some(serde_json::Value::String(v)) if v == crate::core::PROTOCOL_VERSION => {}
        Some(other) => return Err(EnvelopeParseError::UnknownVersion(other.to_string())),
        None => return Err(EnvelopeParseError::UnknownVersion("<absent>".into())),
    }
    check_members("AitpEnvelope", value, AITP_ENVELOPE_MEMBERS)
        .map_err(|e| EnvelopeParseError::UnknownField(e.field))?;
    if obj.get("extensions").is_some_and(|ext| !ext.is_object()) {
        return Err(EnvelopeParseError::Malformed(
            "extensions: must be a JSON object".into(),
        ));
    }
    let envelope: AitpEnvelope = serde_json::from_value(value.clone()).map_err(|e| {
        if let Some(field) = from_serde_error(&e) {
            EnvelopeParseError::UnknownField(field)
        } else {
            EnvelopeParseError::Malformed(e.to_string())
        }
    })?;
    check_envelope_structure(&envelope).map_err(EnvelopeParseError::Malformed)?;
    Ok(envelope)
}

/// Length of the base64url-unpadded part of an envelope `signature`: a
/// 64-byte raw signature (Ed25519, or P-256 `r || s`).
const ENVELOPE_SIGNATURE_B64_LEN: usize = 86;

/// Check the `aitp-envelope.schema.json` rules a typed [`AitpEnvelope`]
/// does not enforce by construction, `signature` aside: `payload` is a
/// JSON object and `timestamp` is `>= 0`.
///
/// A signer runs this before signing so it never produces an envelope
/// [`parse_envelope_wire`] rejects (`aitp::envelope` does). The other
/// members are typed: `version` is checked on its own, `message_type` is
/// an enum, `message_id` deserializes only in the strict UUID v4 form,
/// `sender.agent_id` is a validated [`Aid`], and `extensions` is a map.
pub fn check_unsigned_envelope_structure(envelope: &AitpEnvelope) -> Result<(), String> {
    if !envelope.payload.is_object() {
        return Err("payload: must be a JSON object".into());
    }
    if envelope.timestamp.0 < 0 {
        return Err(format!(
            "timestamp: must be >= 0, got {}",
            envelope.timestamp.0
        ));
    }
    Ok(())
}

/// [`check_unsigned_envelope_structure`], plus the `signature` pattern
/// `^((ed25519|p256)\.)?[A-Za-z0-9_-]{86}$`: an optional algorithm tag
/// (RFC-AITP-0001 §5.4.3) and exactly 86 base64url-unpadded characters.
///
/// These are structure rules (RFC-AITP-0001 §5.4 check order, step 2):
/// a failure is `INVALID_ENVELOPE`, reported before the signature step,
/// not `INVALID_SIGNATURE`. [`parse_envelope_wire`] runs this on every
/// envelope it returns.
pub fn check_envelope_structure(envelope: &AitpEnvelope) -> Result<(), String> {
    check_unsigned_envelope_structure(envelope)?;
    let sig = envelope.signature.as_str();
    let b64 = sig
        .strip_prefix("ed25519.")
        .or_else(|| sig.strip_prefix("p256."))
        .unwrap_or(sig);
    if b64.len() != ENVELOPE_SIGNATURE_B64_LEN
        || !b64.bytes().all(crate::core::aid::is_base64url_byte)
    {
        return Err(
            "signature: must be an optional `ed25519.`/`p256.` tag and 86 base64url characters"
                .into(),
        );
    }
    Ok(())
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

/// The domain tag that prefixes the envelope signing input
/// (RFC-AITP-0001 §5.4): the 16 ASCII bytes `aitp-envelope-v2`. One
/// `0x00` separator byte follows it, so `sig_input_v2` can never equal
/// the bare JCS bytes another JCS-profile artifact signs.
pub const ENVELOPE_SIGNING_DOMAIN_TAG: &[u8; 16] = b"aitp-envelope-v2";

/// Compute the envelope signing input `sig_input_v2` per RFC-AITP-0001
/// §5.4:
///
/// ```text
/// "aitp-envelope-v2" || 0x00 || JCS(envelope_without_signature)
/// ```
///
/// `envelope_without_signature` is `envelope` with its `signature` member
/// removed and every other member kept: `version`, `message_type`,
/// `message_id`, `timestamp`, `sender`, `payload`, and `extensions` when
/// present (absent and `{}` are different inputs). The value of
/// `envelope.signature` is ignored, so a signer calls this on an envelope
/// whose `signature` is still empty.
///
/// A verifier calls this on the envelope [`parse_envelope_wire`] returned.
/// The typed envelope re-serializes to exactly the received members
/// (closed member set, verbatim strings, presence-sensitive `extensions`,
/// `payload` kept as raw JSON), so the JCS bytes are those of the received
/// object minus `signature`.
pub fn envelope_signing_input(envelope: &AitpEnvelope) -> Result<Vec<u8>, jcs::JcsError> {
    let mut value = serde_json::to_value(envelope)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("signature");
    }
    let canonical = jcs::canonicalize(&value)?;
    let mut input = Vec::with_capacity(ENVELOPE_SIGNING_DOMAIN_TAG.len() + 1 + canonical.len());
    input.extend_from_slice(ENVELOPE_SIGNING_DOMAIN_TAG);
    input.push(0x00);
    input.extend_from_slice(&canonical);
    Ok(input)
}

/// Compute `d = sha256(sig_input_v2)` (RFC-AITP-0001 §5.4), the 32 bytes
/// handed to `SIGN_alg` (§5.4.6), hashed exactly once.
///
/// This is the value the sender signs, and the value a verifier
/// re-computes from a received envelope before checking the signature.
/// `envelope.signature` is ignored.
pub fn envelope_signing_digest(envelope: &AitpEnvelope) -> Result<[u8; 32], jcs::JcsError> {
    use sha2::{Digest, Sha256};
    let input = envelope_signing_input(envelope)?;
    Ok(Sha256::digest(&input).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Re-enter an in-memory `Value` through `CheckedJson`'s text-only
    /// constructor (a `Value` has no duplicate key, so this cannot fail).
    fn checked(v: &serde_json::Value) -> crate::core::CheckedJson {
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

    /// RFC-AITP-0001 §5.4 check order, step 1: an unknown, absent or
    /// non-string `version` is `UnknownVersion`, and wins over a member
    /// outside the set (env-010) and over a malformed body. `aitp/0.2`
    /// is rejected like any other unknown revision (env-011, strict
    /// cutover).
    #[test]
    fn parse_envelope_wire_checks_version_before_members_and_structure() {
        let good = serde_json::to_value(sample_envelope(MessageType::Tct)).unwrap();
        for (version, shown) in [
            (json!("aitp/0.2"), "\"aitp/0.2\""),
            (json!("aitp/9.9"), "\"aitp/9.9\""),
            (json!(3), "3"),
            (json!(null), "null"),
        ] {
            let mut v = good.clone();
            v["version"] = version;
            v["trace_id"] = json!("unknown sibling");
            v.as_object_mut().unwrap().remove("message_id");
            assert_eq!(
                parse_envelope_wire(&checked(&v)).unwrap_err(),
                EnvelopeParseError::UnknownVersion(shown.into())
            );
        }
        let mut absent = good.clone();
        absent.as_object_mut().unwrap().remove("version");
        absent["trace_id"] = json!("unknown sibling");
        assert_eq!(
            parse_envelope_wire(&checked(&absent)).unwrap_err(),
            EnvelopeParseError::UnknownVersion("<absent>".into())
        );
        // A known version reaches the member-set check.
        let mut known = good.clone();
        known["trace_id"] = json!("unknown sibling");
        assert_eq!(
            parse_envelope_wire(&checked(&known)).unwrap_err(),
            EnvelopeParseError::UnknownField("trace_id".into())
        );
        assert!(matches!(
            parse_envelope_wire(&checked(&json!([1, 2]))).unwrap_err(),
            EnvelopeParseError::Malformed(_)
        ));
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
    fn signing_input_covers_extensions_and_distinguishes_absent_from_empty() {
        // aitp/0.3 (RFC-AITP-0001 §5.4): `extensions` is inside the
        // signed bytes, and absent vs `{}` are different inputs.
        let absent = sample_envelope(MessageType::MutualHello);
        let mut empty = absent.clone();
        empty.extensions = Some(ExtensionsMap::new());
        let mut populated = absent.clone();
        let mut ext = ExtensionsMap::new();
        ext.insert("com.example/debug_trace", json!({"request_id": "abc"}));
        populated.extensions = Some(ext);

        let a = envelope_signing_input(&absent).unwrap();
        let e = envelope_signing_input(&empty).unwrap();
        let p = envelope_signing_input(&populated).unwrap();
        assert_ne!(a, e, "absent and empty extensions must sign differently");
        assert_ne!(a, p);
        assert_ne!(e, p);
    }

    #[test]
    fn signing_input_is_domain_tagged_jcs_of_envelope_minus_signature() {
        let env = sample_envelope(MessageType::Tct);
        let input = envelope_signing_input(&env).unwrap();
        assert_eq!(&input[..16], b"aitp-envelope-v2");
        assert_eq!(input[16], 0x00);

        let mut expected = serde_json::to_value(&env).unwrap();
        expected.as_object_mut().unwrap().remove("signature");
        assert_eq!(
            &input[17..],
            jcs::canonicalize(&expected).unwrap().as_slice()
        );
        // No pipe composition survives.
        assert!(!input.contains(&b'|'));
    }

    #[test]
    fn signing_input_ignores_the_signature_value() {
        let env = sample_envelope(MessageType::Tct);
        let mut other = env.clone();
        other.signature = String::new();
        assert_eq!(
            envelope_signing_input(&env).unwrap(),
            envelope_signing_input(&other).unwrap()
        );
    }

    #[test]
    fn signing_input_covers_every_non_signature_member() {
        let base = sample_envelope(MessageType::Tct);
        let d0 = envelope_signing_digest(&base).unwrap();
        let mut variants = Vec::new();
        let mut v = base.clone();
        v.version = "aitp/0.2".into();
        variants.push(("version", v));
        let mut v = base.clone();
        v.message_type = MessageType::Error;
        variants.push(("message_type", v));
        let mut v = base.clone();
        v.message_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap();
        variants.push(("message_id", v));
        let mut v = base.clone();
        v.timestamp = Timestamp(base.timestamp.0 + 1);
        variants.push(("timestamp", v));
        let mut v = base.clone();
        v.sender.agent_id = Aid::from_ed25519(&[1u8; 32]);
        variants.push(("sender", v));
        let mut v = base.clone();
        v.payload = json!({"x": 2});
        variants.push(("payload", v));
        for (member, v) in variants {
            assert_ne!(envelope_signing_digest(&v).unwrap(), d0, "{member}");
        }
    }

    #[test]
    fn signing_digest_is_deterministic_and_key_order_independent() {
        let mut env = sample_envelope(MessageType::Tct);
        env.payload = json!({"foo": "bar", "n": 1});
        let d1 = envelope_signing_digest(&env).unwrap();
        assert_eq!(d1, envelope_signing_digest(&env).unwrap());
        // Reordering JSON keys should not change the digest (JCS).
        env.payload = json!({"n": 1, "foo": "bar"});
        assert_eq!(d1, envelope_signing_digest(&env).unwrap());
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

    /// Issue #261: `aitp-envelope.schema.json` declares
    /// `payload: {"type": "object"}`; any other JSON type is a structure
    /// failure (`INVALID_ENVELOPE`), not something the signature step
    /// sees.
    #[test]
    fn non_object_payload_is_malformed() {
        let good = serde_json::to_value(sample_envelope(MessageType::Tct)).unwrap();
        for payload in [
            json!([]),
            json!([1, 2]),
            json!("text"),
            json!(1),
            json!(true),
            json!(null),
        ] {
            let mut v = good.clone();
            v["payload"] = payload.clone();
            let err = parse_envelope_wire(&checked(&v)).unwrap_err();
            assert!(
                matches!(&err, EnvelopeParseError::Malformed(m) if m.contains("payload")),
                "{payload}: {err:?}"
            );
        }
        let mut empty = good;
        empty["payload"] = json!({});
        assert!(parse_envelope_wire(&checked(&empty)).is_ok());
    }

    /// Issue #261: `timestamp` is `{"type": "integer", "minimum": 0}`.
    #[test]
    fn negative_timestamp_is_malformed() {
        let good = serde_json::to_value(sample_envelope(MessageType::Tct)).unwrap();
        for ts in [json!(-1), json!(i64::MIN)] {
            let mut v = good.clone();
            v["timestamp"] = ts.clone();
            let err = parse_envelope_wire(&checked(&v)).unwrap_err();
            assert!(
                matches!(&err, EnvelopeParseError::Malformed(m) if m.contains("timestamp")),
                "{ts}: {err:?}"
            );
        }
        // Non-integers were already rejected by the typed `Timestamp`.
        for ts in [json!(1.5), json!("1711900000"), json!(null)] {
            let mut v = good.clone();
            v["timestamp"] = ts.clone();
            assert!(
                matches!(
                    parse_envelope_wire(&checked(&v)),
                    Err(EnvelopeParseError::Malformed(_))
                ),
                "{ts}"
            );
        }
        let mut zero = good;
        zero["timestamp"] = json!(0);
        assert!(parse_envelope_wire(&checked(&zero)).is_ok());
    }

    /// Issue #261: `signature` matches
    /// `^((ed25519|p256)\.)?[A-Za-z0-9_-]{86}$`.
    #[test]
    fn signature_outside_the_schema_pattern_is_malformed() {
        let good = serde_json::to_value(sample_envelope(MessageType::Tct)).unwrap();
        let b64 = "A".repeat(86);
        for sig in [
            String::new(),
            "A".repeat(85),
            "A".repeat(87),
            format!("{}=", "A".repeat(85)),
            format!("{}+", "A".repeat(85)),
            format!("{}/", "A".repeat(85)),
            format!("{} ", "A".repeat(85)),
            format!("{b64}\n"),
            format!("rsa.{b64}"),
            format!("ED25519.{b64}"),
            format!("ed25519:{b64}"),
            format!("ed25519.p256.{b64}"),
            "ed25519.".into(),
        ] {
            let mut v = good.clone();
            v["signature"] = json!(sig);
            let err = parse_envelope_wire(&checked(&v)).unwrap_err();
            assert!(
                matches!(&err, EnvelopeParseError::Malformed(m) if m.contains("signature")),
                "{sig:?}: {err:?}"
            );
        }
        let mut non_string = good.clone();
        non_string["signature"] = json!(86);
        assert!(matches!(
            parse_envelope_wire(&checked(&non_string)),
            Err(EnvelopeParseError::Malformed(_))
        ));
        for sig in [
            b64.clone(),
            format!("ed25519.{b64}"),
            format!("p256.{b64}"),
            format!("{}-_09az", "A".repeat(80)),
        ] {
            let mut v = good.clone();
            v["signature"] = json!(sig);
            assert!(parse_envelope_wire(&checked(&v)).is_ok(), "{sig}");
        }
    }

    /// `extensions` is `{"type": "object"}`: `null` is not read as
    /// absent, and other JSON types were already rejected by the map.
    #[test]
    fn non_object_extensions_is_malformed() {
        let good = serde_json::to_value(sample_envelope(MessageType::Tct)).unwrap();
        for ext in [json!(null), json!([]), json!("x"), json!(1)] {
            let mut v = good.clone();
            v["extensions"] = ext.clone();
            assert!(
                matches!(
                    parse_envelope_wire(&checked(&v)),
                    Err(EnvelopeParseError::Malformed(_))
                ),
                "{ext}"
            );
        }
    }

    /// RFC-AITP-0001 §5.4 check order: an unknown `version` (step 1)
    /// wins over every issue #261 structure defect, and an unknown member
    /// is still `UnknownField`.
    #[test]
    fn version_and_member_set_win_over_schema_rule_defects() {
        let good = serde_json::to_value(sample_envelope(MessageType::Tct)).unwrap();
        let mut bad = good.clone();
        bad["payload"] = json!([1]);
        bad["timestamp"] = json!(-5);
        bad["signature"] = json!("short");
        bad["extensions"] = json!(null);
        let mut unknown_version = bad.clone();
        unknown_version["version"] = json!("aitp/9.9");
        assert_eq!(
            parse_envelope_wire(&checked(&unknown_version)).unwrap_err(),
            EnvelopeParseError::UnknownVersion("\"aitp/9.9\"".into())
        );
        let mut unknown_member = bad.clone();
        unknown_member["trace_id"] = json!(1);
        assert_eq!(
            parse_envelope_wire(&checked(&unknown_member)).unwrap_err(),
            EnvelopeParseError::UnknownField("trace_id".into())
        );
        assert!(matches!(
            parse_envelope_wire(&checked(&bad)).unwrap_err(),
            EnvelopeParseError::Malformed(_)
        ));
    }

    #[test]
    fn check_unsigned_envelope_structure_ignores_signature() {
        let mut env = sample_envelope(MessageType::Tct);
        env.signature = String::new();
        assert!(check_unsigned_envelope_structure(&env).is_ok());
        assert!(check_envelope_structure(&env).is_err());
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
