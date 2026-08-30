//! Wire-payload structs for the four handshake message types
//! (RFC-AITP-0004 §3).

use crate::IdentityDescriptor;
use aitp_core::ExtensionsMap;
use aitp_manifest::Manifest;
use serde::{Deserialize, Serialize};

/// Payload of a `MUTUAL_HELLO` envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MutualHelloPayload {
    /// Fresh, handshake-bound identity proof.
    pub identity: IdentityDescriptor,
    /// Initiator's full Manifest (inline to avoid a fetch round-trip).
    pub manifest: Manifest,
    /// Capabilities the initiator is requesting from the responder.
    pub requested_grants: Vec<String>,
    /// Random 22-char base64url-unpadded nonce. Responder MUST sign over
    /// this in MUTUAL_COMMIT_ACK.
    pub pop_nonce: String,
    /// Optional extension namespace (RFC-AITP-0001 §7 / RFC-AITP-0012).
    ///
    /// **Presence-sensitive**, deliberately modeled as `Option<ExtensionsMap>`
    /// rather than a defaulted empty map — absence (`None`) omits the key
    /// entirely on the wire, matching the shared convention used
    /// throughout this codebase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionsMap>,
}

/// Full set of top-level members `aitp-mutual-handshake.schema.json`'s
/// `$defs/MutualHelloPayload` declares, including `extensions` itself.
/// Used by the adapter's member-set check (RFC-AITP-0001 §7) on the raw
/// payload value, before typed deserialization.
///
/// Anchored to the vendored schema by `crates/aitp-handshake/tests/schema.rs`,
/// which asserts this list equals the schema's `$defs.MutualHelloPayload.properties`
/// keys — so this cannot silently drift from the spec.
pub const MUTUAL_HELLO_PAYLOAD_MEMBERS: &[&str] = &[
    "identity",
    "manifest",
    "requested_grants",
    "pop_nonce",
    "extensions",
];

/// Payload of a `MUTUAL_HELLO_ACK` envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MutualHelloAckPayload {
    /// Responder's identity proof.
    pub identity: IdentityDescriptor,
    /// Responder's Manifest.
    pub manifest: Manifest,
    /// Capabilities the responder is requesting from the initiator.
    pub requested_grants: Vec<String>,
    /// Responder's own nonce. Initiator MUST sign over this in
    /// MUTUAL_COMMIT.
    pub pop_nonce: String,
    /// Initiator's nonce, echoed.
    pub pop_nonce_echo: String,
    /// Optional extension namespace (RFC-AITP-0001 §7 / RFC-AITP-0012).
    /// Same presence-sensitive modeling as [`MutualHelloPayload::extensions`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionsMap>,
}

/// Full set of top-level members `aitp-mutual-handshake.schema.json`'s
/// `$defs/MutualHelloAckPayload` declares, including `extensions` itself.
/// Same role as [`MUTUAL_HELLO_PAYLOAD_MEMBERS`], anchored by
/// `crates/aitp-handshake/tests/schema.rs`.
pub const MUTUAL_HELLO_ACK_PAYLOAD_MEMBERS: &[&str] = &[
    "identity",
    "manifest",
    "requested_grants",
    "pop_nonce",
    "pop_nonce_echo",
    "extensions",
];

/// Payload of a `MUTUAL_COMMIT` envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MutualCommitPayload {
    /// TCT the initiator issues to the responder — opaque compact JWS,
    /// `typ: aitp-tct+jwt` (RFC-AITP-0005).
    pub tct: String,
    /// Companion grant voucher compact JWS (`typ: aitp-grant+jwt`).
    /// OPTIONAL — the issuer MAY decline when its policy forbids the
    /// peer from delegating (RFC-AITP-0005 §8.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_voucher: Option<String>,
    /// Initiator's signature over `sha256(decoded(B_pop_nonce))`.
    pub pop_signature: String,
    /// Responder's nonce, echoed.
    pub pop_nonce_echo: String,
    /// Optional extension namespace (RFC-AITP-0001 §7 / RFC-AITP-0012).
    /// Same presence-sensitive modeling as [`MutualHelloPayload::extensions`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionsMap>,
}

/// Full set of top-level members `aitp-mutual-handshake.schema.json`'s
/// `$defs/MutualCommitPayload` declares, including `extensions` itself.
/// Same role as [`MUTUAL_HELLO_PAYLOAD_MEMBERS`], anchored by
/// `crates/aitp-handshake/tests/schema.rs`.
pub const MUTUAL_COMMIT_PAYLOAD_MEMBERS: &[&str] = &[
    "tct",
    "grant_voucher",
    "pop_signature",
    "pop_nonce_echo",
    "extensions",
];

/// Payload of a `MUTUAL_COMMIT_ACK` envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MutualCommitAckPayload {
    /// TCT the responder issues to the initiator — opaque compact JWS,
    /// `typ: aitp-tct+jwt` (RFC-AITP-0005).
    pub tct: String,
    /// Companion grant voucher compact JWS (`typ: aitp-grant+jwt`).
    /// OPTIONAL (RFC-AITP-0005 §8.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_voucher: Option<String>,
    /// Responder's signature over `sha256(decoded(A_pop_nonce))`.
    pub pop_signature: String,
    /// Initiator's nonce, echoed.
    pub pop_nonce_echo: String,
    /// Optional extension namespace (RFC-AITP-0001 §7 / RFC-AITP-0012).
    /// Same presence-sensitive modeling as [`MutualHelloPayload::extensions`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionsMap>,
}

/// Full set of top-level members `aitp-mutual-handshake.schema.json`'s
/// `$defs/MutualCommitAckPayload` declares, including `extensions` itself.
/// Same role as [`MUTUAL_HELLO_PAYLOAD_MEMBERS`], anchored by
/// `crates/aitp-handshake/tests/schema.rs`.
pub const MUTUAL_COMMIT_ACK_PAYLOAD_MEMBERS: &[&str] = &[
    "tct",
    "grant_voucher",
    "pop_signature",
    "pop_nonce_echo",
    "extensions",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdentityKind;
    use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
    use aitp_tct::TctBuilder;
    use serde_json::json;

    fn alice() -> aitp_crypto::AitpSigningKey {
        aitp_crypto::AitpSigningKey::from_seed(&[0xA1; 32])
    }

    fn build_manifest(key: &aitp_crypto::AitpSigningKey) -> aitp_manifest::Manifest {
        ManifestBuilder::new(key)
            .handshake_endpoint("https://a.example.com/handshake".parse().unwrap())
            .identity_hint(IdentityHint {
                kind: IdentityHintKind::PinnedKey,
                subject: "alice".into(),
                issuer: None,
                public_key: Some(aitp_core::base64url::encode(
                    &key.verifying_key()
                        .try_to_ed25519_bytes()
                        .expect("key was constructed as Ed25519, never P-256"),
                )),
            })
            .accept_trust_anchor("https://idp.example.com".parse().unwrap())
            .offer("demo.echo")
            .published_at(aitp_core::Timestamp(1_700_000_000))
            .build()
            .unwrap()
    }

    fn build_tct(
        issuer: &aitp_crypto::AitpSigningKey,
        subject_aid: &aitp_core::Aid,
        subject_pk: aitp_crypto::AitpVerifyingKey,
    ) -> aitp_tct::IssuedTct {
        TctBuilder::new(issuer)
            .subject(subject_aid.clone())
            .audience(subject_aid.clone())
            .grants(["demo.echo"])
            .ttl_secs(3600)
            .subject_pubkey(subject_pk)
            .issued_at(aitp_core::Timestamp(1_700_000_000))
            .build()
            .unwrap()
    }

    fn sample_identity() -> IdentityDescriptor {
        IdentityDescriptor {
            kind: IdentityKind::PinnedKey,
            issuer: None,
            subject: "alice".into(),
            proof: "A".repeat(86),
            public_key: Some("A".repeat(43)),
        }
    }

    #[test]
    fn round_trip_mutual_hello() {
        let key = alice();
        let payload = MutualHelloPayload {
            identity: sample_identity(),
            manifest: build_manifest(&key),
            requested_grants: vec!["demo.echo".into()],
            pop_nonce: "A".repeat(22),
            extensions: None,
        };
        let s = serde_json::to_string(&payload).unwrap();
        assert!(!s.contains("\"extensions\":"));
        let back: MutualHelloPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn round_trip_mutual_hello_ack() {
        let key = alice();
        let payload = MutualHelloAckPayload {
            identity: sample_identity(),
            manifest: build_manifest(&key),
            requested_grants: vec![],
            pop_nonce: "B".repeat(22),
            pop_nonce_echo: "A".repeat(22),
            extensions: None,
        };
        let s = serde_json::to_string(&payload).unwrap();
        assert!(!s.contains("\"extensions\":"));
        let back: MutualHelloAckPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn round_trip_mutual_commit_and_ack() {
        let key = alice();
        let subject = aitp_crypto::AitpSigningKey::from_seed(&[0xB2; 32]);
        let issued = build_tct(&key, subject.aid(), subject.verifying_key());
        let commit = MutualCommitPayload {
            tct: issued.token.clone(),
            grant_voucher: issued.voucher.clone(),
            pop_signature: "A".repeat(86),
            pop_nonce_echo: "B".repeat(22),
            extensions: None,
        };
        let s = serde_json::to_string(&commit).unwrap();
        assert!(!s.contains("\"extensions\":"));
        let back: MutualCommitPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, commit);

        // Voucher is optional — issuer policy may decline it.
        let ack = MutualCommitAckPayload {
            tct: issued.token,
            grant_voucher: None,
            pop_signature: "B".repeat(86),
            pop_nonce_echo: "A".repeat(22),
            extensions: None,
        };
        let s = serde_json::to_string(&ack).unwrap();
        assert!(!s.contains("grant_voucher"));
        assert!(!s.contains("\"extensions\":"));
        let back: MutualCommitAckPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ack);
    }

    /// Acceptance criterion 1 (issue #140 Phase 7a): all four handshake
    /// payload types round-trip a present `extensions` object without
    /// error. Complements the `!s.contains("\"extensions\":")` assertions
    /// above, which guard the absent-emits-nothing half.
    #[test]
    fn round_trip_extensions_present_on_all_four_payloads() {
        let key = alice();
        let mut ext = aitp_core::ExtensionsMap::new();
        ext.insert("com.example.trace", json!({"id": "abc-123"}));

        let hello = MutualHelloPayload {
            identity: sample_identity(),
            manifest: build_manifest(&key),
            requested_grants: vec!["demo.echo".into()],
            pop_nonce: "A".repeat(22),
            extensions: Some(ext.clone()),
        };
        let s = serde_json::to_string(&hello).unwrap();
        assert!(s.contains("\"extensions\":"));
        let back: MutualHelloPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, hello);

        let hello_ack = MutualHelloAckPayload {
            identity: sample_identity(),
            manifest: build_manifest(&key),
            requested_grants: vec![],
            pop_nonce: "B".repeat(22),
            pop_nonce_echo: "A".repeat(22),
            extensions: Some(ext.clone()),
        };
        let s = serde_json::to_string(&hello_ack).unwrap();
        assert!(s.contains("\"extensions\":"));
        let back: MutualHelloAckPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, hello_ack);

        let subject = aitp_crypto::AitpSigningKey::from_seed(&[0xB2; 32]);
        let issued = build_tct(&key, subject.aid(), subject.verifying_key());
        let commit = MutualCommitPayload {
            tct: issued.token.clone(),
            grant_voucher: issued.voucher.clone(),
            pop_signature: "A".repeat(86),
            pop_nonce_echo: "B".repeat(22),
            extensions: Some(ext.clone()),
        };
        let s = serde_json::to_string(&commit).unwrap();
        assert!(s.contains("\"extensions\":"));
        let back: MutualCommitPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, commit);

        let commit_ack = MutualCommitAckPayload {
            tct: issued.token,
            grant_voucher: None,
            pop_signature: "B".repeat(86),
            pop_nonce_echo: "A".repeat(22),
            extensions: Some(ext),
        };
        let s = serde_json::to_string(&commit_ack).unwrap();
        assert!(s.contains("\"extensions\":"));
        let back: MutualCommitAckPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, commit_ack);
    }

    #[test]
    fn rejects_unknown_field_in_hello() {
        let key = alice();
        let mut v = serde_json::to_value(MutualHelloPayload {
            identity: sample_identity(),
            manifest: build_manifest(&key),
            requested_grants: vec![],
            pop_nonce: "A".repeat(22),
            extensions: None,
        })
        .unwrap();
        v.as_object_mut().unwrap().insert("rogue".into(), json!(1));
        assert!(serde_json::from_value::<MutualHelloPayload>(v).is_err());
    }

    /// Acceptance criterion 3 (issue #140 Phase 7a): an unknown member
    /// *inside* a nested `IdentityDescriptor` is recovered via
    /// `from_serde_error`, same as any other nested closed object — not
    /// via the top-level `check_members` path, which only inspects the
    /// payload's own top-level keys.
    #[test]
    fn unknown_field_inside_nested_identity_recovers_via_from_serde_error() {
        let key = alice();
        let mut v = serde_json::to_value(MutualHelloPayload {
            identity: sample_identity(),
            manifest: build_manifest(&key),
            requested_grants: vec![],
            pop_nonce: "A".repeat(22),
            extensions: None,
        })
        .unwrap();
        v["identity"]
            .as_object_mut()
            .unwrap()
            .insert("rogue".into(), json!(1));
        let err = serde_json::from_value::<MutualHelloPayload>(v).unwrap_err();
        assert_eq!(aitp_core::from_serde_error(&err), Some("rogue".to_string()));
    }

    /// Acceptance criterion 3, second half: `IdentityDescriptor` — per the
    /// pinned handshake schema's inline `$defs/IdentityDescriptor` copy —
    /// deliberately has NO `extensions` field (unlike the standalone
    /// `aitp-identity.schema.json`, which disagrees at this pinned spec
    /// commit; see the Phase 7a plan notes). Putting `extensions` inside a
    /// nested identity object must therefore still be rejected exactly
    /// like any other unknown member. This test intentionally regresses
    /// the moment `IdentityDescriptor` gains `extensions` — that is the
    /// documented, tracked expiry of this decision, not a bug in this test.
    #[test]
    fn nested_identity_still_rejects_extensions_field() {
        let key = alice();
        let mut v = serde_json::to_value(MutualHelloPayload {
            identity: sample_identity(),
            manifest: build_manifest(&key),
            requested_grants: vec![],
            pop_nonce: "A".repeat(22),
            extensions: None,
        })
        .unwrap();
        v["identity"]
            .as_object_mut()
            .unwrap()
            .insert("extensions".into(), json!({}));
        let err = serde_json::from_value::<MutualHelloPayload>(v).unwrap_err();
        assert_eq!(
            aitp_core::from_serde_error(&err),
            Some("extensions".to_string())
        );
    }
}
