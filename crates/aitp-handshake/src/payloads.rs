//! Wire-payload structs for the four handshake message types
//! (RFC-AITP-0004 §3).

use crate::IdentityDescriptor;
use aitp_manifest::Manifest;
use aitp_tct::TctEnvelope;
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
}

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
}

/// Payload of a `MUTUAL_COMMIT` envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MutualCommitPayload {
    /// TCT initiator issues to responder, wrapped as `{"tct": {...}}`.
    pub tct_for_peer: TctEnvelope,
    /// Initiator's signature over `sha256(B_pop_nonce.as_bytes())`.
    pub pop_signature: String,
    /// Responder's nonce, echoed.
    pub pop_nonce_echo: String,
}

/// Payload of a `MUTUAL_COMMIT_ACK` envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MutualCommitAckPayload {
    /// TCT responder issues to initiator, wrapped as `{"tct": {...}}`.
    pub tct_for_peer: TctEnvelope,
    /// Responder's signature over `sha256(A_pop_nonce.as_bytes())`.
    pub pop_signature: String,
    /// Initiator's nonce, echoed.
    pub pop_nonce_echo: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdentityKind;
    use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
    use aitp_tct::{Tct, TctBuilder};
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
                    &key.verifying_key().to_bytes(),
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
    ) -> Tct {
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
        };
        let s = serde_json::to_string(&payload).unwrap();
        let back: MutualHelloAckPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn round_trip_mutual_commit_and_ack() {
        let key = alice();
        let subject = aitp_crypto::AitpSigningKey::from_seed(&[0xB2; 32]);
        let tct = build_tct(&key, subject.aid(), subject.verifying_key());
        let env = TctEnvelope { tct };
        let commit = MutualCommitPayload {
            tct_for_peer: env.clone(),
            pop_signature: "A".repeat(86),
            pop_nonce_echo: "B".repeat(22),
        };
        let s = serde_json::to_string(&commit).unwrap();
        let back: MutualCommitPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, commit);

        let ack = MutualCommitAckPayload {
            tct_for_peer: env,
            pop_signature: "B".repeat(86),
            pop_nonce_echo: "A".repeat(22),
        };
        let s = serde_json::to_string(&ack).unwrap();
        let back: MutualCommitAckPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ack);
    }

    #[test]
    fn rejects_unknown_field_in_hello() {
        let key = alice();
        let mut v = serde_json::to_value(MutualHelloPayload {
            identity: sample_identity(),
            manifest: build_manifest(&key),
            requested_grants: vec![],
            pop_nonce: "A".repeat(22),
        })
        .unwrap();
        v.as_object_mut().unwrap().insert("rogue".into(), json!(1));
        assert!(serde_json::from_value::<MutualHelloPayload>(v).is_err());
    }
}
