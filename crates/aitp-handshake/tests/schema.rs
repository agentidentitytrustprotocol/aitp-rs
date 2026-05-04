//! Drift firewall: each of the four Mutual Handshake payloads MUST
//! validate against its `$defs/<Name>` sub-schema in
//! `tests/schemas/aitp-mutual-handshake.schema.json`.
//!
//! Drives a real two-peer handshake in-process and validates every
//! payload as it is produced. This guards the wire format end-to-end:
//! if a future change adds, removes, or renames a field on any of the
//! four payload structs, validation here will fail before it reaches
//! the wire.

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_handshake::{
    Initiator, JwkPublicKey, JwksResolver, PeerConfig, PresentedIdentity, ResolveError, Responder,
};
use aitp_manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use boon::{Compiler, Schemas};
use std::path::PathBuf;
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("tests/schemas/aitp-mutual-handshake.schema.json")
}

fn validator_for(payload_name: &str) -> (Schemas, boon::SchemaIndex) {
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
    let path = schema_path();
    let schema_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read schema")).expect("parse schema");
    let base_url = format!("file://{}", path.display());
    compiler
        .add_resource(&base_url, schema_json)
        .expect("add resource");
    let target_url = format!("{base_url}#/$defs/{payload_name}");
    let id = compiler
        .compile(&target_url, &mut schemas)
        .expect("compile sub-schema");
    (schemas, id)
}

fn assert_validates(payload_name: &str, value: &serde_json::Value) {
    let (schemas, id) = validator_for(payload_name);
    if let Err(e) = schemas.validate(value, id) {
        panic!("{payload_name} failed schema validation:\n{e}");
    }
}

fn manifest_for(key: &AitpSigningKey, name: &str) -> Manifest {
    ManifestBuilder::new(key)
        .display_name(name)
        .handshake_endpoint(
            format!("https://{name}.example.com/handshake")
                .parse()
                .unwrap(),
        )
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: name.into(),
            issuer: None,
            public_key: Some(aitp_core::base64url::encode(
                &key.verifying_key().to_bytes(),
            )),
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .published_at(NOW)
        .build()
        .unwrap()
}

#[test]
fn all_four_handshake_payloads_validate_against_schema() {
    let alice = AitpSigningKey::from_seed(&[0xA1; 32]);
    let bob = AitpSigningKey::from_seed(&[0xB2; 32]);
    let alice_manifest = manifest_for(&alice, "alice");
    let bob_manifest = manifest_for(&bob, "bob");
    let resolver = NoOpResolver;

    let alice_cfg = PeerConfig {
        signing_key: &alice,
        manifest: &alice_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        now: NOW,
    };
    let bob_cfg = PeerConfig {
        signing_key: &bob,
        manifest: &bob_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        now: NOW,
    };

    // ── 1. HELLO ─────────────────────────────────────────────────────
    let hello_mid = Uuid::new_v4();
    let hello_ts = NOW;
    let (mut alice_init, hello_payload) = Initiator::start(
        &alice_cfg,
        PresentedIdentity::PinnedKey {
            subject: "alice".into(),
        },
        bob.aid(),
        &hello_mid,
        hello_ts,
        vec!["demo.echo".into()],
    )
    .unwrap();
    assert_validates(
        "MutualHelloPayload",
        &serde_json::to_value(&hello_payload).unwrap(),
    );

    // Wrap in an envelope so Responder can ingest it.
    let hello_env = build_envelope(
        &alice,
        aitp_core::MessageType::MutualHello,
        serde_json::to_value(&hello_payload).unwrap(),
        hello_mid,
        hello_ts,
    );

    // ── 2. HELLO_ACK ─────────────────────────────────────────────────
    let ack_mid = Uuid::new_v4();
    let ack_ts = NOW;
    let (mut bob_resp, ack_payload) = Responder::on_hello(
        &hello_env,
        &hello_payload,
        PresentedIdentity::PinnedKey {
            subject: "bob".into(),
        },
        &ack_mid,
        ack_ts,
        &bob_cfg,
        vec!["demo.echo".into()],
    )
    .unwrap();
    assert_validates(
        "MutualHelloAckPayload",
        &serde_json::to_value(&ack_payload).unwrap(),
    );

    let ack_env = build_envelope(
        &bob,
        aitp_core::MessageType::MutualHelloAck,
        serde_json::to_value(&ack_payload).unwrap(),
        ack_mid,
        ack_ts,
    );

    // ── 3. COMMIT ────────────────────────────────────────────────────
    let commit_payload = alice_init
        .on_hello_ack(&ack_env, &ack_payload, &alice_cfg)
        .unwrap();
    assert_validates(
        "MutualCommitPayload",
        &serde_json::to_value(&commit_payload).unwrap(),
    );

    let commit_env = build_envelope(
        &alice,
        aitp_core::MessageType::MutualCommit,
        serde_json::to_value(&commit_payload).unwrap(),
        Uuid::new_v4(),
        NOW,
    );

    // ── 4. COMMIT_ACK ────────────────────────────────────────────────
    let (commit_ack_payload, _bob_holds) = bob_resp
        .on_commit(&commit_env, &commit_payload, &bob_cfg)
        .unwrap();
    assert_validates(
        "MutualCommitAckPayload",
        &serde_json::to_value(&commit_ack_payload).unwrap(),
    );
}

fn build_envelope(
    sender: &AitpSigningKey,
    mt: aitp_core::MessageType,
    payload: serde_json::Value,
    message_id: Uuid,
    timestamp: Timestamp,
) -> aitp_core::AitpEnvelope {
    let digest =
        aitp_core::envelope_signing_digest(&message_id, timestamp, sender.aid(), &payload).unwrap();
    let sig = sender.sign(&digest);
    aitp_core::AitpEnvelope {
        version: "aitp/0.1".into(),
        message_type: mt,
        message_id,
        timestamp,
        sender: aitp_core::Sender {
            agent_id: sender.aid().clone(),
        },
        payload,
        signature: sig.into_string(),
    }
}
