//! Full Mutual Handshake — both peers in-process, pinned-key identity.

use aitp_core::{AitpEnvelope, MessageType, Sender, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_handshake::{
    Initiator, JwkPublicKey, JwksResolver, PeerConfig, PresentedIdentity, ResolveError, Responder,
};
use aitp_manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use serde_json::json;
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn alice_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xA1; 32])
}
fn bob_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xB2; 32])
}

fn manifest_for(key: &AitpSigningKey, name: &str) -> Manifest {
    ManifestBuilder::new(key)
        .display_name(name)
        .handshake_endpoint(
            format!("https://{}.example.com/handshake", name)
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

fn envelope_with(
    sender: &AitpSigningKey,
    mt: MessageType,
    payload: serde_json::Value,
    message_id: Uuid,
    timestamp: Timestamp,
) -> AitpEnvelope {
    let digest =
        aitp_core::envelope_signing_digest(&message_id, timestamp, sender.aid(), &payload).unwrap();
    let sig = sender.sign(&digest);
    AitpEnvelope {
        version: "aitp/0.1".into(),
        message_type: mt,
        message_id,
        timestamp,
        sender: Sender {
            agent_id: sender.aid().clone(),
        },
        payload,
        signature: sig.into_string(),
    }
}

#[test]
fn full_pinned_key_handshake() {
    let alice = alice_key();
    let bob = bob_key();
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
        revocation_check: None,
        now: NOW,
    };
    let bob_cfg = PeerConfig {
        signing_key: &bob,
        manifest: &bob_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: NOW,
    };

    // ── HELLO ────────────────────────────────────────────────────────
    let hello_mid = Uuid::new_v4();
    let (mut alice_init, hello_payload) = Initiator::start(
        &alice_cfg,
        PresentedIdentity::PinnedKey {
            subject: "alice".into(),
        },
        bob.aid(),
        &hello_mid,
        NOW,
        vec!["demo.echo".into()],
    )
    .unwrap();
    let hello_envelope = envelope_with(
        &alice,
        MessageType::MutualHello,
        serde_json::to_value(&hello_payload).unwrap(),
        hello_mid,
        NOW,
    );

    // ── HELLO_ACK (Bob) ──────────────────────────────────────────────
    let ack_mid = Uuid::new_v4();
    let (mut bob_resp, ack_payload) = Responder::on_hello(
        &hello_envelope,
        &hello_payload,
        PresentedIdentity::PinnedKey {
            subject: "bob".into(),
        },
        &ack_mid,
        NOW,
        &bob_cfg,
        vec!["demo.echo".into()],
    )
    .unwrap();
    let _ack_envelope = envelope_with(
        &bob,
        MessageType::MutualHelloAck,
        serde_json::to_value(&ack_payload).unwrap(),
        ack_mid,
        NOW,
    );

    // ── COMMIT (Alice) ───────────────────────────────────────────────
    let commit_payload = alice_init
        .on_hello_ack(&_ack_envelope, &ack_payload, &alice_cfg)
        .unwrap();
    let commit_mid = Uuid::new_v4();
    let commit_envelope = envelope_with(
        &alice,
        MessageType::MutualCommit,
        serde_json::to_value(&commit_payload).unwrap(),
        commit_mid,
        NOW,
    );

    // ── COMMIT_ACK (Bob) ─────────────────────────────────────────────
    let (commit_ack_payload, bob_holds_tct) = bob_resp
        .on_commit(&commit_envelope, &commit_payload, &bob_cfg)
        .unwrap();
    let commit_ack_mid = Uuid::new_v4();
    let commit_ack_envelope = envelope_with(
        &bob,
        MessageType::MutualCommitAck,
        serde_json::to_value(&commit_ack_payload).unwrap(),
        commit_ack_mid,
        NOW,
    );

    // ── Alice finalizes ──────────────────────────────────────────────
    let alice_holds_tct = alice_init
        .on_commit_ack(&commit_ack_envelope, &commit_ack_payload, &alice_cfg)
        .unwrap();

    // Each peer holds a TCT issued by the other.
    assert_eq!(&bob_holds_tct.issuer, alice.aid());
    assert_eq!(&bob_holds_tct.subject, bob.aid());
    assert_eq!(&bob_holds_tct.audience, bob.aid());

    assert_eq!(&alice_holds_tct.issuer, bob.aid());
    assert_eq!(&alice_holds_tct.subject, alice.aid());
    assert_eq!(&alice_holds_tct.audience, alice.aid());

    assert_eq!(alice_holds_tct.grants, vec!["demo.echo".to_string()]);
    assert_eq!(bob_holds_tct.grants, vec!["demo.echo".to_string()]);
}

#[test]
fn nonce_mismatch_aborts() {
    let alice = alice_key();
    let bob = bob_key();
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
        revocation_check: None,
        now: NOW,
    };
    let bob_cfg = PeerConfig {
        signing_key: &bob,
        manifest: &bob_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: NOW,
    };
    let hello_mid = Uuid::new_v4();
    let (mut alice_init, hello_payload) = Initiator::start(
        &alice_cfg,
        PresentedIdentity::PinnedKey {
            subject: "alice".into(),
        },
        bob.aid(),
        &hello_mid,
        NOW,
        vec!["demo.echo".into()],
    )
    .unwrap();
    let hello_envelope = envelope_with(
        &alice,
        MessageType::MutualHello,
        serde_json::to_value(&hello_payload).unwrap(),
        hello_mid,
        NOW,
    );
    let ack_mid = Uuid::new_v4();
    let (_resp, mut ack_payload) = Responder::on_hello(
        &hello_envelope,
        &hello_payload,
        PresentedIdentity::PinnedKey {
            subject: "bob".into(),
        },
        &ack_mid,
        NOW,
        &bob_cfg,
        vec!["demo.echo".into()],
    )
    .unwrap();
    // Tamper the echo.
    ack_payload.pop_nonce_echo = "Z".repeat(22);
    let bad_envelope = envelope_with(
        &bob,
        MessageType::MutualHelloAck,
        serde_json::to_value(&ack_payload).unwrap(),
        ack_mid,
        NOW,
    );
    let err = alice_init
        .on_hello_ack(&bad_envelope, &ack_payload, &alice_cfg)
        .unwrap_err();
    assert!(matches!(err, aitp_handshake::HandshakeError::NonceMismatch));
}

#[test]
fn insufficient_grants_aborts() {
    // Alice requires `super.power` from Bob, Bob doesn't offer it.
    let alice = alice_key();
    let bob = bob_key();
    let mut alice_manifest = manifest_for(&alice, "alice");
    alice_manifest.required_peer_capabilities = vec!["super.power".into()];
    let bob_manifest = manifest_for(&bob, "bob");
    let resolver = NoOpResolver;
    let alice_cfg = PeerConfig {
        signing_key: &alice,
        manifest: &alice_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: NOW,
    };
    let bob_cfg = PeerConfig {
        signing_key: &bob,
        manifest: &bob_manifest,
        trust_anchors: &[],
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: NOW,
    };
    // Note: alice_manifest now no longer matches the inline manifest's
    // signature (we mutated it after building). Re-sign by rebuilding.
    let alice_manifest = ManifestBuilder::new(&alice)
        .display_name("alice")
        .handshake_endpoint("https://alice.example.com/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "alice".into(),
            issuer: None,
            public_key: Some(aitp_core::base64url::encode(
                &alice.verifying_key().to_bytes(),
            )),
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .require("super.power")
        .published_at(NOW)
        .build()
        .unwrap();
    let alice_cfg = PeerConfig {
        signing_key: &alice,
        manifest: &alice_manifest,
        ..alice_cfg
    };

    let hello_mid = Uuid::new_v4();
    let (mut alice_init, hello_payload) = Initiator::start(
        &alice_cfg,
        PresentedIdentity::PinnedKey {
            subject: "alice".into(),
        },
        bob.aid(),
        &hello_mid,
        NOW,
        vec!["demo.echo".into()],
    )
    .unwrap();
    let hello_envelope = envelope_with(
        &alice,
        MessageType::MutualHello,
        serde_json::to_value(&hello_payload).unwrap(),
        hello_mid,
        NOW,
    );
    let ack_mid = Uuid::new_v4();
    let (mut bob_resp, ack_payload) = Responder::on_hello(
        &hello_envelope,
        &hello_payload,
        PresentedIdentity::PinnedKey {
            subject: "bob".into(),
        },
        &ack_mid,
        NOW,
        &bob_cfg,
        vec!["demo.echo".into()],
    )
    .unwrap();
    let ack_envelope = envelope_with(
        &bob,
        MessageType::MutualHelloAck,
        serde_json::to_value(&ack_payload).unwrap(),
        ack_mid,
        NOW,
    );
    let commit_payload = alice_init
        .on_hello_ack(&ack_envelope, &ack_payload, &alice_cfg)
        .unwrap();
    let commit_mid = Uuid::new_v4();
    let commit_envelope = envelope_with(
        &alice,
        MessageType::MutualCommit,
        serde_json::to_value(&commit_payload).unwrap(),
        commit_mid,
        NOW,
    );
    // Bob processes commit; verifying received TCT against his own
    // required_peer_capabilities (empty) succeeds. He issues his TCT for
    // alice with grants = ["demo.echo"] (alice requested), but alice
    // requires super.power.
    let (commit_ack_payload, _bob_holds) = bob_resp
        .on_commit(&commit_envelope, &commit_payload, &bob_cfg)
        .unwrap();
    let commit_ack_mid = Uuid::new_v4();
    let commit_ack_envelope = envelope_with(
        &bob,
        MessageType::MutualCommitAck,
        serde_json::to_value(&commit_ack_payload).unwrap(),
        commit_ack_mid,
        NOW,
    );
    let err = alice_init
        .on_commit_ack(&commit_ack_envelope, &commit_ack_payload, &alice_cfg)
        .unwrap_err();
    assert!(matches!(
        err,
        aitp_handshake::HandshakeError::InsufficientGrants
    ));
}

#[test]
fn envelope_signing_input_round_trips() {
    let alice = alice_key();
    let mid = Uuid::nil();
    let payload = json!({"hello": "world"});
    let digest =
        aitp_core::envelope_signing_digest(&mid, Timestamp(1), alice.aid(), &payload).unwrap();
    let sig = alice.sign(&digest);
    // Verify with the verifying key.
    alice.verifying_key().verify(&digest, &sig).unwrap();
}
