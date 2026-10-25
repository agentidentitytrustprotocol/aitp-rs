//! Responder rejects a peer whose presented identity subject disagrees
//! with the subject in its own Manifest's identity hint.
//!
//! `bootstrap_verify_peer` (RFC-AITP-0002 §3.2) requires
//! `identity.subject == manifest.identity_hint.subject`. Without this an
//! initiator could present a Manifest for one subject while claiming to
//! be another. The happy paths are covered elsewhere; this proves the
//! mismatch is rejected with `HandshakeError::Identity`.

use aitp_core::{AitpEnvelope, MessageType, Sender, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_handshake::{
    HandshakeError, Initiator, JwkPublicKey, JwksResolver, PeerConfig, PresentedIdentity,
    ResolveError, Responder,
};
use aitp_manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn manifest_for(key: &AitpSigningKey, hint_subject: &str) -> Manifest {
    ManifestBuilder::new(key)
        .display_name(hint_subject)
        .handshake_endpoint("https://peer.example.com/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: hint_subject.into(),
            issuer: None,
            public_key: Some(aitp_core::base64url::encode(
                &key.verifying_key()
                    .try_to_ed25519_bytes()
                    .expect("key was constructed as Ed25519, never P-256"),
            )),
        })
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .published_at(NOW)
        .build()
        .unwrap()
}

fn envelope_with(sender: &AitpSigningKey, payload: serde_json::Value, mid: Uuid) -> AitpEnvelope {
    let mut envelope = AitpEnvelope {
        version: aitp_core::PROTOCOL_VERSION.into(),
        message_type: MessageType::MutualHello,
        message_id: mid,
        timestamp: NOW,
        sender: Sender {
            agent_id: sender.aid().clone(),
        },
        payload,
        extensions: None,
        signature: String::new(),
    };
    let digest = aitp_core::envelope_signing_digest(&envelope).unwrap();
    envelope.signature = sender
        .sign_jcs(&aitp_crypto::Digest32::from(digest))
        .into_string();
    envelope
}

#[test]
fn responder_rejects_subject_disagreeing_with_manifest_hint() {
    let alice = AitpSigningKey::from_seed(&[0x71; 32]);
    let bob = AitpSigningKey::from_seed(&[0x72; 32]);

    // Alice's Manifest declares the subject "alice", but she presents
    // the subject "mallory" in the handshake.
    let alice_manifest = manifest_for(&alice, "alice");
    let bob_manifest = manifest_for(&bob, "bob");
    let resolver = NoOpResolver;

    let alice_cfg_pinned = aitp_handshake::StaticPinnedKeyStore::new([bob.verifying_key()]);
    let alice_cfg = PeerConfig::new(&alice, &alice_manifest, &resolver, &alice_cfg_pinned, NOW);
    let bob_cfg_pinned = aitp_handshake::StaticPinnedKeyStore::new([alice.verifying_key()]);
    let bob_cfg = PeerConfig::new(&bob, &bob_manifest, &resolver, &bob_cfg_pinned, NOW);

    let hello_mid = Uuid::new_v4();
    let (_alice_init, hello_payload) = Initiator::start(
        &alice_cfg,
        PresentedIdentity::PinnedKey {
            subject: "mallory".into(), // ≠ alice_manifest.identity_hint.subject
        },
        bob.aid(),
        &hello_mid,
        NOW,
        vec!["demo.echo".into()],
    )
    .expect("initiator can present any subject; the responder enforces the binding");
    let hello_envelope = envelope_with(
        &alice,
        serde_json::to_value(&hello_payload).unwrap(),
        hello_mid,
    );

    let ack_mid = Uuid::new_v4();
    let result = Responder::on_hello(
        &hello_envelope,
        &hello_payload,
        PresentedIdentity::PinnedKey {
            subject: "bob".into(),
        },
        &ack_mid,
        NOW,
        &bob_cfg,
        vec!["demo.echo".into()],
    );
    // The Ok variant (`Responder`) isn't `Debug`, so match by hand.
    match result {
        Ok(_) => panic!("responder must reject the subject/manifest-hint mismatch"),
        Err(e) => assert!(
            matches!(e, HandshakeError::Identity(_)),
            "expected HandshakeError::Identity, got {e:?}"
        ),
    }
}
