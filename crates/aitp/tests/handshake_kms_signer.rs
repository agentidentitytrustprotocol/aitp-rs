//! `PeerConfig.signing_key` accepts any `AitpSigner`: a full pinned-key
//! Mutual Handshake runs with one side's key behind a KMS-shaped backend
//! (P-256, DER, high-S), and a backend signing with the wrong key fails
//! locally with `CryptoError::Signer`, never a token the peer rejects.

use aitp::core::{AitpEnvelope, MessageType, Timestamp};
use aitp::crypto::testing::{MockKmsSigner, MockOutput};
use aitp::crypto::{AitpSigner, AitpSigningKey, AitpVerifyingKey, CryptoError, SignerError};
use aitp::handshake::{
    HandshakeError, Initiator, NoPinnedKeys, PeerConfig, PresentedIdentity, Responder,
    StaticPinnedKeyStore,
};
use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn vk(signer: &dyn AitpSigner) -> AitpVerifyingKey {
    AitpVerifyingKey::from_aid(signer.aid()).unwrap()
}

fn manifest_for(key: &dyn AitpSigner, name: &str) -> Manifest {
    ManifestBuilder::new(key)
        .display_name(name)
        .handshake_endpoint(
            format!("https://{name}.example.com/handshake")
                .parse()
                .unwrap(),
        )
        .identity_hint(
            IdentityHint::new(IdentityHintKind::PinnedKey, name)
                .with_public_key(aitp::core::base64url::encode(&vk(key).to_compressed())),
        )
        .accept_identity_type(aitp::handshake::IdentityKind::PinnedKey)
        .offer("demo.echo")
        .published_at(NOW)
        .build()
        .unwrap()
}

fn envelope_with(
    sender: &dyn AitpSigner,
    mt: MessageType,
    payload: serde_json::Value,
    message_id: Uuid,
) -> AitpEnvelope {
    let mut envelope = AitpEnvelope::unsigned(sender.aid().clone(), mt, payload, message_id, NOW);
    let digest = aitp::core::envelope_signing_digest(&envelope).unwrap();
    envelope.signature = aitp::crypto::sign_jcs(sender, &aitp::crypto::Digest32::from(digest))
        .unwrap()
        .into_string();
    envelope
}

#[test]
fn pinned_handshake_with_kms_backed_initiator() {
    let alice = MockKmsSigner::new(AitpSigningKey::from_p256_seed(&[0xA1; 32]).unwrap())
        .output(MockOutput::DerHighS);
    let bob = AitpSigningKey::from_ed25519_seed(&[0xB2; 32]);
    let alice_manifest = manifest_for(&alice, "alice");
    let bob_manifest = manifest_for(&bob, "bob");
    let resolver = NoOpResolver;
    let alice_store = StaticPinnedKeyStore::new([bob.verifying_key()]);
    let bob_store = StaticPinnedKeyStore::new([vk(&alice)]);

    let alice_cfg = PeerConfig::new(
        &alice,
        &alice_manifest,
        &resolver,
        &alice_store,
        aitp::tct::RevocationSource::FailOpen,
        NOW,
    );
    let bob_cfg = PeerConfig::new(
        &bob,
        &bob_manifest,
        &resolver,
        &bob_store,
        aitp::tct::RevocationSource::FailOpen,
        NOW,
    );

    let hello_mid = Uuid::new_v4();
    let (mut alice_init, hello) = Initiator::start(
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
    let hello_env = envelope_with(
        &alice,
        MessageType::MutualHello,
        serde_json::to_value(&hello).unwrap(),
        hello_mid,
    );

    let ack_mid = Uuid::new_v4();
    let (mut bob_resp, ack) = Responder::on_hello(
        &hello_env,
        &hello,
        PresentedIdentity::PinnedKey {
            subject: "bob".into(),
        },
        &ack_mid,
        NOW,
        &bob_cfg,
        vec!["demo.echo".into()],
    )
    .unwrap();
    let ack_env = envelope_with(
        &bob,
        MessageType::MutualHelloAck,
        serde_json::to_value(&ack).unwrap(),
        ack_mid,
    );

    let commit = alice_init.on_hello_ack(&ack_env, &ack, &alice_cfg).unwrap();
    let commit_env = envelope_with(
        &alice,
        MessageType::MutualCommit,
        serde_json::to_value(&commit).unwrap(),
        Uuid::new_v4(),
    );
    let (commit_ack, bob_holds) = bob_resp.on_commit(&commit_env, &commit, &bob_cfg).unwrap();
    let commit_ack_env = envelope_with(
        &bob,
        MessageType::MutualCommitAck,
        serde_json::to_value(&commit_ack).unwrap(),
        Uuid::new_v4(),
    );
    let alice_holds = alice_init
        .on_commit_ack(&commit_ack_env, &commit_ack, &alice_cfg)
        .unwrap();

    // Bob holds a TCT minted through Alice's KMS backend, and vice versa.
    assert_eq!(&bob_holds.tct().claims().iss, alice.aid());
    assert_eq!(&alice_holds.tct().claims().iss, bob.aid());
    assert_eq!(&alice_holds.tct().claims().sub, alice.aid());
    assert!(
        alice.calls() >= 4,
        "identity proof, PoP, TCT, envelopes all hit the backend"
    );
}

#[test]
fn kms_backend_with_wrong_key_fails_locally_at_hello() {
    let good = AitpSigningKey::from_p256_seed(&[0xA3; 32]).unwrap();
    let alice_manifest = manifest_for(&good, "alice");
    let alice =
        MockKmsSigner::new(good).sign_with(AitpSigningKey::from_p256_seed(&[0xA4; 32]).unwrap());
    let bob = AitpSigningKey::from_ed25519_seed(&[0xB4; 32]);
    let resolver = NoOpResolver;
    let cfg = PeerConfig::new(
        &alice,
        &alice_manifest,
        &resolver,
        &NoPinnedKeys,
        aitp::tct::RevocationSource::FailOpen,
        NOW,
    );
    let err = match Initiator::start(
        &cfg,
        PresentedIdentity::PinnedKey {
            subject: "alice".into(),
        },
        bob.aid(),
        &Uuid::new_v4(),
        NOW,
        vec!["demo.echo".into()],
    ) {
        Err(e) => e,
        Ok(_) => panic!("wrong-key backend must fail"),
    };
    assert!(
        matches!(
            err,
            HandshakeError::Crypto(CryptoError::Signer(SignerError::VerificationFailed))
        ),
        "{err:?}"
    );
}
