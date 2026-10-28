//! Responder applies its identity-type policy (RFC-AITP-0004 §5.1 step 8)
//! only after the identity proof (step 6): a valid pinned-key peer that the
//! responder does not accept fails with `INCOMPATIBLE_IDENTITY_TYPE`, and a
//! peer that fails both the proof and the policy fails with
//! `IDENTITY_FAILED`, because the order is frozen.

use aitp::core::{AitpEnvelope, MessageType, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::handshake::{
    HandshakeError, IdentityKind, Initiator, JwkPublicKey, JwksResolver, PeerConfig,
    PresentedIdentity, ResolveError, Responder,
};
use aitp::manifest::{IdentityHint, Manifest, ManifestBuilder, ManifestError};
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn manifest_for(
    key: &AitpSigningKey,
    hint_subject: &str,
    accepts: &[aitp::handshake::IdentityKind],
) -> Manifest {
    let builder = ManifestBuilder::new(key)
        .display_name(hint_subject)
        .handshake_endpoint("https://peer.example.com/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityKind::PinnedKey, hint_subject).with_public_key(
                aitp::core::base64url::encode(
                    &key.verifying_key()
                        .try_to_ed25519_bytes()
                        .expect("key was constructed as Ed25519, never P-256"),
                ),
            ),
        )
        .offer("demo.echo")
        .published_at(NOW);
    // An empty `accepts` leaves the field off, which means `["oidc"]`.
    accepts
        .iter()
        .fold(builder, |b, t| b.accept_identity_type(*t))
        .build()
        .unwrap()
}

fn envelope_with(sender: &AitpSigningKey, payload: serde_json::Value, mid: Uuid) -> AitpEnvelope {
    let mut envelope = AitpEnvelope::unsigned(
        sender.aid().clone(),
        MessageType::MutualHello,
        payload,
        mid,
        NOW,
    );
    let digest = aitp::core::envelope_signing_digest(&envelope).unwrap();
    envelope.signature = sender
        .sign_jcs(&aitp::crypto::Digest32::from(digest))
        .into_string();
    envelope
}

/// Alice (pinned_key) says HELLO to bob, whose Manifest accepts
/// `bob_accepts` and whose pinned-key store trusts alice only when
/// `bob_trusts_alice`.
fn bob_on_hello(
    bob_accepts: &[aitp::handshake::IdentityKind],
    bob_trusts_alice: bool,
) -> Result<(), HandshakeError> {
    let alice = AitpSigningKey::from_ed25519_seed(&[0x81; 32]);
    let bob = AitpSigningKey::from_ed25519_seed(&[0x82; 32]);
    let alice_manifest = manifest_for(&alice, "alice", &[aitp::handshake::IdentityKind::PinnedKey]);
    let bob_manifest = manifest_for(&bob, "bob", bob_accepts);
    let resolver = NoOpResolver;

    let alice_pinned = aitp::handshake::StaticPinnedKeyStore::new([bob.verifying_key()]);
    let alice_cfg = PeerConfig::new(
        &alice,
        &alice_manifest,
        &resolver,
        &alice_pinned,
        aitp::tct::RevocationSource::FailOpen,
        NOW,
    );
    let bob_pinned = if bob_trusts_alice {
        aitp::handshake::StaticPinnedKeyStore::new([alice.verifying_key()])
    } else {
        aitp::handshake::StaticPinnedKeyStore::new([])
    };
    let bob_cfg = PeerConfig::new(
        &bob,
        &bob_manifest,
        &resolver,
        &bob_pinned,
        aitp::tct::RevocationSource::FailOpen,
        NOW,
    );

    let hello_mid = Uuid::new_v4();
    let (_alice_init, hello_payload) = Initiator::start(
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
        serde_json::to_value(&hello_payload).unwrap(),
        hello_mid,
    );
    Responder::on_hello(
        &hello_envelope,
        &hello_payload,
        PresentedIdentity::PinnedKey {
            subject: "bob".into(),
        },
        &Uuid::new_v4(),
        NOW,
        &bob_cfg,
        vec!["demo.echo".into()],
    )
    .map(|_| ())
}

#[test]
fn unaccepted_type_with_valid_proof_is_incompatible_identity_type() {
    let err = bob_on_hello(&[aitp::handshake::IdentityKind::Oidc], true).unwrap_err();
    assert!(
        matches!(
            err,
            HandshakeError::Manifest(ManifestError::IncompatibleIdentityType(
                aitp::handshake::IdentityKind::PinnedKey
            ))
        ),
        "got {err:?}"
    );
}

#[test]
fn failed_proof_wins_over_unaccepted_type() {
    // Step 6 (the pinned-key trust store) fails before step 8 runs.
    let err = bob_on_hello(&[aitp::handshake::IdentityKind::Oidc], false).unwrap_err();
    assert!(matches!(err, HandshakeError::Identity(_)), "got {err:?}");
}

#[test]
fn absent_accepted_identity_types_defaults_to_oidc() {
    let err = bob_on_hello(&[], true).unwrap_err();
    assert!(
        matches!(
            err,
            HandshakeError::Manifest(ManifestError::IncompatibleIdentityType(
                aitp::handshake::IdentityKind::PinnedKey
            ))
        ),
        "got {err:?}"
    );
}

#[test]
fn accepted_type_with_valid_proof_succeeds() {
    bob_on_hello(
        &[
            aitp::handshake::IdentityKind::Oidc,
            aitp::handshake::IdentityKind::PinnedKey,
        ],
        true,
    )
    .unwrap();
}
