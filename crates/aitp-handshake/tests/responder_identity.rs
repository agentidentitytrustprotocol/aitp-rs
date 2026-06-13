//! Responder grant_policy receives the verified peer identity (BUG-2).
//!
//! Pre-rc.1, `Responder::on_commit` synthesized a placeholder
//! `IdentityDescriptor` (kind=PinnedKey, empty proof) when issuing the
//! peer's TCT. Any policy that branched on `kind`, `issuer`, `subject`,
//! or OIDC claims would silently see the wrong identity, breaking the
//! RFC-AITP-0004 §4.1 requirement that grant policies be applied
//! symmetrically on both peers.
//!
//! These tests drive a full Mutual Handshake in-process and assert the
//! responder's grant_policy receives the same `IdentityDescriptor` the
//! initiator presented, not a placeholder.

use aitp_core::{AitpEnvelope, MessageType, Sender, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_handshake::state_machine::GrantPolicyFn;
use aitp_handshake::{IdentityDescriptor, IdentityKind};
use aitp_handshake::{
    Initiator, JwkPublicKey, JwksResolver, PeerConfig, PresentedIdentity, ResolveError, Responder,
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
        .offer("write_data")
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

/// Drive a full pinned-key handshake. The responder's grant_policy
/// captures the `IdentityDescriptor` it sees during `on_commit` —
/// it must equal what the initiator presented in `MUTUAL_HELLO`,
/// not a placeholder.
#[test]
fn responder_grant_policy_sees_real_pinned_key_identity() {
    let alice = AitpSigningKey::from_seed(&[0xA1; 32]);
    let bob = AitpSigningKey::from_seed(&[0xB2; 32]);
    let alice_manifest = manifest_for(&alice, "alice");
    let bob_manifest = manifest_for(&bob, "bob");
    let resolver = NoOpResolver;

    // The trait object behind `grant_policy: Option<&dyn Fn(...)>`
    // is `Send + Sync` and outlives `cfg`, so closures can't borrow
    // local stack state directly. Capture into a thread-local so the
    // test can read what the policy actually saw.
    let policy_box: Box<GrantPolicyFn> = Box::new(|id, grants| {
        TEST_CAPTURE.with(|c| {
            *c.borrow_mut() = Some(id.clone());
        });
        grants.to_vec()
    });
    let policy_ref: &GrantPolicyFn = &*policy_box;

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
        grant_policy: Some(policy_ref),
        revocation_check: None,
        now: NOW,
    };

    // Reset capture for this test.
    TEST_CAPTURE.with(|c| *c.borrow_mut() = None);

    // HELLO
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

    // HELLO_ACK
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

    // COMMIT
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

    // COMMIT_ACK — this is where the responder's grant_policy fires
    // for the TCT it issues to Alice.
    let (_ack, _bob_tct) = bob_resp
        .on_commit(&commit_envelope, &commit_payload, &bob_cfg)
        .expect("commit succeeds");

    // The captured identity must mirror what Alice presented in HELLO.
    let captured = TEST_CAPTURE
        .with(|c| c.borrow().clone())
        .expect("responder grant_policy was never invoked — issue_tct didn't apply the policy");
    assert_eq!(
        captured.kind,
        IdentityKind::PinnedKey,
        "responder must see the real PinnedKey identity, not a placeholder"
    );
    assert_eq!(
        captured.subject, "alice",
        "responder must see Alice's subject, not the AID-as-subject placeholder"
    );
    assert!(
        !captured.proof.is_empty(),
        "responder must see the real signed proof, not the empty placeholder"
    );
    assert!(
        captured.public_key.is_some(),
        "responder must see Alice's pinned-key public_key, not None"
    );
    // Round-trip: the captured descriptor should equal the one Alice
    // sent inside MUTUAL_HELLO.
    assert_eq!(captured, hello_payload.identity);
}

thread_local! {
    static TEST_CAPTURE: std::cell::RefCell<Option<IdentityDescriptor>>
        = const { std::cell::RefCell::new(None) };
}
