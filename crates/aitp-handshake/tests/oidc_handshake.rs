//! Drive a Mutual Handshake using an OIDC identity proof minted by an
//! in-process mock OIDC issuer.

mod fixtures;

use aitp_core::{AitpEnvelope, MessageType, Sender, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_handshake::{
    Initiator, MutualCommitAckPayload, MutualHelloAckPayload, PeerConfig, PresentedIdentity,
    Responder,
};
use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use fixtures::mock_oidc::MockOidcIssuer;
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

fn manifest_for_oidc(
    key: &AitpSigningKey,
    name: &str,
    issuer: &url::Url,
) -> aitp_manifest::Manifest {
    ManifestBuilder::new(key)
        .display_name(name)
        .handshake_endpoint(
            format!("https://{name}.example.com/handshake")
                .parse()
                .unwrap(),
        )
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::Oidc,
            subject: name.into(),
            issuer: Some(issuer.clone()),
            public_key: None,
        })
        .accept_trust_anchor(issuer.clone())
        .accept_identity_type("oidc")
        .offer("demo.echo")
        .published_at(NOW)
        .build()
        .unwrap()
}

fn envelope_with(
    key: &AitpSigningKey,
    mt: MessageType,
    payload: serde_json::Value,
    mid: Uuid,
    ts: Timestamp,
) -> AitpEnvelope {
    let digest = aitp_core::envelope_signing_digest(&mid, ts, key.aid(), &payload).unwrap();
    AitpEnvelope {
        version: "aitp/0.1".into(),
        message_type: mt,
        message_id: mid,
        timestamp: ts,
        sender: Sender {
            agent_id: key.aid().clone(),
        },
        payload,
        signature: key.sign(&digest).into_string(),
    }
}

#[test]
fn full_oidc_handshake_in_process() {
    let issuer = MockOidcIssuer::new("https://idp.example.com", "kid-1", [0xC0; 32]);
    let issuer_url = issuer.issuer.clone();

    let alice = AitpSigningKey::from_seed(&[0xA1; 32]);
    let bob = AitpSigningKey::from_seed(&[0xB2; 32]);
    let alice_manifest = manifest_for_oidc(&alice, "alice", &issuer_url);
    let bob_manifest = manifest_for_oidc(&bob, "bob", &issuer_url);

    let resolver = issuer.as_resolver();

    // Mint JWTs for both peers. Each binds the per-handshake nonce to the
    // sender's pubkey via cnf.jkt.
    let alice_pop = "AAAAAAAAAAAAAAAAAAAAAA".to_string(); // 22 chars to pass the schema
    let bob_pop = "BBBBBBBBBBBBBBBBBBBBBB".to_string();

    let alice_jkt = aitp_crypto::AitpVerifyingKey::from_aid(alice.aid())
        .unwrap()
        .to_jwk_thumbprint();
    let bob_jkt = aitp_crypto::AitpVerifyingKey::from_aid(bob.aid())
        .unwrap()
        .to_jwk_thumbprint();

    let alice_jwt = issuer.mint_aitp_jwt(
        "alice",
        bob.aid().as_str(), // alice presents to bob → aud = bob's AID
        &alice_pop,
        &alice_jkt,
        NOW.0,
    );
    let bob_jwt = issuer.mint_aitp_jwt("bob", alice.aid().as_str(), &bob_pop, &bob_jkt, NOW.0);

    let trust_anchors = vec![issuer_url.clone()];
    let alice_cfg = PeerConfig {
        signing_key: &alice,
        manifest: &alice_manifest,
        trust_anchors: &trust_anchors,
        jwks_resolver: &resolver,
        now: NOW,
    };
    let bob_cfg = PeerConfig {
        signing_key: &bob,
        manifest: &bob_manifest,
        trust_anchors: &trust_anchors,
        jwks_resolver: &resolver,
        now: NOW,
    };

    // ── HELLO ────────────────────────────────────────────────────────
    let hello_mid = Uuid::new_v4();
    let (mut alice_init, mut hello_payload) = Initiator::start(
        &alice_cfg,
        PresentedIdentity::Oidc {
            issuer: issuer_url.clone(),
            subject: "alice".into(),
            proof_jwt: alice_jwt.clone(),
        },
        &hello_mid,
        NOW,
        vec!["demo.echo".into()],
    )
    .unwrap();
    // Initiator::start picked its own pop_nonce; overwrite to match the
    // one we minted into Alice's JWT, and re-sign the proof's nonce
    // claim path. Easiest: rebuild the JWT with the picked nonce.
    let alice_jwt = issuer.mint_aitp_jwt(
        "alice",
        bob.aid().as_str(),
        &hello_payload.pop_nonce,
        &alice_jkt,
        NOW.0,
    );
    hello_payload.identity.proof = alice_jwt;
    let hello_envelope = envelope_with(
        &alice,
        MessageType::MutualHello,
        serde_json::to_value(&hello_payload).unwrap(),
        hello_mid,
        NOW,
    );

    // ── HELLO_ACK ────────────────────────────────────────────────────
    let ack_mid = Uuid::new_v4();
    let (mut bob_resp, mut ack_payload) = Responder::on_hello(
        &hello_envelope,
        &hello_payload,
        PresentedIdentity::Oidc {
            issuer: issuer_url.clone(),
            subject: "bob".into(),
            proof_jwt: bob_jwt.clone(),
        },
        &ack_mid,
        NOW,
        &bob_cfg,
        vec!["demo.echo".into()],
    )
    .unwrap();
    // Same trick: rebuild the JWT for Bob's actual chosen nonce.
    let bob_jwt = issuer.mint_aitp_jwt(
        "bob",
        alice.aid().as_str(),
        &ack_payload.pop_nonce,
        &bob_jkt,
        NOW.0,
    );
    ack_payload.identity.proof = bob_jwt;
    let ack_envelope = envelope_with(
        &bob,
        MessageType::MutualHelloAck,
        serde_json::to_value(&ack_payload).unwrap(),
        ack_mid,
        NOW,
    );

    // ── COMMIT ───────────────────────────────────────────────────────
    let commit_payload = alice_init
        .on_hello_ack(&ack_envelope, &ack_payload, &alice_cfg)
        .unwrap();
    let commit_envelope = envelope_with(
        &alice,
        MessageType::MutualCommit,
        serde_json::to_value(&commit_payload).unwrap(),
        Uuid::new_v4(),
        NOW,
    );

    // ── COMMIT_ACK ───────────────────────────────────────────────────
    let (commit_ack_payload, bob_holds) = bob_resp
        .on_commit(&commit_envelope, &commit_payload, &bob_cfg)
        .unwrap();
    let commit_ack_envelope = envelope_with(
        &bob,
        MessageType::MutualCommitAck,
        serde_json::to_value(&commit_ack_payload).unwrap(),
        Uuid::new_v4(),
        NOW,
    );
    let alice_holds = alice_init
        .on_commit_ack(&commit_ack_envelope, &commit_ack_payload, &alice_cfg)
        .unwrap();

    assert_eq!(&alice_holds.issuer, bob.aid());
    assert_eq!(&bob_holds.issuer, alice.aid());
    assert_eq!(alice_holds.grants, vec!["demo.echo".to_string()]);
    assert_eq!(bob_holds.grants, vec!["demo.echo".to_string()]);

    let _: MutualHelloAckPayload = ack_payload;
    let _: MutualCommitAckPayload = commit_ack_payload;
}
