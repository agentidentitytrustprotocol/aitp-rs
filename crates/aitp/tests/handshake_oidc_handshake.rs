//! Drive a Mutual Handshake using an OIDC identity proof minted by an
//! in-process mock OIDC issuer.

#[path = "handshake_fixtures/mod.rs"]
mod fixtures;

use aitp::core::{AitpEnvelope, MessageType, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::handshake::{
    Initiator, MutualCommitAckPayload, MutualHelloAckPayload, PeerConfig, PresentedIdentity,
    Responder,
};
use aitp::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use fixtures::mock_oidc::MockOidcIssuer;
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

fn manifest_for_oidc(
    key: &AitpSigningKey,
    name: &str,
    issuer: &url::Url,
) -> aitp::manifest::Manifest {
    ManifestBuilder::new(key)
        .display_name(name)
        .handshake_endpoint(
            format!("https://{name}.example.com/handshake")
                .parse()
                .unwrap(),
        )
        .identity_hint(
            IdentityHint::new(IdentityHintKind::Oidc, name)
                .with_issuer(aitp::core::RawUrl::from(issuer.clone())),
        )
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
    let mut envelope = AitpEnvelope::unsigned(key.aid().clone(), mt, payload, mid, ts);
    let digest = aitp::core::envelope_signing_digest(&envelope).unwrap();
    envelope.signature = key
        .sign_jcs(&aitp::crypto::Digest32::from(digest))
        .into_string();
    envelope
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

    let alice_jkt = aitp::crypto::AitpVerifyingKey::from_aid(alice.aid())
        .unwrap()
        .to_jwk_thumbprint()
        .unwrap();
    let bob_jkt = aitp::crypto::AitpVerifyingKey::from_aid(bob.aid())
        .unwrap()
        .to_jwk_thumbprint()
        .unwrap();

    let alice_jwt = issuer.mint_aitp_jwt(
        "alice",
        bob.aid().as_str(), // alice presents to bob → aud = bob's AID
        &alice_pop,
        &alice_jkt,
        NOW.0,
    );
    let bob_jwt = issuer.mint_aitp_jwt("bob", alice.aid().as_str(), &bob_pop, &bob_jkt, NOW.0);

    let trust_anchors = vec![aitp::core::RawUrl::from(issuer_url.clone())];
    let alice_cfg = PeerConfig::new(
        &alice,
        &alice_manifest,
        &resolver,
        &aitp::handshake::NoPinnedKeys,
        aitp::tct::RevocationSource::FailOpen,
        NOW,
    )
    .with_trust_anchors(&trust_anchors);
    let bob_cfg = PeerConfig::new(
        &bob,
        &bob_manifest,
        &resolver,
        &aitp::handshake::NoPinnedKeys,
        aitp::tct::RevocationSource::FailOpen,
        NOW,
    )
    .with_trust_anchors(&trust_anchors);

    // ── HELLO ────────────────────────────────────────────────────────
    let hello_mid = Uuid::new_v4();
    let (mut alice_init, mut hello_payload) = Initiator::start(
        &alice_cfg,
        PresentedIdentity::Oidc {
            issuer: issuer_url.clone(),
            subject: "alice".into(),
            proof_jwt: alice_jwt.clone(),
        },
        bob.aid(),
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

    assert_eq!(&alice_holds.tct().claims().iss, bob.aid());
    assert_eq!(&bob_holds.tct().claims().iss, alice.aid());
    assert_eq!(
        alice_holds.tct().claims().grants,
        vec!["demo.echo".to_string()]
    );
    assert_eq!(
        bob_holds.tct().claims().grants,
        vec!["demo.echo".to_string()]
    );

    let _: MutualHelloAckPayload = ack_payload;
    let _: MutualCommitAckPayload = commit_ack_payload;
}

/// Run a full four-message OIDC handshake where both peers present via
/// [`PresentedIdentity::OidcMinter`] — the production path where the JWT
/// is minted *after* the state machine picks the `pop_nonce`. Asserts the
/// callback receives the exact handshake nonce (so no "re-mint with the
/// chosen nonce" dance is needed) and that both peers end up holding the
/// expected TCTs.
///
/// Parameterized by the two signing keys so callers can exercise mixed
/// Ed25519 / P-256 suites: a P-256 agent cannot present a `pinned_key`
/// identity (the Manifest `identity_hint.public_key` is Ed25519-only in
/// v0.1), so OIDC is the path that carries P-256 through a handshake.
fn run_oidc_minter_handshake(alice: &AitpSigningKey, bob: &AitpSigningKey) {
    use std::sync::{Arc, Mutex};

    let issuer = Arc::new(MockOidcIssuer::new(
        "https://idp.example.com",
        "kid-1",
        [0xC0; 32],
    ));
    let issuer_url = issuer.issuer.clone();

    let alice_manifest = manifest_for_oidc(alice, "alice", &issuer_url);
    let bob_manifest = manifest_for_oidc(bob, "bob", &issuer_url);

    let resolver = issuer.as_resolver();

    let alice_jkt = aitp::crypto::AitpVerifyingKey::from_aid(alice.aid())
        .unwrap()
        .to_jwk_thumbprint()
        .unwrap();
    let bob_jkt = aitp::crypto::AitpVerifyingKey::from_aid(bob.aid())
        .unwrap()
        .to_jwk_thumbprint()
        .unwrap();

    let trust_anchors = vec![aitp::core::RawUrl::from(issuer_url.clone())];
    let alice_cfg = PeerConfig::new(
        alice,
        &alice_manifest,
        &resolver,
        &aitp::handshake::NoPinnedKeys,
        aitp::tct::RevocationSource::FailOpen,
        NOW,
    )
    .with_trust_anchors(&trust_anchors);
    let bob_cfg = PeerConfig::new(
        bob,
        &bob_manifest,
        &resolver,
        &aitp::handshake::NoPinnedKeys,
        aitp::tct::RevocationSource::FailOpen,
        NOW,
    )
    .with_trust_anchors(&trust_anchors);

    // ── HELLO (Alice mints via callback) ─────────────────────────────
    // Record the nonce the callback observes so we can assert the state
    // machine forwarded the freshly-generated `pop_nonce` verbatim.
    let alice_seen = Arc::new(Mutex::new(None::<String>));
    let alice_hello_minter = {
        let issuer = Arc::clone(&issuer);
        let bob_aid = bob.aid().as_str().to_string();
        let alice_jkt = alice_jkt.clone();
        let seen = Arc::clone(&alice_seen);
        Box::new(move |nonce: &str| {
            *seen.lock().unwrap() = Some(nonce.to_string());
            Ok(issuer.mint_aitp_jwt("alice", &bob_aid, nonce, &alice_jkt, NOW.0))
        })
    };
    let hello_mid = Uuid::new_v4();
    let (mut alice_init, hello_payload) = Initiator::start(
        &alice_cfg,
        PresentedIdentity::OidcMinter {
            issuer: issuer_url.clone(),
            subject: "alice".into(),
            mint_jwt: alice_hello_minter,
        },
        bob.aid(),
        &hello_mid,
        NOW,
        vec!["demo.echo".into()],
    )
    .unwrap();
    // The callback saw the real nonce — no re-mint dance needed.
    assert_eq!(
        alice_seen.lock().unwrap().as_deref(),
        Some(hello_payload.pop_nonce.as_str())
    );
    let hello_envelope = envelope_with(
        alice,
        MessageType::MutualHello,
        serde_json::to_value(&hello_payload).unwrap(),
        hello_mid,
        NOW,
    );

    // ── HELLO_ACK (Bob mints via callback) ───────────────────────────
    let bob_seen = Arc::new(Mutex::new(None::<String>));
    let bob_ack_minter = {
        let issuer = Arc::clone(&issuer);
        let alice_aid = alice.aid().as_str().to_string();
        let bob_jkt = bob_jkt.clone();
        let seen = Arc::clone(&bob_seen);
        Box::new(move |nonce: &str| {
            *seen.lock().unwrap() = Some(nonce.to_string());
            Ok(issuer.mint_aitp_jwt("bob", &alice_aid, nonce, &bob_jkt, NOW.0))
        })
    };
    let ack_mid = Uuid::new_v4();
    let (mut bob_resp, ack_payload) = Responder::on_hello(
        &hello_envelope,
        &hello_payload,
        PresentedIdentity::OidcMinter {
            issuer: issuer_url.clone(),
            subject: "bob".into(),
            mint_jwt: bob_ack_minter,
        },
        &ack_mid,
        NOW,
        &bob_cfg,
        vec!["demo.echo".into()],
    )
    .unwrap();
    assert_eq!(
        bob_seen.lock().unwrap().as_deref(),
        Some(ack_payload.pop_nonce.as_str())
    );
    let ack_envelope = envelope_with(
        bob,
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
        alice,
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
        bob,
        MessageType::MutualCommitAck,
        serde_json::to_value(&commit_ack_payload).unwrap(),
        Uuid::new_v4(),
        NOW,
    );
    let alice_holds = alice_init
        .on_commit_ack(&commit_ack_envelope, &commit_ack_payload, &alice_cfg)
        .unwrap();

    assert_eq!(&alice_holds.tct().claims().iss, bob.aid());
    assert_eq!(&bob_holds.tct().claims().iss, alice.aid());
    assert_eq!(
        alice_holds.tct().claims().grants,
        vec!["demo.echo".to_string()]
    );
    assert_eq!(
        bob_holds.tct().claims().grants,
        vec!["demo.echo".to_string()]
    );

    let _: MutualCommitAckPayload = commit_ack_payload;
}

/// Baseline: both peers Ed25519, presenting via the minter callback.
#[test]
fn oidc_minter_handshake_ed25519_both() {
    let alice = AitpSigningKey::from_seed(&[0xA1; 32]);
    let bob = AitpSigningKey::from_seed(&[0xB2; 32]);
    run_oidc_minter_handshake(&alice, &bob);
}

/// P-256 initiator ↔ Ed25519 responder. Exercises P-256 envelope signing
/// on the HELLO/COMMIT and P-256 AID verification on the responder, all
/// through the OIDC identity path (pinned-key is Ed25519-only in v0.1).
#[test]
fn oidc_minter_handshake_p256_initiator() {
    let alice = AitpSigningKey::from_p256_seed(&[0xA1; 32]).unwrap();
    let bob = AitpSigningKey::from_seed(&[0xB2; 32]);
    assert!(alice.aid().as_str().starts_with("aid:pubkey:p256:"));
    run_oidc_minter_handshake(&alice, &bob);
}

/// Ed25519 initiator ↔ P-256 responder — the reverse direction, so a
/// P-256 key signs the HELLO_ACK/COMMIT_ACK and the initiator verifies a
/// P-256 AID.
#[test]
fn oidc_minter_handshake_p256_responder() {
    let alice = AitpSigningKey::from_seed(&[0xA1; 32]);
    let bob = AitpSigningKey::from_p256_seed(&[0xB2; 32]).unwrap();
    assert!(bob.aid().as_str().starts_with("aid:pubkey:p256:"));
    run_oidc_minter_handshake(&alice, &bob);
}
