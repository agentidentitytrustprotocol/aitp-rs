//! OIDC handshake demo with an in-process mock IdP.
//!
//! Runs a complete Mutual Handshake where both peers present OIDC
//! identities (RFC-AITP-0002 §2). No external IdP, no network — a
//! self-contained `MockOidcIssuer` holds a fixed Ed25519 key, mints
//! JWTs with the right claims, and exposes its key via a
//! [`JwksResolver`] so the handshake's OIDC verifier finds it.
//!
//! This is a runnable counterpart to the `oidc_handshake.rs` test in
//! `aitp-handshake`; it demonstrates the end-to-end OIDC code path
//! without needing a real IdP and is referenced from the README.

use aitp::core::{AitpEnvelope, MessageType, Sender, Timestamp};
use aitp::crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp::handshake::{
    Initiator, JwkPublicKey, JwksResolver, PeerConfig, PresentedIdentity, ResolveError, Responder,
};
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signer, SigningKey};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::json;
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

fn main() {
    println!("aitp-rs OIDC demo — in-process mock IdP, full Mutual Handshake");
    println!();

    // ── Mock IdP ────────────────────────────────────────────────────────
    let issuer = MockOidcIssuer::new("https://idp.example.com", "kid-demo", [0xC0; 32]);
    let issuer_url = issuer.issuer.clone();
    println!("issuer: {} kid={}", issuer_url, issuer.kid);

    // ── Two peers, OIDC-only Manifests ─────────────────────────────────
    let alice = AitpSigningKey::from_seed(&[0xA1; 32]);
    let bob = AitpSigningKey::from_seed(&[0xB2; 32]);
    let alice_manifest = oidc_manifest(&alice, "alice", &issuer_url);
    let bob_manifest = oidc_manifest(&bob, "bob", &issuer_url);
    println!("alice AID: {}", alice.aid());
    println!("bob   AID: {}", bob.aid());
    println!();

    // ── Pre-compute pubkey thumbprints for the JWT cnf.jkt claim ────────
    let alice_jkt = AitpVerifyingKey::from_aid(alice.aid())
        .unwrap()
        .to_jwk_thumbprint();
    let bob_jkt = AitpVerifyingKey::from_aid(bob.aid())
        .unwrap()
        .to_jwk_thumbprint();
    println!("alice cnf.jkt: {alice_jkt}");
    println!("bob   cnf.jkt: {bob_jkt}");
    println!();

    // ── Drive the handshake ────────────────────────────────────────────
    let resolver = issuer.as_resolver();
    let trust_anchors = vec![aitp::core::RawUrl::from(issuer_url.clone())];
    let alice_cfg = PeerConfig {
        signing_key: &alice,
        manifest: &alice_manifest,
        trust_anchors: &trust_anchors,
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: NOW,
    };
    let bob_cfg = PeerConfig {
        signing_key: &bob,
        manifest: &bob_manifest,
        trust_anchors: &trust_anchors,
        jwks_resolver: &resolver,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: NOW,
    };

    // HELLO (Alice → Bob). Initiator::start picks its own pop_nonce;
    // we mint the JWT *after* learning the nonce and overwrite the
    // descriptor's `proof` field, then sign the envelope. RFC-AITP-0002
    // §2.2 requires the JWT's `nonce` claim to equal `pop_nonce`.
    let hello_mid = Uuid::new_v4();
    let (mut alice_init, mut hello_payload) = Initiator::start(
        &alice_cfg,
        PresentedIdentity::Oidc {
            issuer: issuer_url.clone(),
            subject: "alice".into(),
            // Placeholder JWT — replaced below with one bound to the
            // nonce that `Initiator::start` actually picked.
            proof_jwt: String::new(),
        },
        bob.aid(),
        &hello_mid,
        NOW,
        vec!["demo.echo".into()],
    )
    .expect("alice starts");
    hello_payload.identity.proof = issuer.mint_aitp_jwt(
        "alice",
        bob.aid().as_str(),
        &hello_payload.pop_nonce,
        &alice_jkt,
        NOW.0,
    );
    let hello_envelope = envelope_with(
        &alice,
        MessageType::MutualHello,
        serde_json::to_value(&hello_payload).unwrap(),
        hello_mid,
        NOW,
    );
    println!(
        "→ MUTUAL_HELLO sent (pop_nonce={})",
        hello_payload.pop_nonce
    );

    // HELLO_ACK (Bob → Alice). Same nonce-binding pattern.
    let ack_mid = Uuid::new_v4();
    let (mut bob_resp, mut ack_payload) = Responder::on_hello(
        &hello_envelope,
        &hello_payload,
        PresentedIdentity::Oidc {
            issuer: issuer_url.clone(),
            subject: "bob".into(),
            proof_jwt: String::new(),
        },
        &ack_mid,
        NOW,
        &bob_cfg,
        vec!["demo.echo".into()],
    )
    .expect("bob acks hello");
    ack_payload.identity.proof = issuer.mint_aitp_jwt(
        "bob",
        alice.aid().as_str(),
        &ack_payload.pop_nonce,
        &bob_jkt,
        NOW.0,
    );
    let ack_envelope = envelope_with(
        &bob,
        MessageType::MutualHelloAck,
        serde_json::to_value(&ack_payload).unwrap(),
        ack_mid,
        NOW,
    );
    println!(
        "← MUTUAL_HELLO_ACK received (pop_nonce={})",
        ack_payload.pop_nonce
    );

    // COMMIT (Alice → Bob)
    let commit_payload = alice_init
        .on_hello_ack(&ack_envelope, &ack_payload, &alice_cfg)
        .expect("alice commits");
    let commit_mid = Uuid::new_v4();
    let commit_envelope = envelope_with(
        &alice,
        MessageType::MutualCommit,
        serde_json::to_value(&commit_payload).unwrap(),
        commit_mid,
        NOW,
    );
    println!("→ MUTUAL_COMMIT sent");

    // COMMIT_ACK (Bob → Alice)
    let (commit_ack_payload, bob_holds_tct) = bob_resp
        .on_commit(&commit_envelope, &commit_payload, &bob_cfg)
        .expect("bob acks commit");
    let commit_ack_mid = Uuid::new_v4();
    let commit_ack_envelope = envelope_with(
        &bob,
        MessageType::MutualCommitAck,
        serde_json::to_value(&commit_ack_payload).unwrap(),
        commit_ack_mid,
        NOW,
    );
    println!("← MUTUAL_COMMIT_ACK received");

    let alice_holds_tct = alice_init
        .on_commit_ack(&commit_ack_envelope, &commit_ack_payload, &alice_cfg)
        .expect("alice finalizes");

    println!();
    println!("handshake complete:");
    println!(
        "  alice holds TCT issued_by={} grants={:?}",
        alice_holds_tct.issuer, alice_holds_tct.grants
    );
    println!(
        "  bob   holds TCT issued_by={} grants={:?}",
        bob_holds_tct.issuer, bob_holds_tct.grants
    );
}

fn oidc_manifest(key: &AitpSigningKey, name: &str, issuer: &url::Url) -> Manifest {
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
            issuer: Some(aitp::core::RawUrl::from(issuer.clone())),
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
    let digest = aitp::core::envelope_signing_digest(&mid, ts, key.aid(), &payload).unwrap();
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

// ── In-process mock OIDC issuer ────────────────────────────────────────
//
// Mirrors the test fixture in `aitp-handshake/tests/fixtures/mock_oidc.rs`,
// duplicated here because the test fixture is not exposed as a public
// helper crate (and we don't want a bin to depend on dev-deps of an
// internal crate). The implementation is intentionally minimal: one
// fixed Ed25519 key, hand-built compact JWTs, a single-key resolver.

struct MockOidcIssuer {
    issuer: url::Url,
    kid: String,
    signing: SigningKey,
}

impl MockOidcIssuer {
    fn new(issuer: &str, kid: &str, seed: [u8; 32]) -> Self {
        Self {
            issuer: issuer.parse().unwrap(),
            kid: kid.to_string(),
            signing: SigningKey::from_bytes(&seed),
        }
    }

    fn pubkey_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    fn mint_jwt(&self, claims: serde_json::Value) -> String {
        let header = json!({"alg": "EdDSA", "typ": "JWT", "kid": self.kid});
        let header_b64 =
            Base64UrlUnpadded::encode_string(serde_json::to_string(&header).unwrap().as_bytes());
        let payload_b64 =
            Base64UrlUnpadded::encode_string(serde_json::to_string(&claims).unwrap().as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = self.signing.sign(signing_input.as_bytes());
        let sig_b64 = Base64UrlUnpadded::encode_string(&sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }

    fn mint_aitp_jwt(
        &self,
        subject: &str,
        audience: &str,
        nonce: &str,
        cnf_jkt: &str,
        now_unix: i64,
    ) -> String {
        self.mint_jwt(json!({
            "iss": self.issuer.as_str(),
            "sub": subject,
            "aud": audience,
            "iat": now_unix,
            "exp": now_unix + 3600,
            "nonce": nonce,
            "cnf": { "jkt": cnf_jkt }
        }))
    }

    fn as_jwk(&self) -> JwkPublicKey {
        JwkPublicKey {
            kid: Some(self.kid.clone()),
            alg: Algorithm::EdDSA,
            key: DecodingKey::from_ed_der(&self.pubkey_bytes()),
        }
    }

    fn as_resolver(&self) -> MockJwksResolver {
        MockJwksResolver {
            issuer: self.issuer.clone(),
            keys: vec![self.as_jwk()],
        }
    }
}

struct MockJwksResolver {
    issuer: url::Url,
    keys: Vec<JwkPublicKey>,
}

impl JwksResolver for MockJwksResolver {
    fn resolve(&self, issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        if issuer == &self.issuer {
            Ok(self.keys.clone())
        } else {
            Ok(vec![])
        }
    }
}
