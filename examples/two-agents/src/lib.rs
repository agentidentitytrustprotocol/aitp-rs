//! Shared helpers for the two-agent demo.

use aitp::core::{Aid, AitpEnvelope, MessageType, Sender, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use aitp::tct::Tct;
use uuid::Uuid;

/// Build a pinned-key Manifest for an agent listening on `port`.
pub fn build_demo_manifest(
    key: &AitpSigningKey,
    display_name: &str,
    port: u16,
    offered: &[&str],
    required: &[&str],
) -> Manifest {
    let pubkey_b64 = aitp::core::base64url::encode(&key.verifying_key().to_bytes());
    let endpoint = format!("http://localhost:{}/aitp/handshake", port);
    let mut builder = ManifestBuilder::new(key)
        .display_name(display_name)
        .handshake_endpoint(endpoint.parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: display_name.into(),
            issuer: None,
            public_key: Some(pubkey_b64),
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .accept_identity_type("pinned_key")
        .ttl_secs(3600);
    for cap in offered {
        builder = builder.offer(*cap);
    }
    for cap in required {
        builder = builder.require(*cap);
    }
    builder.build().expect("demo manifest builds")
}

/// Sign and wrap a payload as an envelope using a caller-provided
/// `message_id` and `timestamp`.
///
/// Pinned-key identity proofs inside `payload.identity` are signed over
/// the envelope's `message_id` and `timestamp`. Callers MUST therefore
/// use the SAME `message_id` and `timestamp` here that they passed to
/// `Initiator::start` / `Responder::on_hello` to construct the identity
/// proof. Otherwise the receiving peer reads `envelope.message_id` /
/// `envelope.timestamp` (different values) and verification fails.
pub fn sign_envelope_with(
    key: &AitpSigningKey,
    message_type: MessageType,
    payload: serde_json::Value,
    message_id: Uuid,
    timestamp: Timestamp,
) -> AitpEnvelope {
    let digest = aitp::core::envelope_signing_digest(&message_id, timestamp, key.aid(), &payload)
        .expect("jcs canonicalises payload");
    let signature = key.sign(&digest).into_string();
    AitpEnvelope {
        version: "aitp/0.1".into(),
        message_type,
        message_id,
        timestamp,
        sender: Sender {
            agent_id: key.aid().clone(),
        },
        payload,
        signature,
    }
}

/// Convenience: build and sign an envelope with a fresh `message_id` /
/// `timestamp`. **Do not use** for envelopes that carry a pinned-key
/// identity proof in the payload — use [`sign_envelope_with`] and pass
/// the same `(message_id, timestamp)` that built the proof.
pub fn sign_envelope(
    key: &AitpSigningKey,
    message_type: MessageType,
    payload: serde_json::Value,
) -> AitpEnvelope {
    sign_envelope_with(key, message_type, payload, Uuid::new_v4(), Timestamp::now())
}

/// Verify a TCT presented by a peer to authorize a capability.
pub fn verify_presented_tct(
    tct: &Tct,
    issuer_aid: &Aid,
    expected_audience: &Aid,
) -> Result<(), String> {
    use aitp::tct::{verify_tct, TctVerifyContext};
    let issuer_pk = aitp::crypto::AitpVerifyingKey::from_aid(issuer_aid)
        .map_err(|e| format!("bad issuer aid: {e}"))?;
    let ctx = TctVerifyContext {
        expected_audience,
        issuer_pubkey: &issuer_pk,
        now: Timestamp::now(),
        revocation_check: None,
    };
    verify_tct(tct, &ctx).map_err(|e| format!("{e}"))?;
    Ok(())
}
