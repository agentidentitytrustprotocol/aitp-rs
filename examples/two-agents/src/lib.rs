//! Shared helpers for the two-agent demo.
//!
//! The demo drives the Mutual Handshake through the high-level
//! [`aitp::facade`] / [`aitp::transport`] APIs, so this module is small:
//! a Manifest builder, a seed expander, and the request-time TCT check
//! the `/echo` capability uses. There is no hand-rolled envelope signing
//! here — the facade ([`aitp::facade::run_initiator_handshake`]) and the
//! server ([`aitp::transport::HandshakeServer`]) own that.

use aitp::core::{Aid, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};

/// Build a pinned-key Manifest for an agent listening on `port`.
///
/// The `handshake_endpoint` deliberately ends in a trailing slash:
/// [`aitp::facade::run_initiator_handshake`] resolves the per-message
/// routes with `endpoint.join("hello")` / `join("commit")`, which only
/// appends (rather than replacing the last path segment) when the base
/// ends in `/`.
pub fn build_demo_manifest(
    key: &AitpSigningKey,
    display_name: &str,
    port: u16,
    offered: &[&str],
) -> Manifest {
    let pubkey_b64 = aitp::core::base64url::encode(&key.verifying_key().to_bytes());
    let endpoint = format!("http://localhost:{port}/aitp/handshake/");
    let mut builder = ManifestBuilder::new(key)
        .display_name(display_name)
        .handshake_endpoint(endpoint.parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: display_name.into(),
            issuer: None,
            public_key: Some(pubkey_b64),
        })
        .accept_identity_type("pinned_key")
        .ttl_secs(3600);
    for cap in offered {
        builder = builder.offer(*cap);
    }
    builder.build().expect("demo manifest builds")
}

/// Verify a TCT compact JWS presented to the `/echo` capability.
///
/// The TCT was issued by this server during the handshake, so:
/// - its issuer MUST be `server_aid` (we issued it — the verifying key
///   and JWS `alg` are both pinned from that AID),
/// - it MUST still verify and be unexpired,
/// - it MUST carry the `demo.echo` grant.
///
/// On success returns the caller's AID (the TCT subject) for the echo
/// reply.
pub fn verify_echo_tct(token: &str, server_aid: &Aid) -> Result<Aid, String> {
    use aitp::crypto::jws;
    use aitp::tct::{verify_tct, TctClaims, TctVerifyContext};

    // Peek (unverified) at the claims to learn the presented subject;
    // `verify_tct` re-establishes everything cryptographically below.
    let payload = jws::decode_payload_unverified(token).map_err(|e| e.to_string())?;
    let peeked: TctClaims =
        serde_json::from_slice(&payload).map_err(|e| format!("malformed TCT claims: {e}"))?;
    if &peeked.iss != server_aid {
        return Err("TCT not issued by this server".into());
    }
    // Holder receipt: subject == audience == caller. Demo verifier —
    // no revocation source or issuer Manifest is resolved here.
    let ctx = TctVerifyContext::permissive_at(&peeked.sub, server_aid, Timestamp::now());
    let verified = verify_tct(token, &ctx).map_err(|e| e.to_string())?;
    if !verified.claims.grants.iter().any(|g| g == "demo.echo") {
        return Err("demo.echo not granted".into());
    }
    Ok(verified.claims.sub)
}

/// Expand a short CLI seed string into a deterministic 32-byte key seed.
/// Demo-only: real deployments load a key from a KMS / file, never from
/// a repeating ASCII pattern.
pub fn expand_seed(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = bytes[i % bytes.len()];
    }
    out
}
