//! Mint the two JCS-profile artifacts whose signing input changed, and
//! print them to stdout as JSON.
//!
//! This exists for the cross-implementation acceptance job. `aitp-rs`
//! mints here; an **independent** verifier (`aitp-verifier-py`, written
//! from the RFC texts and sharing no code with this workspace) verifies
//! these exact bytes, with no re-minting on either side.
//!
//! Re-minting is the escape hatch that hid the wrapped-vs-inner
//! divergence for a whole release: each stack re-signed under its own
//! convention and then verified its own output, so both passed while their
//! wire formats disagreed. A test that re-mints before verifying cannot
//! detect a signing-input divergence, by construction.
//!
//! Everything is derived from the spec's pinned KAT keypairs under a fixed
//! reference clock, so the output is deterministic and the revocation
//! snapshot is expected to be byte-identical to the spec's committed
//! example — which was minted by the Python reference implementation. That
//! collapses "Rust mints → Python verifies" and "Rust reproduces the
//! reference-minted bytes" into one check.

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_session_bundle::SessionBundleBuilder;
use aitp_tct::{sign_revocation_list, RevocationEntry, RevocationList, TctBuilder};
use uuid::Uuid;

/// kat-keypair-001 (all-zero seed) — the coordinator / snapshot issuer.
const KP_001_SEED: [u8; 32] = [0u8; 32];
/// kat-keypair-002 — the session participant.
const KP_002_SEED: [u8; 32] = [0x11u8; 32];

/// The spec's reference clock for signed examples.
const NOW: i64 = 1_711_900_000;

fn main() {
    let issuer = AitpSigningKey::from_seed(&KP_001_SEED);
    let participant = AitpSigningKey::from_seed(&KP_002_SEED);

    // ── Revocation snapshot ──────────────────────────────────────────
    // Field-for-field the spec's committed
    // signed-examples/revocation/kat-keypair-001-snapshot.json, so the
    // output can be compared byte-for-byte against it.
    let body = RevocationList {
        version: aitp_core::PROTOCOL_VERSION.to_string(),
        issuer: issuer.aid().clone(),
        published_at: Timestamp(NOW),
        expires_at: Timestamp(NOW + 3600),
        entries: vec![RevocationEntry {
            jti: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440099").unwrap(),
            revoked_at: Timestamp(NOW + 60),
            reason: Some("key_compromised".into()),
        }],
    };
    let snapshot = sign_revocation_list(body, &issuer).expect("sign revocation snapshot");

    // ── Session trust bundle ─────────────────────────────────────────
    let tct = TctBuilder::new(&issuer)
        .subject(participant.aid().clone())
        .audience(participant.aid().clone())
        .grants(["session.participate"])
        .ttl_secs(3600)
        .subject_pubkey(participant.verifying_key())
        .issued_at(Timestamp(NOW))
        .build()
        .expect("issue participant TCT")
        .token;

    let bundle = SessionBundleBuilder::new(&issuer)
        .session_id(Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap())
        .issued_at(Timestamp(NOW))
        .participant(participant.aid().clone(), tct)
        .build()
        .expect("build session bundle");

    // Emit the transport-wrapped wire shapes an independent verifier
    // consumes, plus the reference clock it should verify at.
    //
    // The bundle is framed with `signature` as a SIBLING of the wrapper,
    // matching `aitp-session-bundle.schema.json` and the `bundle-001`
    // fixture. RFC-AITP-0010 §3's example instead places it inside the
    // body; the spec is inconsistent here (filed upstream as
    // agentidentitytrustprotocol#23). This is purely envelope framing:
    // the SIGNED BYTES are the body excluding `signature` under either
    // reading, so reframing is not a re-mint. The signature below is the
    // one `bundle_signing_bytes` produced, carried verbatim.
    let mut body = serde_json::to_value(&bundle).expect("bundle serializes");
    let signature = body
        .as_object_mut()
        .expect("bundle is an object")
        .remove("signature")
        .expect("bundle carries a signature");

    let out = serde_json::json!({
        "minted_by": "aitp-rs",
        "now": NOW,
        "expected_issuer": issuer.aid().to_string(),
        "verifier_aid": participant.aid().to_string(),
        "snapshot": { "revocation_list": snapshot.revocation_list, "signature": snapshot.signature },
        "session_bundle": { "session_bundle": body, "signature": signature },
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
