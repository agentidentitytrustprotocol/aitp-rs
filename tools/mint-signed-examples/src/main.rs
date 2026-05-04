//! Mint cryptographically valid AITP signed examples from the spec's
//! pinned known-answer keypairs.
//!
//! Output goes to `<base>/signed-examples/{manifest,tct,delegation,
//! revocation}/...`. Default base is the sibling spec repo at
//! `../agentidentitytrustprotocol/schemas/conformance/known-answer/`.
//! Override with `AITP_SPEC_KAT_DIR=<path>`.
//!
//! Each output file carries a top-level `_kat_input` companion object
//! per `signed-examples/README.md` so a re-minter can recover the
//! exact byte sequence without out-of-band knowledge.
//!
//! Closes BLOCKED-SPEC-EXAMPLE (agentidentitytrustprotocol#5).

use aitp_core::{base64url, Aid, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_delegation::{DelegationBuilder, DelegationEnvelope};
use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder, ManifestEnvelope};
use aitp_tct::{sign_revocation_list, RevocationEntry, RevocationList, TctBuilder, TctEnvelope};
use serde_json::json;
use std::path::PathBuf;
use uuid::Uuid;

// ── Pinned KAT inputs ────────────────────────────────────────────────────

const KAT_001_SEED_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const KAT_002_SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const KAT_003_SEED_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

const FIXED_NOW: i64 = 1_711_900_000;
const MANIFEST_TTL: i64 = 86_400; // 1 day
const TCT_TTL: i64 = 3_600; // 1 hour
const DELEGATION_TTL: i64 = 1_800; // 30 minutes
const REVOCATION_TTL: i64 = 3_600;

const FIXED_TCT_JTI: &str = "550e8400-e29b-41d4-a716-446655440000";
const FIXED_REVOKED_JTI: &str = "550e8400-e29b-41d4-a716-446655440099";

fn key_from_hex(seed_hex: &str) -> AitpSigningKey {
    let bytes = hex::decode(seed_hex).expect("hex");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    AitpSigningKey::from_seed(&seed)
}

fn output_root() -> PathBuf {
    let base = std::env::var("AITP_SPEC_KAT_DIR").unwrap_or_else(|_| {
        "../agentidentitytrustprotocol/schemas/conformance/known-answer".into()
    });
    PathBuf::from(base).join("signed-examples")
}

fn write_pretty(path: PathBuf, value: serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("mkdir -p");
    }
    let s = serde_json::to_string_pretty(&value).expect("serialize");
    std::fs::write(&path, s + "\n").expect("write");
    println!("wrote {}", path.display());
}

fn mint_manifest() {
    let key = key_from_hex(KAT_001_SEED_HEX);
    let pubkey_b64 = base64url::encode(&key.verifying_key().to_bytes());
    let manifest = ManifestBuilder::new(&key)
        .display_name("kat-keypair-001")
        .handshake_endpoint("https://example.com/aitp/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "kat-keypair-001".into(),
            issuer: None,
            public_key: Some(pubkey_b64),
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .accept_identity_type("pinned_key")
        .offer("macp.mode.task.v1")
        .ttl_secs(MANIFEST_TTL)
        .published_at(Timestamp(FIXED_NOW))
        .build()
        .expect("manifest");
    let env = ManifestEnvelope { manifest };
    write_pretty(
        output_root().join("manifest/kat-keypair-001-manifest.json"),
        json!({
            "_kat_input": {
                "issuer_seed_id": "kat-keypair-001",
                "published_at": FIXED_NOW,
                "ttl_secs": MANIFEST_TTL,
                "identity_type": "pinned_key",
                "offered_capabilities": ["macp.mode.task.v1"],
                "accepted_trust_anchors": ["https://idp.example.com"],
            },
            "manifest": env.manifest,
        }),
    );
}

fn mint_tct() {
    let issuer = key_from_hex(KAT_001_SEED_HEX);
    let subject = key_from_hex(KAT_002_SEED_HEX);
    let tct = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["macp.mode.task.v1"])
        .ttl_secs(TCT_TTL)
        .subject_pubkey(subject.verifying_key())
        .issued_at(Timestamp(FIXED_NOW))
        .jti(Uuid::parse_str(FIXED_TCT_JTI).unwrap())
        .build()
        .expect("tct");
    let env = TctEnvelope { tct };
    write_pretty(
        output_root().join("tct/kat-keypair-001-issues-002.json"),
        json!({
            "_kat_input": {
                "issuer_seed_id": "kat-keypair-001",
                "subject_seed_id": "kat-keypair-002",
                "jti": FIXED_TCT_JTI,
                "issued_at": FIXED_NOW,
                "ttl_secs": TCT_TTL,
                "grants": ["macp.mode.task.v1"],
            },
            "tct": env.tct,
        }),
    );
}

fn mint_delegation() {
    // A=001 issues TCT to B=002; B delegates a subset to C=003.
    let alice = key_from_hex(KAT_001_SEED_HEX);
    let bob = key_from_hex(KAT_002_SEED_HEX);
    let carol = key_from_hex(KAT_003_SEED_HEX);
    let source_tct = TctBuilder::new(&alice)
        .subject(bob.aid().clone())
        .audience(bob.aid().clone())
        .grants(["macp.mode.task.v1", "macp.mode.respond.v1"])
        .ttl_secs(TCT_TTL)
        .subject_pubkey(bob.verifying_key())
        .issued_at(Timestamp(FIXED_NOW))
        .jti(Uuid::parse_str(FIXED_TCT_JTI).unwrap())
        .build()
        .expect("source tct");

    let delegation = DelegationBuilder::new(&bob, &source_tct)
        .delegatee(carol.aid().clone())
        .delegatee_pubkey(carol.verifying_key())
        .scope(["macp.mode.task.v1"])
        .ttl_secs(DELEGATION_TTL)
        .now(Timestamp(FIXED_NOW))
        .build()
        .expect("delegation");
    let env = DelegationEnvelope { delegation };
    write_pretty(
        output_root().join("delegation/single-hop-001-002-003.json"),
        json!({
            "_kat_input": {
                "delegator_seed_id": "kat-keypair-002",
                "delegatee_seed_id": "kat-keypair-003",
                "source_tct": {
                    "issuer_seed_id": "kat-keypair-001",
                    "jti": FIXED_TCT_JTI,
                    "issued_at": FIXED_NOW,
                    "ttl_secs": TCT_TTL,
                    "grants": ["macp.mode.task.v1", "macp.mode.respond.v1"],
                },
                "issued_at": FIXED_NOW,
                "ttl_secs": DELEGATION_TTL,
                "scope": ["macp.mode.task.v1"],
            },
            "delegation": env.delegation,
        }),
    );
}

fn mint_revocation_snapshot() {
    let issuer = key_from_hex(KAT_001_SEED_HEX);
    let body = RevocationList {
        version: "aitp/0.1".into(),
        issuer: issuer.aid().clone(),
        published_at: Timestamp(FIXED_NOW),
        expires_at: Timestamp(FIXED_NOW + REVOCATION_TTL),
        entries: vec![RevocationEntry {
            jti: Uuid::parse_str(FIXED_REVOKED_JTI).unwrap(),
            revoked_at: Timestamp(FIXED_NOW + 60),
            reason: Some("key_compromised".into()),
        }],
    };
    let env = sign_revocation_list(body, &issuer).expect("sign revocation");
    write_pretty(
        output_root().join("revocation/kat-keypair-001-snapshot.json"),
        json!({
            "_kat_input": {
                "issuer_seed_id": "kat-keypair-001",
                "published_at": FIXED_NOW,
                "ttl_secs": REVOCATION_TTL,
                "entries": [
                    {"jti": FIXED_REVOKED_JTI, "revoked_at": FIXED_NOW + 60, "reason": "key_compromised"}
                ],
            },
            "revocation_list": env.revocation_list,
            "signature": env.signature,
        }),
    );
}

// Sanity: spec defines two derived AIDs we already validated against
// elsewhere; this binary needs to fail loudly if the seed → AID
// mapping diverges from the spec KAT, since the whole minting
// operation depends on it.
fn assert_kat_aids() {
    let cases = [
        (
            KAT_001_SEED_HEX,
            "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
        ),
        (
            KAT_002_SEED_HEX,
            "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
        ),
        (
            KAT_003_SEED_HEX,
            "aid:pubkey:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU",
        ),
    ];
    for (seed_hex, expected_aid) in cases {
        let key = key_from_hex(seed_hex);
        let actual = key.aid().as_str().to_string();
        assert_eq!(
            actual, expected_aid,
            "seed → AID mismatch for {seed_hex}; spec KAT diverged from implementation"
        );
    }
    let _ = Aid::parse("aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik").expect("aid");
}

fn main() {
    assert_kat_aids();
    println!("minting signed examples into {}", output_root().display());
    mint_manifest();
    mint_tct();
    mint_delegation();
    mint_revocation_snapshot();
    println!("done.");
}
