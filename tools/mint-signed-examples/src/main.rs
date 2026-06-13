//! Mint cryptographically valid AITP signed examples from the spec's
//! pinned known-answer keypairs.
//!
//! Output goes to `<base>/signed-examples/{manifest,tct,grant-voucher,
//! delegation,revocation}/...`. Default base is the sibling spec repo
//! at `../agentidentitytrustprotocol/schemas/conformance/known-answer/`.
//! Override with `AITP_SPEC_KAT_DIR=<path>`.
//!
//! Each output file carries a top-level `_kat_input` companion object
//! per `signed-examples/README.md` so a re-minter can recover the
//! exact byte sequence without out-of-band knowledge; the JWS artifact
//! files additionally carry a `decoded_claims` companion for human
//! review. Re-running this tool against the v0.2 vectors MUST
//! reproduce every file byte-for-byte.
//!
//! Closes BLOCKED-SPEC-EXAMPLE (agentidentitytrustprotocol#5).

use aitp_core::{base64url, Aid, Timestamp, PROTOCOL_VERSION};
use aitp_crypto::{jws, AitpSigningKey};
use aitp_delegation::{DelegationBuilder, DelegationClaims};
use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder, ManifestEnvelope};
use aitp_tct::{
    sign_revocation_list, GrantVoucherClaims, IssuedTct, RevocationEntry, RevocationList,
    TctBuilder,
};
use serde_json::json;
use sha2::{Digest, Sha256};
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

/// JTI of the single-grant TCT KAT (`tct/kat-keypair-001-issues-002`).
const FIXED_TCT_JTI: &str = "550e8400-e29b-41d4-a716-446655440000";
/// JTI of the two-grant companion TCT whose voucher is the
/// `grant-voucher/kat-voucher-001` artifact (and the delegation root).
const FIXED_VOUCHER_SRC_JTI: &str = "550e8400-e29b-41d4-a716-446655440001";
const FIXED_REVOKED_JTI: &str = "550e8400-e29b-41d4-a716-446655440099";

/// Pinned 16-byte PoP challenge of the manifest KAT (22-char
/// base64url). `ManifestBuilder` draws a random challenge, so the
/// minter overwrites it with this value and re-signs to keep the
/// vector byte-stable.
const FIXED_MANIFEST_POP_CHALLENGE: &str = "DtcTFXEOpmcBtVhduQuJDQ";

/// Grants of the two-grant companion TCT, in the pinned vector order.
const VOUCHER_GRANTS: [&str; 2] = ["macp.mode.respond.v1", "macp.mode.task.v1"];

/// Shared `$comment` tail about the byte-stability minting conventions.
const JWS_CONVENTIONS: &str = "Protected header is exactly {\"alg\":\"EdDSA\",\"typ\":\"<typ>\"} \
     in that member order; payload bytes are the RFC 8785 (JCS) canonical form of the claims \
     object — fixed here only so re-mints are byte-stable; verifiers operate on the transmitted \
     bytes and never re-serialize (RFC-AITP-0001 §5.4.5).";

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
    let mut manifest = ManifestBuilder::new(&key)
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

    // Pin the PoP challenge (the builder draws a random one) and
    // re-sign, mirroring the builder's own conventions:
    //  - PoP signature over `sha256(base64url_decode(challenge))`
    //    (RFC-AITP-0001 §5.4.2 / RFC-AITP-0003 §3);
    //  - manifest signature over `sha256(JCS(manifest sans signature))`.
    let challenge_bytes = base64url::decode_strict_exact::<16>(FIXED_MANIFEST_POP_CHALLENGE)
        .expect("pinned challenge decodes to 16 bytes");
    manifest.proof_of_possession = aitp_manifest::ManifestPop {
        challenge: FIXED_MANIFEST_POP_CHALLENGE.into(),
        signature: key.sign(&Sha256::digest(challenge_bytes)).into_string(),
    };
    let mut unsigned = serde_json::to_value(&manifest).expect("manifest to value");
    unsigned.as_object_mut().unwrap().remove("signature");
    let canonical = aitp_core::jcs::canonicalize(&unsigned).expect("canonicalize manifest");
    manifest.signature = key.sign(&Sha256::digest(&canonical)).into_string();

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
    let issued = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["macp.mode.task.v1"])
        .ttl_secs(TCT_TTL)
        .subject_pubkey(subject.verifying_key())
        .issued_at(Timestamp(FIXED_NOW))
        .jti(Uuid::parse_str(FIXED_TCT_JTI).unwrap())
        .build()
        .expect("tct");
    write_pretty(
        output_root().join("tct/kat-keypair-001-issues-002.json"),
        json!({
            "_kat_input": {
                "$comment": format!(
                    "Real Ed25519-signed compact JWS TCT (RFC-AITP-0005). {JWS_CONVENTIONS} \
                     Any off-the-shelf JOSE library MUST verify this token given the issuer \
                     public key."
                ),
                "issuer_seed_id": "kat-keypair-001",
                "subject_seed_id": "kat-keypair-002",
                "typ": jws::TYP_TCT,
                "jti": FIXED_TCT_JTI,
                "iat": FIXED_NOW,
                "ttl_secs": TCT_TTL,
                "grants": ["macp.mode.task.v1"],
            },
            "tct_token": issued.token,
            "decoded_claims": issued.claims,
        }),
    );
}

/// Mint the two-grant companion TCT (jti …440001) whose voucher is both
/// the `grant-voucher/kat-voucher-001` artifact and the root of the
/// delegation KAT.
fn mint_companion_tct() -> IssuedTct {
    let issuer = key_from_hex(KAT_001_SEED_HEX);
    let subject = key_from_hex(KAT_002_SEED_HEX);
    TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(VOUCHER_GRANTS)
        .ttl_secs(TCT_TTL)
        .subject_pubkey(subject.verifying_key())
        .issued_at(Timestamp(FIXED_NOW))
        .jti(Uuid::parse_str(FIXED_VOUCHER_SRC_JTI).unwrap())
        .build()
        .expect("companion tct")
}

fn mint_grant_voucher() -> String {
    let voucher = mint_companion_tct().voucher.expect("voucher minted");
    let payload = jws::decode_payload_unverified(&voucher).expect("voucher payload");
    let claims: GrantVoucherClaims = serde_json::from_slice(&payload).expect("voucher claims");
    write_pretty(
        output_root().join("grant-voucher/kat-voucher-001.json"),
        json!({
            "_kat_input": {
                "$comment": format!(
                    "Real Ed25519-signed grant voucher (RFC-AITP-0005 §8). {JWS_CONVENTIONS} \
                     Companion of a two-grant TCT (jti ...440001) so the delegation KAT can \
                     delegate a strict subset."
                ),
                "issuer_seed_id": "kat-keypair-001",
                "subject_seed_id": "kat-keypair-002",
                "typ": jws::TYP_GRANT_VOUCHER,
                "src_jti": FIXED_VOUCHER_SRC_JTI,
                "iat": FIXED_NOW,
                "ttl_secs": TCT_TTL,
                "grants": VOUCHER_GRANTS,
            },
            "voucher_token": voucher,
            "decoded_claims": claims,
        }),
    );
    voucher
}

fn mint_delegation(voucher: &str) {
    // A=001 issued B=002 the two-grant TCT + voucher; B delegates a
    // strict subset to C=003, embedding A's voucher verbatim.
    let bob = key_from_hex(KAT_002_SEED_HEX);
    let carol = key_from_hex(KAT_003_SEED_HEX);

    let delegation = DelegationBuilder::new(&bob, voucher)
        .expect("voucher entitles B to delegate")
        .delegatee(carol.aid().clone())
        .scope(["macp.mode.task.v1"])
        .ttl_secs(DELEGATION_TTL)
        .now(Timestamp(FIXED_NOW))
        .build()
        .expect("delegation");
    let payload = jws::decode_payload_unverified(&delegation).expect("delegation payload");
    let claims: DelegationClaims = serde_json::from_slice(&payload).expect("delegation claims");
    write_pretty(
        output_root().join("delegation/single-hop-001-002-003.json"),
        json!({
            "_kat_input": {
                "$comment": format!(
                    "Real single-hop delegation compact JWS (RFC-AITP-0006): B delegates a \
                     strict subset to C, audience A, embedding kat-voucher-001 verbatim. \
                     {JWS_CONVENTIONS}"
                ),
                "delegator_seed_id": "kat-keypair-002",
                "delegatee_seed_id": "kat-keypair-003",
                "typ": jws::TYP_DELEGATION,
                "voucher_ref": "grant-voucher/kat-voucher-001.json",
                "iat": FIXED_NOW,
                "ttl_secs": DELEGATION_TTL,
                "scope": ["macp.mode.task.v1"],
            },
            "delegation_token": delegation,
            "decoded_claims": claims,
        }),
    );
}

fn mint_revocation_snapshot() {
    let issuer = key_from_hex(KAT_001_SEED_HEX);
    let body = RevocationList {
        version: PROTOCOL_VERSION.into(),
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
    let voucher = mint_grant_voucher();
    mint_delegation(&voucher);
    mint_revocation_snapshot();
    println!("done.");
}
