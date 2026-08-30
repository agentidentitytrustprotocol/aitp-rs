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

use aitp_core::{AidAlgorithm, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp_session_bundle::SessionBundleBuilder;
use aitp_tct::{sign_revocation_list, RevocationEntry, RevocationList, TctBuilder};
use uuid::Uuid;

/// kat-keypair-001 (all-zero seed) — the coordinator / snapshot issuer.
const KP_001_SEED: [u8; 32] = [0u8; 32];
/// kat-keypair-002 — the session participant.
const KP_002_SEED: [u8; 32] = [0x11u8; 32];

/// The spec's reference clock for signed examples.
const NOW: i64 = 1_711_900_000;

// ── OIDC identity binding (RFC-AITP-0002) ────────────────────────────
//
// This closes a real gap: the OIDC identity-binding path had zero
// cross-implementation coverage of any kind before this vector existed,
// discovered while investigating a fail-open bug in `aitp-verifier-py`'s
// OIDC verifier (fixed in agentidentitytrustprotocol/aitp-verifier-py#14
// — a JWT whose issuer key could not be resolved used to verify
// successfully instead of failing closed). We mint the minimal
// identity-descriptor + envelope shape `verify_oidc`'s own unit tests
// build (see `crates/aitp-handshake/src/identity_oidc.rs` and
// `crates/aitp-handshake/tests/fixtures/mock_oidc.rs`), not a full
// `MUTUAL_HELLO` envelope (Manifest + PoP + envelope signature) — that
// is enough to reach `aitp_verifier.identity.verify_identity` directly.
//
// EdDSA and ES256 only. `aitp-rs` has no RSA *signing* capability: PR
// #122 (merged) deliberately moved `aitp-handshake` to `ring` for RSA
// verification only, and adding an RSA signer solely to mint one test
// vector is out of scope for a test/CI-only change. RS256 stays covered
// by `aitp-verifier-py`'s own unit tests (`tests/test_identity_oidc.py`,
// added in the same PR), just not cross-checked here.
const OIDC_ISSUER_URL: &str = "https://issuer.aitp-xcheck.example";
const OIDC_SUBJECT: &str = "agent-under-test";
const OIDC_NONCE: &str = "xcheck-oidc-pop-nonce";
/// The peer presenting the OIDC identity binding binds its own AITP key
/// via the JWT's `cnf.jkt` claim — this is that key. It never signs
/// anything; only its AID (and that AID's JWK thumbprint) is used.
const OIDC_SENDER_SEED: [u8; 32] = [0x33u8; 32];
/// The relying party verifying the binding — only its AID is used, as
/// the JWT's `aud` claim and `verify_identity`'s `self_aid` parameter.
const OIDC_VERIFIER_SEED: [u8; 32] = [0x44u8; 32];
/// OIDC issuer signing keys, one per algorithm under cross-check.
const OIDC_ISSUER_ED25519_SEED: [u8; 32] = [0x55u8; 32];
const OIDC_ISSUER_P256_SEED: [u8; 32] = [0x66u8; 32];

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
        extensions: None,
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
    // The bundle is emitted in its natural shape: `signature` stays a
    // member of the inner body (RFC-AITP-0010 §3; spec commit
    // `45b5ef978e13` corrected the schema and the `bundle-*` fixtures to
    // match). Earlier revisions of this tool reframed `signature` as a
    // sibling of the `{"session_bundle": ...}` wrapper to accommodate
    // `aitp-verifier-py`'s older reading (the two implementations' signed
    // bytes always agreed — this was purely wire-shape accommodation, not
    // a re-mint). That accommodation is now obsolete: both sides read
    // `signature` from inside the body, so no reframing is needed.
    let body = serde_json::to_value(&bundle).expect("bundle serializes");

    // ── OIDC identity binding ────────────────────────────────────────
    let oidc_sender = AitpSigningKey::from_seed(&OIDC_SENDER_SEED);
    let oidc_verifier = AitpSigningKey::from_seed(&OIDC_VERIFIER_SEED);
    let oidc_issuer_eddsa = AitpSigningKey::from_seed(&OIDC_ISSUER_ED25519_SEED);
    let oidc_issuer_es256 =
        AitpSigningKey::from_p256_seed(&OIDC_ISSUER_P256_SEED).expect("valid p256 seed");

    let oidc_eddsa = mint_oidc_vector(&oidc_issuer_eddsa, &oidc_sender, &oidc_verifier);
    let oidc_es256 = mint_oidc_vector(&oidc_issuer_es256, &oidc_sender, &oidc_verifier);

    let out = serde_json::json!({
        "minted_by": "aitp-rs",
        "now": NOW,
        "expected_issuer": issuer.aid().to_string(),
        "verifier_aid": participant.aid().to_string(),
        "snapshot": { "revocation_list": snapshot.revocation_list, "signature": snapshot.signature },
        "session_bundle": { "session_bundle": body },
        "oidc_identity": {
            "now": NOW,
            "eddsa": oidc_eddsa,
            "es256": oidc_es256,
        },
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

/// Mint one OIDC identity-binding cross-check vector: an issuer-signed
/// JWT plus everything `aitp_verifier.identity.verify_identity` needs to
/// check it (the identity descriptor, the minimal envelope shape it
/// reads `sender.agent_id` / `payload.pop_nonce` from, the verifier's
/// own AID, and the issuer's public key as a JWK).
fn mint_oidc_vector(
    issuer_key: &AitpSigningKey,
    sender: &AitpSigningKey,
    verifier: &AitpSigningKey,
) -> serde_json::Value {
    let claims = serde_json::json!({
        "iss": OIDC_ISSUER_URL,
        "sub": OIDC_SUBJECT,
        "aud": verifier.aid().to_string(),
        "nonce": OIDC_NONCE,
        "iat": NOW,
        "exp": NOW + 3600,
        "cnf": {
            "jkt": sender
                .verifying_key()
                .to_jwk_thumbprint()
                .expect("sender jwk thumbprint"),
        },
    });
    // `sign_compact` is the exact same production path that mints the
    // TCT / grant voucher / delegation token: it derives `EdDSA` vs.
    // `ES256` from the signing key's own algorithm (never guessed or
    // hand-picked here), so there is no OIDC-specific signing logic in
    // this tool to drift out of sync with the library.
    let proof =
        aitp_crypto::jws::sign_compact(issuer_key, "JWT", &claims).expect("sign oidc id token");

    serde_json::json!({
        "issuer": OIDC_ISSUER_URL,
        "subject": OIDC_SUBJECT,
        "proof": proof,
        "issuer_jwk": issuer_jwk(&issuer_key.verifying_key()),
        "self_aid": verifier.aid().to_string(),
        "envelope": {
            "sender": { "agent_id": sender.aid().to_string() },
            "payload": { "pop_nonce": OIDC_NONCE },
        },
    })
}

/// Encode a verifying key as the JWK form `aitp_verifier.jwk` parses
/// (RFC 7517 §4), so the cross-check exercises that JWK-parsing path —
/// added in the same fix this vector validates — rather than only the
/// legacy 43/44-char config-string form.
fn issuer_jwk(vk: &AitpVerifyingKey) -> serde_json::Value {
    match vk.algorithm() {
        AidAlgorithm::Ed25519 => {
            let raw = vk
                .try_to_ed25519_bytes()
                .expect("Ed25519 algorithm() implies try_to_ed25519_bytes() is Some");
            serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": aitp_core::base64url::encode(&raw),
            })
        }
        AidAlgorithm::P256 => {
            // `AitpVerifyingKey` deliberately doesn't expose P-256
            // affine coordinates through its public API (its seal
            // invariant keeps `p256` types out of it) — only the
            // SEC1-compressed encoding. Decompress that back into x/y
            // ourselves; this is point-format conversion (RFC 7517
            // §6.2.2), not new signing infrastructure, and is local to
            // this tool crate.
            let compressed = vk.to_compressed();
            let point = p256::ecdsa::VerifyingKey::from_sec1_bytes(&compressed)
                .expect("valid P-256 point from to_compressed()");
            let uncompressed = point.to_sec1_point(false);
            let bytes = uncompressed.as_bytes();
            let x = &bytes[1..33];
            let y = &bytes[33..65];
            serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": aitp_core::base64url::encode(x),
                "y": aitp_core::base64url::encode(y),
            })
        }
        other => panic!("xcheck-mint: unsupported OIDC issuer key algorithm {other:?}"),
    }
}
