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

use aitp::core::{AidAlgorithm, ExtensionsMap, Timestamp};
use aitp::crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp::tct::{sign_revocation_list, RevocationEntry, RevocationList, TctBuilder};
use aitp_experimental::session_bundle::SessionBundleBuilder;
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
// build (see `crates/aitp/src/handshake/identity_oidc.rs` and
// `crates/aitp/tests/handshake_fixtures/mock_oidc.rs`), not a full
// `MUTUAL_HELLO` envelope (Manifest + PoP + envelope signature) — that
// is enough to reach `aitp_verifier.identity.verify_identity` directly.
//
// EdDSA and ES256 only. `aitp-rs` has no RSA *signing* capability: PR
// #122 (merged) deliberately moved `aitp::handshake` to `ring` for RSA
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
    let issuer = AitpSigningKey::from_ed25519_seed(&KP_001_SEED);
    let participant = AitpSigningKey::from_ed25519_seed(&KP_002_SEED);

    // ── Revocation snapshot ──────────────────────────────────────────
    // Field-for-field the spec's committed
    // signed-examples/revocation/kat-keypair-001-snapshot.json, so the
    // output can be compared byte-for-byte against it.
    let body = RevocationList::new(
        issuer.aid().clone(),
        Timestamp(NOW),
        Timestamp(NOW + 3600),
        vec![RevocationEntry::new(
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440099").unwrap(),
            Timestamp(NOW + 60),
        )
        .with_reason("key_compromised")],
    );
    let snapshot = sign_revocation_list(body, &issuer).expect("sign revocation snapshot");

    // Otherwise-identical revocation snapshot, but with a populated
    // `extensions` map (D8 / issue #140 follow-up): `extensions` is not
    // a trust-decision input, but it IS part of the JCS-canonicalized
    // signing body (RFC-AITP-0001 §5.4.1), so a populated map must flow
    // through both implementations' canonicalization identically. The
    // content below deliberately stresses JCS agreement rather than just
    // being "any non-empty map": a nested object, a key containing a
    // non-ASCII character, and an integer value.
    let mut extensions_with_content = ExtensionsMap::new();
    extensions_with_content.insert("café", serde_json::json!("stress ünïcödé \u{1F600}"));
    extensions_with_content.insert(
        "nested",
        serde_json::json!({"inner": {"count": 3, "flag": true}, "list": [1, 2, 3]}),
    );
    extensions_with_content.insert("count", serde_json::json!(42));
    let body_with_extensions = {
        let mut list = RevocationList::new(
            issuer.aid().clone(),
            Timestamp(NOW),
            Timestamp(NOW + 3600),
            vec![RevocationEntry::new(
                Uuid::parse_str("550e8400-e29b-41d4-a716-446655440099").unwrap(),
                Timestamp(NOW + 60),
            )
            .with_reason("key_compromised")],
        );
        list.extensions = Some(extensions_with_content);
        list
    };
    let snapshot_with_extensions =
        sign_revocation_list(body_with_extensions, &issuer).expect("sign revocation snapshot");

    // ── Manifest ─────────────────────────────────────────────────────
    // D9 / issue #140 follow-up: manifest had zero cross-impl coverage
    // of any kind before this — not even the base signing-input shape,
    // let alone the `Option<ExtensionsMap>` migration (Phase 3). Two
    // vectors: no `extensions` at all, and a populated one (real
    // content, not empty). `Some(ExtensionsMap::new())`
    // (present-but-empty) is deliberately not covered here — it is
    // unreachable from the public `ManifestBuilder` API.
    let manifest_pubkey_b64 = aitp::core::base64url::encode(
        &issuer
            .verifying_key()
            .try_to_ed25519_bytes()
            .expect("issuer key was constructed as Ed25519, never P-256"),
    );
    let manifest_identity_hint = || {
        IdentityHint::new(IdentityHintKind::PinnedKey, "xcheck-manifest")
            .with_public_key(manifest_pubkey_b64.clone())
    };
    let manifest_no_extensions = ManifestBuilder::new(&issuer)
        .handshake_endpoint("https://xcheck.aitp.example/handshake".parse().unwrap())
        .identity_hint(manifest_identity_hint())
        .accept_trust_anchor("https://idp.aitp-xcheck.example".parse().unwrap())
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .ttl_secs(3600)
        .published_at(Timestamp(NOW))
        .build()
        .expect("mint manifest without extensions");
    let manifest_with_extensions = ManifestBuilder::new(&issuer)
        .handshake_endpoint("https://xcheck.aitp.example/handshake".parse().unwrap())
        .identity_hint(manifest_identity_hint())
        .accept_trust_anchor("https://idp.aitp-xcheck.example".parse().unwrap())
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .ttl_secs(3600)
        .published_at(Timestamp(NOW))
        .extension("café", serde_json::json!("stress ünïcödé"))
        .extension(
            "nested",
            serde_json::json!({"inner": {"count": 3, "flag": true}, "list": [1, 2, 3]}),
        )
        .extension("count", serde_json::json!(42))
        .build()
        .expect("mint manifest with populated extensions");

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
    let oidc_sender = AitpSigningKey::from_ed25519_seed(&OIDC_SENDER_SEED);
    let oidc_verifier = AitpSigningKey::from_ed25519_seed(&OIDC_VERIFIER_SEED);
    let oidc_issuer_eddsa = AitpSigningKey::from_ed25519_seed(&OIDC_ISSUER_ED25519_SEED);
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
        "snapshot_with_extensions": {
            "revocation_list": snapshot_with_extensions.revocation_list,
            "signature": snapshot_with_extensions.signature,
        },
        "manifest_no_extensions": manifest_no_extensions,
        "manifest_with_extensions": manifest_with_extensions,
        "session_bundle": { "session_bundle": body },
        "oidc_identity": {
            "now": NOW,
            "eddsa": oidc_eddsa,
            "es256": oidc_es256,
        },
        "p256": mint_p256_vectors(),
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

// ── P-256 legs (proposal agentidentitytrustprotocol#72 Items 1, 2, 4, 5) ──
//
// Every artifact class aitp-rs can sign, minted by `kat-keypair-005-p256`
// through the production path. Before 0.14 aitp-rs signed the JCS profile
// as ECDSA-with-SHA-256 over the 32-byte digest `d` (a double hash), which
// no independent verifier accepted; these legs pin the single-hash
// primitive (RFC-AITP-0001 §5.4.6) on the wire.
//
// The negatives are produced here rather than in the verifier script,
// because two of them need the private key: a signature over the
// double-hashed digest (the pre-0.14 aitp-rs bug), and a revocation-free
// way to state "this is the one wrong thing". The script derives the
// other two (high-S, stripped `p256.` tag) from the positive bytes, so
// nothing is re-signed on the verifying side.

/// kat-keypair-005-p256: private scalar 0x05 × 32.
const KP_005_P256_SCALAR: [u8; 32] = [0x05u8; 32];
/// The P-256 legs' relying party (Ed25519, kat-keypair-002's seed is
/// already the bundle participant; this one only appears as an AID).
const P256_VERIFIER_SEED: [u8; 32] = [0x77u8; 32];
/// Fixed UUID v4 message ids, so the output is deterministic.
const P256_ENVELOPE_MESSAGE_ID: u128 = 0x7c1d_6e0a_5b2f_4c3e_9a8b_1f2e_3d4c_5b6a;
const P256_PINNED_MESSAGE_ID: u128 = 0x2a9f_4e1b_8c7d_4a6e_b5f4_e3d2_c1b0_a998;
const P256_PINNED_NONCE: &str = "AAECAwQFBgcICQoLDA0ODw";
const P256_REVOKED_JTI: &str = "550e8400-e29b-41d4-a716-446655440098";

fn mint_p256_vectors() -> serde_json::Value {
    use aitp::core::MessageType;

    let signer = AitpSigningKey::from_p256_seed(&KP_005_P256_SCALAR).expect("valid p256 scalar");
    let verifier = AitpSigningKey::from_ed25519_seed(&P256_VERIFIER_SEED);
    let participant = AitpSigningKey::from_ed25519_seed(&KP_002_SEED);

    // Revocation snapshot: also the TCT legs' revocation source.
    let snapshot = sign_revocation_list(
        RevocationList::new(
            signer.aid().clone(),
            Timestamp(NOW),
            Timestamp(NOW + 3600),
            vec![RevocationEntry::new(
                Uuid::parse_str(P256_REVOKED_JTI).unwrap(),
                Timestamp(NOW + 60),
            )
            .with_reason("key_compromised")],
        ),
        &signer,
    )
    .expect("sign p256 revocation snapshot");

    // Manifest whose pinned_key identity_hint is the 44-char P-256 form.
    let manifest = ManifestBuilder::new(&signer)
        .handshake_endpoint("https://xcheck.aitp.example/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityHintKind::PinnedKey, "xcheck-manifest-p256")
                .with_public_key(signer.aid().identifier().to_string()),
        )
        .accept_trust_anchor("https://idp.aitp-xcheck.example".parse().unwrap())
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .ttl_secs(3600)
        .published_at(Timestamp(NOW))
        .build()
        .expect("mint p256 manifest");

    // Envelope, plus the same envelope signed the pre-0.14 way.
    let envelope = aitp::envelope::sign_envelope_with(
        &signer,
        MessageType::Tct,
        serde_json::json!({ "note": "xcheck p256 envelope" }),
        Uuid::from_u128(P256_ENVELOPE_MESSAGE_ID),
        Timestamp(NOW),
    )
    .expect("sign p256 envelope");
    let envelope_double_hash = {
        let digest =
            aitp::core::envelope::envelope_signing_digest(&envelope).expect("envelope digest");
        let mut e = envelope.clone();
        e.signature = double_hash_signature(&digest);
        e
    };

    // Pinned-key identity (RFC-AITP-0002 §3, proposal Item 2): a P-256
    // sender's tagged proof over the five-field input.
    let pinned_message_id = Uuid::from_u128(P256_PINNED_MESSAGE_ID);
    let pinned_proof = aitp::handshake::sign_pinned_key_proof(
        &signer,
        signer.aid(),
        verifier.aid(),
        &pinned_message_id,
        Timestamp(NOW),
        P256_PINNED_NONCE,
    )
    .expect("sign p256 pinned-key proof");
    let pinned_envelope = aitp::envelope::sign_envelope_with(
        &signer,
        MessageType::IdentityPresentation,
        serde_json::json!({ "pop_nonce": P256_PINNED_NONCE }),
        pinned_message_id,
        Timestamp(NOW),
    )
    .expect("sign p256 pinned-key envelope");
    let pinned_input = aitp::handshake::pinned_key_proof_input(
        signer.aid(),
        verifier.aid(),
        &pinned_message_id,
        Timestamp(NOW),
        P256_PINNED_NONCE,
    )
    .expect("pinned-key proof input");

    // ES256 TCT (peer-issued) and an ES256 self-attestation (Item 5).
    let tct = TctBuilder::new(&signer)
        .subject(participant.aid().clone())
        .audience(participant.aid().clone())
        .grants(["session.participate"])
        .ttl_secs(3600)
        .subject_pubkey(participant.verifying_key())
        .issued_at(Timestamp(NOW))
        .jti(Uuid::from_u128(0x5d3c_2b1a_0f9e_4d8c_8b7a_6f5e_4d3c_2b1a))
        .build()
        .expect("issue p256 TCT")
        .token;
    let mut statement = serde_json::Map::new();
    statement.insert(
        "xcheck.statement".into(),
        serde_json::json!({ "build": "xcheck" }),
    );
    let attestation = TctBuilder::new(&signer)
        .self_attestation()
        .ext(statement)
        .ttl_secs(3600)
        .issued_at(Timestamp(NOW))
        .jti(Uuid::from_u128(0x6e4d_3c2b_1a0f_4e9d_9c8b_7a6f_5e4d_3c2b))
        .build()
        .expect("issue p256 self-attestation")
        .token;

    // Session bundle coordinated by the P-256 key.
    let bundle_tct = TctBuilder::new(&signer)
        .subject(participant.aid().clone())
        .audience(participant.aid().clone())
        .grants(["session.participate"])
        .ttl_secs(3600)
        .subject_pubkey(participant.verifying_key())
        .issued_at(Timestamp(NOW))
        .jti(Uuid::from_u128(0x7f5e_4d3c_2b1a_4f0e_8d9c_8b7a_6f5e_4d3c))
        .build()
        .expect("issue p256 bundle TCT")
        .token;
    let bundle = SessionBundleBuilder::new(&signer)
        .session_id(Uuid::parse_str("1f0e2d3c-4b5a-4968-8776-655443322110").unwrap())
        .issued_at(Timestamp(NOW))
        .participant(participant.aid().clone(), bundle_tct)
        .build()
        .expect("build p256 session bundle");

    serde_json::json!({
        "aid": signer.aid().to_string(),
        "public_key": signer.aid().identifier(),
        "verifier_aid": verifier.aid().to_string(),
        "participant_aid": participant.aid().to_string(),
        "snapshot": { "revocation_list": snapshot.revocation_list, "signature": snapshot.signature },
        "manifest": manifest,
        "envelope": envelope,
        "envelope_double_hash": envelope_double_hash,
        "pinned_key": {
            "identity": {
                "type": "pinned_key",
                "subject": "xcheck-p256-agent",
                "public_key": signer.aid().identifier(),
                "proof": pinned_proof,
            },
            "envelope": pinned_envelope,
            "proof_input_hex": hex::encode(&pinned_input),
        },
        "tct": tct,
        "attestation": attestation,
        "session_bundle": { "session_bundle": serde_json::to_value(&bundle).expect("bundle serializes") },
    })
}

/// The pre-0.14 aitp-rs P-256 JCS signature: ECDSA-with-SHA-256 over the
/// 32-byte digest `d`, i.e. `e = SHA-256(d)` instead of `e = d`. Low-S and
/// `p256.`-tagged, so the hash input is the only thing wrong with it.
fn double_hash_signature(digest: &[u8; 32]) -> String {
    use p256::ecdsa::signature::Signer as _;
    let sk = p256::ecdsa::SigningKey::from_slice(&KP_005_P256_SCALAR).expect("valid p256 scalar");
    let sig: p256::ecdsa::Signature = sk.sign(digest);
    let sig = sig.normalize_s();
    format!("p256.{}", aitp::core::base64url::encode(&sig.to_bytes()))
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
                .to_jwk_thumbprint_sha256()
                .expect("sender jwk thumbprint"),
        },
    });
    // `sign_compact` is the exact same production path that mints the
    // TCT / grant voucher / delegation token: it derives `EdDSA` vs.
    // `ES256` from the signing key's own algorithm (never guessed or
    // hand-picked here), so there is no OIDC-specific signing logic in
    // this tool to drift out of sync with the library.
    let proof =
        aitp::crypto::jws::sign_compact(issuer_key, "JWT", &claims).expect("sign oidc id token");

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
                "x": aitp::core::base64url::encode(&raw),
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
                "x": aitp::core::base64url::encode(x),
                "y": aitp::core::base64url::encode(y),
            })
        }
        other => panic!("xcheck-mint: unsupported OIDC issuer key algorithm {other:?}"),
    }
}
