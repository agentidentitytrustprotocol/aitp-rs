//! Manifest PoP signing-input regression tests.
//!
//! RFC-AITP-0001 §5.4.2 unifies all PoP signing inputs to
//! `sha256(base64url_decode(x))`. Pre-rc.1, the Manifest builder and
//! verifier both hashed the ASCII bytes of the encoded challenge, which
//! was internally consistent but rejected by any cross-implementation
//! verifier reading the spec. These tests pin the post-fix behavior
//! against the spec's KAT vector and guard against the legacy form
//! coming back.

use aitp_core::{base64url, Aid, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey, Signature};
use aitp_manifest::{
    verify_manifest, IdentityHint, IdentityHintKind, ManifestBuilder, ManifestError, ManifestPop,
    VerifyManifestContext,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct KatFile {
    vectors: Vec<KatEntry>,
}

#[derive(Deserialize)]
struct KatEntry {
    id: String,
    #[serde(default)]
    challenge: Option<String>,
    #[serde(default)]
    decoded_hex: Option<String>,
    #[serde(default)]
    sha256_hex: Option<String>,
    #[serde(default)]
    signer_aid: Option<String>,
    #[serde(default)]
    signature_b64url: Option<String>,
}

fn load_pop_kat() -> KatEntry {
    let path = format!(
        "{}/../../tests/schemas/known-answer/jcs-sha256.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).expect("read jcs-sha256.json");
    let file: KatFile = serde_json::from_str(&raw).expect("parse jcs-sha256.json");
    file.vectors
        .into_iter()
        .find(|v| v.id == "kat-manifest-pop-001")
        .expect("kat-manifest-pop-001 vector must exist in vendored schemas")
}

/// kat-manifest-pop-001 is the spec's pinned vector for the unified
/// `sha256(base64url_decode(x))` PoP signing input. Decoding the
/// challenge MUST produce `decoded_hex`; SHA-256 of those raw bytes
/// MUST equal `sha256_hex`; and the recorded signature MUST verify
/// against `signer_aid`'s public key over that digest. Any failure
/// here means our crypto layer disagrees with the spec on the signing
/// input.
#[test]
fn pop_signing_input_matches_spec_kat() {
    let kat = load_pop_kat();
    let challenge_bytes =
        base64url::decode_strict(kat.challenge.as_ref().unwrap()).expect("kat challenge decodes");
    let expected_decoded =
        hex::decode(kat.decoded_hex.as_ref().unwrap()).expect("kat decoded_hex parses");
    assert_eq!(
        challenge_bytes, expected_decoded,
        "decoded challenge must equal the spec's pinned bytes"
    );

    let digest = Sha256::digest(&challenge_bytes);
    let expected_digest =
        hex::decode(kat.sha256_hex.as_ref().unwrap()).expect("kat sha256_hex parses");
    assert_eq!(
        digest.as_slice(),
        expected_digest.as_slice(),
        "sha256 of decoded bytes must equal the spec's pinned digest"
    );

    let aid = Aid::parse(kat.signer_aid.as_ref().unwrap()).expect("kat signer_aid parses");
    let pubkey = AitpVerifyingKey::from_aid(&aid).expect("kat aid resolves to pubkey");
    let sig = Signature::parse(kat.signature_b64url.as_ref().unwrap()).expect("kat sig parses");
    pubkey
        .verify(&digest, &sig)
        .expect("kat signature verifies under unified signing-input convention");
}

/// End-to-end: build a Manifest with `ManifestBuilder`, re-derive the
/// PoP input the same way the spec mandates (decode → sha256), and
/// verify the builder's signature accepts that input. This proves the
/// builder uses the unified convention rather than secretly hashing
/// `challenge.as_bytes()`.
#[test]
fn builder_pop_uses_decoded_challenge() {
    let key = AitpSigningKey::from_seed(&[1u8; 32]);
    let manifest = ManifestBuilder::new(&key)
        .handshake_endpoint("https://alice.example.com/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "alice".into(),
            issuer: None,
            public_key: Some(base64url::encode(&key.verifying_key().to_bytes())),
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .offer("demo.echo")
        .ttl_secs(3600)
        .build()
        .expect("builder produces a manifest");

    let challenge_bytes = base64url::decode_strict(&manifest.proof_of_possession.challenge)
        .expect("builder-emitted challenge decodes");
    let expected_input = Sha256::digest(&challenge_bytes);
    let pubkey = AitpVerifyingKey::from_aid(&manifest.aid).unwrap();
    let sig = Signature::parse(&manifest.proof_of_possession.signature).unwrap();
    pubkey
        .verify(&expected_input, &sig)
        .expect("builder PoP signature must verify against sha256(decoded(challenge))");
}

/// Legacy guard. Replace the PoP signature with one signed under the
/// pre-rc.1 buggy convention (hash the ASCII bytes of the encoded
/// challenge). Either the outer-signature check (which now runs
/// first after the rc.4-era reorder so `mh-002`'s
/// MANIFEST_SIGNATURE_INVALID expectation is preserved) or the
/// PoP check itself rejects the manifest. The exact error code is
/// implementation-defined; what matters is that the legacy PoP
/// convention does NOT verify.
#[test]
fn legacy_ascii_bytes_pop_is_rejected() {
    let key = AitpSigningKey::from_seed(&[2u8; 32]);
    let mut manifest = ManifestBuilder::new(&key)
        .handshake_endpoint("https://alice.example.com/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "alice".into(),
            issuer: None,
            public_key: Some(base64url::encode(&key.verifying_key().to_bytes())),
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .offer("demo.echo")
        .ttl_secs(3600)
        .build()
        .unwrap();

    let legacy_input = Sha256::digest(manifest.proof_of_possession.challenge.as_bytes());
    let legacy_sig = key.sign(&legacy_input).into_string();
    manifest.proof_of_possession = ManifestPop {
        challenge: manifest.proof_of_possession.challenge.clone(),
        signature: legacy_sig,
    };

    let err = verify_manifest(
        &manifest,
        &VerifyManifestContext {
            now: Timestamp::now(),
        },
    )
    .expect_err("legacy ASCII-bytes PoP must be rejected");
    assert!(
        matches!(
            err,
            ManifestError::PopFailed | ManifestError::SignatureInvalid
        ),
        "expected PopFailed or SignatureInvalid, got {err:?}"
    );
}
