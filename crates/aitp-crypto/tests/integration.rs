//! End-to-end sign/verify round-trip tests.
//!
//! These exercise the full `AitpSigningKey` ↔ `AitpVerifyingKey` ↔
//! `Signature` triangle, using both `from_seed` (for reproducibility) and
//! `generate` (for "real" key flows).

use aitp_crypto::{AitpSigningKey, AitpVerifyingKey, CryptoError, Signature};

#[test]
fn happy_path_sign_then_verify_via_aid() {
    let key = AitpSigningKey::from_seed(&[1u8; 32]);
    let msg = b"hello aitp";
    let sig = key.sign(msg);
    // Verifier learns the key from the AID alone.
    let vk = AitpVerifyingKey::from_aid(key.aid()).expect("AID decodes");
    vk.verify(msg, &sig).expect("signature verifies");
}

#[test]
fn wrong_key_fails_verification() {
    let alice = AitpSigningKey::from_seed(&[1u8; 32]);
    let bob = AitpSigningKey::from_seed(&[2u8; 32]);
    let msg = b"alice wrote this";
    let sig = alice.sign(msg);
    let bob_vk = AitpVerifyingKey::from_aid(bob.aid()).unwrap();
    assert!(bob_vk.verify(msg, &sig).is_err());
}

#[test]
fn mutated_message_fails_verification() {
    let key = AitpSigningKey::from_seed(&[3u8; 32]);
    let mut msg = b"trust me".to_vec();
    let sig = key.sign(&msg);
    msg[0] ^= 0x01;
    assert!(key.verifying_key().verify(&msg, &sig).is_err());
}

#[test]
fn mutated_signature_fails_verification() {
    let key = AitpSigningKey::from_seed(&[4u8; 32]);
    let msg = b"don't tamper";
    let sig = key.sign(msg);
    let mut s = sig.into_string();
    let last = s.pop().unwrap();
    // Flip last char to a different valid base64url char.
    let new = if last == 'A' { 'B' } else { 'A' };
    s.push(new);
    let sig = Signature::parse(&s).unwrap();
    assert!(key.verifying_key().verify(msg, &sig).is_err());
}

#[test]
fn empty_message_round_trip() {
    let key = AitpSigningKey::from_seed(&[5u8; 32]);
    let sig = key.sign(b"");
    key.verifying_key().verify(b"", &sig).unwrap();
}

#[test]
fn one_megabyte_message_round_trip() {
    let key = AitpSigningKey::from_seed(&[6u8; 32]);
    let msg = vec![0xABu8; 1024 * 1024];
    let sig = key.sign(&msg);
    key.verifying_key().verify(&msg, &sig).unwrap();
}

#[test]
fn from_seed_is_reproducible() {
    let k1 = AitpSigningKey::from_seed(&[42u8; 32]);
    let k2 = AitpSigningKey::from_seed(&[42u8; 32]);
    assert_eq!(k1.aid(), k2.aid());
    let msg = b"deterministic";
    assert_eq!(k1.sign(msg), k2.sign(msg));
}

#[test]
fn from_compressed_round_trips_ed25519() {
    // 32-byte input → Ed25519. The `cnf`/pinned-key wire form decodes
    // through here, so a length-confusion bug is a key-substitution vector.
    let key = AitpSigningKey::from_seed(&[0x21; 32]);
    let compressed = key.verifying_key().to_compressed();
    assert_eq!(compressed.len(), 32);
    let parsed = AitpVerifyingKey::from_compressed(&compressed).expect("ed25519 compressed parses");
    assert_eq!(parsed.to_compressed(), compressed);
    assert_eq!(parsed.to_bytes(), key.verifying_key().to_bytes());
}

#[test]
fn from_compressed_round_trips_p256() {
    // 33-byte SEC1-compressed input → P-256.
    let key = AitpSigningKey::generate_p256();
    let compressed = key.verifying_key().to_compressed();
    assert_eq!(compressed.len(), 33);
    let parsed = AitpVerifyingKey::from_compressed(&compressed).expect("p256 compressed parses");
    assert_eq!(parsed.to_compressed(), compressed);
}

#[test]
fn from_compressed_rejects_wrong_lengths() {
    for bad in [vec![], vec![0u8; 31], vec![0u8; 64], vec![0u8; 65]] {
        assert!(
            matches!(
                AitpVerifyingKey::from_compressed(&bad),
                Err(CryptoError::KeyParseFailed(_))
            ),
            "length {} must be rejected as KeyParseFailed",
            bad.len()
        );
    }
}

#[test]
#[should_panic]
fn to_bytes_panics_on_p256() {
    // `to_bytes` returns the 32-byte raw Ed25519 form and documents a
    // panic for P-256 keys (which have no 32-byte raw encoding). Lock
    // that contract so a regression can't silently return wrong bytes.
    let key = AitpSigningKey::generate_p256();
    let _ = key.verifying_key().to_bytes();
}

#[test]
fn signature_round_trips_through_string() {
    let key = AitpSigningKey::from_seed(&[7u8; 32]);
    let sig = key.sign(b"x");
    let s = sig.as_str().to_string();
    let again = Signature::parse(&s).unwrap();
    assert_eq!(again.as_str(), s);
}

#[test]
fn from_aid_round_trips_through_pubkey_bytes() {
    let key = AitpSigningKey::from_seed(&[8u8; 32]);
    let vk = AitpVerifyingKey::from_aid(key.aid()).unwrap();
    assert_eq!(vk.to_bytes(), key.verifying_key().to_bytes());
}

#[test]
fn thumbprint_is_43_chars_and_deterministic() {
    let key = AitpSigningKey::from_seed(&[9u8; 32]);
    let t1 = key.verifying_key().to_jwk_thumbprint().unwrap();
    let t2 = key.verifying_key().to_jwk_thumbprint().unwrap();
    assert_eq!(t1, t2);
    assert_eq!(t1.len(), 43);
    // Charset is base64url-unpadded.
    assert!(t1
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
}
