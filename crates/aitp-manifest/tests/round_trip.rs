//! End-to-end Manifest issue + verify + tamper-detection.

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_manifest::{
    verify_manifest, IdentityHint, IdentityHintKind, ManifestBuilder, ManifestError,
    VerifyManifestContext,
};

fn alice_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[1u8; 32])
}

fn build_alice_manifest_at(now: Timestamp) -> aitp_manifest::Manifest {
    let key = alice_key();
    ManifestBuilder::new(&key)
        .handshake_endpoint("https://alice.example.com/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::Oidc,
            subject: "alice".into(),
            issuer: Some("https://idp.example.com".parse().unwrap()),
            public_key: None,
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .offer("demo.echo")
        .published_at(now)
        .ttl_secs(3600)
        .build()
        .expect("builder produces a manifest")
}

#[test]
fn happy_path_round_trip() {
    let now = Timestamp(1_700_000_000);
    let m = build_alice_manifest_at(now);
    verify_manifest(&m, &VerifyManifestContext { now }).expect("fresh manifest verifies");
}

#[test]
fn tampered_outer_signature_fails() {
    let now = Timestamp(1_700_000_000);
    let mut m = build_alice_manifest_at(now);
    let mut s = m.signature.clone();
    let last = s.pop().unwrap();
    s.push(if last == 'A' { 'B' } else { 'A' });
    m.signature = s;
    let err = verify_manifest(&m, &VerifyManifestContext { now }).unwrap_err();
    assert!(
        matches!(err, ManifestError::SignatureInvalid),
        "got: {:?}",
        err
    );
}

#[test]
fn tampered_pop_signature_fails() {
    let now = Timestamp(1_700_000_000);
    let mut m = build_alice_manifest_at(now);
    let mut s = m.proof_of_possession.signature.clone();
    let last = s.pop().unwrap();
    s.push(if last == 'A' { 'B' } else { 'A' });
    m.proof_of_possession.signature = s;
    let err = verify_manifest(&m, &VerifyManifestContext { now }).unwrap_err();
    // Either error is acceptable: tampering the PoP signature also
    // invalidates the outer signature (the outer covers the whole
    // body including `proof_of_possession.signature`). The verifier
    // checks the outer signature first (rc.4 ordering — see
    // `mh-002` conformance), so SignatureInvalid is the typical
    // observable. Accept either to keep this test robust to the
    // outer/PoP check ordering.
    assert!(
        matches!(
            err,
            ManifestError::PopFailed | ManifestError::SignatureInvalid
        ),
        "got: {:?}",
        err
    );
}

#[test]
fn tampered_pop_challenge_fails() {
    let now = Timestamp(1_700_000_000);
    let mut m = build_alice_manifest_at(now);
    // Mutate the challenge — sha256(challenge) input changes, PoP fails.
    let bytes = m.proof_of_possession.challenge.as_bytes();
    let mut chars: Vec<u8> = bytes.to_vec();
    chars[0] ^= 1; // still a base64url char (A↔B etc when in range)
    if !chars[0].is_ascii_alphanumeric() {
        chars[0] = b'B';
    }
    m.proof_of_possession.challenge = String::from_utf8(chars).unwrap();
    let err = verify_manifest(&m, &VerifyManifestContext { now }).unwrap_err();
    // Tampering the challenge invalidates BOTH the pop_signature
    // and the outer signature. The rc.4-era verifier checks the
    // outer signature first (so `mh-002` reports
    // MANIFEST_SIGNATURE_INVALID), hence SignatureInvalid is the
    // typical observable here; accept either to keep the test
    // robust to ordering changes.
    assert!(
        matches!(
            err,
            ManifestError::PopFailed | ManifestError::SignatureInvalid
        ),
        "got: {:?}",
        err
    );
}

#[test]
fn expired_fails() {
    let issued = Timestamp(1_700_000_000);
    let m = build_alice_manifest_at(issued);
    let later = Timestamp(1_700_000_000 + 7200); // 2h after issuance, TTL was 1h
    let err = verify_manifest(&m, &VerifyManifestContext { now: later }).unwrap_err();
    assert!(matches!(err, ManifestError::Expired), "got: {:?}", err);
}

#[test]
fn unknown_version_fails() {
    let now = Timestamp(1_700_000_000);
    let mut m = build_alice_manifest_at(now);
    m.version = "aitp/9.9".into();
    let err = verify_manifest(&m, &VerifyManifestContext { now }).unwrap_err();
    assert!(
        matches!(err, ManifestError::VersionUnknown),
        "got: {:?}",
        err
    );
}

#[test]
fn empty_extensions_omitted_from_canonical_form() {
    let now = Timestamp(1_700_000_000);
    let m = build_alice_manifest_at(now);
    let s = serde_json::to_string(&m).unwrap();
    assert!(
        !s.contains("\"extensions\":"),
        "empty extensions must not serialize: {}",
        s
    );
}

#[test]
fn pinned_key_manifest_round_trips() {
    let key = alice_key();
    let pubkey_b64 = aitp_core::base64url::encode(&key.verifying_key().to_bytes());
    let now = Timestamp(1_700_000_000);
    let m = ManifestBuilder::new(&key)
        .handshake_endpoint("https://alice.example.com/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "internal-1".into(),
            issuer: None,
            public_key: Some(pubkey_b64),
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .offer("demo.echo")
        .published_at(now)
        .build()
        .unwrap();
    verify_manifest(&m, &VerifyManifestContext { now }).unwrap();
}

#[test]
fn builder_rejects_missing_handshake_endpoint() {
    let key = alice_key();
    let err = ManifestBuilder::new(&key)
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::Oidc,
            subject: "x".into(),
            issuer: Some("https://idp.example.com".parse().unwrap()),
            public_key: None,
        })
        .build()
        .unwrap_err();
    assert!(matches!(
        err,
        ManifestError::MissingField("handshake_endpoint")
    ));
}

#[test]
fn builder_rejects_oidc_with_pubkey() {
    let key = alice_key();
    let err = ManifestBuilder::new(&key)
        .handshake_endpoint("https://x".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::Oidc,
            subject: "x".into(),
            issuer: Some("https://idp.example.com".parse().unwrap()),
            public_key: Some("A".repeat(43)),
        })
        .build()
        .unwrap_err();
    assert!(matches!(err, ManifestError::IdentityHintMalformed(_)));
}

#[test]
fn builder_rejects_pinned_without_pubkey() {
    let key = alice_key();
    let err = ManifestBuilder::new(&key)
        .handshake_endpoint("https://x".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "x".into(),
            issuer: None,
            public_key: None,
        })
        .build()
        .unwrap_err();
    assert!(matches!(err, ManifestError::IdentityHintMalformed(_)));
}

#[test]
fn pop_corruption_surfaces_as_signature_invalid_not_pop_failed() {
    // `proof_of_possession` is part of the outer-signed view, so
    // corrupting only the PoP signature (without re-signing) breaks the
    // OUTER signature too. The verifier checks the outer signature before
    // the PoP (rc.4 ordering, conformance `mh-002`), so this MUST surface
    // as `SignatureInvalid`, never `PopFailed`. This locks the ordering
    // that the looser `tampered_pop_signature_fails` test leaves open.
    let now = Timestamp(1_700_000_000);
    let mut m = build_alice_manifest_at(now);
    // Replace the PoP signature with a different, well-formed Ed25519
    // signature (a self-sign over unrelated bytes) so it parses but does
    // not match — isolating verification (not a parse) failure.
    let other = AitpSigningKey::from_seed(&[2u8; 32]);
    m.proof_of_possession.signature = other.sign(b"unrelated").into_string();
    let err = verify_manifest(&m, &VerifyManifestContext { now }).unwrap_err();
    assert!(
        matches!(err, ManifestError::SignatureInvalid),
        "PoP corruption must surface as SignatureInvalid (outer-sig-first), got: {err:?}"
    );
}
