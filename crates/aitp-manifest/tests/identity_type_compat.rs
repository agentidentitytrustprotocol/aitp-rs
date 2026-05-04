//! `accepted_identity_types` pre-handshake screening (BUG-6).
//!
//! RFC-AITP-0003 §3.2 / §5 step 5: a fetching peer MUST check that
//! its own identity type appears in the target Manifest's
//! `accepted_identity_types`. Pre-rc.1, neither `verify_manifest` nor
//! the handshake facade checked this — pinned-key initiators would
//! attempt a HELLO against an OIDC-only peer and learn after several
//! round trips that the responder rejects them.

use aitp_core::{base64url, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_manifest::{
    check_identity_type_compatibility, IdentityHint, IdentityHintKind, Manifest, ManifestBuilder,
    ManifestError,
};

const NOW: Timestamp = Timestamp(1_700_000_000);

fn manifest_for(key: &AitpSigningKey, accept: &[&str]) -> Manifest {
    let mut b = ManifestBuilder::new(key)
        .handshake_endpoint("https://example.com/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "subj".into(),
            issuer: None,
            public_key: Some(base64url::encode(&key.verifying_key().to_bytes())),
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .offer("demo.echo")
        .ttl_secs(3600)
        .published_at(NOW);
    for t in accept {
        b = b.accept_identity_type(*t);
    }
    b.build().expect("manifest")
}

#[test]
fn pinned_key_initiator_against_pinned_key_only_peer_passes() {
    let m = manifest_for(&AitpSigningKey::from_seed(&[0xD1; 32]), &["pinned_key"]);
    check_identity_type_compatibility(&m, "pinned_key").expect("compatible");
}

#[test]
fn pinned_key_initiator_against_mixed_peer_passes() {
    let m = manifest_for(
        &AitpSigningKey::from_seed(&[0xD2; 32]),
        &["oidc", "pinned_key"],
    );
    check_identity_type_compatibility(&m, "pinned_key").expect("compatible");
}

#[test]
fn pinned_key_initiator_against_oidc_only_peer_is_blocked() {
    let m = manifest_for(&AitpSigningKey::from_seed(&[0xD3; 32]), &["oidc"]);
    let err = check_identity_type_compatibility(&m, "pinned_key").expect_err("incompatible");
    assert!(
        matches!(err, ManifestError::IncompatibleIdentityType("pinned_key")),
        "got {err:?}"
    );
}

#[test]
fn empty_accepted_list_rejects_every_peer() {
    let m = manifest_for(&AitpSigningKey::from_seed(&[0xD4; 32]), &[]);
    let err = check_identity_type_compatibility(&m, "pinned_key").expect_err("blocked");
    assert!(matches!(
        err,
        ManifestError::IncompatibleIdentityType("pinned_key")
    ));
    let err = check_identity_type_compatibility(&m, "oidc").expect_err("blocked");
    assert!(matches!(
        err,
        ManifestError::IncompatibleIdentityType("oidc")
    ));
}

#[test]
fn oidc_initiator_against_pinned_key_only_peer_is_blocked() {
    let m = manifest_for(&AitpSigningKey::from_seed(&[0xD5; 32]), &["pinned_key"]);
    let err = check_identity_type_compatibility(&m, "oidc").expect_err("incompatible");
    assert!(matches!(
        err,
        ManifestError::IncompatibleIdentityType("oidc")
    ));
}
