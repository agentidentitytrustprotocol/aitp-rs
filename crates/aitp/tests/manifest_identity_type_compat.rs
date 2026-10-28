//! `accepted_identity_types` pre-handshake screening (BUG-6).
//!
//! RFC-AITP-0003 §3.2 / §5 step 5: a fetching peer MUST check that
//! its own identity type appears in the target Manifest's
//! `accepted_identity_types`. Pre-rc.1, neither `verify_manifest` nor
//! the handshake facade checked this — pinned-key initiators would
//! attempt a HELLO against an OIDC-only peer and learn after several
//! round trips that the responder rejects them.

use aitp::core::{base64url, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::handshake::IdentityKind;
use aitp::manifest::{
    check_identity_type_compatibility, IdentityHint, Manifest, ManifestBuilder, ManifestError,
};

const NOW: Timestamp = Timestamp(1_700_000_000);

fn manifest_for(key: &AitpSigningKey, accept: &[aitp::handshake::IdentityKind]) -> Manifest {
    let mut b = ManifestBuilder::new(key)
        .handshake_endpoint("https://example.com/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityKind::PinnedKey, "subj").with_public_key(base64url::encode(
                &key.verifying_key()
                    .try_to_ed25519_bytes()
                    .expect("key was constructed as Ed25519, never P-256"),
            )),
        )
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .offer("demo.echo")
        .ttl(std::time::Duration::from_secs(3600))
        .published_at(NOW);
    if accept.is_empty() {
        // Empty input list = explicit-empty test (BUG-6 case):
        // wire form carries `"accepted_identity_types": []` so the
        // verifier rejects every peer.
        b = b.accept_no_identity_types();
    } else {
        for t in accept {
            b = b.accept_identity_type(*t);
        }
    }
    b.build().expect("manifest")
}

#[test]
fn pinned_key_initiator_against_pinned_key_only_peer_passes() {
    let m = manifest_for(
        &AitpSigningKey::from_ed25519_seed(&[0xD1; 32]),
        &[aitp::handshake::IdentityKind::PinnedKey],
    );
    check_identity_type_compatibility(&m, aitp::handshake::IdentityKind::PinnedKey)
        .expect("compatible");
}

#[test]
fn pinned_key_initiator_against_mixed_peer_passes() {
    let m = manifest_for(
        &AitpSigningKey::from_ed25519_seed(&[0xD2; 32]),
        &[
            aitp::handshake::IdentityKind::Oidc,
            aitp::handshake::IdentityKind::PinnedKey,
        ],
    );
    check_identity_type_compatibility(&m, aitp::handshake::IdentityKind::PinnedKey)
        .expect("compatible");
}

#[test]
fn pinned_key_initiator_against_oidc_only_peer_is_blocked() {
    let m = manifest_for(
        &AitpSigningKey::from_ed25519_seed(&[0xD3; 32]),
        &[aitp::handshake::IdentityKind::Oidc],
    );
    let err = check_identity_type_compatibility(&m, aitp::handshake::IdentityKind::PinnedKey)
        .expect_err("incompatible");
    assert!(
        matches!(
            err,
            ManifestError::IncompatibleIdentityType(aitp::handshake::IdentityKind::PinnedKey)
        ),
        "got {err:?}"
    );
}

#[test]
fn empty_accepted_list_rejects_every_peer() {
    let m = manifest_for(&AitpSigningKey::from_ed25519_seed(&[0xD4; 32]), &[]);
    let err = check_identity_type_compatibility(&m, aitp::handshake::IdentityKind::PinnedKey)
        .expect_err("blocked");
    assert!(matches!(
        err,
        ManifestError::IncompatibleIdentityType(aitp::handshake::IdentityKind::PinnedKey)
    ));
    let err = check_identity_type_compatibility(&m, aitp::handshake::IdentityKind::Oidc)
        .expect_err("blocked");
    assert!(matches!(
        err,
        ManifestError::IncompatibleIdentityType(aitp::handshake::IdentityKind::Oidc)
    ));
}

#[test]
fn oidc_initiator_against_pinned_key_only_peer_is_blocked() {
    let m = manifest_for(
        &AitpSigningKey::from_ed25519_seed(&[0xD5; 32]),
        &[aitp::handshake::IdentityKind::PinnedKey],
    );
    let err = check_identity_type_compatibility(&m, aitp::handshake::IdentityKind::Oidc)
        .expect_err("incompatible");
    assert!(matches!(
        err,
        ManifestError::IncompatibleIdentityType(aitp::handshake::IdentityKind::Oidc)
    ));
}
