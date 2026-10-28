//! RFC-AITP-0010 §5 verification order (issue #197).
//!
//! For each adjacent pair of numbered checks, an input that fails BOTH
//! must surface the EARLIER check's error. Plus the step-5 coordinator
//! Manifest checks themselves.

use aitp::core::{jcs, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder, ManifestError};
use aitp::tct::{TctBuilder, TctError};
use aitp_experimental::session_bundle::{
    verify_session_bundle, BundleOutcome, CoordinatorKeySource, SessionBundleBuilder,
    SessionBundleError, SessionTrustBundle, VerifySessionBundleContext,
};

const NOW: Timestamp = Timestamp(1_700_000_000);

fn key(seed: u8) -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&[seed; 32])
}

fn issue_tct(coord: &AitpSigningKey, aud: &AitpSigningKey, ttl_secs: u64) -> String {
    TctBuilder::new(coord)
        .subject(aud.aid().clone())
        .audience(aud.aid().clone())
        .grants(["session.participate"])
        .ttl(std::time::Duration::from_secs(ttl_secs))
        .subject_pubkey(aud.verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
        .token
}

fn manifest_for(key: &AitpSigningKey, ttl_secs: u64) -> Manifest {
    ManifestBuilder::new(key)
        .display_name("coordinator")
        .handshake_endpoint("https://coord.example/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityHintKind::PinnedKey, "coordinator")
                .with_public_key(key.aid().identifier().to_string()),
        )
        .offer("session.coordinate")
        .published_at(NOW)
        .ttl(std::time::Duration::from_secs(ttl_secs))
        .build()
        .unwrap()
}

/// Valid bundle: coordinator `0xC0`, single participant Alice (`0xA0`).
fn valid_bundle(coord: &AitpSigningKey, alice: &AitpSigningKey) -> SessionTrustBundle {
    SessionBundleBuilder::new(coord)
        .issued_at(NOW)
        .participant(alice.aid().clone(), issue_tct(coord, alice, 3600))
        .build()
        .unwrap()
}

/// Re-sign `bundle` after a mutation, so the mutated body still passes
/// the outer signature (step 6).
fn resign(bundle: &mut SessionTrustBundle, coord: &AitpSigningKey) {
    let mut body = serde_json::to_value(&*bundle).unwrap();
    body.as_object_mut().unwrap().remove("signature");
    let canonical = jcs::canonicalize(&body).unwrap();
    bundle.signature = coord
        .sign_jcs(&aitp::crypto::Digest32::sha256(&canonical))
        .into_string();
}

fn corrupt_signature(bundle: &mut SessionTrustBundle) {
    let mut sig = std::mem::take(&mut bundle.signature).into_bytes();
    sig[0] = if sig[0] == b'A' { b'B' } else { b'A' };
    bundle.signature = String::from_utf8(sig).unwrap();
}

fn verify(
    bundle: &SessionTrustBundle,
    verifier: &AitpSigningKey,
    now: Timestamp,
    coordinator_key: CoordinatorKeySource<'_>,
) -> Result<BundleOutcome, SessionBundleError> {
    verify_session_bundle(
        bundle,
        &VerifySessionBundleContext {
            verifier_aid: verifier.aid(),
            now,
            revocation_check: None,
            coordinator_key,
        },
    )
}

#[test]
fn happy_path_with_verified_coordinator_manifest() {
    let (coord, alice) = (key(0xC0), key(0xA0));
    let bundle = valid_bundle(&coord, &alice);
    let manifest = manifest_for(&coord, 24 * 3600);
    let outcome = verify(
        &bundle,
        &alice,
        NOW,
        CoordinatorKeySource::Manifest(&manifest),
    );
    assert!(
        matches!(outcome, Ok(BundleOutcome::Clear { .. })),
        "{outcome:?}"
    );
}

/// Steps 1 vs 2: unknown version AND expired → version wins.
#[test]
fn version_beats_expiry() {
    let (coord, alice) = (key(0xC0), key(0xA0));
    let mut bundle = valid_bundle(&coord, &alice);
    bundle.version = "aitp/9.9".into();
    let later = Timestamp(NOW.0 + 10 * 3600);
    let err = verify(
        &bundle,
        &alice,
        later,
        CoordinatorKeySource::UnverifiedAidDangerous,
    );
    assert!(
        matches!(err, Err(SessionBundleError::VersionMismatch)),
        "{err:?}"
    );
}

/// Steps 2 vs 3: expired AND `expires_at != min(exp)` → expiry wins.
#[test]
fn expiry_beats_expiry_window() {
    let (coord, alice) = (key(0xC0), key(0xA0));
    let mut bundle = valid_bundle(&coord, &alice);
    bundle.expires_at = Timestamp(NOW.0 - 1);
    resign(&mut bundle, &coord);
    let err = verify(
        &bundle,
        &alice,
        NOW,
        CoordinatorKeySource::UnverifiedAidDangerous,
    );
    assert!(matches!(err, Err(SessionBundleError::Expired)), "{err:?}");
}

/// Steps 3 vs 4: the expiry-window invariant has no minimum to compare
/// against on an empty `participants` array, so it is vacuous there and
/// an empty bundle with an arbitrary `expires_at` is reported by step 4.
/// (No input can fail both.) Before #197 the empty check ran first.
#[test]
fn empty_participants_reported_by_step_4_not_step_3() {
    let (coord, alice) = (key(0xC0), key(0xA0));
    let mut bundle = valid_bundle(&coord, &alice);
    bundle.participants.clear();
    bundle.expires_at = Timestamp(NOW.0 + 99);
    resign(&mut bundle, &coord);
    let err = verify(
        &bundle,
        &alice,
        NOW,
        CoordinatorKeySource::UnverifiedAidDangerous,
    );
    assert!(
        matches!(err, Err(SessionBundleError::EmptyParticipants)),
        "{err:?}"
    );
}

/// Steps 3 vs 5: expiry-window violated AND the supplied coordinator
/// Manifest is someone else's → the invariant wins.
#[test]
fn expiry_window_beats_coordinator_manifest() {
    let (coord, alice) = (key(0xC0), key(0xA0));
    let mut bundle = valid_bundle(&coord, &alice);
    bundle.expires_at = Timestamp(bundle.expires_at.0 - 1);
    resign(&mut bundle, &coord);
    let other = manifest_for(&key(0x77), 24 * 3600);
    let err = verify(&bundle, &alice, NOW, CoordinatorKeySource::Manifest(&other));
    assert!(
        matches!(err, Err(SessionBundleError::ExpiryWindowInvariant)),
        "{err:?}"
    );
}

/// Steps 4 vs 5: empty participants AND wrong coordinator Manifest →
/// empty wins.
#[test]
fn empty_participants_beats_coordinator_manifest() {
    let (coord, alice) = (key(0xC0), key(0xA0));
    let mut bundle = valid_bundle(&coord, &alice);
    bundle.participants.clear();
    resign(&mut bundle, &coord);
    let other = manifest_for(&key(0x77), 24 * 3600);
    let err = verify(&bundle, &alice, NOW, CoordinatorKeySource::Manifest(&other));
    assert!(
        matches!(err, Err(SessionBundleError::EmptyParticipants)),
        "{err:?}"
    );
}

/// Steps 5 vs 6: a Manifest for a different AID AND a corrupted bundle
/// signature → the Manifest mismatch wins.
#[test]
fn coordinator_manifest_mismatch_beats_signature() {
    let (coord, alice) = (key(0xC0), key(0xA0));
    let mut bundle = valid_bundle(&coord, &alice);
    corrupt_signature(&mut bundle);
    let other = manifest_for(&key(0x77), 24 * 3600);
    let err = verify(&bundle, &alice, NOW, CoordinatorKeySource::Manifest(&other));
    assert!(
        matches!(err, Err(SessionBundleError::CoordinatorManifestMismatch)),
        "{err:?}"
    );
}

/// Steps 5 vs 6: an expired coordinator Manifest AND a corrupted bundle
/// signature → the Manifest verification failure wins.
#[test]
fn expired_coordinator_manifest_beats_signature() {
    let (coord, alice) = (key(0xC0), key(0xA0));
    let mut bundle = valid_bundle(&coord, &alice);
    corrupt_signature(&mut bundle);
    let manifest = manifest_for(&coord, 60);
    let err = verify(
        &bundle,
        &alice,
        Timestamp(NOW.0 + 120),
        CoordinatorKeySource::Manifest(&manifest),
    );
    assert!(
        matches!(
            err,
            Err(SessionBundleError::CoordinatorManifest(
                ManifestError::Expired
            ))
        ),
        "{err:?}"
    );
}

/// Step 5: a coordinator Manifest whose own signature is broken is
/// rejected, even though the bundle itself is valid.
#[test]
fn tampered_coordinator_manifest_rejected() {
    let (coord, alice) = (key(0xC0), key(0xA0));
    let bundle = valid_bundle(&coord, &alice);
    let mut manifest = manifest_for(&coord, 24 * 3600);
    manifest.display_name = Some("tampered".into());
    let err = verify(
        &bundle,
        &alice,
        NOW,
        CoordinatorKeySource::Manifest(&manifest),
    );
    assert!(
        matches!(
            err,
            Err(SessionBundleError::CoordinatorManifest(
                ManifestError::SignatureInvalid
            ))
        ),
        "{err:?}"
    );
}

/// Step 5 → 7: the verified coordinator Manifest's `expires_at` caps each
/// embedded TCT's `exp` (RFC-AITP-0005 §10.4) — the coordinator issued them.
#[test]
fn coordinator_manifest_expiry_caps_participant_tcts() {
    let (coord, alice) = (key(0xC0), key(0xA0));
    let bundle = valid_bundle(&coord, &alice); // TCT exp = NOW + 3600
    let manifest = manifest_for(&coord, 1800);
    let err = verify(
        &bundle,
        &alice,
        NOW,
        CoordinatorKeySource::Manifest(&manifest),
    );
    assert!(
        matches!(
            err,
            Err(SessionBundleError::TctVerification(
                TctError::ExpiresAfterManifest
            ))
        ),
        "{err:?}"
    );
}

/// Steps 6 vs 7: corrupted bundle signature AND a participant TCT whose
/// `aud` is not its entry's AID → signature wins.
#[test]
fn signature_beats_participant_tct() {
    let (coord, alice, bob, carol) = (key(0xC0), key(0xA0), key(0xB0), key(0xCA));
    let mut bundle = valid_bundle(&coord, &alice);
    // Bob's entry carries a TCT addressed to Carol (same exp).
    let mut entry = bundle.participants[0].clone();
    entry.aid = bob.aid().clone();
    entry.tct = issue_tct(&coord, &carol, 3600);
    bundle.participants.push(entry);
    corrupt_signature(&mut bundle);
    let manifest = manifest_for(&coord, 24 * 3600);
    let err = verify(
        &bundle,
        &alice,
        NOW,
        CoordinatorKeySource::Manifest(&manifest),
    );
    assert!(
        matches!(err, Err(SessionBundleError::InvalidSignature)),
        "{err:?}"
    );
}

/// Steps 7 vs 8: a correctly signed bundle with a participant TCT whose
/// `aud` is not its entry's AID, verified by a NON-member → the TCT
/// failure wins; self-membership is the last check. Before #197 the
/// membership check ran ahead of the signature.
#[test]
fn participant_tct_beats_self_membership() {
    let (coord, alice, bob, carol, evan) = (key(0xC0), key(0xA0), key(0xB0), key(0xCA), key(0xEE));
    let mut bundle = valid_bundle(&coord, &alice);
    let mut entry = bundle.participants[0].clone();
    entry.aid = bob.aid().clone();
    entry.tct = issue_tct(&coord, &carol, 3600);
    bundle.participants.push(entry);
    resign(&mut bundle, &coord);
    let manifest = manifest_for(&coord, 24 * 3600);
    let err = verify(
        &bundle,
        &evan,
        NOW,
        CoordinatorKeySource::Manifest(&manifest),
    );
    assert!(
        matches!(err, Err(SessionBundleError::AudienceMismatch)),
        "{err:?}"
    );
}

/// Step 6 vs 8 (non-adjacent, but the other half of the old ordering bug):
/// a non-member presented a bundle with a broken signature gets
/// `InvalidSignature`, not `NotMember`.
#[test]
fn signature_beats_self_membership() {
    let (coord, alice, evan) = (key(0xC0), key(0xA0), key(0xEE));
    let mut bundle = valid_bundle(&coord, &alice);
    corrupt_signature(&mut bundle);
    let err = verify(
        &bundle,
        &evan,
        NOW,
        CoordinatorKeySource::UnverifiedAidDangerous,
    );
    assert!(
        matches!(err, Err(SessionBundleError::InvalidSignature)),
        "{err:?}"
    );
}

/// Step 8 alone: a valid bundle presented to a non-member.
#[test]
fn non_member_rejected_last() {
    let (coord, alice, evan) = (key(0xC0), key(0xA0), key(0xEE));
    let bundle = valid_bundle(&coord, &alice);
    let manifest = manifest_for(&coord, 24 * 3600);
    let err = verify(
        &bundle,
        &evan,
        NOW,
        CoordinatorKeySource::Manifest(&manifest),
    );
    assert!(matches!(err, Err(SessionBundleError::NotMember)), "{err:?}");
}
