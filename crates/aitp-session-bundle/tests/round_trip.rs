//! End-to-end Session Trust Bundle issuance + verification
//! (RFC-AITP-0010).
//!
//! Topology: coordinator + 3 participants (Alice, Bob, Carol). Each
//! participant has a coordinator-issued TCT from their bilateral
//! handshake; the coordinator collects all three into a bundle and
//! distributes it. Any participant can verify the bundle and learn
//! the full session roster.

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_session_bundle::{
    verify_session_bundle, BundleOutcome, SessionBundleBuilder, SessionBundleError,
    VerifySessionBundleContext,
};
use aitp_tct::TctBuilder;
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

fn key(seed: u8) -> AitpSigningKey {
    AitpSigningKey::from_seed(&[seed; 32])
}

fn issue_tct(coord: &AitpSigningKey, holder: &AitpSigningKey, ttl_secs: i64) -> String {
    TctBuilder::new(coord)
        .subject(holder.aid().clone())
        .audience(holder.aid().clone())
        .grants(["session.participate"])
        .ttl_secs(ttl_secs)
        .subject_pubkey(holder.verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
        .token
}

#[test]
fn happy_path_three_participants() {
    let coord = key(0xC0);
    let alice = key(0xA0);
    let bob = key(0xB0);
    let carol = key(0xCA);

    let tct_a = issue_tct(&coord, &alice, 3600);
    let tct_b = issue_tct(&coord, &bob, 3600);
    let tct_c = issue_tct(&coord, &carol, 3600);

    let bundle = SessionBundleBuilder::new(&coord)
        .session_id(Uuid::parse_str("00000000-0000-4000-8000-000000000000").unwrap())
        .issued_at(NOW)
        .participant(alice.aid().clone(), tct_a)
        .participant(bob.aid().clone(), tct_b)
        .participant(carol.aid().clone(), tct_c)
        .build()
        .unwrap();

    // Each participant verifies and sees the full roster.
    for me in [alice.aid(), bob.aid(), carol.aid()] {
        let ctx = VerifySessionBundleContext {
            verifier_aid: me,
            now: NOW,
            revocation_check: None,
        };
        let outcome = verify_session_bundle(&bundle, &ctx).unwrap();
        match outcome {
            BundleOutcome::Clear { active_aids } => {
                assert_eq!(active_aids.len(), 3);
                assert!(active_aids.contains(alice.aid()));
                assert!(active_aids.contains(bob.aid()));
                assert!(active_aids.contains(carol.aid()));
            }
            other => panic!("expected Clear, got {other:?}"),
        }
    }
}

#[test]
fn non_member_rejected() {
    let coord = key(0xC0);
    let alice = key(0xA0);
    let bob = key(0xB0);
    let evan = key(0xEE); // not a participant

    let bundle = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .participant(alice.aid().clone(), issue_tct(&coord, &alice, 3600))
        .participant(bob.aid().clone(), issue_tct(&coord, &bob, 3600))
        .build()
        .unwrap();

    let ctx = VerifySessionBundleContext {
        verifier_aid: evan.aid(),
        now: NOW,
        revocation_check: None,
    };
    let err = verify_session_bundle(&bundle, &ctx).unwrap_err();
    assert!(matches!(err, SessionBundleError::NotMember));
}

#[test]
fn expired_bundle_rejected() {
    let coord = key(0xC0);
    let alice = key(0xA0);
    let tct_a = issue_tct(&coord, &alice, 100); // 100s TTL
    let bundle = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .participant(alice.aid().clone(), tct_a)
        .build()
        .unwrap();
    // Pretend a year has passed.
    let ctx = VerifySessionBundleContext {
        verifier_aid: alice.aid(),
        now: Timestamp(NOW.0 + 3600 * 24 * 365),
        revocation_check: None,
    };
    let err = verify_session_bundle(&bundle, &ctx).unwrap_err();
    assert!(matches!(err, SessionBundleError::Expired));
}

#[test]
fn tampered_signature_rejected() {
    let coord = key(0xC0);
    let alice = key(0xA0);
    let mut bundle = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .participant(alice.aid().clone(), issue_tct(&coord, &alice, 3600))
        .build()
        .unwrap();
    // Flip a bit in the bundle signature.
    let mut sig = bundle.signature.into_bytes();
    sig[0] = if sig[0] == b'A' { b'B' } else { b'A' };
    bundle.signature = String::from_utf8(sig).unwrap();
    let ctx = VerifySessionBundleContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
    };
    let err = verify_session_bundle(&bundle, &ctx).unwrap_err();
    assert!(matches!(err, SessionBundleError::InvalidSignature));
}

#[test]
fn revoked_participant_degrades_subset() {
    let coord = key(0xC0);
    let alice = key(0xA0);
    let bob = key(0xB0);
    let carol = key(0xCA);
    let tct_a = issue_tct(&coord, &alice, 3600);
    let tct_b = issue_tct(&coord, &bob, 3600);
    let tct_c = issue_tct(&coord, &carol, 3600);
    let bob_claims: aitp_tct::TctClaims =
        serde_json::from_slice(&aitp_crypto::jws::decode_payload_unverified(&tct_b).unwrap())
            .unwrap();
    let bob_jti = bob_claims.jti;
    let bundle = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .participant(alice.aid().clone(), tct_a)
        .participant(bob.aid().clone(), tct_b)
        .participant(carol.aid().clone(), tct_c)
        .build()
        .unwrap();
    let revoke = |jti: &Uuid| *jti == bob_jti;
    let ctx = VerifySessionBundleContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: Some(&revoke),
    };
    match verify_session_bundle(&bundle, &ctx).unwrap() {
        BundleOutcome::DegradedSubset {
            active_aids,
            dropped_aids,
        } => {
            assert_eq!(dropped_aids, vec![bob.aid().clone()]);
            assert_eq!(active_aids.len(), 2);
            assert!(active_aids.contains(alice.aid()));
            assert!(active_aids.contains(carol.aid()));
        }
        other => panic!("expected DegradedSubset, got {other:?}"),
    }
}

#[test]
fn empty_participants_rejected_at_build() {
    let coord = key(0xC0);
    let err = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .build()
        .unwrap_err();
    assert!(matches!(err, SessionBundleError::EmptyParticipants));
}

#[test]
fn audience_mismatch_rejected_at_build() {
    let coord = key(0xC0);
    let alice = key(0xA0);
    let bob = key(0xB0);
    // TCT issued to bob but listed under alice's aid.
    let tct_b = issue_tct(&coord, &bob, 3600);
    let err = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .participant(alice.aid().clone(), tct_b)
        .build()
        .unwrap_err();
    assert!(matches!(err, SessionBundleError::AudienceMismatch));
}

// ── Ordering guard: the pre-signature exp peek cannot bypass the
//    outer signature (RFC-AITP-0010 verify steps 3–6).
//
// `verify_session_bundle` peeks each participant TCT's `exp`
// (unverified) to compute the expiry-window invariant *before* the
// outer bundle signature is checked. That is sound only because the
// outer signature covers the participant TCT strings verbatim, so any
// tampering that changes a peeked value also breaks the signature.
// This test pins that property: mutating a participant TCT inside a
// built bundle must be rejected, never silently accepted via the peek.
#[test]
fn tampered_participant_tct_cannot_bypass_via_peek() {
    let coord = key(0xC0);
    let alice = key(0xA0);
    let bob = key(0xB0);

    let mut bundle = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .participant(alice.aid().clone(), issue_tct(&coord, &alice, 3600))
        .participant(bob.aid().clone(), issue_tct(&coord, &bob, 7200))
        .build()
        .unwrap();

    // Mutate a byte inside the first participant's TCT payload segment
    // (between the two dots) — this is exactly the region the peek
    // decodes for `exp`. It must not verify.
    let tct = &bundle.participants[0].tct;
    let dot1 = tct.find('.').unwrap();
    let dot2 = tct[dot1 + 1..].find('.').unwrap() + dot1 + 1;
    let mut bytes = tct.clone().into_bytes();
    let mid = (dot1 + dot2) / 2;
    bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
    bundle.participants[0].tct = String::from_utf8(bytes).unwrap();

    let ctx = VerifySessionBundleContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
    };
    let err = verify_session_bundle(&bundle, &ctx).unwrap_err();
    // Rejected — the tampered peek value can never yield acceptance.
    // Any of these defensive layers may fire first depending on where
    // the mutated byte lands: the peek's own claim decode
    // (`Canonicalization`), the expiry-window invariant, the outer
    // signature (which covers the participant strings), or the
    // per-participant TCT verification.
    assert!(
        matches!(
            err,
            SessionBundleError::InvalidSignature
                | SessionBundleError::TctVerification(_)
                | SessionBundleError::ExpiryWindowInvariant
                | SessionBundleError::Canonicalization(_)
        ),
        "tampered participant TCT must be rejected, got {err:?}"
    );
}
