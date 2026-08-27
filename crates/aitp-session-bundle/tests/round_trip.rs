//! End-to-end Session Trust Bundle issuance + verification
//! (RFC-AITP-0010).
//!
//! Topology: coordinator + 3 participants (Alice, Bob, Carol). Each
//! participant has a coordinator-issued TCT from their bilateral
//! handshake; the coordinator collects all three into a bundle and
//! distributes it. Any participant can verify the bundle and learn
//! the full session roster.

use aitp_core::{jcs, ExtensionsMap, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_session_bundle::{
    verify_session_bundle, BundleOutcome, SessionBundleBuilder, SessionBundleError,
    SessionTrustBundle, VerifySessionBundleContext,
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

/// A bundle whose outer signature was computed over the legacy WRAPPED
/// `{"session_bundle": {…}}` form must be rejected.
///
/// RFC-AITP-0010 grants no transition window (unlike RFC-AITP-0008 §1.5 for
/// revocation), and per DECISIONS.md D1 this repo implements no dual-accept
/// for either artifact. RFC-AITP-0010 §5 step 6 requires
/// `BUNDLE_INVALID_SIGNATURE` here.
#[test]
fn wrapped_signed_bundle_is_rejected() {
    use aitp_core::jcs;
    use sha2::{Digest, Sha256};

    let coord = key(0xC0);
    let alice = key(0xA0);
    let mut bundle = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .participant(alice.aid().clone(), issue_tct(&coord, &alice, 3600))
        .build()
        .unwrap();

    // Re-sign over the wrapped form: serialize the bundle, drop `signature`,
    // wrap in the transport key, and sign that.
    let mut body = serde_json::to_value(&bundle).unwrap();
    body.as_object_mut().unwrap().remove("signature");
    let wrapped = serde_json::json!({ "session_bundle": body });
    let canonical = jcs::canonicalize(&wrapped).unwrap();
    bundle.signature = coord.sign(&Sha256::digest(&canonical)).into_string();

    let ctx = VerifySessionBundleContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
    };
    let err = verify_session_bundle(&bundle, &ctx).unwrap_err();
    assert!(
        matches!(err, SessionBundleError::InvalidSignature),
        "a wrapped-signed bundle must be rejected; got {err:?}"
    );
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

#[test]
fn foreign_issued_tct_rejected_at_build() {
    // A participant TCT minted by someone *other* than the coordinator
    // (correct audience, wrong issuer) must be caught when the
    // coordinator assembles the bundle — the coordinator only vouches
    // for TCTs it issued (RFC-AITP-0010 §3, verify step 7).
    let coord = key(0xC0);
    let rogue = key(0x99); // not the coordinator
    let alice = key(0xA0);

    // iss == rogue, aud == alice; listed under alice's (correct) aid so
    // the issuer check fires before the audience check.
    let tct_a = issue_tct(&rogue, &alice, 3600);
    let err = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .participant(alice.aid().clone(), tct_a)
        .build()
        .unwrap_err();
    assert!(matches!(err, SessionBundleError::CoordinatorIssuerMismatch));
}

#[test]
fn version_mismatch_rejected() {
    // The version gate is verify step 1 — it fires before the outer
    // signature is even checked, so a downgraded/foreign `version`
    // string is rejected regardless of signature validity.
    let coord = key(0xC0);
    let alice = key(0xA0);
    let mut bundle = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .participant(alice.aid().clone(), issue_tct(&coord, &alice, 3600))
        .build()
        .unwrap();
    bundle.version = "aitp/0.1".into();

    let ctx = VerifySessionBundleContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
    };
    let err = verify_session_bundle(&bundle, &ctx).unwrap_err();
    assert!(matches!(err, SessionBundleError::VersionMismatch));
}

// ── `extensions` (RFC-AITP-0001 §7, issue #87) ──────────────────────

/// A bundle carrying a populated `extensions` object round-trips
/// (deserialize → re-serialize → JCS-canonicalize produces byte-identical
/// output to the input's canonical form), and its signature still
/// verifies.
#[test]
fn populated_extensions_round_trip_and_signature_verifies() {
    let coord = key(0xC0);
    let alice = key(0xA0);

    let mut extensions = ExtensionsMap::new();
    extensions.insert(
        "vendor.example/feature",
        serde_json::json!({"enabled": true}),
    );

    let bundle = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .extensions(extensions)
        .participant(alice.aid().clone(), issue_tct(&coord, &alice, 3600))
        .build()
        .unwrap();

    // Serialize -> canonicalize once (the "input's canonical form").
    let original_value = serde_json::to_value(&bundle).unwrap();
    let original_canonical = jcs::canonicalize(&original_value).unwrap();

    // Deserialize -> re-serialize -> canonicalize again.
    let round_tripped: SessionTrustBundle = serde_json::from_value(original_value).unwrap();
    assert_eq!(round_tripped, bundle);
    let round_tripped_value = serde_json::to_value(&round_tripped).unwrap();
    let round_tripped_canonical = jcs::canonicalize(&round_tripped_value).unwrap();

    assert_eq!(
        original_canonical, round_tripped_canonical,
        "populated extensions must canonicalize identically before and after a round-trip"
    );

    let ctx = VerifySessionBundleContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
    };
    let outcome = verify_session_bundle(&round_tripped, &ctx).unwrap();
    assert!(matches!(outcome, BundleOutcome::Clear { .. }));
}

/// Absent `extensions` and present-but-empty `extensions` (`{}`) MUST
/// canonicalize to different byte strings, and each must round-trip
/// back to its own original form. This is the test that catches the
/// "defaulted empty map" trap: an implementation that silently
/// normalizes `None` and `Some(ExtensionsMap::new())` into each other
/// would pass every other test here but fail this one.
#[test]
fn absent_vs_present_empty_extensions_are_distinguishable_and_stable() {
    let coord = key(0xC0);
    let alice = key(0xA0);

    let bundle_absent = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .participant(alice.aid().clone(), issue_tct(&coord, &alice, 3600))
        .build()
        .unwrap();
    assert!(bundle_absent.extensions.is_none());

    let bundle_empty = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .extensions(ExtensionsMap::new())
        .participant(alice.aid().clone(), issue_tct(&coord, &alice, 3600))
        .build()
        .unwrap();
    assert!(bundle_empty.extensions.is_some());

    let absent_value = serde_json::to_value(&bundle_absent).unwrap();
    let empty_value = serde_json::to_value(&bundle_empty).unwrap();

    // No `extensions` key at all when absent.
    assert!(absent_value.get("extensions").is_none());
    // An explicit `"extensions":{}` when present-but-empty.
    assert_eq!(empty_value.get("extensions"), Some(&serde_json::json!({})));

    let absent_canonical = jcs::canonicalize(&absent_value).unwrap();
    let empty_canonical = jcs::canonicalize(&empty_value).unwrap();
    assert_ne!(
        absent_canonical, empty_canonical,
        "absent and present-but-empty extensions must canonicalize to DIFFERENT bytes"
    );

    // Each is stable under its own round-trip.
    let absent_rt: SessionTrustBundle = serde_json::from_value(absent_value).unwrap();
    assert_eq!(absent_rt, bundle_absent);
    assert!(absent_rt.extensions.is_none());

    let empty_rt: SessionTrustBundle = serde_json::from_value(empty_value).unwrap();
    assert_eq!(empty_rt, bundle_empty);
    assert!(empty_rt.extensions.is_some());
}

/// Unknown keys *inside* `extensions` are preserved through a
/// round-trip (RFC-AITP-0001 §7: unknown keys inside `extensions` MUST
/// be ignored semantically, but the bytes must survive so the signature
/// — computed over exactly these bytes — still verifies).
#[test]
fn unknown_keys_inside_extensions_are_preserved_through_round_trip() {
    let coord = key(0xC0);
    let alice = key(0xA0);

    let mut extensions = ExtensionsMap::new();
    extensions.insert(
        "vendor.example/future-feature",
        serde_json::json!({
            "unknown_nested_field": "some value",
            "another_unknown": [1, 2, 3],
        }),
    );

    let bundle = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .extensions(extensions)
        .participant(alice.aid().clone(), issue_tct(&coord, &alice, 3600))
        .build()
        .unwrap();

    let value = serde_json::to_value(&bundle).unwrap();
    let round_tripped: SessionTrustBundle = serde_json::from_value(value).unwrap();

    assert_eq!(round_tripped, bundle);
    assert_eq!(
        round_tripped
            .extensions
            .as_ref()
            .and_then(|e| e.get("vendor.example/future-feature")),
        Some(&serde_json::json!({
            "unknown_nested_field": "some value",
            "another_unknown": [1, 2, 3],
        }))
    );

    // Verification still succeeds — unknown keys inside `extensions`
    // are opaque payload, not a parse/verify failure.
    let ctx = VerifySessionBundleContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
    };
    let outcome = verify_session_bundle(&round_tripped, &ctx).unwrap();
    assert!(matches!(outcome, BundleOutcome::Clear { .. }));
}

/// Regression guard: existing bundles with no `extensions` continue to
/// verify unchanged now that the field exists on the struct.
#[test]
fn bundle_without_extensions_still_verifies_unchanged() {
    let coord = key(0xC0);
    let alice = key(0xA0);
    let bundle = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .participant(alice.aid().clone(), issue_tct(&coord, &alice, 3600))
        .build()
        .unwrap();

    assert!(bundle.extensions.is_none());
    let value = serde_json::to_value(&bundle).unwrap();
    assert!(
        value.get("extensions").is_none(),
        "no extensions key should be emitted when unset"
    );

    let ctx = VerifySessionBundleContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
    };
    let outcome = verify_session_bundle(&bundle, &ctx).unwrap();
    assert!(matches!(outcome, BundleOutcome::Clear { .. }));
}
