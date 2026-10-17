//! `SessionBundleBuilder` accepts any `AitpSigner`: a KMS-shaped
//! coordinator backend signs a bundle that verifies, and a backend
//! signing with the wrong key is refused locally.

use aitp_core::Timestamp;
use aitp_crypto::testing::{MockKmsSigner, MockOutput};
use aitp_crypto::{AitpSigner, AitpSigningKey, CryptoError, SignerError};
use aitp_session_bundle::{
    verify_session_bundle, BundleOutcome, SessionBundleBuilder, SessionBundleError,
    VerifySessionBundleContext,
};
use aitp_tct::TctBuilder;

const NOW: Timestamp = Timestamp(1_700_000_000);

fn p256(seed: u8) -> AitpSigningKey {
    AitpSigningKey::from_p256_seed(&[seed; 32]).expect("valid P-256 scalar")
}

fn issue_tct(coord: &dyn AitpSigner, holder: &AitpSigningKey) -> String {
    TctBuilder::new(coord)
        .subject(holder.aid().clone())
        .audience(holder.aid().clone())
        .grants(["session.participate"])
        .ttl_secs(3600)
        .subject_pubkey(holder.verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
        .token
}

#[test]
fn kms_coordinator_signs_a_verifying_bundle() {
    let coord = MockKmsSigner::new(p256(0xC0)).output(MockOutput::DerHighS);
    let alice = AitpSigningKey::from_seed(&[0xA0; 32]);
    let bundle = SessionBundleBuilder::new(&coord)
        .issued_at(NOW)
        .participant(alice.aid().clone(), issue_tct(&coord, &alice))
        .build()
        .expect("KMS-backed bundle builds");
    let ctx = VerifySessionBundleContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
    };
    match verify_session_bundle(&bundle, &ctx).expect("KMS bundle verifies") {
        BundleOutcome::Clear { active_aids } => assert_eq!(active_aids, vec![alice.aid().clone()]),
        other => panic!("expected Clear, got {other:?}"),
    }
}

#[test]
fn kms_coordinator_with_wrong_key_returns_signer_error() {
    let real = MockKmsSigner::new(p256(0xC1));
    let bad = MockKmsSigner::new(p256(0xC1)).sign_with(p256(0xC2));
    let alice = AitpSigningKey::from_seed(&[0xA1; 32]);
    let err = SessionBundleBuilder::new(&bad)
        .issued_at(NOW)
        .participant(alice.aid().clone(), issue_tct(&real, &alice))
        .build()
        .expect_err("wrong-key backend must fail");
    assert!(
        matches!(
            err,
            SessionBundleError::Crypto(CryptoError::Signer(SignerError::VerificationFailed))
        ),
        "{err:?}"
    );
}

// ---- async signing path -------------------------------------------------

use std::sync::Arc;

const SESSION: &str = "770e8400-e29b-41d4-a716-446655440a01";

/// Sync and async bundles are byte identical for deterministic keys
/// (Ed25519; P-256 via RFC 6979 through the mock's Raw and Der outputs).
#[tokio::test]
async fn async_bundle_is_byte_identical_to_sync() {
    let session = uuid::Uuid::parse_str(SESSION).unwrap();
    let cases: [(fn() -> AitpSigningKey, MockOutput); 3] = [
        (|| AitpSigningKey::from_seed(&[0xC3; 32]), MockOutput::Raw),
        (|| p256(0xC4), MockOutput::Raw),
        (|| p256(0xC5), MockOutput::Der),
    ];
    for (make, output) in cases {
        let coord = make();
        let alice = AitpSigningKey::from_seed(&[0xA2; 32]);
        let tct = issue_tct(&coord, &alice);
        let sync = SessionBundleBuilder::new(&coord)
            .session_id(session)
            .issued_at(NOW)
            .participant(alice.aid().clone(), tct.clone())
            .build()
            .unwrap();
        let kms = MockKmsSigner::new(make()).output(output);
        let asyn = SessionBundleBuilder::new_async(&kms)
            .session_id(session)
            .issued_at(NOW)
            .participant(alice.aid().clone(), tct)
            .build_async()
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_vec(&sync).unwrap(),
            serde_json::to_vec(&asyn).unwrap()
        );
        assert_eq!(kms.calls(), 1);
    }
}

#[tokio::test]
async fn async_build_validates_like_sync() {
    let kms = MockKmsSigner::new(p256(0xC6));
    let err = SessionBundleBuilder::new_async(&kms)
        .build_async()
        .await
        .unwrap_err();
    assert!(
        matches!(err, SessionBundleError::EmptyParticipants),
        "{err:?}"
    );
    assert_eq!(kms.calls(), 0, "validation runs before the backend");
}

#[tokio::test]
async fn async_wrong_key_backend_returns_signer_error() {
    let real = MockKmsSigner::new(p256(0xC7));
    let bad = MockKmsSigner::new(p256(0xC7)).sign_with(p256(0xC8));
    let alice = AitpSigningKey::from_seed(&[0xA3; 32]);
    let err = SessionBundleBuilder::new_async(&bad)
        .issued_at(NOW)
        .participant(alice.aid().clone(), issue_tct(&real, &alice))
        .build_async()
        .await
        .expect_err("wrong-key backend must fail");
    assert!(
        matches!(
            err,
            SessionBundleError::Crypto(CryptoError::Signer(SignerError::VerificationFailed))
        ),
        "{err:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn async_bundle_future_is_send() {
    let kms = MockKmsSigner::new(p256(0xC9)).output(MockOutput::RandomizedDer);
    let alice = AitpSigningKey::from_seed(&[0xA4; 32]);
    let tct = issue_tct(&kms, &alice);
    let alice_aid = alice.aid().clone();
    let coord: Arc<dyn aitp_crypto::DynAsyncAitpSigner> = Arc::new(kms);
    // tokio::spawn requires the future to be Send + 'static.
    let bundle = tokio::spawn(async move {
        SessionBundleBuilder::new_async(&*coord)
            .issued_at(NOW)
            .participant(alice_aid, tct)
            .build_async()
            .await
    })
    .await
    .unwrap()
    .expect("async bundle builds on another task");
    let ctx = VerifySessionBundleContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
    };
    verify_session_bundle(&bundle, &ctx).expect("verifies");
}
