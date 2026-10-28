//! The TCT signing APIs accept any `AitpSigner`, not just an in-process
//! key: a KMS-shaped backend (DER, high-S, randomized nonces) mints
//! artifacts that verify, and a backend signing with the wrong key is
//! refused locally with `CryptoError::Signer(VerificationFailed)`.

use aitp::core::{base64url, Timestamp};
use aitp::crypto::testing::{MockKmsSigner, MockOutput};
use aitp::crypto::{AitpSigner, AitpSigningKey, AitpVerifyingKey, CryptoError, SignerError};
use aitp::tct::{
    sign_pop_response, sign_revocation_list, verify_pop_response, verify_revocation_list,
    verify_tct, PopChallenge, RevocationList, TctBuilder, TctError, TctVerifyContext,
    VerifyRevocationListContext,
};

fn p256(seed: u8) -> AitpSigningKey {
    AitpSigningKey::from_p256_seed(&[seed; 32]).expect("valid P-256 scalar")
}

fn issue(
    issuer: &dyn AitpSigner,
    subject: &AitpSigningKey,
    now: Timestamp,
) -> Result<aitp::tct::IssuedTct, TctError> {
    TctBuilder::new(issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["demo.echo"])
        .ttl_secs(3600)
        .subject_pubkey(subject.verifying_key())
        .issued_at(now)
        .build()
}

#[test]
fn kms_backend_with_der_high_s_mints_a_verifying_tct() {
    let now = Timestamp(1_700_000_000);
    let kms = MockKmsSigner::new(p256(0x21)).output(MockOutput::DerHighS);
    let subject = AitpSigningKey::from_ed25519_seed(&[0x22; 32]);
    let issued = issue(&kms, &subject, now).expect("KMS-backed TctBuilder builds");
    assert!(kms.calls() >= 1, "the backend was actually used");
    let ctx = TctVerifyContext::builder(subject.aid(), kms.aid(), now)
        .revocation(aitp::tct::RevocationSource::FailOpen)
        .skip_manifest_expiry_cap_dangerous()
        .build()
        .unwrap();
    verify_tct(&issued.token, &ctx).expect("KMS-minted TCT verifies");
}

#[test]
fn kms_backend_signing_with_wrong_key_is_refused_locally() {
    let now = Timestamp(1_700_000_000);
    let kms = MockKmsSigner::new(p256(0x31)).sign_with(p256(0x32));
    let subject = AitpSigningKey::from_ed25519_seed(&[0x33; 32]);
    let err = issue(&kms, &subject, now).expect_err("wrong-key backend must fail");
    assert!(
        matches!(
            err,
            TctError::Crypto(CryptoError::Signer(SignerError::VerificationFailed))
        ),
        "{err:?}"
    );
}

fn holder_tct(
    issuer: &dyn AitpSigner,
    holder: &dyn AitpSigner,
    now: Timestamp,
) -> aitp::tct::IssuedTct {
    let holder_aid = holder.aid().clone();
    TctBuilder::new(issuer)
        .subject(holder_aid.clone())
        .audience(holder_aid.clone())
        .grants(["demo.echo"])
        .ttl_secs(3600)
        .subject_pubkey(AitpVerifyingKey::from_aid(&holder_aid).unwrap())
        .issued_at(now)
        .build()
        .expect("KMS TCT")
}

#[test]
fn kms_backend_signs_pop_response_and_revocation_list() {
    let now = Timestamp(1_700_000_000);
    let issuer = MockKmsSigner::new(p256(0x41)).output(MockOutput::RandomizedDer);
    let holder = MockKmsSigner::new(p256(0x42)).output(MockOutput::DerHighS);
    let issued = holder_tct(&issuer, &holder, now);

    let challenge = PopChallenge::new(
        issued.claims.jti,
        base64url::encode(&[7u8; 16]),
        Timestamp(now.0 + 60),
    );
    let resp = sign_pop_response(&challenge, &holder).expect("KMS PoP signs");
    verify_pop_response(&challenge, &resp, &issued.claims, now).expect("KMS PoP verifies");

    let body = RevocationList::new(issuer.aid().clone(), now, Timestamp(now.0 + 600), vec![]);
    let env = sign_revocation_list(body, &issuer).expect("KMS revocation list signs");
    verify_revocation_list(&env, &VerifyRevocationListContext::new(issuer.aid(), now))
        .expect("KMS revocation list verifies");

    let bad = MockKmsSigner::new(p256(0x43)).sign_with(p256(0x44));
    let err = sign_pop_response(&challenge, &bad).expect_err("wrong-key PoP refused");
    assert!(
        matches!(
            err,
            TctError::Crypto(CryptoError::Signer(SignerError::VerificationFailed))
        ),
        "{err:?}"
    );
}

// Spelled out so the signature itself asserts the future is `Send`.
#[allow(clippy::manual_async_fn)]
fn issue_async(
    issuer: std::sync::Arc<dyn aitp::crypto::DynAsyncAitpSigner>,
    subject: AitpSigningKey,
    now: Timestamp,
) -> impl std::future::Future<Output = Result<aitp::tct::IssuedTct, TctError>> + Send {
    async move {
        TctBuilder::new_async(&*issuer)
            .subject(subject.aid().clone())
            .audience(subject.aid().clone())
            .grants(["demo.echo"])
            .ttl_secs(3600)
            .subject_pubkey(subject.verifying_key())
            .issued_at(now)
            .build_async()
            .await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn async_kms_backend_mints_tct_and_voucher_on_another_task() {
    let now = Timestamp(1_700_000_000);
    let kms = std::sync::Arc::new(MockKmsSigner::new(p256(0x51)).output(MockOutput::RandomizedDer));
    let subject = AitpSigningKey::from_ed25519_seed(&[0x52; 32]);
    // tokio::spawn proves the build_async future is Send + 'static-able.
    let issued = tokio::spawn(issue_async(
        kms.clone(),
        AitpSigningKey::from_ed25519_seed(&[0x52; 32]),
        now,
    ))
    .await
    .unwrap()
    .expect("async KMS-backed build");
    assert_eq!(kms.calls(), 2, "TCT and voucher, one backend call each");
    let ctx = TctVerifyContext::builder(subject.aid(), AitpSigner::aid(&*kms), now)
        .revocation(aitp::tct::RevocationSource::FailOpen)
        .skip_manifest_expiry_cap_dangerous()
        .build()
        .unwrap();
    verify_tct(&issued.token, &ctx).expect("verifies");
    assert!(issued.voucher.is_some());
}

#[tokio::test]
async fn async_build_matches_sync_build_for_deterministic_keys() {
    let now = Timestamp(1_700_000_000);
    let jti = uuid::Uuid::parse_str("770e8400-e29b-41d4-a716-446655440702").unwrap();
    let subject = AitpSigningKey::from_ed25519_seed(&[0x62; 32]);
    let issuers: [fn() -> AitpSigningKey; 2] = [
        || AitpSigningKey::from_ed25519_seed(&[0x61; 32]),
        || p256(0x63),
    ];
    for make in issuers {
        let issuer = make();
        let sync = TctBuilder::new(&issuer)
            .subject(subject.aid().clone())
            .audience(subject.aid().clone())
            .grants(["demo.echo"])
            .subject_pubkey(subject.verifying_key())
            .issued_at(now)
            .jti(jti)
            .build()
            .unwrap();
        let kms = MockKmsSigner::new(make());
        let asyn = TctBuilder::new_async(&kms)
            .subject(subject.aid().clone())
            .audience(subject.aid().clone())
            .grants(["demo.echo"])
            .subject_pubkey(subject.verifying_key())
            .issued_at(now)
            .jti(jti)
            .build_async()
            .await
            .unwrap();
        assert_eq!(sync.token, asyn.token);
        assert_eq!(sync.voucher, asyn.voucher);
    }
}

#[tokio::test]
async fn async_wrong_key_backend_refused() {
    let kms = MockKmsSigner::new(p256(0x71)).sign_with(p256(0x72));
    let subject = AitpSigningKey::from_ed25519_seed(&[0x73; 32]);
    let err = TctBuilder::new_async(&kms)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["demo.echo"])
        .subject_pubkey(subject.verifying_key())
        .build_async()
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            TctError::Crypto(CryptoError::Signer(SignerError::VerificationFailed))
        ),
        "{err:?}"
    );
}
