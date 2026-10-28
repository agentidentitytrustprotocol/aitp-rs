//! `DelegationBuilder` accepts any `AitpSigner`: a KMS-shaped delegator
//! backend mints a delegation that verifies, and a backend signing with
//! the wrong key is refused locally.

use aitp::core::Timestamp;
use aitp::crypto::testing::{MockKmsSigner, MockOutput};
use aitp::crypto::{AitpSigner, AitpSigningKey, AitpVerifyingKey, CryptoError, SignerError};
use aitp::delegation::{verify_delegation, DelegationBuilder, DelegationError};
use aitp::tct::TctBuilder;

#[path = "delegation_common/mod.rs"]
mod common;

const NOW: Timestamp = Timestamp(1_700_000_000);

fn p256(seed: u8) -> AitpSigningKey {
    AitpSigningKey::from_p256_seed(&[seed; 32]).expect("valid P-256 scalar")
}

fn voucher_for(a: &dyn AitpSigner, b: &dyn AitpSigner) -> String {
    TctBuilder::new(a)
        .subject(b.aid().clone())
        .audience(b.aid().clone())
        .grants(["read_data", "write_data"])
        .ttl(std::time::Duration::from_secs(7200))
        .subject_pubkey(AitpVerifyingKey::from_aid(b.aid()).unwrap())
        .issued_at(NOW)
        .build()
        .unwrap()
        .voucher()
        .unwrap()
        .to_string()
}

#[test]
fn kms_delegator_mints_a_verifying_delegation() {
    let a = MockKmsSigner::new(p256(0xA1)).output(MockOutput::RandomizedDer);
    let b = MockKmsSigner::new(p256(0xB1)).output(MockOutput::DerHighS);
    let c = AitpSigningKey::from_ed25519_seed(&[0xC1; 32]);
    let token = DelegationBuilder::new(&b, &voucher_for(&a, &b))
        .unwrap()
        .delegatee(c.aid().clone())
        .scope(["read_data"])
        .ttl(std::time::Duration::from_secs(3600))
        .now(NOW)
        .build()
        .expect("KMS-backed delegation builds");
    // B's Manifest, signed through the same KMS-shaped backend.
    let manifests = vec![common::manifest_for(&b, NOW)];
    let ctx = common::verify_ctx(a.aid(), Timestamp(NOW.0 + 60), &manifests);
    let verified = verify_delegation(&token, &ctx).expect("KMS delegation verifies");
    assert_eq!(&verified.claims().iss, b.aid());
}

#[test]
fn kms_delegator_with_wrong_key_returns_signer_error() {
    let a = AitpSigningKey::from_ed25519_seed(&[0xA2; 32]);
    let b = MockKmsSigner::new(p256(0xB2)).sign_with(p256(0xB3));
    let c = AitpSigningKey::from_ed25519_seed(&[0xC2; 32]);
    let err = DelegationBuilder::new(&b, &voucher_for(&a, &b))
        .unwrap()
        .delegatee(c.aid().clone())
        .scope(["read_data"])
        .now(NOW)
        .build()
        .expect_err("wrong-key backend must fail");
    assert!(
        matches!(
            err,
            DelegationError::Crypto(CryptoError::Signer(SignerError::VerificationFailed))
        ),
        "{err:?}"
    );
}

// ---- async signing path -------------------------------------------------

use std::sync::Arc;

type MakeKey = fn(u8) -> AitpSigningKey;

/// Sync and async delegations are byte identical for deterministic keys (Ed25519; P-256 via RFC 6979 through
/// the mock's Raw and Der outputs).
#[tokio::test]
async fn async_delegations_are_byte_identical_to_sync() {
    let cases: [(MakeKey, MockOutput); 3] = [
        (
            |s| AitpSigningKey::from_ed25519_seed(&[s; 32]),
            MockOutput::Raw,
        ),
        (p256, MockOutput::Raw),
        (p256, MockOutput::Der),
    ];
    for (make, output) in cases {
        let a = make(0xA3);
        let b = make(0xB4);
        let c = make(0xC4);
        let voucher = voucher_for(&a, &b);

        let sync1 = DelegationBuilder::new(&b, &voucher)
            .unwrap()
            .delegatee(c.aid().clone())
            .scope(["read_data"])
            .now(NOW)
            .build()
            .unwrap();
        let b_kms = MockKmsSigner::new(make(0xB4)).output(output);
        let async1 = DelegationBuilder::new_async(&b_kms, &voucher)
            .unwrap()
            .delegatee(c.aid().clone())
            .scope(["read_data"])
            .now(NOW)
            .build_async()
            .await
            .unwrap();
        assert_eq!(sync1, async1);
        assert_eq!(b_kms.calls(), 1);
    }
}

#[tokio::test]
async fn async_constructors_validate_like_sync() {
    let a = AitpSigningKey::from_ed25519_seed(&[0xA5; 32]);
    let b = AitpSigningKey::from_ed25519_seed(&[0xB5; 32]);
    let stranger = MockKmsSigner::new(AitpSigningKey::from_ed25519_seed(&[0xE5; 32]));
    let voucher = voucher_for(&a, &b);
    assert!(matches!(
        DelegationBuilder::new_async(&stranger, &voucher).err(),
        Some(DelegationError::InvalidVoucher)
    ));
}

#[tokio::test]
async fn async_wrong_key_backend_returns_signer_error() {
    let a = AitpSigningKey::from_ed25519_seed(&[0xA6; 32]);
    let b = MockKmsSigner::new(p256(0xB6)).sign_with(p256(0xB7));
    let c = AitpSigningKey::from_ed25519_seed(&[0xC6; 32]);
    let err = DelegationBuilder::new_async(&b, &voucher_for(&a, &b))
        .unwrap()
        .delegatee(c.aid().clone())
        .scope(["read_data"])
        .now(NOW)
        .build_async()
        .await
        .expect_err("wrong-key backend must fail");
    assert!(
        matches!(
            err,
            DelegationError::Crypto(CryptoError::Signer(SignerError::VerificationFailed))
        ),
        "{err:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn async_delegation_future_is_send() {
    let a = AitpSigningKey::from_ed25519_seed(&[0xA7; 32]);
    let b_kms = MockKmsSigner::new(p256(0xB8)).output(MockOutput::RandomizedDer);
    let b_aid = b_kms.aid().clone();
    let manifests = vec![common::manifest_for(&b_kms, NOW)];
    let voucher = voucher_for(&a, &b_kms);
    let b: Arc<dyn aitp::crypto::DynAsyncAitpSigner> = Arc::new(b_kms);
    let c = AitpSigningKey::from_ed25519_seed(&[0xC7; 32]);
    let c_aid = c.aid().clone();
    // tokio::spawn requires the future to be Send + 'static.
    let token = tokio::spawn(async move {
        DelegationBuilder::new_async(&*b, &voucher)?
            .delegatee(c_aid)
            .scope(["read_data"])
            .now(NOW)
            .build_async()
            .await
    })
    .await
    .unwrap()
    .expect("async delegation builds on another task");
    let ctx = common::verify_ctx(a.aid(), Timestamp(NOW.0 + 60), &manifests);
    let verified = verify_delegation(&token, &ctx).expect("verifies");
    assert_eq!(verified.claims().iss, b_aid);
}
