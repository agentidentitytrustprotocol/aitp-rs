//! Renewal accepts any `AitpSigner`: a KMS-shaped issuer (DER, high-S)
//! mints a renewed TCT that verifies, and an issuer backend signing
//! with the wrong key is a local fault.

use aitp::core::nonce_store::InMemoryNonceStore;
use aitp::core::{base64url, Timestamp};
use aitp::crypto::testing::{MockKmsSigner, MockOutput};
use aitp::crypto::{AitpSigner, AitpSigningKey, AitpVerifyingKey};
use aitp::tct::{verify_tct, IssuedTct, TctBuilder, TctVerifyContext};
use aitp_experimental::renewal::{
    build_renewal_request, process_renewal_request, RenewalContext, RenewalError,
};

fn p256(seed: u8) -> AitpSigningKey {
    AitpSigningKey::from_p256_seed(&[seed; 32]).expect("valid P-256 scalar")
}

fn holder_tct(issuer: &dyn AitpSigner, holder: &dyn AitpSigner, now: Timestamp) -> IssuedTct {
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

async fn renew(
    issuer: &dyn AitpSigner,
    holder: &dyn AitpSigner,
    current: String,
    now: Timestamp,
) -> Result<IssuedTct, RenewalError> {
    let req = build_renewal_request(holder, current, base64url::encode(&[9u8; 16]))
        .expect("KMS renewal request");
    let store = InMemoryNonceStore::new(4);
    let offered = vec!["demo.echo".to_string()];
    let not_revoked = |_: &aitp::tct::RevocationQuery<'_>| Ok(aitp::tct::RevocationStatus::Clear);
    let ctx = RenewalContext::new(
        Timestamp(now.0 + 7200),
        &offered,
        aitp::tct::RevocationSource::Check(&not_revoked),
        &store,
        now,
    )
    .ttl_secs(600);
    process_renewal_request(&req, issuer, &ctx).await
}

#[tokio::test]
async fn kms_backend_signs_renewal() {
    let now = Timestamp(1_700_000_000);
    let issuer = MockKmsSigner::new(p256(0x51)).output(MockOutput::DerHighS);
    let holder = MockKmsSigner::new(p256(0x52));
    let issued = holder_tct(&issuer, &holder, now);
    let renewed = renew(&issuer, &holder, issued.token, now)
        .await
        .expect("KMS renewal");
    let ctx = TctVerifyContext::builder(holder.aid(), issuer.aid(), now)
        .revocation(aitp::tct::RevocationSource::FailOpen)
        .skip_manifest_expiry_cap_dangerous()
        .build()
        .unwrap();
    verify_tct(&renewed.token, &ctx).expect("renewed TCT verifies");
}

#[tokio::test]
async fn issuer_backend_with_wrong_key_is_a_local_fault() {
    let now = Timestamp(1_700_000_000);
    let good = p256(0x53);
    let holder = AitpSigningKey::from_seed(&[0x54; 32]);
    let issued = holder_tct(&good, &holder, now);
    let bad = MockKmsSigner::new(p256(0x53)).sign_with(p256(0x55));
    let err = renew(&bad, &holder, issued.token, now).await.unwrap_err();
    assert!(err.is_local_fault(), "{err:?}");
}
