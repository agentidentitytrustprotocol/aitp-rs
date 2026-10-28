//! `ManifestBuilder` accepts any `AitpSigner`: a KMS-shaped backend
//! produces a Manifest whose PoP and outer signature verify, and a
//! backend signing with the wrong key is refused locally.

use aitp::core::Timestamp;
use aitp::crypto::testing::{MockKmsSigner, MockOutput};
use aitp::crypto::{AitpSigner, AitpSigningKey, CryptoError, SignerError};
use aitp::manifest::{
    verify_manifest, IdentityHint, IdentityHintKind, Manifest, ManifestBuilder, ManifestError,
    ManifestVerifyContext,
};

fn build(signer: &dyn AitpSigner, now: Timestamp) -> Result<Manifest, ManifestError> {
    ManifestBuilder::new(signer)
        .handshake_endpoint("https://kms.example.com/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityHintKind::Oidc, "kms-agent")
                .with_issuer("https://idp.example.com".parse().unwrap()),
        )
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .offer("demo.echo")
        .published_at(now)
        .ttl(std::time::Duration::from_secs(3600))
        .build()
}

#[test]
fn kms_backend_builds_a_verifying_manifest() {
    let now = Timestamp(1_700_000_000);
    for output in [
        MockOutput::Der,
        MockOutput::DerHighS,
        MockOutput::RandomizedDer,
    ] {
        let kms =
            MockKmsSigner::new(AitpSigningKey::from_p256_seed(&[5; 32]).unwrap()).output(output);
        let m = build(&kms, now).expect("KMS-backed ManifestBuilder builds");
        assert_eq!(
            kms.calls(),
            2,
            "PoP and outer signature both go to the backend"
        );
        assert_eq!(&m.aid, kms.aid());
        verify_manifest(&m, &ManifestVerifyContext::at(now)).expect("KMS manifest verifies");
    }
}

#[test]
fn kms_backend_ed25519_builds_a_verifying_manifest() {
    let now = Timestamp(1_700_000_000);
    let kms = MockKmsSigner::new(AitpSigningKey::from_ed25519_seed(&[6; 32]));
    let m = build(&kms, now).expect("KMS-backed ManifestBuilder builds");
    verify_manifest(&m, &ManifestVerifyContext::at(now)).expect("KMS manifest verifies");
}

#[test]
fn kms_backend_with_wrong_key_returns_signer_error() {
    let now = Timestamp(1_700_000_000);
    let kms = MockKmsSigner::new(AitpSigningKey::from_p256_seed(&[5; 32]).unwrap())
        .sign_with(AitpSigningKey::from_p256_seed(&[6; 32]).unwrap());
    let err = build(&kms, now).expect_err("wrong-key backend must fail");
    assert!(
        matches!(
            err,
            ManifestError::Crypto(CryptoError::Signer(SignerError::VerificationFailed))
        ),
        "{err:?}"
    );
}

// ---- async signing path -------------------------------------------------

use aitp::core::{base64url, jcs};
use aitp::crypto::Digest32;
use std::sync::Arc;

fn build_async<'a>(
    signer: &'a dyn aitp::crypto::DynAsyncAitpSigner,
    now: Timestamp,
) -> impl std::future::Future<Output = Result<Manifest, ManifestError>> + Send + 'a {
    ManifestBuilder::new_async(signer)
        .handshake_endpoint("https://kms.example.com/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityHintKind::Oidc, "kms-agent")
                .with_issuer("https://idp.example.com".parse().unwrap()),
        )
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .offer("demo.echo")
        .published_at(now)
        .ttl(std::time::Duration::from_secs(3600))
        .build_async()
}

/// The manifest's PoP challenge is fresh randomness, so two builds never
/// match byte for byte. Instead: every field other than the PoP and the
/// signature matches the sync build, and both async signatures are
/// exactly what the in-process key produces (deterministically) over the
/// same PoP challenge and the same signed body.
#[tokio::test]
async fn async_manifest_matches_sync_for_deterministic_keys() {
    let now = Timestamp(1_700_000_000);
    let cases: [(fn() -> AitpSigningKey, MockOutput); 3] = [
        (
            || AitpSigningKey::from_ed25519_seed(&[0x21; 32]),
            MockOutput::Raw,
        ),
        (
            || AitpSigningKey::from_p256_seed(&[0x22; 32]).unwrap(),
            MockOutput::Raw,
        ),
        (
            || AitpSigningKey::from_p256_seed(&[0x23; 32]).unwrap(),
            MockOutput::Der,
        ),
    ];
    for (make, output) in cases {
        let key = make();
        let sync = build(&key, now).expect("sync build");
        let kms = MockKmsSigner::new(make()).output(output);
        let asyn = build_async(&kms, now).await.expect("async build");
        assert_eq!(kms.calls(), 2, "PoP and outer signature");

        let strip = |m: &Manifest| {
            let mut v = serde_json::to_value(m).unwrap();
            let o = v.as_object_mut().unwrap();
            o.remove("proof_of_possession");
            o.remove("signature");
            v
        };
        assert_eq!(strip(&sync), strip(&asyn));

        let challenge = base64url::decode_strict(&asyn.proof_of_possession.challenge).unwrap();
        let pop = aitp::crypto::sign_jcs(&key, &Digest32::sha256(&challenge)).unwrap();
        assert_eq!(asyn.proof_of_possession.signature, pop.into_string());

        let mut body = serde_json::to_value(&asyn).unwrap();
        body.as_object_mut().unwrap().remove("signature");
        let digest = Digest32::sha256(&jcs::canonicalize(&body).unwrap());
        let sig = aitp::crypto::sign_jcs(&key, &digest).unwrap();
        assert_eq!(asyn.signature, sig.into_string());

        verify_manifest(&asyn, &ManifestVerifyContext::at(now)).expect("async manifest verifies");
    }
}

#[tokio::test]
async fn async_wrong_key_backend_returns_signer_error() {
    let now = Timestamp(1_700_000_000);
    let kms = MockKmsSigner::new(AitpSigningKey::from_p256_seed(&[0x24; 32]).unwrap())
        .sign_with(AitpSigningKey::from_p256_seed(&[0x25; 32]).unwrap());
    let err = build_async(&kms, now)
        .await
        .expect_err("wrong-key backend must fail");
    assert!(
        matches!(
            err,
            ManifestError::Crypto(CryptoError::Signer(SignerError::VerificationFailed))
        ),
        "{err:?}"
    );
    assert_eq!(kms.calls(), 1, "refused at the PoP, before the body");
}

#[tokio::test(flavor = "multi_thread")]
async fn async_manifest_future_is_send() {
    let now = Timestamp(1_700_000_000);
    let signer: Arc<dyn aitp::crypto::DynAsyncAitpSigner> = Arc::new(
        MockKmsSigner::new(AitpSigningKey::from_p256_seed(&[0x26; 32]).unwrap())
            .output(MockOutput::RandomizedDer),
    );
    let task_signer = signer.clone();
    // tokio::spawn requires the future to be Send + 'static.
    let m = tokio::spawn(async move { build_async(&*task_signer, now).await })
        .await
        .unwrap()
        .expect("async manifest builds on another task");
    assert_eq!(&m.aid, signer.aid());
    verify_manifest(&m, &ManifestVerifyContext::at(now)).expect("verifies");
}
