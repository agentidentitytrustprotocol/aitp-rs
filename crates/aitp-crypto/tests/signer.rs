//! `aitp_crypto::signer` against the mock KMS backend: every library-side
//! duty of the Cloud KMS fit (plan addendum; spec proposal Item 3).

use aitp_crypto::testing::{MockKmsSigner, MockOutput, AWS_KMS_RAW_MAX};
use aitp_crypto::{
    check_public_key, check_public_key_async, jws, sign_jcs, sign_jcs_async, sign_raw,
    sign_raw_async, AitpSigner, AitpSigningKey, BlockingSigner, CryptoError, Digest32,
    DynAsyncAitpSigner, SignRequest, SignerError,
};
use std::sync::Arc;
use std::time::Duration;

fn p256() -> AitpSigningKey {
    AitpSigningKey::from_p256_seed(&[0x05; 32]).unwrap()
}

fn ed() -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&[0x07; 32])
}

fn is_low_s(raw: &[u8; 64]) -> bool {
    // n/2, big-endian.
    const HALF_N: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
        0x92, 0xa8,
    ];
    raw[32..] <= HALF_N[..]
}

#[test]
fn p256_der_backend_matches_in_process_key_byte_for_byte() {
    let d = Digest32::sha256(b"manifest signing input");
    let kms = MockKmsSigner::new(p256()).output(MockOutput::Der);
    let via_kms = sign_jcs(&kms, &d).unwrap();
    assert_eq!(
        via_kms,
        p256().sign_jcs(&d),
        "DER -> R||S, same RFC 6979 nonce"
    );
    assert_eq!(kms.calls(), 1);
}

#[test]
fn p256_high_s_backend_output_is_normalised() {
    let d = Digest32::sha256(b"x");
    for out in [MockOutput::DerHighS, MockOutput::RawHighS] {
        let kms = MockKmsSigner::new(p256()).output(out);
        let sig = sign_jcs(&kms, &d).unwrap();
        assert_eq!(sig, p256().sign_jcs(&d), "{out:?} must come out low-S");
        p256().verifying_key().verify_jcs(&d, &sig).unwrap();
    }
}

#[test]
fn p256_randomized_backend_is_accepted_and_low_s() {
    let kms = MockKmsSigner::new(p256()).output(MockOutput::RandomizedDer);
    let vk = p256().verifying_key();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..16 {
        let raw = sign_raw(&kms, b"es256 input").unwrap();
        assert!(is_low_s(&raw));
        vk.verify_raw(b"es256 input", &raw).unwrap();
        seen.insert(raw);
    }
    assert!(seen.len() > 1, "random nonces produce distinct signatures");
}

#[test]
fn p256_backend_receives_the_digest_not_the_message() {
    // The single-hash rule (§5.4.6) holds through a backend: sign_raw
    // hashes once and the KMS signs the 32-byte digest in DIGEST mode.
    struct Spy(AitpSigningKey, std::sync::Mutex<Vec<Vec<u8>>>);
    impl AitpSigner for Spy {
        fn aid(&self) -> &aitp_core::Aid {
            self.0.aid()
        }
        fn public_key(&self) -> Result<aitp_crypto::AitpVerifyingKey, SignerError> {
            Ok(self.0.verifying_key())
        }
        fn sign(&self, req: SignRequest<'_>) -> Result<aitp_crypto::BackendSignature, SignerError> {
            self.1.lock().unwrap().push(req.bytes().to_vec());
            AitpSigner::sign(&self.0, req)
        }
    }
    let spy = Spy(p256(), Default::default());
    let msg = vec![0xab; 10_000];
    sign_raw(&spy, &msg).unwrap();
    let seen = spy.1.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0], Digest32::sha256(&msg).as_bytes());
}

#[test]
fn oversize_ed25519_message_is_refused_before_the_backend() {
    let kms = MockKmsSigner::new(ed());
    let msg = vec![0u8; AWS_KMS_RAW_MAX + 1];
    let err = sign_raw(&kms, &msg).unwrap_err();
    assert!(matches!(
        err,
        SignerError::MessageTooLarge { len, max } if len == AWS_KMS_RAW_MAX + 1 && max == AWS_KMS_RAW_MAX
    ));
    assert_eq!(kms.calls(), 0, "the backend must never see it");

    // At the limit it goes through.
    let at = vec![0u8; AWS_KMS_RAW_MAX];
    ed().verifying_key()
        .verify_raw(&at, &sign_raw(&kms, &at).unwrap())
        .unwrap();
    assert_eq!(kms.calls(), 1);
}

#[test]
fn oversize_p256_message_is_fine_because_only_the_digest_travels() {
    let kms = MockKmsSigner::new(p256());
    let msg = vec![0u8; AWS_KMS_RAW_MAX * 4];
    let raw = sign_raw(&kms, &msg).unwrap();
    p256().verifying_key().verify_raw(&msg, &raw).unwrap();
}

#[test]
fn wrong_backend_key_is_refused_before_emit() {
    for (real, other) in [
        (p256(), AitpSigningKey::from_p256_seed(&[0x06; 32]).unwrap()),
        (ed(), AitpSigningKey::from_ed25519_seed(&[0x08; 32])),
    ] {
        let kms = MockKmsSigner::new(real).sign_with(other);
        assert!(matches!(
            sign_jcs(&kms, &Digest32::sha256(b"t")),
            Err(SignerError::VerificationFailed)
        ));
        assert!(matches!(
            sign_raw(&kms, b"t"),
            Err(SignerError::VerificationFailed)
        ));
        assert!(matches!(
            check_public_key(&kms),
            Err(SignerError::KeyMismatch { .. })
        ));
    }
}

#[test]
fn startup_check_catches_a_misreported_public_key() {
    let ok = MockKmsSigner::new(p256());
    check_public_key(&ok).unwrap();
    let lying = MockKmsSigner::new(p256()).report_public_key(ed().verifying_key());
    let err = check_public_key(&lying).unwrap_err();
    match err {
        SignerError::KeyMismatch { expected, reported } => {
            assert_eq!(&expected, p256().aid());
            assert_eq!(&reported, ed().aid());
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn malformed_backend_output_is_refused() {
    let kms = MockKmsSigner::new(p256()).output(MockOutput::MalformedDer);
    assert!(matches!(
        sign_jcs(&kms, &Digest32::sha256(b"t")),
        Err(SignerError::MalformedSignature(_))
    ));
    // DER is never a valid Ed25519 encoding. The mock returns Raw for
    // Ed25519 whatever the knob, so build the case directly.
    struct DerEd(AitpSigningKey);
    impl AitpSigner for DerEd {
        fn aid(&self) -> &aitp_core::Aid {
            self.0.aid()
        }
        fn public_key(&self) -> Result<aitp_crypto::AitpVerifyingKey, SignerError> {
            Ok(self.0.verifying_key())
        }
        fn sign(&self, _: SignRequest<'_>) -> Result<aitp_crypto::BackendSignature, SignerError> {
            Ok(aitp_crypto::BackendSignature::Der(vec![0x30, 0x00]))
        }
    }
    assert!(matches!(
        sign_raw(&DerEd(ed()), b"t"),
        Err(SignerError::MalformedSignature(_))
    ));
}

#[test]
fn ed25519_non_canonical_s_is_refused_before_emit() {
    let kms = MockKmsSigner::new(ed()).output(MockOutput::Ed25519NonCanonicalS);
    assert!(matches!(
        sign_jcs(&kms, &Digest32::sha256(b"t")),
        Err(SignerError::VerificationFailed)
    ));
}

#[test]
fn ed25519_backend_matches_in_process_key() {
    let kms = MockKmsSigner::new(ed());
    let d = Digest32::sha256(b"envelope");
    assert_eq!(sign_jcs(&kms, &d).unwrap(), ed().sign_jcs(&d));
    assert_eq!(sign_raw(&kms, b"jws").unwrap(), ed().sign_raw(b"jws"));
}

#[test]
fn transient_errors_carry_retry_after_and_are_not_retried_by_the_library() {
    let kms = MockKmsSigner::new(p256()).fail_transient(1, Some(Duration::from_millis(250)));
    let err = sign_jcs(&kms, &Digest32::sha256(b"t")).unwrap_err();
    assert!(err.is_transient());
    assert_eq!(err.retry_after(), Some(Duration::from_millis(250)));
    assert_eq!(kms.calls(), 1, "no hidden retry");
    // The caller's retry succeeds.
    sign_jcs(&kms, &Digest32::sha256(b"t")).unwrap();
    // Permanent errors are not transient.
    assert!(!SignerError::permanent("AccessDeniedException").is_transient());
}

#[test]
fn jws_minted_through_a_kms_verifies_and_surfaces_signer_errors() {
    let claims = serde_json::json!({"iss": "a", "n": 1});
    for make in [p256 as fn() -> AitpSigningKey, ed] {
        let key = make();
        let kms = MockKmsSigner::new(make());
        let token = jws::sign_compact(&kms, jws::TYP_TCT, &claims).unwrap();
        assert_eq!(
            token,
            jws::sign_compact(&key, jws::TYP_TCT, &claims).unwrap(),
            "deterministic backends are byte-identical to in-process minting"
        );
        jws::verify_compact(key.aid(), jws::TYP_TCT, &token).unwrap();
    }
    let broken =
        MockKmsSigner::new(p256()).sign_with(AitpSigningKey::from_p256_seed(&[0x09; 32]).unwrap());
    assert!(matches!(
        jws::sign_compact(&broken, jws::TYP_TCT, &claims),
        Err(CryptoError::Signer(SignerError::VerificationFailed))
    ));
}

#[tokio::test]
async fn async_round_trip_through_a_type_erased_backend() {
    let kms: Arc<dyn DynAsyncAitpSigner> =
        Arc::new(MockKmsSigner::new(p256()).output(MockOutput::RandomizedDer));
    check_public_key_async(kms.as_ref()).await.unwrap();
    let d = Digest32::sha256(b"async");
    let sig = sign_jcs_async(kms.as_ref(), &d).await.unwrap();
    p256().verifying_key().verify_jcs(&d, &sig).unwrap();
    let raw = sign_raw_async(kms.as_ref(), b"m").await.unwrap();
    p256().verifying_key().verify_raw(b"m", &raw).unwrap();
    let token = jws::sign_compact_async(kms.as_ref(), jws::TYP_TCT, &serde_json::json!({"a": 1}))
        .await
        .unwrap();
    jws::verify_compact(p256().aid(), jws::TYP_TCT, &token).unwrap();

    // The future is Send: it can be spawned on a multi-threaded runtime.
    let kms2 = kms.clone();
    tokio::spawn(async move { sign_raw_async(kms2.as_ref(), b"spawned").await })
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn async_oversize_refusal_and_wrong_key() {
    let kms = MockKmsSigner::new(ed());
    let err = sign_raw_async(&kms, &vec![0u8; AWS_KMS_RAW_MAX + 1])
        .await
        .unwrap_err();
    assert!(matches!(err, SignerError::MessageTooLarge { .. }));
    assert_eq!(kms.calls(), 0);

    let wrong = MockKmsSigner::new(ed()).sign_with(AitpSigningKey::from_ed25519_seed(&[1; 32]));
    assert!(matches!(
        sign_raw_async(&wrong, b"m").await,
        Err(SignerError::VerificationFailed)
    ));
    assert!(matches!(
        check_public_key_async(&wrong).await,
        Err(SignerError::KeyMismatch { .. })
    ));
}

#[tokio::test]
async fn in_process_key_and_blocking_adapter_work_async() {
    let d = Digest32::sha256(b"local");
    assert_eq!(
        sign_jcs_async(&p256(), &d).await.unwrap(),
        p256().sign_jcs(&d)
    );
    let wrapped = BlockingSigner(MockKmsSigner::new(p256()));
    assert_eq!(
        sign_jcs_async(&wrapped, &d).await.unwrap(),
        p256().sign_jcs(&d)
    );
    assert_eq!(wrapped.0.calls(), 1);
}
