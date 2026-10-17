//! `sign_envelope*` accept any `AitpSigner`: a KMS-shaped backend signs
//! an envelope that verifies, and a backend signing with the wrong key
//! is refused locally.

use aitp_core::{MessageType, Timestamp};
use aitp_crypto::testing::{MockKmsSigner, MockOutput};
use aitp_crypto::{AitpSigner, AitpSigningKey, AitpVerifyingKey};
use aitp_envelope::{sign_envelope, sign_envelope_with, verify_envelope_signature};
use uuid::Uuid;

fn p256(seed: u8) -> AitpSigningKey {
    AitpSigningKey::from_p256_seed(&[seed; 32]).expect("valid P-256 scalar")
}

#[test]
fn kms_backend_signs_a_verifying_envelope() {
    for kms in [
        MockKmsSigner::new(p256(1)).output(MockOutput::DerHighS),
        MockKmsSigner::new(AitpSigningKey::from_seed(&[2; 32])),
    ] {
        let vk = AitpVerifyingKey::from_aid(kms.aid()).unwrap();
        let env = sign_envelope_with(
            &kms,
            MessageType::MutualHello,
            serde_json::json!({ "hello": "kms" }),
            Uuid::new_v4(),
            Timestamp(1_700_000_000),
        )
        .expect("KMS envelope signs");
        assert_eq!(&env.sender.agent_id, kms.aid());
        verify_envelope_signature(&env, &vk).expect("KMS envelope verifies");
    }
}

#[test]
fn kms_backend_with_wrong_key_is_refused() {
    let kms = MockKmsSigner::new(p256(3)).sign_with(p256(4));
    let err = sign_envelope(&kms, MessageType::MutualHello, serde_json::json!({}))
        .expect_err("wrong-key backend must fail");
    assert!(err.starts_with("signing backend failed"), "{err}");
}

// ---- async signing path -------------------------------------------------

use aitp_crypto::SignerError;
use aitp_envelope::{sign_envelope_async, sign_envelope_with_async};
use std::sync::Arc;

/// Deterministic signers for the byte-identity check: Ed25519, and P-256
/// through the mock's Raw and Der outputs (both reproduce RFC 6979).
fn deterministic_pairs() -> Vec<(AitpSigningKey, MockKmsSigner)> {
    vec![
        (
            AitpSigningKey::from_seed(&[0x11; 32]),
            MockKmsSigner::new(AitpSigningKey::from_seed(&[0x11; 32])),
        ),
        (
            p256(0x12),
            MockKmsSigner::new(p256(0x12)).output(MockOutput::Raw),
        ),
        (
            p256(0x13),
            MockKmsSigner::new(p256(0x13)).output(MockOutput::Der),
        ),
    ]
}

#[tokio::test]
async fn async_envelope_is_byte_identical_to_sync() {
    let mid = Uuid::parse_str("770e8400-e29b-41d4-a716-446655440801").unwrap();
    let ts = Timestamp(1_700_000_000);
    let payload = serde_json::json!({ "hello": "async", "n": [1, 2, 3] });
    for (key, kms) in deterministic_pairs() {
        let sync = sign_envelope_with(&key, MessageType::MutualHello, payload.clone(), mid, ts)
            .expect("sync signs");
        let asyn =
            sign_envelope_with_async(&kms, MessageType::MutualHello, payload.clone(), mid, ts)
                .await
                .expect("async signs");
        assert_eq!(
            serde_json::to_vec(&sync).unwrap(),
            serde_json::to_vec(&asyn).unwrap()
        );
        assert_eq!(kms.calls(), 1);
    }
}

#[tokio::test]
async fn async_wrong_key_backend_is_refused() {
    let kms = MockKmsSigner::new(p256(0x14)).sign_with(p256(0x15));
    let err = sign_envelope_async(&kms, MessageType::MutualHello, serde_json::json!({}))
        .await
        .expect_err("wrong-key backend must fail");
    assert_eq!(
        err,
        format!(
            "signing backend failed: {}",
            SignerError::VerificationFailed
        )
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn async_envelope_future_is_send() {
    let kms = MockKmsSigner::new(p256(0x16)).output(MockOutput::RandomizedDer);
    let vk = AitpVerifyingKey::from_aid(kms.aid()).unwrap();
    let signer: Arc<dyn aitp_crypto::DynAsyncAitpSigner> = Arc::new(kms);
    let task_signer = signer.clone();
    // tokio::spawn requires the future to be Send + 'static.
    let env = tokio::spawn(async move {
        sign_envelope_async(
            &*task_signer,
            MessageType::MutualHello,
            serde_json::json!({ "on": "another task" }),
        )
        .await
    })
    .await
    .unwrap()
    .expect("async envelope signs on another task");
    assert_eq!(&env.sender.agent_id, signer.aid());
    verify_envelope_signature(&env, &vk).expect("verifies");
}

/// Proposal #72 Item 6b: verifiers reject a non-v4 `message_id`, so the
/// signer refuses one before calling the backend.
#[test]
fn non_v4_message_id_is_refused_before_signing() {
    let key = aitp_crypto::AitpSigningKey::from_seed(&[7; 32]);
    let v7 = uuid::Uuid::parse_str("01890a5d-ac96-774b-bcce-b302099a8057").unwrap();
    let err = aitp_envelope::sign_envelope_with(
        &key,
        aitp_core::MessageType::Tct,
        serde_json::json!({}),
        v7,
        aitp_core::Timestamp(1_700_000_000),
    )
    .unwrap_err();
    assert!(err.starts_with("message_id:"), "{err}");
}
