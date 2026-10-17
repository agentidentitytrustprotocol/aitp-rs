//! Pinned-key admission (proposal agentidentitytrustprotocol#72 Items 5
//! and 7d). Mirrors the planned id-013..016 fixtures.
#![cfg(feature = "pinned-admission")]

use aitp_core::{base64url, AitpEnvelope, MessageType, Timestamp};
use aitp_crypto::testing::MockKmsSigner;
use aitp_crypto::{AitpSigningKey, DynAsyncAitpSigner};
use aitp_handshake::admission::{
    present_pinned, present_pinned_async, AdmissionError, ChallengeSource, InMemoryNonceStore,
    NonceStore, PinnedAdmission, RecommendedLimiter, RefusalCause, TokenBucketLimiter,
};
use aitp_handshake::StaticPinnedKeyStore;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

const NOW: Timestamp = Timestamp(1_711_900_000);

fn verifier_key() -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&[0x11; 32])
}
fn subject_ed() -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&[0x22; 32])
}
fn subject_p256() -> AitpSigningKey {
    AitpSigningKey::from_p256_seed(&[0x33; 32]).unwrap()
}

fn admission_with(store: Arc<dyn NonceStore>) -> PinnedAdmission {
    let trusted =
        StaticPinnedKeyStore::new([subject_ed().verifying_key(), subject_p256().verifying_key()]);
    PinnedAdmission::builder(verifier_key().aid().clone(), store, Arc::new(trusted)).build()
}

fn admission() -> PinnedAdmission {
    admission_with(Arc::new(InMemoryNonceStore::default()))
}

/// A distinct transport identity per name: a TLS client-cert fingerprint
/// derived from it.
fn src(name: &str) -> ChallengeSource {
    let mut fp = [0u8; 32];
    for (i, b) in name.bytes().enumerate() {
        fp[i % 32] ^= b.wrapping_add(i as u8);
    }
    ChallengeSource::tls_client_cert(fp)
}

fn code(e: &AdmissionError) -> &'static str {
    e.code().unwrap_or("LOCAL")
}

#[tokio::test]
async fn ed25519_and_p256_subjects_are_admitted() {
    let a = admission();
    for key in [subject_ed(), subject_p256()] {
        let ch = a.challenge_at(&src("10.0.0.1"), NOW).await.unwrap();
        let env = present_pinned(&key, "agent-x", &ch, NOW).unwrap();
        assert_eq!(env.message_type, MessageType::IdentityPresentation);
        let ok = a.admit_at(&env, NOW).await.unwrap();
        assert_eq!(&ok.key.aid, key.aid());
        assert_eq!(ok.key.key, key.verifying_key());
        assert_eq!(ok.subject, "agent-x");
    }
}

#[tokio::test]
async fn kms_backed_async_presenter_is_admitted() {
    let a = admission();
    let kms: Arc<dyn DynAsyncAitpSigner> = Arc::new(MockKmsSigner::new(subject_p256()));
    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    let env = present_pinned_async(kms.as_ref(), "kms", &ch, NOW)
        .await
        .unwrap();
    a.admit_at(&env, NOW).await.unwrap();
}

#[tokio::test]
async fn wire_round_trip() {
    let a = admission();
    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    // The challenge itself is JSON the transport can carry.
    let ch: aitp_handshake::admission::AdmissionChallenge =
        serde_json::from_value(serde_json::to_value(&ch).unwrap()).unwrap();
    let env = present_pinned(&subject_ed(), "w", &ch, NOW).unwrap();
    let wire = serde_json::to_value(&env).unwrap();
    assert_eq!(wire["message_type"], "identity_presentation");
    a.admit_wire_at(&wire, NOW).await.unwrap();
}

/// id-013: a nonce is single-use.
#[tokio::test]
async fn id_013_nonce_reuse_rejected() {
    let a = admission();
    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    let env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    a.admit_at(&env, NOW).await.unwrap();
    let again = a.admit_at(&env, NOW).await.unwrap_err();
    assert_eq!(code(&again), "IDENTITY_FAILED");
    // A fresh envelope over the same nonce is also refused.
    let env2 = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    assert_eq!(
        code(&a.admit_at(&env2, NOW).await.unwrap_err()),
        "IDENTITY_FAILED"
    );
}

/// id-014: a nonce that is not exactly 16 bytes fails before any
/// signature work: the envelope here carries garbage signatures.
#[tokio::test]
async fn id_014_nonce_wrong_length_rejected_before_signature() {
    let a = admission();
    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    let mut env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    for len in [15usize, 17, 0, 32] {
        env.payload["pop_nonce"] = base64url::encode(&vec![7u8; len]).into();
        env.payload["identity"]["proof"] = "not-a-signature".into();
        env.signature = "not-a-signature".into();
        let e = a.admit_at(&env, NOW).await.unwrap_err();
        assert_eq!(code(&e), "IDENTITY_FAILED", "len {len}");
        assert!(e.to_string().contains("16 bytes"), "{e}");
    }
}

/// id-015: any other message_type is refused.
#[tokio::test]
async fn id_015_wrong_message_type_rejected() {
    let a = admission();
    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    let mut env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    env.message_type = MessageType::PopResponse;
    assert_eq!(
        code(&a.admit_at(&env, NOW).await.unwrap_err()),
        "INVALID_ENVELOPE"
    );
    // And the nonce was not consumed by the refused attempt.
    env.message_type = MessageType::IdentityPresentation;
    a.admit_at(&env, NOW).await.unwrap();
}

/// id-016: at the bound, new challenges are refused and outstanding
/// nonces stay valid (no eviction).
#[tokio::test]
async fn id_016_bound_refuses_new_challenge_outstanding_stay_valid() {
    let a = admission_with(Arc::new(InMemoryNonceStore::new(2)));
    let c1 = a.challenge_at(&src("honest"), NOW).await.unwrap();
    let _c2 = a.challenge_at(&src("flood"), NOW).await.unwrap();
    let e = a.challenge_at(&src("flood"), NOW).await.unwrap_err();
    assert!(matches!(e, AdmissionError::ChallengeRefused { .. }), "{e}");
    let env = present_pinned(&subject_ed(), "h", &c1, NOW).unwrap();
    a.admit_at(&env, NOW).await.unwrap();
    // Consuming freed a slot.
    a.challenge_at(&src("flood"), NOW).await.unwrap();
}

#[tokio::test]
async fn expired_nonces_free_capacity_and_are_refused() {
    let a = admission_with(Arc::new(InMemoryNonceStore::new(1)));
    let c1 = a.challenge_at(&src("s"), NOW).await.unwrap();
    let later = NOW.plus_secs(301);
    // The expired record no longer counts against the bound.
    let _c2 = a.challenge_at(&src("s"), later).await.unwrap();
    let env = present_pinned(&subject_ed(), "s", &c1, later).unwrap();
    let e = a.admit_at(&env, later).await.unwrap_err();
    assert_eq!(code(&e), "IDENTITY_FAILED");
}

#[tokio::test]
async fn expired_challenge_rejected() {
    let a = PinnedAdmission::builder(
        verifier_key().aid().clone(),
        Arc::new(InMemoryNonceStore::default()),
        Arc::new(StaticPinnedKeyStore::new([subject_ed().verifying_key()])),
    )
    .nonce_ttl(Duration::from_secs(30))
    .build();
    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    assert_eq!(ch.expires_at, NOW.plus_secs(30));
    let t = NOW.plus_secs(31);
    let env = present_pinned(&subject_ed(), "s", &ch, t).unwrap();
    let e = a.admit_at(&env, t).await.unwrap_err();
    assert!(e.to_string().contains("expired"), "{e}");
}

#[test]
fn ttl_is_clamped_to_300s() {
    let a = PinnedAdmission::builder(
        verifier_key().aid().clone(),
        Arc::new(InMemoryNonceStore::default()),
        Arc::new(StaticPinnedKeyStore::new([])),
    )
    .nonce_ttl(Duration::from_secs(3600))
    .build();
    let ch = futures_block(a.challenge_at(&src("s"), NOW)).unwrap();
    assert_eq!(ch.expires_at, NOW.plus_secs(300));
}

#[tokio::test]
async fn nonce_bound_to_verifier() {
    let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::default());
    let a = admission_with(store.clone());
    let other_key = AitpSigningKey::from_ed25519_seed(&[0x44; 32]);
    let b = PinnedAdmission::builder(
        other_key.aid().clone(),
        store,
        Arc::new(StaticPinnedKeyStore::new([subject_ed().verifying_key()])),
    )
    .build();
    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    // A presentation of A's nonce addressed to B: B never issued it.
    let mut forged = ch.clone();
    forged.verifier_aid = other_key.aid().clone();
    let env = present_pinned(&subject_ed(), "s", &forged, NOW).unwrap();
    assert_eq!(
        code(&b.admit_at(&env, NOW).await.unwrap_err()),
        "IDENTITY_FAILED"
    );
    // A presentation addressed to B, replayed at A: proof's receiver
    // is B, so A's §3.2 check fails, and A's nonce survives.
    assert_eq!(
        code(&a.admit_at(&env, NOW).await.unwrap_err()),
        "IDENTITY_FAILED"
    );
    let good = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    a.admit_at(&good, NOW).await.unwrap();
}

#[tokio::test]
async fn untrusted_key_rejected_and_nonce_survives() {
    let a = admission();
    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    let stranger = AitpSigningKey::from_ed25519_seed(&[0x55; 32]);
    let env = present_pinned(&stranger, "s", &ch, NOW).unwrap();
    assert_eq!(
        code(&a.admit_at(&env, NOW).await.unwrap_err()),
        "IDENTITY_FAILED"
    );
    a.admit_at(&present_pinned(&subject_ed(), "s", &ch, NOW).unwrap(), NOW)
        .await
        .unwrap();
}

#[tokio::test]
async fn tampered_payload_fails_envelope_signature() {
    let a = admission();
    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    let mut env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    // `subject` is outside the proof; only the envelope signature covers it.
    env.payload["identity"]["subject"] = "admin".into();
    assert_eq!(
        code(&a.admit_at(&env, NOW).await.unwrap_err()),
        "INVALID_SIGNATURE"
    );
}

#[tokio::test]
async fn stale_timestamp_and_unknown_member_rejected() {
    let a = admission();
    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    let env = present_pinned(&subject_ed(), "s", &ch, NOW.plus_secs(-301)).unwrap();
    assert_eq!(
        code(&a.admit_at(&env, NOW).await.unwrap_err()),
        "TIMESTAMP_EXPIRED"
    );
    let mut env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    env.payload["role"] = "admin".into();
    assert_eq!(
        code(&a.admit_at(&env, NOW).await.unwrap_err()),
        "UNKNOWN_FIELD"
    );
}

#[tokio::test]
async fn non_v4_message_id_rejected() {
    let a = admission();
    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    let mut env: AitpEnvelope = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    env.message_id = uuid::Uuid::parse_str("01890a5d-ac96-774b-bcce-b302099a8057").unwrap();
    assert_eq!(
        code(&a.admit_at(&env, NOW).await.unwrap_err()),
        "INVALID_ENVELOPE"
    );
}

#[tokio::test]
async fn rate_limit_refuses_per_source() {
    let a = PinnedAdmission::builder(
        verifier_key().aid().clone(),
        Arc::new(InMemoryNonceStore::default()),
        Arc::new(StaticPinnedKeyStore::new([])),
    )
    .rate_limiter(Arc::new(TokenBucketLimiter::new(2, 0.01)))
    .build();
    a.challenge_at(&src("x"), NOW).await.unwrap();
    a.challenge_at(&src("x"), NOW).await.unwrap();
    match a.challenge_at(&src("x"), NOW).await.unwrap_err() {
        AdmissionError::ChallengeRefused { retry_after, cause } => {
            assert!(retry_after.is_some());
            assert_eq!(cause, RefusalCause::RateLimited);
        }
        e => panic!("{e}"),
    }
    a.challenge_at(&src("y"), NOW).await.unwrap();
}

/// Many tasks race to admit the same presentation; exactly one wins.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_consume_admits_exactly_once() {
    let a = Arc::new(admission());
    for _ in 0..20 {
        let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
        let env = Arc::new(present_pinned(&subject_ed(), "s", &ch, NOW).unwrap());
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let (a, env) = (a.clone(), env.clone());
                tokio::spawn(async move { a.admit_at(&env, NOW).await.is_ok() })
            })
            .collect();
        let mut wins = 0;
        for t in tasks {
            wins += t.await.unwrap() as usize;
        }
        assert_eq!(wins, 1);
    }
}

/// Concurrent issuance never exceeds the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_issue_respects_bound() {
    let a = Arc::new(admission_with(Arc::new(InMemoryNonceStore::new(50))));
    let tasks: Vec<_> = (0..400)
        .map(|i| {
            let a = a.clone();
            tokio::spawn(async move { a.challenge_at(&src(&format!("s{i}")), NOW).await.is_ok() })
        })
        .collect();
    let mut ok = 0;
    for t in tasks {
        ok += t.await.unwrap() as usize;
    }
    assert_eq!(ok, 50);
}

fn futures_block<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

#[tokio::test]
async fn subject_binding_sender_aid_is_enforced_by_admission() {
    let trusted = StaticPinnedKeyStore::new([subject_ed().verifying_key()]);
    let a = PinnedAdmission::builder(
        verifier_key().aid().clone(),
        Arc::new(InMemoryNonceStore::default()),
        Arc::new(trusted),
    )
    .subject_binding(aitp_handshake::SubjectBinding::SenderAid)
    .build();
    let key = subject_ed();

    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    let env = present_pinned(&key, "free-form-label", &ch, NOW).unwrap();
    let e = a.admit_at(&env, NOW).await.unwrap_err();
    assert_eq!(code(&e), "IDENTITY_FAILED", "{e:?}");

    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    let env = present_pinned(&key, key.aid().as_str(), &ch, NOW).unwrap();
    let ok = a.admit_at(&env, NOW).await.unwrap();
    assert_eq!(ok.subject, key.aid().as_str());
}

/// id-016 / Item 5: a refusal is `CHALLENGE_REFUSED` (retryable) and
/// does not say whether the rate limit or the nonce bound fired.
#[tokio::test]
async fn refusal_is_challenge_refused_without_naming_the_cause() {
    let bound = admission_with(Arc::new(InMemoryNonceStore::new(1)));
    bound.challenge_at(&src("a"), NOW).await.unwrap();
    let at_bound = bound.challenge_at(&src("b"), NOW).await.unwrap_err();

    let limited = PinnedAdmission::builder(
        verifier_key().aid().clone(),
        Arc::new(InMemoryNonceStore::default()),
        Arc::new(StaticPinnedKeyStore::new([])),
    )
    .rate_limiter(Arc::new(TokenBucketLimiter::new(1, 0.01)))
    .build();
    limited.challenge_at(&src("a"), NOW).await.unwrap();
    let rate = limited.challenge_at(&src("a"), NOW).await.unwrap_err();

    for e in [&at_bound, &rate] {
        assert_eq!(e.code(), Some("CHALLENGE_REFUSED"));
        assert!(aitp_core::ErrorCode::ChallengeRefused.is_retryable());
    }
    // Same peer-visible text for both causes.
    assert_eq!(at_bound.to_string(), rate.to_string());
    assert!(matches!(
        at_bound,
        AdmissionError::ChallengeRefused {
            cause: RefusalCause::AtCapacity,
            ..
        }
    ));
}

/// Item 5 / #69: rate limiting is on by default, at RFC-AITP-0009 §3.1's
/// 30 per minute per transport source.
#[tokio::test]
async fn rate_limit_is_on_by_default() {
    let a = admission();
    let ip = ChallengeSource::ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
    for _ in 0..RecommendedLimiter::PER_TRANSPORT_PER_MINUTE {
        a.challenge_at(&ip, NOW).await.unwrap();
    }
    let e = a.challenge_at(&ip, NOW).await.unwrap_err();
    assert_eq!(e.code(), Some("CHALLENGE_REFUSED"));
}

/// A self-asserted label (a claimed AID) never replaces the transport
/// key: rotating labels from one address does not reset its budget.
#[tokio::test]
async fn rotating_labels_does_not_bypass_transport_limit() {
    let a = PinnedAdmission::builder(
        verifier_key().aid().clone(),
        Arc::new(InMemoryNonceStore::default()),
        Arc::new(StaticPinnedKeyStore::new([])),
    )
    .rate_limiter(Arc::new(RecommendedLimiter::new(
        2,
        0.001,
        Some((100, 1.0)),
    )))
    .build();
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    a.challenge_at(&ChallengeSource::ip(ip).with_label("aid:a"), NOW)
        .await
        .unwrap();
    a.challenge_at(&ChallengeSource::ip(ip).with_label("aid:b"), NOW)
        .await
        .unwrap();
    assert!(a
        .challenge_at(&ChallengeSource::ip(ip).with_label("aid:c"), NOW)
        .await
        .is_err());
}

/// The per-label limit (RFC-AITP-0009 §3.1: per initiator AID) applies
/// across addresses.
#[tokio::test]
async fn per_label_limit_applies_across_addresses() {
    let a = PinnedAdmission::builder(
        verifier_key().aid().clone(),
        Arc::new(InMemoryNonceStore::default()),
        Arc::new(StaticPinnedKeyStore::new([])),
    )
    .rate_limiter(Arc::new(RecommendedLimiter::new(
        100,
        1.0,
        Some((2, 0.001)),
    )))
    .build();
    for n in 1..=2 {
        let s = ChallengeSource::ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))).with_label("aid:x");
        a.challenge_at(&s, NOW).await.unwrap();
    }
    let s = ChallengeSource::ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))).with_label("aid:x");
    assert!(a.challenge_at(&s, NOW).await.is_err());
    let s = ChallengeSource::ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))).with_label("aid:y");
    a.challenge_at(&s, NOW).await.unwrap();
}

/// IPv6 sources are keyed by /64: one subscriber allocation is one
/// source, however many addresses it rotates through.
#[test]
fn ipv6_sources_share_a_slash_64() {
    let a = ChallengeSource::ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1)));
    let b = ChallengeSource::ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 9, 9, 9, 9)));
    let c = ChallengeSource::ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1)));
    assert_eq!(a.transport_key(), b.transport_key());
    assert_ne!(a.transport_key(), c.transport_key());
    // An IPv4-mapped address is the IPv4 source.
    let v4 = ChallengeSource::ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    let mapped = ChallengeSource::ip(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped()));
    assert_eq!(v4.transport_key(), mapped.transport_key());
}
