//! Pinned-key admission (proposal agentidentitytrustprotocol#72 Items 5
//! and 7d). Mirrors the planned id-013..016 fixtures.
#![cfg(feature = "pinned-admission")]

use aitp::core::nonce_store::{InMemoryNonceStore, NonceStore};
use aitp::core::{base64url, AitpEnvelope, MessageType, Timestamp};
use aitp::crypto::testing::MockKmsSigner;
use aitp::crypto::{AitpSigningKey, DynAsyncAitpSigner};
use aitp::handshake::admission::{
    present_pinned, present_pinned_async, AdmissionError, ChallengeSource,
    InMemoryMessageIdDenyList, PinnedAdmission, RecommendedLimiter, RefusalCause,
    TokenBucketLimiter,
};
use aitp::handshake::StaticPinnedKeyStore;
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
    ChallengeSource::tls_client_cert_sha256(fp)
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
        let ok = a.admit_at(&env, &src("p"), NOW).await.unwrap();
        assert_eq!(ok.key().aid(), key.aid());
        assert_eq!(ok.key().key(), &key.verifying_key());
        assert_eq!(ok.subject(), "agent-x");
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
    a.admit_at(&env, &src("p"), NOW).await.unwrap();
}

#[tokio::test]
async fn wire_round_trip() {
    let a = admission();
    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    // The challenge itself is JSON the transport can carry.
    let ch: aitp::handshake::admission::AdmissionChallenge =
        serde_json::from_value(serde_json::to_value(&ch).unwrap()).unwrap();
    let env = present_pinned(&subject_ed(), "w", &ch, NOW).unwrap();
    let wire: aitp::core::CheckedJson = serde_json::to_string(&env).unwrap().parse().unwrap();
    assert_eq!(wire["message_type"], "identity_presentation");
    a.admit_wire_at(&wire, &src("p"), NOW).await.unwrap();
}

/// id-013: a nonce is single-use.
#[tokio::test]
async fn id_013_nonce_reuse_rejected() {
    let a = admission();
    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    let env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    a.admit_at(&env, &src("p"), NOW).await.unwrap();
    // The exact envelope again is a replay (§3.4 check order, step 1).
    let again = a.admit_at(&env, &src("p"), NOW).await.unwrap_err();
    assert_eq!(code(&again), "REPLAY_DETECTED");
    // A fresh envelope over the same nonce fails at the consume.
    let env2 = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    assert_eq!(
        code(&a.admit_at(&env2, &src("p"), NOW).await.unwrap_err()),
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
        let e = a.admit_at(&env, &src("p"), NOW).await.unwrap_err();
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
        code(&a.admit_at(&env, &src("p"), NOW).await.unwrap_err()),
        "INVALID_ENVELOPE"
    );
    // And the nonce was not consumed by the refused attempt.
    env.message_type = MessageType::IdentityPresentation;
    a.admit_at(&env, &src("p"), NOW).await.unwrap();
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
    a.admit_at(&env, &src("p"), NOW).await.unwrap();
    // Consuming freed a slot.
    a.challenge_at(&src("flood"), NOW).await.unwrap();
}

#[tokio::test]
async fn expired_nonces_free_capacity_and_are_refused() {
    let a = admission_with(Arc::new(InMemoryNonceStore::new(1)));
    let c1 = a.challenge_at(&src("s"), NOW).await.unwrap();
    let later = NOW.saturating_add(std::time::Duration::from_secs(301));
    // The expired record no longer counts against the bound.
    let _c2 = a.challenge_at(&src("s"), later).await.unwrap();
    let env = present_pinned(&subject_ed(), "s", &c1, later).unwrap();
    let e = a.admit_at(&env, &src("p"), later).await.unwrap_err();
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
    assert_eq!(
        ch.expires_at,
        NOW.saturating_add(std::time::Duration::from_secs(30))
    );
    let t = NOW.saturating_add(std::time::Duration::from_secs(31));
    let env = present_pinned(&subject_ed(), "s", &ch, t).unwrap();
    let e = a.admit_at(&env, &src("p"), t).await.unwrap_err();
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
    assert_eq!(
        ch.expires_at,
        NOW.saturating_add(std::time::Duration::from_secs(300))
    );
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
        code(&b.admit_at(&env, &src("p"), NOW).await.unwrap_err()),
        "IDENTITY_FAILED"
    );
    // A presentation addressed to B, replayed at A: proof's receiver
    // is B, so A's §3.2 check fails, and A's nonce survives.
    assert_eq!(
        code(&a.admit_at(&env, &src("p"), NOW).await.unwrap_err()),
        "IDENTITY_FAILED"
    );
    let good = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    a.admit_at(&good, &src("p"), NOW).await.unwrap();
}

#[tokio::test]
async fn untrusted_key_rejected_and_nonce_survives() {
    let a = admission();
    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    let stranger = AitpSigningKey::from_ed25519_seed(&[0x55; 32]);
    let env = present_pinned(&stranger, "s", &ch, NOW).unwrap();
    assert_eq!(
        code(&a.admit_at(&env, &src("p"), NOW).await.unwrap_err()),
        "IDENTITY_FAILED"
    );
    a.admit_at(
        &present_pinned(&subject_ed(), "s", &ch, NOW).unwrap(),
        &src("p"),
        NOW,
    )
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
        code(&a.admit_at(&env, &src("p"), NOW).await.unwrap_err()),
        "INVALID_SIGNATURE"
    );
}

#[tokio::test]
async fn stale_timestamp_and_unknown_member_rejected() {
    let a = admission();
    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    let env = present_pinned(
        &subject_ed(),
        "s",
        &ch,
        NOW.saturating_sub(std::time::Duration::from_secs(301)),
    )
    .unwrap();
    assert_eq!(
        code(&a.admit_at(&env, &src("p"), NOW).await.unwrap_err()),
        "TIMESTAMP_EXPIRED"
    );
    let mut env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    env.payload["role"] = "admin".into();
    assert_eq!(
        code(&a.admit_at(&env, &src("p"), NOW).await.unwrap_err()),
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
        code(&a.admit_at(&env, &src("p"), NOW).await.unwrap_err()),
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
        e @ AdmissionError::RateLimited { .. } => {
            assert!(e.retry_after().is_some());
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
            .map(|i| {
                let (a, env) = (a.clone(), env.clone());
                tokio::spawn(
                    async move { a.admit_at(&env, &src(&format!("p{i}")), NOW).await.is_ok() },
                )
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
    .subject_binding(aitp::handshake::SubjectBinding::SenderAid)
    .build();
    let key = subject_ed();

    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    let env = present_pinned(&key, "free-form-label", &ch, NOW).unwrap();
    let e = a.admit_at(&env, &src("p"), NOW).await.unwrap_err();
    assert_eq!(code(&e), "IDENTITY_FAILED", "{e:?}");

    let ch = a.challenge_at(&src("s"), NOW).await.unwrap();
    let env = present_pinned(&key, key.aid().as_str(), &ch, NOW).unwrap();
    let ok = a.admit_at(&env, &src("p"), NOW).await.unwrap();
    assert_eq!(ok.subject(), key.aid().as_str());
}

/// id-016 / RFC-AITP-0002 §3.4 (spec cfd2f16): the nonce bound refuses
/// with `CHALLENGE_REFUSED` (retryable), over HTTP a 503 with
/// `Retry-After` and `{"error":"CHALLENGE_REFUSED"}`. A rate-limited
/// challenge request is exactly HTTP 429 with no code and an empty body,
/// so the client can tell the two apart.
#[tokio::test]
async fn refusal_is_503_and_rate_limit_is_429() {
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

    assert!(matches!(
        at_bound,
        AdmissionError::ChallengeRefused {
            cause: RefusalCause::AtCapacity,
            ..
        }
    ));
    assert_eq!(at_bound.code(), Some("CHALLENGE_REFUSED"));
    assert!(aitp::core::ErrorCode::ChallengeRefused.is_retryable());
    assert_eq!(at_bound.http_status(), Some(503));
    assert_eq!(at_bound.retry_after(), Some(Duration::from_secs(301)));
    assert_eq!(
        at_bound.http_body(),
        Some(r#"{"error":"CHALLENGE_REFUSED"}"#)
    );
    let body: serde_json::Value = serde_json::from_str(at_bound.http_body().unwrap()).unwrap();
    assert_eq!(body, serde_json::json!({"error": "CHALLENGE_REFUSED"}));

    assert!(
        matches!(rate, AdmissionError::RateLimited { .. }),
        "{rate:?}"
    );
    assert_eq!(rate.code(), None);
    assert_eq!(rate.http_status(), Some(429));
    assert!(rate.retry_after().is_some());
    assert_eq!(rate.http_body(), None);
}

/// A store that cannot say when a slot frees still yields a
/// `Retry-After`: `MAX_NONCE_TTL` bounds every outstanding nonce.
#[test]
fn refusal_without_store_hint_retries_after_max_ttl() {
    let e = AdmissionError::ChallengeRefused {
        retry_after: None,
        cause: RefusalCause::AtCapacity,
    };
    assert_eq!(
        e.retry_after(),
        Some(aitp::handshake::admission::MAX_NONCE_TTL)
    );
    assert_eq!(e.http_status(), Some(503));
}

/// Item 5 / #69: rate limiting is on by default, at RFC-AITP-0009 §3.1's
/// 30 per minute per transport source.
#[tokio::test]
async fn rate_limit_is_on_by_default() {
    let a = admission();
    let ip = ChallengeSource::ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
    for _ in 0..aitp::handshake::RECOMMENDED_REQUESTS_PER_SOURCE_PER_60S {
        a.challenge_at(&ip, NOW).await.unwrap();
    }
    let e = a.challenge_at(&ip, NOW).await.unwrap_err();
    assert_eq!(e.http_status(), Some(429), "{e:?}");
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

/// aitp-rs#205 A-1: an at-capacity refusal says when the earliest
/// outstanding nonce expires, so a transport can always send
/// `Retry-After`. `expires_at` is inclusive: the slot frees one second
/// after it.
#[tokio::test]
async fn at_capacity_refusal_carries_retry_after() {
    let a = admission_with(Arc::new(InMemoryNonceStore::new(1)));
    let ch = a.challenge_at(&src("a"), NOW).await.unwrap();
    assert_eq!(ch.expires_at, Timestamp(NOW.0 + 300));
    let later = Timestamp(NOW.0 + 10);
    match a.challenge_at(&src("b"), later).await.unwrap_err() {
        AdmissionError::ChallengeRefused {
            retry_after,
            cause: RefusalCause::AtCapacity,
        } => assert_eq!(retry_after, Some(Duration::from_secs(291))),
        other => panic!("expected AtCapacity, got {other:?}"),
    }
    // At the advertised time the slot is free.
    a.challenge_at(&src("b"), Timestamp(later.0 + 291))
        .await
        .unwrap();
}

// ── RFC-AITP-0002 §3.4 check order ──────────────────────────────────────

fn limited_admission(per_source: u32) -> PinnedAdmission {
    PinnedAdmission::builder(
        verifier_key().aid().clone(),
        Arc::new(InMemoryNonceStore::default()),
        Arc::new(StaticPinnedKeyStore::new([subject_ed().verifying_key()])),
    )
    .presentation_rate_limiter(Arc::new(TokenBucketLimiter::new(per_source, 1.0 / 60.0)))
    .build()
}

/// id-022: the deny list answers before the rate limit, a replay costs
/// no slot, a rate-limited presentation is HTTP 429 with no wire code
/// and records nothing.
#[tokio::test]
async fn id_022_replay_detected_before_rate_limit() {
    let a = limited_admission(1);
    let (s7, s8) = (src("198.51.100.7"), src("198.51.100.8"));
    let ch = a.challenge_at(&src("c"), NOW).await.unwrap();
    let env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    a.admit_at(&env, &s7, NOW).await.unwrap();

    let replay = a.admit_at(&env, &s7, NOW).await.unwrap_err();
    assert_eq!(code(&replay), "REPLAY_DETECTED");

    let fresh = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    let limited = a.admit_at(&fresh, &s7, NOW).await.unwrap_err();
    assert!(
        matches!(limited, AdmissionError::RateLimited { .. }),
        "{limited:?}"
    );
    assert_eq!(limited.code(), None);
    assert_eq!(limited.http_status(), Some(429));

    // The 429 recorded nothing: the same envelope from a fresh source
    // passes both gates and fails at the consumed nonce.
    assert_eq!(
        code(&a.admit_at(&fresh, &s8, NOW).await.unwrap_err()),
        "IDENTITY_FAILED"
    );
}

/// A replay never charges the source's presentation limit.
#[tokio::test]
async fn replays_do_not_consume_rate_limit_slots() {
    let a = limited_admission(2);
    let s = src("s");
    let ch = a.challenge_at(&src("c"), NOW).await.unwrap();
    let env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    a.admit_at(&env, &s, NOW).await.unwrap();
    for _ in 0..10 {
        assert_eq!(
            code(&a.admit_at(&env, &s, NOW).await.unwrap_err()),
            "REPLAY_DETECTED"
        );
    }
    let ch = a.challenge_at(&src("c"), NOW).await.unwrap();
    let env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    a.admit_at(&env, &s, NOW).await.unwrap();
}

/// Only an admitted presentation is recorded: a rejected one can be
/// corrected and resent under the same `message_id`.
#[tokio::test]
async fn rejected_presentation_is_not_recorded() {
    let a = admission();
    let ch = a.challenge_at(&src("c"), NOW).await.unwrap();
    let env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    let mut bad = env.clone();
    bad.signature = present_pinned(&subject_ed(), "s", &ch, NOW)
        .unwrap()
        .signature;
    assert_eq!(
        code(&a.admit_at(&bad, &src("p"), NOW).await.unwrap_err()),
        "INVALID_SIGNATURE"
    );
    a.admit_at(&env, &src("p"), NOW).await.unwrap();
}

/// Step 3 before step 4: a stale envelope is TIMESTAMP_EXPIRED even when
/// its structure is also wrong.
#[tokio::test]
async fn timestamp_checked_before_structure() {
    let a = admission();
    let ch = a.challenge_at(&src("c"), NOW).await.unwrap();
    let mut env = present_pinned(
        &subject_ed(),
        "s",
        &ch,
        NOW.saturating_sub(std::time::Duration::from_secs(301)),
    )
    .unwrap();
    env.message_type = MessageType::MutualHello;
    assert_eq!(
        code(&a.admit_at(&env, &src("p"), NOW).await.unwrap_err()),
        "TIMESTAMP_EXPIRED"
    );
}

/// Step 4: the payload is exactly `{identity, pop_nonce}`; there is no
/// payload `extensions` member.
#[tokio::test]
async fn payload_extensions_member_is_unknown() {
    let a = admission();
    let ch = a.challenge_at(&src("c"), NOW).await.unwrap();
    let mut env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    env.payload["extensions"] = serde_json::json!({});
    assert_eq!(
        code(&a.admit_at(&env, &src("p"), NOW).await.unwrap_err()),
        "UNKNOWN_FIELD"
    );
}

/// Step 7 before step 8: with both a forged envelope signature and a
/// forged proof, the envelope signature is reported.
#[tokio::test]
async fn envelope_signature_checked_before_proof() {
    let a = admission();
    let ch = a.challenge_at(&src("c"), NOW).await.unwrap();
    let mut env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    let other = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    env.payload["identity"]["proof"] = other.payload["identity"]["proof"].clone();
    env.signature = other.signature;
    assert_eq!(
        code(&a.admit_at(&env, &src("p"), NOW).await.unwrap_err()),
        "INVALID_SIGNATURE"
    );
    // With a valid envelope signature over the forged proof, step 8
    // reports the proof.
    let mut env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    env.payload["identity"]["proof"] = other.payload["identity"]["proof"].clone();
    let digest = aitp::core::envelope_signing_digest(&env).unwrap();
    env.signature = subject_ed()
        .sign_jcs(&aitp::crypto::Digest32::from_bytes(digest))
        .into_string();
    assert_eq!(
        code(&a.admit_at(&env, &src("p"), NOW).await.unwrap_err()),
        "IDENTITY_FAILED"
    );
}

/// Step 6 before step 7: an untrusted key is IDENTITY_FAILED even with a
/// forged envelope signature.
#[tokio::test]
async fn trust_store_checked_before_envelope_signature() {
    let a = limited_admission(30);
    let stranger = AitpSigningKey::from_ed25519_seed(&[0x44; 32]);
    let ch = a.challenge_at(&src("c"), NOW).await.unwrap();
    let mut env = present_pinned(&stranger, "s", &ch, NOW).unwrap();
    env.signature = present_pinned(&stranger, "s", &ch, NOW).unwrap().signature;
    assert_eq!(
        code(&a.admit_at(&env, &src("p"), NOW).await.unwrap_err()),
        "IDENTITY_FAILED"
    );
}

/// `admit_wire` runs steps 1–3 on the raw JSON, before structure: a
/// replayed `message_id` is REPLAY_DETECTED even under a broken envelope.
#[tokio::test]
async fn wire_replay_is_detected_before_structure() {
    let a = admission();
    let ch = a.challenge_at(&src("c"), NOW).await.unwrap();
    let env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    let mut wire = serde_json::to_value(&env).unwrap();
    let checked: aitp::core::CheckedJson = wire.to_string().parse().unwrap();
    a.admit_wire_at(&checked, &src("p"), NOW).await.unwrap();
    wire["bogus"] = true.into();
    let checked: aitp::core::CheckedJson = wire.to_string().parse().unwrap();
    assert_eq!(
        code(&a.admit_wire_at(&checked, &src("p"), NOW).await.unwrap_err()),
        "REPLAY_DETECTED"
    );
}

/// RFC-AITP-0001 §5.4 envelope check order inside step 4: `version`
/// first (UNKNOWN_VERSION, even beside an unknown member and a broken
/// signature; `aitp/0.2` included, strict cutover), then the member set
/// (UNKNOWN_FIELD), then the signature (INVALID_SIGNATURE).
#[tokio::test]
async fn wire_envelope_check_order_is_version_then_members_then_signature() {
    type Mutate<'a> = &'a dyn Fn(&mut serde_json::Value);
    let cases: [(Mutate, &str); 4] = [
        (
            &|w| {
                w["version"] = "aitp/9.9".into();
                w["bogus"] = true.into();
            },
            "UNKNOWN_VERSION",
        ),
        (&|w| w["version"] = "aitp/0.2".into(), "UNKNOWN_VERSION"),
        (
            &|w| {
                w["bogus"] = true.into();
                w["signature"] = "A".repeat(86).into();
            },
            "UNKNOWN_FIELD",
        ),
        (
            &|w| w["message_type"] = "mutual_hello".into(),
            "INVALID_ENVELOPE",
        ),
    ];
    for (mutate, want) in cases {
        let a = admission();
        let ch = a.challenge_at(&src("c"), NOW).await.unwrap();
        let env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
        let mut wire = serde_json::to_value(&env).unwrap();
        mutate(&mut wire);
        let checked: aitp::core::CheckedJson = wire.to_string().parse().unwrap();
        assert_eq!(
            code(&a.admit_wire_at(&checked, &src("p"), NOW).await.unwrap_err()),
            want
        );
    }
}

/// `version` is signed under the v2 input: a presentation re-labelled to
/// another field value after signing fails its signature, not structure.
#[tokio::test]
async fn wire_payload_tamper_after_signing_is_invalid_signature() {
    let a = admission();
    let ch = a.challenge_at(&src("c"), NOW).await.unwrap();
    let env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    let mut wire = serde_json::to_value(&env).unwrap();
    wire["extensions"] = serde_json::json!({"com.example.x": 1});
    let checked: aitp::core::CheckedJson = wire.to_string().parse().unwrap();
    assert_eq!(
        code(&a.admit_wire_at(&checked, &src("p"), NOW).await.unwrap_err()),
        "INVALID_SIGNATURE"
    );
}

/// A deny list shared by two verifiers rejects a presentation the other
/// already admitted, and a full list is a local error, never an eviction.
#[tokio::test]
async fn deny_list_is_pluggable_and_bounded() {
    let deny = Arc::new(InMemoryMessageIdDenyList::new(1));
    let nonces: Arc<InMemoryNonceStore> = Arc::new(InMemoryNonceStore::default());
    let mk = || {
        PinnedAdmission::builder(
            verifier_key().aid().clone(),
            nonces.clone(),
            Arc::new(StaticPinnedKeyStore::new([subject_ed().verifying_key()])),
        )
        .message_id_deny_list(deny.clone())
        .build()
    };
    let (a, b) = (mk(), mk());
    let ch = a.challenge_at(&src("c"), NOW).await.unwrap();
    let env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    a.admit_at(&env, &src("p"), NOW).await.unwrap();
    assert_eq!(
        code(&b.admit_at(&env, &src("p"), NOW).await.unwrap_err()),
        "REPLAY_DETECTED"
    );
    let ch = a.challenge_at(&src("c"), NOW).await.unwrap();
    let env = present_pinned(&subject_ed(), "s", &ch, NOW).unwrap();
    let e = b.admit_at(&env, &src("p"), NOW).await.unwrap_err();
    assert!(matches!(e, AdmissionError::DenyList(_)), "{e:?}");
    assert_eq!(e.code(), None);
}
