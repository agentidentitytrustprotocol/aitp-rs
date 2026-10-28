//! aitp-rs#205 A-4: admission counters and the outstanding-nonce gauge.
#![cfg(all(feature = "pinned-admission", feature = "metrics"))]

use aitp::core::Timestamp;
use aitp::crypto::AitpSigningKey;
use aitp::handshake::admission::{
    metrics_names, present_pinned, ChallengeSource, InMemoryNonceStore, PinnedAdmission,
    TokenBucketLimiter,
};
use aitp::handshake::StaticPinnedKeyStore;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use metrics_util::MetricKind;
use std::sync::Arc;

const NOW: Timestamp = Timestamp(1_711_900_000);

#[test]
fn admission_emits_bounded_counters_and_gauge() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let verifier = AitpSigningKey::from_ed25519_seed(&[0x11; 32]);
            let subject = AitpSigningKey::from_ed25519_seed(&[0x22; 32]);
            let a = PinnedAdmission::builder(
                verifier.aid().clone(),
                Arc::new(InMemoryNonceStore::new(2)),
                Arc::new(StaticPinnedKeyStore::new([subject.verifying_key()])),
            )
            .rate_limiter(Arc::new(TokenBucketLimiter::new(100, 0.01)))
            .build();
            let src = ChallengeSource::tls_client_cert_sha256([7; 32]);
            let ch = a.challenge_at(&src, NOW).await.unwrap();
            a.challenge_at(&src, NOW).await.unwrap();
            a.challenge_at(&src, NOW).await.unwrap_err(); // at capacity
            let env = present_pinned(&subject, "s", &ch, NOW).unwrap();
            a.admit_at(&env, &src, NOW).await.unwrap();
            a.admit_at(&env, &src, NOW).await.unwrap_err(); // replay
            let env2 = present_pinned(&subject, "s", &ch, NOW).unwrap();
            a.admit_at(&env2, &src, NOW).await.unwrap_err(); // nonce used
        });
    });

    let mut seen = std::collections::BTreeMap::new();
    for (key, _, _, value) in snapshotter.snapshot().into_vec() {
        let k = key.key();
        let label = k
            .labels()
            .map(|l| format!("{}={}", l.key(), l.value()))
            .collect::<Vec<_>>()
            .join(",");
        let v = match (key.kind(), value) {
            (MetricKind::Counter, DebugValue::Counter(n)) => n as f64,
            (MetricKind::Gauge, DebugValue::Gauge(g)) => g.into_inner(),
            other => panic!("unexpected {other:?}"),
        };
        seen.insert(format!("{}{{{label}}}", k.name()), v);
    }
    let get = |k: &str| seen.get(k).copied();
    let c = metrics_names::CHALLENGE_TOTAL;
    let ad = metrics_names::ADMIT_TOTAL;
    assert_eq!(get(&format!("{c}{{result=issued}}")), Some(2.0), "{seen:?}");
    assert_eq!(get(&format!("{c}{{result=at_capacity}}")), Some(1.0));
    assert_eq!(get(&format!("{ad}{{result=admitted}}")), Some(1.0));
    assert_eq!(get(&format!("{ad}{{result=replay_detected}}")), Some(1.0));
    assert_eq!(get(&format!("{ad}{{result=identity_failed}}")), Some(1.0));
    assert_eq!(
        get(&format!("{}{{}}", metrics_names::NONCES_OUTSTANDING)),
        Some(1.0)
    );
}
