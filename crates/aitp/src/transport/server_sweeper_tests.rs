//! Unit tests for the session-table defaults (#198): the automatic
//! background sweeper and the RFC-AITP-0009 §3.1 session cap. Kept out
//! of `server.rs` so they can reach `HandshakeState` internals without
//! growing that file's test module.

use super::*;
use crate::crypto::AitpSigningKey;
use crate::handshake::{Initiator, JwkPublicKey, ResolveError, StaticPinnedKeyStore};
use crate::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use std::sync::atomic::Ordering;

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn manifest_for(key: &AitpSigningKey, name: &str) -> Manifest {
    ManifestBuilder::new(key)
        .display_name(name)
        .handshake_endpoint("https://localhost/aitp/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: name.into(),
            issuer: None,
            public_key: Some(crate::core::base64url::encode(
                &key.verifying_key()
                    .try_to_ed25519_bytes()
                    .expect("Ed25519 key"),
            )),
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .build()
        .unwrap()
}

/// Bob's server with the given TTL; trusts Alice (seed 0x71).
fn server(ttl: Duration) -> HandshakeServer<NoOpResolver> {
    let bob = AitpSigningKey::from_seed(&[0x72; 32]);
    let manifest = manifest_for(&bob, "bob");
    HandshakeServer::with_session_ttl(
        bob,
        manifest,
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
        ttl,
    )
    .with_pinned_key_store(Arc::new(StaticPinnedKeyStore::new([
        AitpSigningKey::from_seed(&[0x71; 32]).verifying_key(),
    ])))
}

/// Drive a real HELLO through `Responder::on_hello` and park the
/// resulting session in the server's table, as the HELLO handler does.
fn insert_session<R: JwksResolver + Send + Sync + 'static>(state: &HandshakeState<R>) {
    let alice = AitpSigningKey::from_seed(&[0x71; 32]);
    let alice_manifest = manifest_for(&alice, "alice");
    let pinned =
        StaticPinnedKeyStore::new([AitpSigningKey::from_seed(&[0x72; 32]).verifying_key()]);
    let resolver = NoOpResolver;
    let init_cfg = PeerConfig::new(
        &alice,
        &alice_manifest,
        &resolver,
        &pinned,
        crate::handshake::RevocationSource::FailOpen,
        Timestamp::now(),
    );
    let mid = Uuid::new_v4();
    let ts = Timestamp::now();
    let (_initiator, hello) = Initiator::start(
        &init_cfg,
        PresentedIdentity::PinnedKey {
            subject: "alice".into(),
        },
        state.signing_key.aid(),
        &mid,
        ts,
        vec!["demo.echo".into()],
    )
    .unwrap();
    let envelope = sign_envelope_with(
        &alice,
        MessageType::MutualHello,
        serde_json::to_value(&hello).unwrap(),
        mid,
        ts,
    )
    .unwrap();

    let store = state.pinned_key_store.lock().clone();
    let resp_cfg = PeerConfig::new(
        &*state.signing_key,
        &state.manifest,
        &state.jwks_resolver,
        &*store,
        crate::handshake::RevocationSource::FailOpen,
        Timestamp::now(),
    )
    .with_trust_anchors(&state.trust_anchors);
    let (responder, _ack) = Responder::on_hello(
        &envelope,
        &hello,
        PresentedIdentity::PinnedKey {
            subject: "bob".into(),
        },
        &Uuid::new_v4(),
        Timestamp::now(),
        &resp_cfg,
        state.requested_grants.clone(),
    )
    .unwrap();
    state.sessions.lock().insert(
        Uuid::new_v4(),
        SessionEntry {
            responder,
            created_at: Instant::now(),
        },
    );
}

/// Poll until the session table is empty or `deadline` passes.
async fn wait_for_empty<R: JwksResolver + Send + Sync + 'static>(
    state: &HandshakeState<R>,
    deadline: Duration,
) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if state.sessions.lock().is_empty() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    state.sessions.lock().is_empty()
}

#[tokio::test]
async fn router_starts_session_sweeper_by_default() {
    let srv = server(DEFAULT_SESSION_TTL);
    let state = srv.state.clone();
    assert_eq!(
        *state.session_sweep_interval.lock(),
        Some(DEFAULT_SESSION_SWEEP_INTERVAL),
        "sweeper is configured on by default"
    );
    assert!(!state.sweeper_started.load(Ordering::Relaxed));
    let _router = srv.router();
    assert!(
        state.sweeper_started.load(Ordering::Relaxed),
        "router() inside a runtime starts the sweeper"
    );
}

#[tokio::test]
async fn sweeper_evicts_expired_sessions_without_traffic() {
    let srv =
        server(Duration::from_millis(30)).with_session_sweep_interval(Duration::from_millis(20));
    let state = srv.state.clone();
    insert_session(&state);
    let _router = srv.router();
    assert_eq!(state.sessions.lock().len(), 1);
    // No request ever arrives, so only the background sweeper can
    // evict the expired session.
    assert!(
        wait_for_empty(&state, Duration::from_secs(2)).await,
        "background sweeper should evict the expired session"
    );
}

#[tokio::test]
async fn without_session_sweeper_disables_it() {
    let srv = server(Duration::from_millis(30)).without_session_sweeper();
    let state = srv.state.clone();
    insert_session(&state);
    let _router = srv.router();
    assert!(!state.sweeper_started.load(Ordering::Relaxed));
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        state.sessions.lock().len(),
        1,
        "no sweeper: the expired session waits for the next request"
    );
}

#[tokio::test]
async fn zero_sweep_interval_disables_it() {
    let srv = server(DEFAULT_SESSION_TTL).with_session_sweep_interval(Duration::ZERO);
    let state = srv.state.clone();
    let _router = srv.router();
    assert!(!state.sweeper_started.load(Ordering::Relaxed));
}

#[test]
fn router_outside_runtime_defers_sweeper_to_first_request() {
    // No Tokio runtime at construction: router() must not panic, and
    // the sweeper starts later from inside the runtime (the HELLO
    // handler calls `ensure_session_sweeper`).
    let srv =
        server(Duration::from_millis(30)).with_session_sweep_interval(Duration::from_millis(20));
    let state = srv.state.clone();
    let _router = srv.router();
    assert!(!state.sweeper_started.load(Ordering::Relaxed));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    rt.block_on(async {
        insert_session(&state);
        HandshakeServer::<NoOpResolver>::ensure_session_sweeper(&state);
        assert!(state.sweeper_started.load(Ordering::Relaxed));
        assert!(wait_for_empty(&state, Duration::from_secs(2)).await);
    });
}

#[tokio::test]
async fn sweeper_starts_only_once() {
    let srv = server(DEFAULT_SESSION_TTL);
    let state = srv.state.clone();
    HandshakeServer::<NoOpResolver>::ensure_session_sweeper(&state);
    let weak_before = Arc::weak_count(&state);
    HandshakeServer::<NoOpResolver>::ensure_session_sweeper(&state);
    let _router = srv.router();
    assert_eq!(
        Arc::weak_count(&state),
        weak_before,
        "a second start must not spawn another sweeper"
    );
}

#[test]
fn default_max_sessions_is_rfc_0009_recommendation() {
    // RFC-AITP-0009 §3.1: maximum concurrent in-flight handshake
    // sessions, recommended default 1000.
    assert_eq!(DEFAULT_MAX_SESSIONS, 1_000);
    let srv = server(DEFAULT_SESSION_TTL);
    let cap = srv.state.max_sessions.load(Ordering::Relaxed);
    assert_eq!(cap, DEFAULT_MAX_SESSIONS);

    // The HELLO handler evicts to `cap - 1` before each insert, so the
    // table never holds more than `cap` sessions.
    let mut map: HashMap<Uuid, Instant> = HashMap::new();
    for _ in 0..cap + 50 {
        evict_oldest_to_capacity(&mut map, cap.saturating_sub(1), |t| *t);
        map.insert(Uuid::new_v4(), Instant::now());
    }
    assert_eq!(map.len(), DEFAULT_MAX_SESSIONS);
}
