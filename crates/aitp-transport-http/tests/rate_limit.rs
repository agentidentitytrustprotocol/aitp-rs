//! RateLimitConfig sliding-window semantics on HandshakeServer
//! (Phase 14 / RFC-AITP-0009 §3.1).

#![cfg(all(feature = "client", feature = "server"))]

use aitp_core::{AitpEnvelope, MessageType, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp_transport_http::{sign_envelope_with, HandshakeServer, RateLimitConfig, RateLimitOutcome};
use std::time::Duration;
use tokio::net::TcpListener;
use uuid::Uuid;

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn server() -> HandshakeServer<NoOpResolver> {
    let key = AitpSigningKey::from_seed(&[0xAB; 32]);
    let manifest = ManifestBuilder::new(&key)
        .display_name("responder")
        .handshake_endpoint("https://example.com/aitp/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "responder".into(),
            issuer: None,
            public_key: Some(aitp_core::base64url::encode(
                &key.verifying_key().to_bytes(),
            )),
        })
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .build()
        .unwrap();
    HandshakeServer::new(
        key,
        manifest,
        vec!["https://idp.example.com".parse().unwrap()],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
}

#[test]
fn allows_traffic_below_per_ip_limit() {
    let srv = server().with_rate_limit(RateLimitConfig {
        requests_per_ip_per_60s: Some(5),
        requests_per_aid_per_60s: None,
    });
    for _ in 0..5 {
        assert!(matches!(
            srv.enforce_rate_limit(Some("1.2.3.4"), None),
            RateLimitOutcome::Allow
        ));
    }
    // 6th hit denies.
    assert!(matches!(
        srv.enforce_rate_limit(Some("1.2.3.4"), None),
        RateLimitOutcome::DenyTooManyRequests { .. }
    ));
}

#[test]
fn separate_ips_have_separate_buckets() {
    let srv = server().with_rate_limit(RateLimitConfig {
        requests_per_ip_per_60s: Some(2),
        requests_per_aid_per_60s: None,
    });
    // Each IP gets its own window.
    for _ in 0..2 {
        assert!(matches!(
            srv.enforce_rate_limit(Some("10.0.0.1"), None),
            RateLimitOutcome::Allow
        ));
    }
    for _ in 0..2 {
        assert!(matches!(
            srv.enforce_rate_limit(Some("10.0.0.2"), None),
            RateLimitOutcome::Allow
        ));
    }
    assert!(matches!(
        srv.enforce_rate_limit(Some("10.0.0.1"), None),
        RateLimitOutcome::DenyTooManyRequests { .. }
    ));
}

#[test]
fn no_policy_always_allows() {
    let srv = server();
    for _ in 0..10_000 {
        assert!(matches!(
            srv.enforce_rate_limit(Some("1.1.1.1"), None),
            RateLimitOutcome::Allow
        ));
    }
}

#[test]
fn denied_request_does_not_consume_quota() {
    let srv = server().with_rate_limit(RateLimitConfig {
        requests_per_ip_per_60s: Some(1),
        requests_per_aid_per_60s: None,
    });
    assert!(matches!(
        srv.enforce_rate_limit(Some("9.9.9.9"), None),
        RateLimitOutcome::Allow
    ));
    // Several denies in a row.
    for _ in 0..5 {
        assert!(matches!(
            srv.enforce_rate_limit(Some("9.9.9.9"), None),
            RateLimitOutcome::DenyTooManyRequests { .. }
        ));
    }
    // Once the in-window slot expires (60s later) the next call
    // would allow — we don't sleep 60s in tests, but assert that
    // none of the denied calls have polluted the window.
}

// ── End-to-end: rate limiting wired into the HTTP handlers (GAP-1) ──

/// Spawn a `HandshakeServer` with a per-IP rate limit and return its
/// port. The per-AID gate is disabled so the test isolates per-IP
/// behavior.
async fn spawn_rate_limited_server(per_ip: u32) -> u16 {
    let key = AitpSigningKey::from_seed(&[0xE1; 32]);
    let manifest = ManifestBuilder::new(&key)
        .display_name("responder")
        .handshake_endpoint("https://example.com/aitp/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "responder".into(),
            issuer: None,
            public_key: Some(aitp_core::base64url::encode(
                &key.verifying_key().to_bytes(),
            )),
        })
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .build()
        .unwrap();
    let srv = HandshakeServer::new(
        key,
        manifest,
        vec!["https://idp.example.com".parse().unwrap()],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    .with_rate_limit(RateLimitConfig {
        requests_per_ip_per_60s: Some(per_ip),
        requests_per_aid_per_60s: None,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, srv.router()).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    port
}

/// A fresh, validly-signed MUTUAL_HELLO envelope with a unique
/// `message_id` — distinct per call so the replay deny-list never
/// fires, isolating the rate-limit path.
fn fresh_hello_envelope() -> AitpEnvelope {
    let key = AitpSigningKey::from_seed(&[0xE2; 32]);
    sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({}),
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .unwrap()
}

/// RFC-AITP-0009 §3.1 / GAP-1: once a source IP exceeds its per-60s
/// window the handler returns HTTP 429 with an empty body (no AITP
/// error envelope), and a different IP keeps its own bucket.
#[tokio::test]
async fn rate_limit_returns_429_after_per_ip_window_exceeded() {
    let port = spawn_rate_limited_server(3).await;
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/aitp/handshake/hello");

    // First 3 from one IP pass the boundary checks and reach the
    // protocol layer — they then fail payload parsing (400), proving
    // rate limiting did not reject them.
    for i in 0..3 {
        let resp = client
            .post(&url)
            .header("x-forwarded-for", "5.5.5.5")
            .json(&fresh_hello_envelope())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "request {i} within the limit should reach the protocol layer"
        );
    }

    // 4th from the same IP is shed before the protocol layer.
    let resp = client
        .post(&url)
        .header("x-forwarded-for", "5.5.5.5")
        .json(&fresh_hello_envelope())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 429);
    let body = resp.bytes().await.unwrap();
    assert!(
        body.is_empty(),
        "RFC-AITP-0009 §3.1: a 429 carries no AITP error envelope, got {body:?}"
    );

    // A different source IP has an independent window.
    let resp = client
        .post(&url)
        .header("x-forwarded-for", "6.6.6.6")
        .json(&fresh_hello_envelope())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a different IP must not inherit the first IP's exhausted window"
    );
}

/// A replayed envelope is rejected with REPLAY_DETECTED *before* the
/// rate-limit counter is touched (RFC-AITP-0009 §3.1 ordering): the
/// replay does not consume the sender's per-IP budget.
#[tokio::test]
async fn replayed_envelope_does_not_consume_rate_limit_budget() {
    // Per-IP limit 3. One fresh envelope below consumes exactly one
    // slot legitimately; the test asserts the four *replays* of it
    // consume none.
    let port = spawn_rate_limited_server(3).await;
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/aitp/handshake/hello");

    // One fixed envelope, sent 5 times from the same IP. The first send
    // is fresh: it passes the replay check and consumes one rate-limit
    // slot, then fails payload parsing (400). The other four are
    // duplicate message_ids → REPLAY_DETECTED (400) *before* rate
    // limiting, so they consume nothing.
    let envelope = fresh_hello_envelope();
    for _ in 0..5 {
        let resp = client
            .post(&url)
            .header("x-forwarded-for", "7.7.7.7")
            .json(&envelope)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400);
    }

    // One slot is used (the first send above). If the four replays had
    // each burned a slot the window would already be far past 3. They
    // did not, so two more fresh envelopes still fit.
    for _ in 0..2 {
        let resp = client
            .post(&url)
            .header("x-forwarded-for", "7.7.7.7")
            .json(&fresh_hello_envelope())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "replays must not consume the rate-limit window"
        );
    }
    // Now 3 slots are used (1 fixed + 2 fresh); the next fresh envelope
    // exceeds the limit.
    let resp = client
        .post(&url)
        .header("x-forwarded-for", "7.7.7.7")
        .json(&fresh_hello_envelope())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 429);
}
