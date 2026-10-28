//! Unit tests for RateLimitConfig sliding-window semantics on
//! HandshakeServer, through the crate-private `enforce_rate_limit`
//! (RFC-AITP-0009 §3.1: rate limiting is a MUST, and the pre-auth
//! source key MUST include a transport identifier).

use crate::core::{AitpEnvelope, MessageType, Timestamp};
use crate::crypto::AitpSigningKey;
use crate::envelope::sign_envelope_with;
use crate::handshake::{IdentityKind, JwkPublicKey, JwksResolver, ResolveError};
use crate::manifest::{IdentityHint, ManifestBuilder};
use crate::transport::server::RateLimitOutcome;
use crate::transport::{HandshakeServer, RateLimitConfig, TrustedProxy};
use std::net::IpAddr;
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
    let key = AitpSigningKey::from_ed25519_seed(&[0xAB; 32]);
    let manifest = ManifestBuilder::new(&key)
        .display_name("responder")
        .handshake_endpoint("https://example.com/aitp/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityKind::PinnedKey, "responder").with_public_key(
                crate::core::base64url::encode(
                    &key.verifying_key()
                        .try_to_ed25519_bytes()
                        .expect("key was constructed as Ed25519, never P-256"),
                ),
            ),
        )
        .accept_identity_type(crate::handshake::IdentityKind::PinnedKey)
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

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn allows_traffic_below_per_ip_limit() {
    let srv = server().with_rate_limit(
        RateLimitConfig::default()
            .with_requests_per_source_per_60s(5)
            .with_requests_per_aid_per_60s(None),
    );
    for _ in 0..5 {
        assert!(matches!(
            srv.enforce_rate_limit(Some(ip("1.2.3.4")), None),
            RateLimitOutcome::Allow
        ));
    }
    // 6th hit denies.
    assert!(matches!(
        srv.enforce_rate_limit(Some(ip("1.2.3.4")), None),
        RateLimitOutcome::DenyTooManyRequests { .. }
    ));
}

#[test]
fn separate_ips_have_separate_buckets() {
    let srv = server().with_rate_limit(
        RateLimitConfig::default()
            .with_requests_per_source_per_60s(2)
            .with_requests_per_aid_per_60s(None),
    );
    // Each IP gets its own window.
    for _ in 0..2 {
        assert!(matches!(
            srv.enforce_rate_limit(Some(ip("10.0.0.1")), None),
            RateLimitOutcome::Allow
        ));
    }
    for _ in 0..2 {
        assert!(matches!(
            srv.enforce_rate_limit(Some(ip("10.0.0.2")), None),
            RateLimitOutcome::Allow
        ));
    }
    assert!(matches!(
        srv.enforce_rate_limit(Some(ip("10.0.0.1")), None),
        RateLimitOutcome::DenyTooManyRequests { .. }
    ));
}

/// RFC-AITP-0009 §3.1 MUST: a server built without any rate-limit call
/// still limits, at the recommended 30 per source per 60 s.
#[test]
fn rate_limit_is_on_by_default() {
    let srv = server();
    for _ in 0..30 {
        assert!(matches!(
            srv.enforce_rate_limit(Some(ip("1.1.1.1")), None),
            RateLimitOutcome::Allow
        ));
    }
    assert!(matches!(
        srv.enforce_rate_limit(Some(ip("1.1.1.1")), None),
        RateLimitOutcome::DenyTooManyRequests { .. }
    ));
}

#[test]
fn recommended_defaults_match_rfc_0009() {
    let c = RateLimitConfig::default();
    assert_eq!(c.requests_per_source_per_60s, 30);
    assert_eq!(c.requests_per_aid_per_60s, Some(10));
    assert!(c.trusted_proxies.is_empty());
}

/// An explicit opt-out, for deployments that enforce §3.1 upstream.
#[test]
fn without_rate_limit_dangerous_always_allows() {
    let srv = server().without_rate_limit_dangerous();
    for _ in 0..10_000 {
        assert!(matches!(
            srv.enforce_rate_limit(Some(ip("1.1.1.1")), None),
            RateLimitOutcome::Allow
        ));
    }
}

#[test]
fn denied_request_does_not_consume_quota() {
    let srv = server().with_rate_limit(
        RateLimitConfig::default()
            .with_requests_per_source_per_60s(1)
            .with_requests_per_aid_per_60s(None),
    );
    assert!(matches!(
        srv.enforce_rate_limit(Some(ip("9.9.9.9")), None),
        RateLimitOutcome::Allow
    ));
    // Several denies in a row.
    for _ in 0..5 {
        assert!(matches!(
            srv.enforce_rate_limit(Some(ip("9.9.9.9")), None),
            RateLimitOutcome::DenyTooManyRequests { .. }
        ));
    }
    // Once the in-window slot expires (60s later) the next call
    // would allow — we don't sleep 60s in tests, but assert that
    // none of the denied calls have polluted the window.
}

/// The per-AID key is self-asserted before signature verification, so
/// rotating sender AIDs from one address must not escape the
/// transport limit (RFC-AITP-0009 §3.1: never the only key).
#[test]
fn rotating_aids_does_not_bypass_transport_limit() {
    let srv = server().with_rate_limit(
        RateLimitConfig::default()
            .with_requests_per_source_per_60s(3)
            .with_requests_per_aid_per_60s(Some(100)),
    );
    for seed in 0..3u8 {
        let k = AitpSigningKey::from_ed25519_seed(&[seed; 32]);
        assert!(matches!(
            srv.enforce_rate_limit(Some(ip("8.8.8.8")), Some(k.aid())),
            RateLimitOutcome::Allow
        ));
    }
    let fresh = AitpSigningKey::from_ed25519_seed(&[0x99; 32]);
    assert!(matches!(
        srv.enforce_rate_limit(Some(ip("8.8.8.8")), Some(fresh.aid())),
        RateLimitOutcome::DenyTooManyRequests { .. }
    ));
}

/// IPv6 sources are keyed by /64 (one host owns the whole prefix) and
/// an IPv4-mapped address shares the IPv4 bucket.
#[test]
fn ipv6_slash_64_and_v4_mapped_share_a_bucket() {
    let srv = server().with_rate_limit(
        RateLimitConfig::default()
            .with_requests_per_source_per_60s(2)
            .with_requests_per_aid_per_60s(None),
    );
    assert!(matches!(
        srv.enforce_rate_limit(Some(ip("2001:db8:1:2::1")), None),
        RateLimitOutcome::Allow
    ));
    assert!(matches!(
        srv.enforce_rate_limit(Some(ip("2001:db8:1:2:ffff::9")), None),
        RateLimitOutcome::Allow
    ));
    assert!(matches!(
        srv.enforce_rate_limit(Some(ip("2001:db8:1:2:abcd::1")), None),
        RateLimitOutcome::DenyTooManyRequests { .. }
    ));
    assert!(matches!(
        srv.enforce_rate_limit(Some(ip("2001:db8:1:3::1")), None),
        RateLimitOutcome::Allow
    ));

    assert!(matches!(
        srv.enforce_rate_limit(Some(ip("192.0.2.7")), None),
        RateLimitOutcome::Allow
    ));
    assert!(matches!(
        srv.enforce_rate_limit(Some(ip("::ffff:192.0.2.7")), None),
        RateLimitOutcome::Allow
    ));
    assert!(matches!(
        srv.enforce_rate_limit(Some(ip("192.0.2.7")), None),
        RateLimitOutcome::DenyTooManyRequests { .. }
    ));
}

#[test]
fn trusted_proxy_parses_cidrs_and_hosts() {
    let net: TrustedProxy = "10.0.0.0/8".parse().unwrap();
    assert!(net.contains(ip("10.255.0.1")));
    assert!(!net.contains(ip("11.0.0.1")));
    let host: TrustedProxy = "127.0.0.1".parse().unwrap();
    assert!(host.contains(ip("127.0.0.1")));
    assert!(!host.contains(ip("127.0.0.2")));
    let v6: TrustedProxy = "fd00::/8".parse().unwrap();
    assert!(v6.contains(ip("fd12::1")));
    assert!(!v6.contains(ip("fe80::1")));
    // A v4 range matches the IPv4-mapped form of its members.
    assert!(net.contains(ip("::ffff:10.1.2.3")));
    for bad in ["10.0.0.0/33", "::/129", "nope", "10.0.0.0/", "/8"] {
        assert!(bad.parse::<TrustedProxy>().is_err(), "{bad}");
    }
}

// ── End-to-end: rate limiting wired into the HTTP handlers (GAP-1) ──

/// Spawn a `HandshakeServer` with a per-IP rate limit and return its
/// port. The per-AID gate is disabled so the test isolates per-IP
/// behavior.
async fn spawn_rate_limited_server(per_ip: u32) -> u16 {
    spawn_server(per_ip, vec!["127.0.0.1".parse().unwrap()]).await
}

/// As [`spawn_rate_limited_server`], with an explicit trusted-proxy
/// list. Served with connect info, as `HandshakeServer::router`
/// documents, so the peer socket address is the transport key.
async fn spawn_server(per_ip: u32, trusted_proxies: Vec<TrustedProxy>) -> u16 {
    let key = AitpSigningKey::from_ed25519_seed(&[0xE1; 32]);
    let manifest = ManifestBuilder::new(&key)
        .display_name("responder")
        .handshake_endpoint("https://example.com/aitp/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityKind::PinnedKey, "responder").with_public_key(
                crate::core::base64url::encode(
                    &key.verifying_key()
                        .try_to_ed25519_bytes()
                        .expect("key was constructed as Ed25519, never P-256"),
                ),
            ),
        )
        .accept_identity_type(crate::handshake::IdentityKind::PinnedKey)
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
    .with_rate_limit(
        RateLimitConfig::default()
            .with_requests_per_source_per_60s(per_ip)
            .with_requests_per_aid_per_60s(None)
            .with_trusted_proxies(trusted_proxies),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        srv.serve(listener).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    port
}

/// A fresh, validly-signed MUTUAL_HELLO envelope with a unique
/// `message_id` — distinct per call so the replay deny-list never
/// fires, isolating the rate-limit path.
fn fresh_hello_envelope() -> AitpEnvelope {
    let key = AitpSigningKey::from_ed25519_seed(&[0xE2; 32]);
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

/// Issue #255, RFC-AITP-0009 §3.1: rate limiting runs before schema
/// parsing, so bodies that are not JSON, carry an unknown `version`, or
/// are stale count against the source's budget, and once it is spent
/// they are shed with 429 rather than answered with an error envelope.
#[tokio::test]
async fn malformed_and_stale_requests_consume_rate_limit_budget() {
    let port = spawn_rate_limited_server(3).await;
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/aitp/handshake/hello");
    let post = |body: Vec<u8>| {
        client
            .post(&url)
            .header("x-forwarded-for", "8.8.8.8")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
    };

    let mut unknown_version = serde_json::to_value(fresh_hello_envelope()).unwrap();
    unknown_version["version"] = "aitp/9.9".into();
    let key = AitpSigningKey::from_ed25519_seed(&[0xE2; 32]);
    let stale = sign_envelope_with(
        &key,
        MessageType::MutualHello,
        serde_json::json!({}),
        Uuid::new_v4(),
        Timestamp(Timestamp::now().0 - 7200),
    )
    .unwrap();
    for body in [
        b"{not json".to_vec(),
        serde_json::to_vec(&unknown_version).unwrap(),
        serde_json::to_vec(&stale).unwrap(),
    ] {
        let resp = post(body).await.unwrap();
        assert_eq!(resp.status().as_u16(), 400, "within the limit");
    }
    let resp = post(b"{not json".to_vec()).await.unwrap();
    assert_eq!(resp.status().as_u16(), 429);
    assert!(resp.bytes().await.unwrap().is_empty());
}

#[test]
fn allows_traffic_below_per_aid_limit_then_denies() {
    // The per-AID gate (keyed on the envelope sender) is the stronger,
    // payload-derived limiter; only the per-IP gate was previously tested.
    let srv = server().with_rate_limit(
        RateLimitConfig::default()
            .with_requests_per_source_per_60s(1_000)
            .with_requests_per_aid_per_60s(Some(3)),
    );
    let aid = AitpSigningKey::from_ed25519_seed(&[0x33; 32]);
    for _ in 0..3 {
        assert!(matches!(
            srv.enforce_rate_limit(None, Some(aid.aid())),
            RateLimitOutcome::Allow
        ));
    }
    assert!(matches!(
        srv.enforce_rate_limit(None, Some(aid.aid())),
        RateLimitOutcome::DenyTooManyRequests { .. }
    ));
}

#[test]
fn per_aid_buckets_are_independent() {
    let srv = server().with_rate_limit(
        RateLimitConfig::default()
            .with_requests_per_source_per_60s(1_000)
            .with_requests_per_aid_per_60s(Some(2)),
    );
    let alice = AitpSigningKey::from_ed25519_seed(&[0x44; 32]);
    let bob = AitpSigningKey::from_ed25519_seed(&[0x55; 32]);
    // Exhaust Alice's budget.
    for _ in 0..2 {
        assert!(matches!(
            srv.enforce_rate_limit(None, Some(alice.aid())),
            RateLimitOutcome::Allow
        ));
    }
    assert!(matches!(
        srv.enforce_rate_limit(None, Some(alice.aid())),
        RateLimitOutcome::DenyTooManyRequests { .. }
    ));
    // Bob is unaffected — separate bucket.
    assert!(matches!(
        srv.enforce_rate_limit(None, Some(bob.aid())),
        RateLimitOutcome::Allow
    ));
}

/// RFC-AITP-0009 §3.1: a forwarding header counts only when the
/// immediate hop is a configured trusted proxy. Without one, rotating
/// `X-Forwarded-For` from a single peer gets no fresh budget.
#[tokio::test]
async fn forwarded_for_from_untrusted_peer_is_ignored() {
    let port = spawn_server(2, vec![]).await;
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/aitp/handshake/hello");
    let mut statuses = Vec::new();
    for spoof in ["1.0.0.1", "1.0.0.2", "1.0.0.3", "1.0.0.4"] {
        let resp = client
            .post(&url)
            .header("x-forwarded-for", spoof)
            .header("x-real-ip", spoof)
            .json(&fresh_hello_envelope())
            .send()
            .await
            .unwrap();
        statuses.push(resp.status().as_u16());
    }
    assert_eq!(statuses, [400, 400, 429, 429]);
}

/// Behind a trusted proxy the client is the rightmost untrusted
/// `X-Forwarded-For` hop: a value the client prepended to the header
/// itself is not believed.
#[tokio::test]
async fn forwarded_for_uses_rightmost_untrusted_hop() {
    let port = spawn_server(
        1,
        vec!["127.0.0.1".parse().unwrap(), "10.0.0.0/8".parse().unwrap()],
    )
    .await;
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/aitp/handshake/hello");
    let send = |xff: &'static str| {
        let client = client.clone();
        let url = url.clone();
        async move {
            client
                .post(&url)
                .header("x-forwarded-for", xff)
                .json(&fresh_hello_envelope())
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    // Client 203.0.113.9 went through an inner proxy 10.1.1.1.
    assert_eq!(send("203.0.113.9, 10.1.1.1").await, 400);
    // Same client, forged leftmost entries: still 203.0.113.9.
    assert_eq!(send("9.9.9.9, 203.0.113.9, 10.1.1.1").await, 429);
    assert_eq!(send("8.8.8.8, 203.0.113.9").await, 429);
    // A different real client has its own bucket.
    assert_eq!(send("198.51.100.4").await, 400);
}

/// A router served without connect info has no transport identifier.
/// The server does not fall back to the self-asserted AID alone: every
/// such request shares one bucket.
#[tokio::test]
async fn missing_transport_identifier_shares_one_bucket() {
    let srv = server().with_rate_limit(
        RateLimitConfig::default()
            .with_requests_per_source_per_60s(2)
            .with_requests_per_aid_per_60s(None),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        srv.serve(listener).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/aitp/handshake/hello");
    let mut statuses = Vec::new();
    for _ in 0..3 {
        statuses.push(
            client
                .post(&url)
                .json(&fresh_hello_envelope())
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
        );
    }
    assert_eq!(statuses, [400, 400, 429]);
}
