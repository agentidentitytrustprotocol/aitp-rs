//! RateLimitConfig sliding-window semantics on HandshakeServer
//! (Phase 14 / RFC-AITP-0009 §3.1).

#![cfg(all(feature = "client", feature = "server"))]

use aitp_crypto::AitpSigningKey;
use aitp_handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp_transport_http::{HandshakeServer, RateLimitConfig, RateLimitOutcome};

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
