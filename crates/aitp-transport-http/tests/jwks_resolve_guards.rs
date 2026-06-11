//! Transport guards on `JwksFetcher::resolve`.
//!
//! `resolve` fetches issuer keys from an attacker-influenced host, so it
//! refuses any non-HTTPS issuer before touching the network (RFC-AITP-0007
//! §2.3 transport requirement) — a plaintext/SSRF guard that had no test
//! at this entry point.
//!
//! Note: the full §2.3 discovery-vs-aitp-keys *branch* (valid discovery
//! ⇒ never fall back) can only be driven against a live HTTPS endpoint,
//! since `resolve` rejects plaintext. That needs a rustls test fixture
//! and is intentionally not exercised here.

#![cfg(feature = "client")]

use aitp_transport_http::{JwksFetcher, JwksFetcherError};

#[tokio::test]
async fn resolve_rejects_non_https_issuer() {
    let fetcher = JwksFetcher::new();
    let http_issuer = "http://idp.example.com".parse().unwrap();
    let err = fetcher
        .resolve(&http_issuer)
        .await
        .expect_err("a plaintext issuer URL must be refused before any fetch");
    assert!(
        matches!(err, JwksFetcherError::InsecureUrl),
        "expected InsecureUrl, got {err:?}"
    );
}
