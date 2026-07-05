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

use aitp_transport_http::{HostGuard, JwksFetcher, JwksFetcherError};

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

#[tokio::test]
async fn resolve_rejects_link_local_issuer_host() {
    // An issuer URL pointing at the cloud-metadata range must be
    // rejected by the host guard before any request is made — SSRF
    // defense on the (issuer-derived) discovery fetch.
    let fetcher = JwksFetcher::new();
    let metadata_issuer = "https://169.254.169.254".parse().unwrap();
    let err = fetcher
        .resolve(&metadata_issuer)
        .await
        .expect_err("link-local issuer host must be refused");
    assert!(
        matches!(err, JwksFetcherError::InsecureUrl),
        "expected InsecureUrl (guard rejection), got {err:?}"
    );
}

#[tokio::test]
async fn strict_guard_rejects_private_issuer_host() {
    let fetcher = JwksFetcher::new().with_host_guard(HostGuard::strict());
    let private_issuer = "https://10.20.30.40".parse().unwrap();
    let err = fetcher
        .resolve(&private_issuer)
        .await
        .expect_err("strict guard must refuse a private issuer host");
    assert!(
        matches!(err, JwksFetcherError::InsecureUrl),
        "expected InsecureUrl (strict guard), got {err:?}"
    );
}
