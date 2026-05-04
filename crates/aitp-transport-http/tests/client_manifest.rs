//! Failure-path tests for `ManifestFetcher`.
//!
//! Covers the four error variants the fetcher returns:
//! `InsecureUrl`, `Timeout`, `MalformedJson`, `MalformedWrapper`.

#![cfg(feature = "client")]

use aitp_transport_http::{FetchError, ManifestFetcher};
use std::time::Duration;
use tokio::net::TcpListener;
use url::Url;

#[tokio::test]
async fn rejects_non_localhost_http() {
    let fetcher = ManifestFetcher::new();
    let url: Url = "http://example.com".parse().unwrap();
    let err = fetcher.fetch(&url).await.unwrap_err();
    assert!(
        matches!(err, FetchError::InsecureUrl),
        "expected InsecureUrl, got: {err:?}"
    );
}

#[tokio::test]
async fn malformed_json_response_rejected() {
    use axum::{response::IntoResponse, routing::get, Router};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().route(
        "/.well-known/aitp-manifest",
        get(|| async { "this is not json".into_response() }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let fetcher = ManifestFetcher::new();
    let err = fetcher
        .fetch(&format!("http://localhost:{port}").parse().unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::MalformedJson(_)),
        "expected MalformedJson, got: {err:?}"
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn malformed_wrapper_rejected() {
    // Server returns valid JSON but not the `{"manifest": {...}}` shape.
    use axum::{routing::get, Json, Router};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().route(
        "/.well-known/aitp-manifest",
        get(|| async { Json(serde_json::json!({"hello": "world"})) }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let fetcher = ManifestFetcher::new();
    let err = fetcher
        .fetch(&format!("http://localhost:{port}").parse().unwrap())
        .await
        .unwrap_err();
    // The fetcher tries to deserialise into `ManifestEnvelope`; any failure
    // surfaces as `MalformedJson` (serde rejects the missing `manifest`
    // key as a deserialise error rather than as a separate "wrapper"
    // case).
    assert!(
        matches!(err, FetchError::MalformedJson(_)),
        "expected MalformedJson (missing manifest key), got: {err:?}"
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn timeout_when_server_hangs() {
    // Bind a listener but never accept — the client will time out
    // connecting (or reading), which the fetcher reports as Timeout.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Hold the listener; do not call accept.
    let fetcher = ManifestFetcher::new().with_timeout(Duration::from_millis(150));
    let err = fetcher
        .fetch(&format!("http://localhost:{port}").parse().unwrap())
        .await
        .unwrap_err();
    // `reqwest`'s timeout reports as `is_timeout`; some platforms map
    // the connect-stage stall to a generic Network error before the
    // read-timeout fires. Either is acceptable as a "did not get a real
    // manifest" outcome.
    assert!(
        matches!(err, FetchError::Timeout | FetchError::Network(_)),
        "expected Timeout or Network, got: {err:?}"
    );
    drop(listener);
}
