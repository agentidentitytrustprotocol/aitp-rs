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
    // Plain string responses come back with Content-Type: text/plain;
    // P13 hardening rejects this at the boundary as WrongContentType.
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
        matches!(err, FetchError::WrongContentType(_)),
        "expected WrongContentType, got: {err:?}"
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn malformed_json_with_correct_content_type_rejected() {
    // Server claims application/json but body is invalid JSON — we
    // should fall through to MalformedJson.
    use axum::{
        http::header,
        response::{IntoResponse, Response},
        routing::get,
        Router,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().route(
        "/.well-known/aitp-manifest",
        get(|| async {
            Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from("not valid json"))
                .unwrap()
                .into_response()
        }),
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
async fn non_2xx_upstream_status_returned() {
    use axum::{http::StatusCode, routing::get, Router};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().route(
        "/.well-known/aitp-manifest",
        get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "broken") }),
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
        matches!(err, FetchError::UpstreamStatus(500)),
        "expected UpstreamStatus(500), got: {err:?}"
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn oversized_response_rejected() {
    use axum::{
        http::header,
        response::{IntoResponse, Response},
        routing::get,
        Router,
    };
    // Build a large JSON-shaped string the size limit will trip on.
    let big = format!("{{\"manifest\":{}}}", "0".repeat(200_000));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().route(
        "/.well-known/aitp-manifest",
        get(move || {
            let big = big.clone();
            async move {
                Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(big))
                    .unwrap()
                    .into_response()
            }
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let fetcher = ManifestFetcher::new().with_max_bytes(64 * 1024);
    let err = fetcher
        .fetch(&format!("http://localhost:{port}").parse().unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::OversizedResponse { limit: 65_536 }),
        "expected OversizedResponse, got: {err:?}"
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

// --- SSRF hardening (net_guard + no-redirect) ---------------------------

#[tokio::test]
async fn redirects_are_rejected() {
    // A peer-controlled origin must not be able to bounce the fetch
    // elsewhere: the fetcher's client carries redirect::Policy::none(),
    // so a 302 surfaces as its non-2xx status instead of being followed.
    use axum::{http::StatusCode, response::IntoResponse, routing::get, Router};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().route(
        "/.well-known/aitp-manifest",
        get(|| async {
            (
                StatusCode::FOUND,
                [(axum::http::header::LOCATION, "http://10.0.0.1/steal")],
            )
                .into_response()
        }),
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
        matches!(err, FetchError::UpstreamStatus(302)),
        "expected UpstreamStatus(302) (redirect not followed), got: {err:?}"
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn forbidden_literal_host_rejected_by_guard() {
    // Link-local (cloud-metadata) targets are rejected before any
    // connection is attempted, in the default guard mode.
    let fetcher = ManifestFetcher::new();
    let url: Url = "https://169.254.169.254".parse().unwrap();
    let err = fetcher.fetch(&url).await.unwrap_err();
    assert!(
        matches!(err, FetchError::InsecureUrl),
        "expected InsecureUrl (guard rejection), got: {err:?}"
    );
}

#[tokio::test]
async fn private_literal_host_rejected_by_strict_guard() {
    use aitp_transport_http::HostGuard;
    let fetcher = ManifestFetcher::new().with_host_guard(HostGuard::strict());
    let url: Url = "https://10.255.255.1".parse().unwrap();
    let err = fetcher.fetch(&url).await.unwrap_err();
    assert!(
        matches!(err, FetchError::InsecureUrl),
        "expected InsecureUrl (strict guard), got: {err:?}"
    );
}

#[tokio::test]
async fn guard_mode_decides_loopback_domain_over_https() {
    use aitp_transport_http::HostGuard;
    // Nothing listens on this port; what matters is *which* error we
    // get. Default (WarnPrivate) guard: loopback is allowed, the fetch
    // proceeds through the pinned-client path, and fails as a network
    // error. Strict guard: rejected up front as InsecureUrl.
    let url: Url = "https://localhost:47999".parse().unwrap();

    let permissive_err = ManifestFetcher::new().fetch(&url).await.unwrap_err();
    assert!(
        matches!(permissive_err, FetchError::Network(_) | FetchError::Timeout),
        "default guard should allow loopback (then fail to connect), got: {permissive_err:?}"
    );

    let strict_err = ManifestFetcher::new()
        .with_host_guard(HostGuard::strict())
        .fetch(&url)
        .await
        .unwrap_err();
    assert!(
        matches!(strict_err, FetchError::InsecureUrl),
        "strict guard should reject loopback, got: {strict_err:?}"
    );
}

#[tokio::test]
async fn insecure_localhost_flag_disables_dev_exception() {
    let fetcher = ManifestFetcher::new().with_insecure_localhost(false);
    let url: Url = "http://127.0.0.1:1".parse().unwrap();
    let err = fetcher.fetch(&url).await.unwrap_err();
    assert!(
        matches!(err, FetchError::InsecureUrl),
        "expected InsecureUrl with the dev exception disabled, got: {err:?}"
    );
}
