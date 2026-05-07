//! Server-side request limits — body size cap (axum-level) and a
//! reference recipe for the header-size cap (hyper-builder level).
//!
//! axum 0.7's `axum::serve` uses hyper-util's default
//! `hyper::server::conn::http1::Builder`, which has no library-side
//! knob for the maximum HTTP header buffer. The header cap is set
//! when the binary launches the server with a custom hyper builder.
//! See [`RECOMMENDED_MAX_HEADER_BYTES`] and the recipe in
//! `examples/observability/README.md`.
//!
//! For the request body, axum exposes
//! [`axum::extract::DefaultBodyLimit`] as a router-level layer; the
//! [`with_request_body_limit`] helper applies the AITP-recommended
//! cap.
//!
//! # Recommended caps
//!
//! AITP messages on the wire are envelopes wrapping JCS-canonicalized
//! JSON. Realistic sizes:
//!
//! | Endpoint | Largest realistic body | Recommended cap |
//! |---|---|---|
//! | `/.well-known/aitp-manifest` | ~4 KiB (manifest + signature) | 16 KiB |
//! | `/aitp/handshake/*` | ~8 KiB (envelope + identity proof) | 32 KiB |
//! | `/.well-known/aitp-revocation-list` | grows with #revoked JTIs | 256 KiB |
//!
//! The default applied by [`DEFAULT_REQUEST_BODY_LIMIT`] (64 KiB) is
//! a safe one-size-fits-all that comfortably covers handshake and
//! manifest endpoints. Tune up for revocation-list uploads if your
//! deployment supports very large lists.
//!
//! Headers should typically not exceed 8 KiB; AITP itself adds at
//! most a handful of small headers (`DPoP`, `Authorization`,
//! `If-None-Match`). Cap at 16 KiB and rely on the body limit for
//! the bulk of request size.

use axum::extract::DefaultBodyLimit;
use axum::Router;

/// Default request body limit applied by
/// [`with_request_body_limit_default`]: 64 KiB. Safe default for
/// every AITP endpoint except revocation-list uploads.
pub const DEFAULT_REQUEST_BODY_LIMIT: usize = 64 * 1024;

/// Recommended HTTP header buffer size for AITP servers: 16 KiB.
///
/// Pass to `hyper::server::conn::http1::Builder::max_buf_size`
/// when launching the server. Headers larger than this cause
/// hyper to terminate the connection before the request reaches
/// the application. The full recipe is in
/// `examples/observability/README.md`.
pub const RECOMMENDED_MAX_HEADER_BYTES: usize = 16 * 1024;

/// Wrap a router with [`DefaultBodyLimit::max(limit)`].
///
/// Applies to every route in `router`. The AITP-recommended default
/// is [`DEFAULT_REQUEST_BODY_LIMIT`]; use a higher value for
/// endpoints that accept large signed payloads (revocation lists).
///
/// # Example
///
/// ```no_run
/// use aitp_transport_http::server_limits::{
///     with_request_body_limit, DEFAULT_REQUEST_BODY_LIMIT,
/// };
/// use aitp_transport_http::ManifestServer;
/// # fn build_manifest() -> aitp_manifest::Manifest { unimplemented!() }
///
/// let router = ManifestServer::new(build_manifest()).router();
/// let router = with_request_body_limit(router, DEFAULT_REQUEST_BODY_LIMIT);
/// ```
pub fn with_request_body_limit(router: Router, limit: usize) -> Router {
    router.layer(DefaultBodyLimit::max(limit))
}

/// Same as [`with_request_body_limit`] with
/// [`DEFAULT_REQUEST_BODY_LIMIT`].
pub fn with_request_body_limit_default(router: Router) -> Router {
    with_request_body_limit(router, DEFAULT_REQUEST_BODY_LIMIT)
}

// Header-size cap is binary-side: `axum::serve` uses hyper's
// defaults and does not expose a builder hook. To cap header size,
// drop down to `hyper-util`'s `http1::Builder` directly and pass
// [`RECOMMENDED_MAX_HEADER_BYTES`] to `max_buf_size`. The full
// recipe lives in `examples/observability/README.md` so callers
// don't have to context-switch into rustdoc.

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use tower::ServiceExt;

    async fn echo(body: axum::body::Bytes) -> StatusCode {
        let _ = body;
        StatusCode::OK
    }

    fn small_app() -> Router {
        Router::new().route("/echo", post(echo))
    }

    #[tokio::test]
    async fn body_under_limit_passes() {
        let app = with_request_body_limit(small_app(), 1024);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/echo")
            .body(Body::from(vec![0u8; 512]))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn body_over_limit_rejected() {
        let app = with_request_body_limit(small_app(), 1024);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/echo")
            .body(Body::from(vec![0u8; 4096]))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn header_constant_is_documented() {
        // Sanity: the constant must compose with hyper's API
        // (`max_buf_size` takes `usize`).
        let _v: usize = RECOMMENDED_MAX_HEADER_BYTES;
        assert_eq!(RECOMMENDED_MAX_HEADER_BYTES, 16 * 1024);
    }
}
