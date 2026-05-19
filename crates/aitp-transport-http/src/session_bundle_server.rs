//! Session Trust Bundle HTTP transport (RFC-AITP-0010 §4.3.1).
//!
//! Draft / non-normative: §4.3.1 RECOMMENDS these paths so independent
//! implementations interoperate without out-of-band configuration:
//!
//! - `POST /aitp/session/bundle` — a coordinator stores a bundle.
//! - `GET  /aitp/session/bundle/:session_id` — a participant fetches it.
//!
//! This server is a **delivery convenience only**. Per §4.3.1 "the HTTP
//! transport is a delivery convenience, not a trust upgrade", and §5
//! requires every participant to verify the bundle on receipt
//! ([`aitp_session_bundle::verify_session_bundle`]) regardless of how it
//! was delivered. The server therefore performs NO trust verification —
//! it stores and serves envelopes verbatim.
//!
//! Coordinators offering this endpoint MUST advertise its concrete URL
//! in their Manifest `extensions` map under
//! [`aitp_session_bundle::RFC_AITP_0010_BUNDLE_URI`]; participants that
//! do not find that key MUST NOT probe these paths (§4.3.1 — the
//! absence of the extension key is the discovery signal).

use aitp_session_bundle::SessionBundleEnvelope;
use axum::{
    body::to_bytes,
    extract::{Path, Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;
use uuid::Uuid;

/// Maximum accepted `POST /aitp/session/bundle` body size. A bundle
/// with dozens of participant TCTs is well under this; the cap rejects
/// accidental large uploads.
pub const MAX_BUNDLE_BYTES: usize = 512 * 1024;

type BundleStore = Arc<Mutex<HashMap<Uuid, SessionBundleEnvelope>>>;

/// In-memory Session Trust Bundle store with the RFC-AITP-0010 §4.3.1
/// HTTP endpoints.
///
/// The store is process-local and unbounded by design — it is a
/// reference transport for the experimental session-bundle feature, not
/// a production artifact store. Operators needing persistence or
/// eviction should wrap their own store behind the same two routes.
#[derive(Clone, Default)]
pub struct SessionBundleServer {
    bundles: BundleStore,
}

impl SessionBundleServer {
    /// Construct an empty bundle server.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of bundles currently stored (for tests / introspection).
    pub fn len(&self) -> usize {
        self.bundles.lock().len()
    }

    /// True when no bundles are stored.
    pub fn is_empty(&self) -> bool {
        self.bundles.lock().is_empty()
    }

    /// The axum router for the two §4.3.1 routes. Mount under whatever
    /// prefix the advertised `bundle_uri` resolves to (usually `/`).
    pub fn router(self) -> Router {
        Router::new()
            .route("/aitp/session/bundle", post(store_bundle))
            .route("/aitp/session/bundle/:session_id", get(fetch_bundle))
            .with_state(self.bundles)
    }
}

/// `POST /aitp/session/bundle` — accept a `SessionBundleEnvelope` and
/// store it keyed by its inner `session_id`. Re-posting the same
/// `session_id` overwrites the prior bundle.
async fn store_bundle(State(store): State<BundleStore>, request: Request) -> Response {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.starts_with("application/json") {
        return (
            StatusCode::BAD_REQUEST,
            "expected Content-Type: application/json",
        )
            .into_response();
    }
    let body = match to_bytes(request.into_body(), MAX_BUNDLE_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("oversized or unreadable body (limit {MAX_BUNDLE_BYTES} bytes)"),
            )
                .into_response()
        }
    };
    let envelope: SessionBundleEnvelope = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("malformed session bundle: {e}"),
            )
                .into_response()
        }
    };
    let session_id = envelope.session_bundle.session_id;
    store.lock().insert(session_id, envelope);
    debug!(%session_id, "session bundle stored");
    Json(serde_json::json!({ "session_id": session_id })).into_response()
}

/// `GET /aitp/session/bundle/:session_id` — return the stored bundle
/// envelope for `session_id`, or HTTP 404 when none is held.
async fn fetch_bundle(
    State(store): State<BundleStore>,
    Path(session_id): Path<String>,
) -> Response {
    let Ok(session_id) = Uuid::parse_str(&session_id) else {
        return (StatusCode::BAD_REQUEST, "session_id is not a UUID").into_response();
    };
    match store.lock().get(&session_id) {
        Some(envelope) => Json(envelope.clone()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "no session bundle stored for that session_id",
        )
            .into_response(),
    }
}
