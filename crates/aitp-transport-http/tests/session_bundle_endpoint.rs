//! Session-bundle HTTP transport (RFC-AITP-0010 §4.3.1) — store/fetch
//! round trip over the `SessionBundleServer` router.

#![cfg(feature = "experimental-session-bundle")]

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_session_bundle::{SessionBundleEnvelope, SessionTrustBundle};
use aitp_transport_http::SessionBundleServer;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt; // for `oneshot`
use uuid::Uuid;

fn sample_bundle(session_id: Uuid) -> SessionBundleEnvelope {
    let coordinator = AitpSigningKey::from_seed(&[0x55; 32]);
    SessionBundleEnvelope {
        session_bundle: SessionTrustBundle {
            version: "aitp/0.1".into(),
            session_id,
            coordinator: coordinator.aid().clone(),
            issued_at: Timestamp(1_700_000_000),
            expires_at: Timestamp(1_700_003_600),
            participants: vec![],
            signature: aitp_core::base64url::encode(&[0u8; 64]),
        },
    }
}

#[tokio::test]
async fn store_then_fetch_round_trips() {
    let server = SessionBundleServer::new();
    let session_id = Uuid::new_v4();
    let envelope = sample_bundle(session_id);
    let router = server.clone().router();

    let body = serde_json::to_vec(&envelope).unwrap();
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/aitp/session/bundle")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(server.len(), 1, "POST should have stored the bundle");

    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/aitp/session/bundle/{session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let got: SessionBundleEnvelope = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(got, envelope, "fetched bundle must match the stored one");
}

#[tokio::test]
async fn fetch_unknown_session_id_returns_404() {
    let router = SessionBundleServer::new().router();
    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/aitp/session/bundle/{}", Uuid::new_v4()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn malformed_bundle_body_is_rejected() {
    let router = SessionBundleServer::new().router();
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/aitp/session/bundle")
                .header("content-type", "application/json")
                .body(Body::from("{not a bundle"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
