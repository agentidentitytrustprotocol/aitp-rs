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
            version: "aitp/0.2".into(),
            session_id,
            coordinator: coordinator.aid().clone(),
            issued_at: Timestamp(1_700_000_000),
            expires_at: Timestamp(1_700_003_600),
            participants: vec![],
            // Absent, not `Some(empty)`: the two are different signing
            // inputs (RFC-AITP-0001 §5.4.1). This endpoint only stores and
            // returns the envelope verbatim, but the fixture should still
            // be a shape a coordinator would actually mint.
            extensions: None,
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

/// Regression for `bundle-004-signature-sibling-rejected`: `signature` as
/// a SIBLING of the `{"session_bundle": …}` wrapper — the pre-erratum
/// shape RFC-AITP-0010 §3 now forbids — must be rejected with HTTP 400
/// and must NOT be stored. `SessionBundleEnvelope` is
/// `#[serde(deny_unknown_fields)]` with a single `session_bundle` member,
/// so `store_bundle`'s direct `serde_json::from_slice::<SessionBundleEnvelope>`
/// already does this rejection for free — this test pins that it keeps
/// doing so.
#[tokio::test]
async fn sibling_signature_shape_is_rejected_and_not_stored() {
    let envelope = sample_bundle(Uuid::new_v4());
    let mut wire = serde_json::to_value(&envelope).unwrap();
    let inner = wire.get_mut("session_bundle").unwrap();
    let signature = inner
        .as_object_mut()
        .unwrap()
        .remove("signature")
        .expect("sample bundle carries a signature");
    wire.as_object_mut()
        .unwrap()
        .insert("signature".to_string(), signature);

    let server = SessionBundleServer::new();
    let router = server.clone().router();
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/aitp/session/bundle")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&wire).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        server.is_empty(),
        "sibling-shaped bundle must not be stored"
    );
}

/// `bundle-006-unknown-field-rejected`'s shape over HTTP: an unknown
/// member of the INNER body (not a wrapper sibling, not inside
/// `extensions`) must be reported as the `UNKNOWN_FIELD` class, not a
/// bare "malformed session bundle" 400 — `store_bundle` now routes
/// through `parse_session_bundle_wire`, the same wire-form discipline
/// the conformance adapter has always applied.
#[tokio::test]
async fn unknown_body_member_is_reported_as_unknown_field_and_not_stored() {
    let envelope = sample_bundle(Uuid::new_v4());
    let mut wire = serde_json::to_value(&envelope).unwrap();
    wire.get_mut("session_bundle")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "coordinator_note".to_string(),
            serde_json::json!("primary-region"),
        );

    let server = SessionBundleServer::new();
    let router = server.clone().router();
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/aitp/session/bundle")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&wire).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        text.contains("UNKNOWN_FIELD"),
        "expected the UNKNOWN_FIELD class in the response body, got: {text}"
    );
    assert!(
        server.is_empty(),
        "a bundle with an unknown body member must not be stored"
    );
}

/// A **genuinely signed** bundle survives the store/fetch round trip and
/// still verifies — and its signature is over the inner body, not the
/// `{"session_bundle": …}` transport wrapper.
///
/// The tests above deliberately use `sample_bundle`, whose `signature`
/// is 64 zero bytes: they exercise routing, storage and rejection paths,
/// where the signature is irrelevant. The consequence is that no test in
/// this file ever put a real signature through the transport. The
/// session bundle is one of the two artifacts whose JCS signing input
/// changed in 0.5.0, so that gap is worth closing at the layer that
/// re-serializes the JSON.
///
/// As with the revocation snapshot's wire test, the signing input is
/// rebuilt here from the fetched JSON — not via `bundle_signing_bytes`
/// (which is crate-private anyway) — so signer and verifier agreeing
/// with each other is not sufficient to make it pass.
#[tokio::test]
async fn signed_bundle_round_trips_and_is_signed_over_the_inner_body() {
    use aitp_session_bundle::{
        verify_session_bundle, SessionBundleBuilder, VerifySessionBundleContext,
    };
    use aitp_tct::TctBuilder;
    use sha2::{Digest, Sha256};

    const NOW: Timestamp = Timestamp(1_700_000_000);

    let coordinator = AitpSigningKey::from_seed(&[0xC0; 32]);
    let alice = AitpSigningKey::from_seed(&[0xA1; 32]);
    let tct = TctBuilder::new(&coordinator)
        .subject(alice.aid().clone())
        .audience(alice.aid().clone())
        .grants(["session.participate"])
        .ttl_secs(3600)
        .subject_pubkey(alice.verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
        .token;

    let session_id = Uuid::new_v4();
    let bundle = SessionBundleBuilder::new(&coordinator)
        .session_id(session_id)
        .issued_at(NOW)
        .participant(alice.aid().clone(), tct)
        .build()
        .expect("bundle builds");
    let envelope = SessionBundleEnvelope {
        session_bundle: bundle,
    };

    let server = SessionBundleServer::new();
    let router = server.clone().router();
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/aitp/session/bundle")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&envelope).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

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

    // 1. The fetched bundle still verifies after a JSON round trip.
    let got: SessionBundleEnvelope = serde_json::from_slice(&bytes).unwrap();
    let ctx = VerifySessionBundleContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
    };
    verify_session_bundle(&got.session_bundle, &ctx)
        .expect("fetched bundle must verify under the coordinator's key");

    // 2. Independently: the signature is over the inner body with
    //    `signature` removed — the bundle carries it as a *member*, so
    //    the exclusion is what makes this shape distinct from the
    //    revocation snapshot's sibling placement.
    let raw: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut body = raw
        .get("session_bundle")
        .expect("served envelope carries the transport wrapper")
        .clone();
    let sig_str = body
        .as_object_mut()
        .unwrap()
        .remove("signature")
        .expect("bundle carries `signature` as a member of the body");
    let sig = aitp_crypto::Signature::parse(sig_str.as_str().unwrap()).unwrap();
    let pubkey = aitp_crypto::AitpVerifyingKey::from_aid(coordinator.aid()).unwrap();

    let inner_digest = Sha256::digest(aitp_core::jcs::canonicalize(&body).unwrap());
    pubkey
        .verify(&inner_digest, &sig)
        .expect("signature must verify over sha256(JCS(body without `signature`))");

    // 3. And NOT over the wrapped form.
    let wrapped = serde_json::json!({ "session_bundle": body });
    let wrapped_digest = Sha256::digest(aitp_core::jcs::canonicalize(&wrapped).unwrap());
    assert!(
        pubkey.verify(&wrapped_digest, &sig).is_err(),
        "signature must NOT verify over the wrapped \
         {{\"session_bundle\": …}} form — the transport wrapper is not signed"
    );
}
