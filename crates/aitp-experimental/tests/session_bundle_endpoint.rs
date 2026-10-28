//! Session-bundle HTTP transport (RFC-AITP-0010 §4.3.1) — store/fetch
//! round trip over the `SessionBundleServer` router.

use aitp::core::Timestamp;
use aitp::crypto::AitpSigningKey;
use aitp_experimental::session_bundle::{
    SessionBundleEnvelope, SessionBundleServer, SessionTrustBundle,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt; // for `oneshot`
use uuid::Uuid;

fn sample_bundle(session_id: Uuid) -> SessionBundleEnvelope {
    let coordinator = AitpSigningKey::from_ed25519_seed(&[0x55; 32]);
    SessionBundleEnvelope {
        session_bundle: SessionTrustBundle {
            version: "aitp/0.3".into(),
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
            signature: aitp::core::base64url::encode(&[0u8; 64]),
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

/// RFC-AITP-0001 §5.4.5 / issue #140: a duplicate top-level key in the
/// posted body — a raw text defect no `serde_json::Value` can even
/// represent — must be rejected as malformed, not silently collapsed to
/// its last occurrence and stored. Deliberately raw text, not built via
/// `serde_json::json!`/`Value`, since that is exactly what the bug this
/// guards against would otherwise erase.
#[tokio::test]
async fn duplicate_top_level_key_in_body_is_rejected_and_not_stored() {
    let body = r#"{"session_bundle":{"version":"aitp/0.2","version":"aitp/0.3","session_id":"00000000-0000-4000-8000-000000000000","coordinator":"aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik","issued_at":1700000000,"expires_at":1700003600,"participants":[],"signature":"AA"}}"#;

    let server = SessionBundleServer::new();
    let router = server.clone().router();
    let resp = router
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
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        text.contains("duplicate field `version`"),
        "expected a duplicate-field diagnostic, got: {text}"
    );
    assert!(
        server.is_empty(),
        "a bundle with a duplicate top-level key must not be stored"
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
    use aitp::tct::TctBuilder;
    use aitp_experimental::session_bundle::{
        verify_session_bundle, SessionBundleBuilder, SessionBundleVerifyContext,
    };

    const NOW: Timestamp = Timestamp(1_700_000_000);

    let coordinator = AitpSigningKey::from_ed25519_seed(&[0xC0; 32]);
    let alice = AitpSigningKey::from_ed25519_seed(&[0xA1; 32]);
    let tct = TctBuilder::new(&coordinator)
        .subject(alice.aid().clone())
        .audience(alice.aid().clone())
        .grants(["session.participate"])
        .ttl(std::time::Duration::from_secs(3600))
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
    let ctx = SessionBundleVerifyContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
        coordinator_key:
            aitp_experimental::session_bundle::CoordinatorKeySource::UnverifiedAidDangerous,
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
    let sig = aitp::crypto::Signature::parse(sig_str.as_str().unwrap()).unwrap();
    let pubkey = aitp::crypto::AitpVerifyingKey::from_aid(coordinator.aid()).unwrap();

    let inner_digest =
        aitp::crypto::Digest32::sha256(&aitp::core::jcs::canonicalize(&body).unwrap());
    pubkey
        .verify_jcs(&inner_digest, &sig)
        .expect("signature must verify over sha256(JCS(body without `signature`))");

    // 3. And NOT over the wrapped form.
    let wrapped = serde_json::json!({ "session_bundle": body });
    let wrapped_digest =
        aitp::crypto::Digest32::sha256(&aitp::core::jcs::canonicalize(&wrapped).unwrap());
    assert!(
        pubkey.verify_jcs(&wrapped_digest, &sig).is_err(),
        "signature must NOT verify over the wrapped \
         {{\"session_bundle\": …}} form — the transport wrapper is not signed"
    );
}

/// RFC-AITP-0010 §4.3.1 (issue #195): the endpoint accepts only the
/// wrapped `{"session_bundle": {…}}` envelope; a bare inner body MUST be
/// rejected — as `SESSION_BUNDLE_INVALID` — and not stored.
#[tokio::test]
async fn bare_body_is_rejected_and_not_stored() {
    let envelope = sample_bundle(Uuid::new_v4());
    let bare = serde_json::to_vec(&envelope.session_bundle).unwrap();

    let server = SessionBundleServer::new();
    let router = server.clone().router();
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/aitp/session/bundle")
                .header("content-type", "application/json")
                .body(Body::from(bare))
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
        text.contains("SESSION_BUNDLE_INVALID"),
        "expected the SESSION_BUNDLE_INVALID class, got: {text}"
    );
    assert!(server.is_empty(), "a bare body must not be stored");
}

/// RFC-AITP-0010 §4.3.1 (issue #195): a coordinator advertises the
/// concrete endpoint URL under `extensions["rfc-aitp-0010.bundle_uri"]`
/// INSIDE its signed Manifest. The advertised URL routes to this
/// server's POST path, the Manifest still verifies with it, tampering
/// with the advertised value breaks the Manifest signature, and a
/// Manifest without the key advertises nothing.
#[tokio::test]
async fn bundle_uri_is_advertised_in_the_signed_manifest() {
    use aitp::manifest::{verify_manifest, IdentityHint, IdentityHintKind, ManifestBuilder};
    use aitp::manifest::{ManifestError, ManifestVerifyContext};
    use aitp_experimental::session_bundle::{
        advertise_bundle_uri, bundle_uri_from_manifest, RFC_AITP_0010_BUNDLE_URI,
    };

    const NOW: Timestamp = Timestamp(1_700_000_000);
    let coordinator = AitpSigningKey::from_ed25519_seed(&[0xC0; 32]);
    let builder = || {
        ManifestBuilder::new(&coordinator)
            .display_name("coordinator")
            .handshake_endpoint("https://coord.example/handshake".parse().unwrap())
            .identity_hint(
                IdentityHint::new(IdentityHintKind::PinnedKey, "coordinator")
                    .with_public_key(coordinator.aid().identifier().to_string()),
            )
            .offer("session.coordinate")
            .published_at(NOW)
    };

    let bundle_uri =
        SessionBundleServer::bundle_uri(&"https://coord.example".parse().unwrap()).unwrap();
    assert_eq!(
        bundle_uri.as_str(),
        "https://coord.example/aitp/session/bundle"
    );
    let manifest = advertise_bundle_uri(builder(), &bundle_uri)
        .build()
        .unwrap();
    let ctx = ManifestVerifyContext::at(NOW);
    verify_manifest(&manifest, &ctx).expect("advertising Manifest verifies");
    assert_eq!(
        bundle_uri_from_manifest(&manifest),
        Some(bundle_uri.clone())
    );
    assert_eq!(
        bundle_uri.path(),
        aitp_experimental::session_bundle::SESSION_BUNDLE_PATH
    );

    // The advertised URL is covered by the Manifest signature.
    let mut tampered = manifest.clone();
    tampered.extensions.as_mut().unwrap().insert(
        RFC_AITP_0010_BUNDLE_URI,
        serde_json::json!("https://attacker.example/aitp/session/bundle"),
    );
    assert!(matches!(
        verify_manifest(&tampered, &ctx),
        Err(ManifestError::SignatureInvalid)
    ));

    // Absent key: HTTPS is unavailable for this coordinator (§4.3.1).
    let plain = builder().build().unwrap();
    assert_eq!(bundle_uri_from_manifest(&plain), None);

    // Plain HTTP is only tolerated for localhost development.
    let http = advertise_bundle_uri(
        builder(),
        &"http://coord.example/aitp/session/bundle".parse().unwrap(),
    )
    .build()
    .unwrap();
    assert_eq!(bundle_uri_from_manifest(&http), None);

    // The advertised path is the one this server's POST route serves.
    let server = SessionBundleServer::new();
    let resp = server
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(bundle_uri.path())
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&sample_bundle(Uuid::new_v4())).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(server.len(), 1);
}
