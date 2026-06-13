//! Server-side DPoP policy gating (`HandshakeServer::verify_dpop_request`).
//!
//! `dpop.rs`'s unit tests cover the proof *verifier* (round-trip, wrong
//! method, ath binding, replay). What was untested is the server method
//! that wires the policy in: whether a `required` policy rejects a
//! request missing the `Authorization`/`DPoP` headers, and whether the
//! default (not-required) policy skips cleanly. Those branches return
//! before any proof is parsed, so no minted proof is needed here.

#![cfg(all(feature = "client", feature = "server"))]

use aitp_crypto::AitpSigningKey;
use aitp_handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp_transport_http::{DpopError, DpopPolicy, HandshakeServer};
use axum::body::Body;
use axum::extract::Request;

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
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
}

fn bare_request() -> Request {
    Request::builder()
        .method("POST")
        .uri("https://example.com/aitp/handshake/commit")
        .body(Body::empty())
        .unwrap()
}

#[test]
fn required_policy_rejects_request_without_dpop_headers() {
    let srv = server().with_dpop_policy(DpopPolicy {
        required: true,
        iat_tolerance_secs: 60,
    });
    let err = srv
        .verify_dpop_request(
            &bare_request(),
            "expected-jkt",
            "POST",
            "https://example.com/aitp/handshake/commit",
        )
        .expect_err("required policy must reject a request with no DPoP headers");
    assert!(
        matches!(err, DpopError::MalformedHeader),
        "expected MalformedHeader, got {err:?}"
    );
}

#[test]
fn default_policy_skips_when_headers_absent() {
    // No `with_dpop_policy` ⇒ default (not required). A request without
    // DPoP headers must pass through as `Ok(None)`, not error.
    let srv = server();
    let outcome = srv
        .verify_dpop_request(
            &bare_request(),
            "expected-jkt",
            "POST",
            "https://example.com/aitp/handshake/commit",
        )
        .expect("default policy must not require DPoP");
    assert!(
        outcome.is_none(),
        "no DPoP headers under a non-required policy ⇒ Ok(None)"
    );
}
