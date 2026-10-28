//! `HandshakeServer::serve_with` and `ManifestServer::serve_with`: the
//! stable way to host the servers, with no axum type in the signature.

#![cfg(all(feature = "http-client", feature = "http-server"))]

use aitp::crypto::AitpSigningKey;
use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use aitp::transport::{
    HandshakeServer, ManifestFetcher, ManifestServer, ServeConfig, DEFAULT_REQUEST_BODY_LIMIT,
};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use url::Url;

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn manifest(key: &AitpSigningKey) -> Manifest {
    ManifestBuilder::new(key)
        .display_name("serve")
        .handshake_endpoint("https://localhost:9000/aitp/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityHintKind::PinnedKey, "serve").with_public_key(
                aitp::core::base64url::encode(&key.verifying_key().to_compressed()),
            ),
        )
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .ttl_secs(3600)
        .build()
        .unwrap()
}

async fn listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://localhost:{}", listener.local_addr().unwrap().port());
    (listener, origin)
}

#[test]
fn the_default_body_limit_is_the_recommended_one() {
    assert_eq!(
        ServeConfig::default().request_body_limit,
        DEFAULT_REQUEST_BODY_LIMIT
    );
    assert_eq!(
        ServeConfig::default()
            .with_request_body_limit(10)
            .request_body_limit,
        10
    );
}

#[tokio::test]
async fn a_handshake_server_also_serves_its_manifest() {
    let key = AitpSigningKey::from_seed(&[0x31; 32]);
    let manifest = manifest(&key);
    let server = HandshakeServer::new(
        AitpSigningKey::from_seed(&[0x31; 32]),
        manifest.clone(),
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    );
    let (listener, origin) = listener().await;
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(
        server.serve_with(listener, ServeConfig::default(), async move {
            let _ = stopped.await;
        }),
    );

    let fetched = ManifestFetcher::new()
        .with_insecure_localhost_dangerous()
        .fetch(&origin.parse::<Url>().unwrap())
        .await
        .unwrap();
    assert_eq!(fetched.manifest().signature, manifest.signature);

    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("serve_with returns once shutdown completes")
        .unwrap()
        .unwrap();
}

/// POST `body` to HELLO on a server limited to `limit` bytes; the HTTP
/// status and the response body.
async fn hello_with_limit(limit: usize, body: &'static str) -> (u16, String) {
    let key = AitpSigningKey::from_seed(&[0x32; 32]);
    let server = HandshakeServer::new(
        AitpSigningKey::from_seed(&[0x32; 32]),
        manifest(&key),
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    );
    let (listener, origin) = listener().await;
    let config = ServeConfig::default().with_request_body_limit(limit);
    tokio::spawn(server.serve_with(listener, config, std::future::pending()));

    let resp = reqwest::Client::new()
        .post(format!("{origin}/aitp/handshake/hello"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    (resp.status().as_u16(), resp.text().await.unwrap())
}

#[tokio::test]
async fn the_handshake_routes_honour_the_body_limit() {
    // The handshake handlers read the raw body, which axum's
    // `DefaultBodyLimit` alone would not cap.
    const BODY: &str =
        r#"{"padding": "0123456789012345678901234567890123456789012345678901234567890123"}"#;
    assert!(BODY.len() > 64);
    let (status, over) = hello_with_limit(64, BODY).await;
    // RFC-AITP-0009 §3.1: an oversized body is `INVALID_ENVELOPE`.
    assert_eq!(status, 400);
    assert!(over.contains("INVALID_ENVELOPE"), "{over}");
    assert!(over.contains("oversized"), "{over}");

    let (_, under) = hello_with_limit(DEFAULT_REQUEST_BODY_LIMIT, BODY).await;
    assert!(!under.contains("oversized"), "{under}");
}

#[tokio::test]
async fn a_manifest_server_serves_until_shutdown() {
    let key = AitpSigningKey::from_seed(&[0x33; 32]);
    let manifest = manifest(&key);
    let (listener, origin) = listener().await;
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(ManifestServer::new(manifest.clone()).serve_with(
        listener,
        ServeConfig::default(),
        async move {
            let _ = stopped.await;
        },
    ));

    let fetched = ManifestFetcher::new()
        .with_insecure_localhost_dangerous()
        .fetch(&origin.parse::<Url>().unwrap())
        .await
        .unwrap();
    assert_eq!(fetched.manifest().aid, manifest.aid);

    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
