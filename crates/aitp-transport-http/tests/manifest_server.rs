//! Integration test: serve a manifest, fetch + verify it round-trip via
//! a real TCP socket.

#![cfg(all(feature = "client", feature = "server"))]

use aitp_crypto::AitpSigningKey;
use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp_transport_http::{ManifestFetcher, ManifestServer};
use std::time::Duration;
use tokio::net::TcpListener;
use url::Url;

#[tokio::test]
async fn round_trip_manifest_server() {
    let key = AitpSigningKey::from_seed(&[7u8; 32]);
    let manifest = ManifestBuilder::new(&key)
        .display_name("server-side")
        .handshake_endpoint("https://localhost:9000/aitp/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "server-side".into(),
            issuer: None,
            public_key: Some(aitp_core::base64url::encode(
                &key.verifying_key().to_bytes(),
            )),
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .ttl_secs(3600)
        .build()
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = ManifestServer::new(manifest.clone());
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, server.router().into_make_service())
            .await
            .unwrap();
    });

    // Give the server a moment to start.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let fetcher = ManifestFetcher::new();
    let url: Url = format!("http://localhost:{}", port).parse().unwrap();
    let fetched = fetcher.fetch(&url).await.unwrap();
    assert_eq!(fetched.aid, manifest.aid);
    assert_eq!(fetched.signature, manifest.signature);

    server_handle.abort();
    let _ = server_handle.await;
}
