//! Integration test: serve a manifest, fetch + verify it round-trip via
//! a real TCP socket.

#![cfg(all(feature = "http-client", feature = "http-server"))]

use aitp::crypto::AitpSigningKey;
use aitp::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp::transport::{ManifestFetcher, ManifestServer};
use std::time::Duration;
use tokio::net::TcpListener;
use url::Url;

#[tokio::test]
async fn round_trip_manifest_server() {
    let key = AitpSigningKey::from_ed25519_seed(&[7u8; 32]);
    let manifest = ManifestBuilder::new(&key)
        .display_name("server-side")
        .handshake_endpoint("https://localhost:9000/aitp/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityHintKind::PinnedKey, "server-side").with_public_key(
                aitp::core::base64url::encode(
                    &key.verifying_key()
                        .try_to_ed25519_bytes()
                        .expect("key was constructed as Ed25519, never P-256"),
                ),
            ),
        )
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .ttl(std::time::Duration::from_secs(3600))
        .build()
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = ManifestServer::new(manifest.clone());
    let server_handle = tokio::spawn(async move {
        server.serve(listener).await.unwrap();
    });

    // Give the server a moment to start.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let fetcher = ManifestFetcher::new().with_insecure_localhost_dangerous();
    let url: Url = format!("http://localhost:{}", port).parse().unwrap();
    let fetched = fetcher.fetch(&url).await.unwrap();
    assert_eq!(fetched.manifest().aid, manifest.aid);
    assert_eq!(fetched.manifest().signature, manifest.signature);

    server_handle.abort();
    let _ = server_handle.await;
}
