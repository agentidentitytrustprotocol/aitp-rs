//! Revocation demo (P15.5).
//!
//! Spawns an issuer agent that publishes a signed revocation list
//! at `/.well-known/aitp-revocation-list`, then a consumer that fetches
//! the snapshot and queries `RevocationCache::is_revoked`. Demonstrates
//! the end-to-end RFC-AITP-0008 §1.5 surface added in beta.1.
//!
//! ```sh
//! cargo run -p aitp-example-two-agents --bin revocation-demo
//! ```
//!
//! Expected output:
//!
//! ```text
//! issuer listening on http://127.0.0.1:<port>
//! revoked-jti check       → true   (in deny list)
//! unknown-jti check       → false  (not in deny list)
//! demo OK
//! ```

use aitp::core::Timestamp;
use aitp::crypto::AitpSigningKey;
use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp::tct::{sign_revocation_list, RevocationEntry, RevocationList, RevocationListEnvelope};
use aitp::transport::{
    HandshakeServer, RevocationCache, RevocationListProducer, RevocationPolicy, RevocationProvider,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use uuid::Uuid;

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

struct StaticProducer(RevocationListEnvelope);
impl RevocationListProducer for StaticProducer {
    fn current(&self) -> RevocationListEnvelope {
        self.0.clone()
    }
}

struct HttpRevocationProvider {
    base: url::Url,
}
impl RevocationProvider for HttpRevocationProvider {
    fn fetch(
        &self,
        _issuer: &aitp::core::Aid,
    ) -> Result<RevocationListEnvelope, aitp::transport::RevocationError> {
        let url = self.base.join(".well-known/aitp-revocation-list").unwrap();
        // sync HTTP for the demo — production would use the async client
        // and a runtime handle.
        let body = ureq_get(url.as_str())
            .map_err(|e| aitp::transport::RevocationError::Network(e.to_string()))?;
        serde_json::from_str(&body)
            .map_err(|e| aitp::transport::RevocationError::Network(e.to_string()))
    }
}

fn ureq_get(url: &str) -> Result<String, String> {
    let url = url.to_string();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        rt.block_on(async {
            reqwest::get(&url)
                .await
                .map_err(|e| e.to_string())?
                .text()
                .await
                .map_err(|e| e.to_string())
        })
    })
    .join()
    .map_err(|_| "thread join failed".to_string())?
}

#[tokio::main]
async fn main() {
    let issuer = AitpSigningKey::from_seed(&[0x42; 32]);
    let now = Timestamp::now();
    let revoked_jti = Uuid::new_v4();

    let snapshot = sign_revocation_list(
        RevocationList {
            version: "aitp/0.1".into(),
            issuer: issuer.aid().clone(),
            published_at: now,
            expires_at: Timestamp(now.0 + 3600),
            entries: vec![RevocationEntry {
                jti: revoked_jti,
                revoked_at: now,
                reason: Some("compromised".into()),
            }],
        },
        &issuer,
    )
    .expect("sign snapshot");

    let manifest = ManifestBuilder::new(&issuer)
        .display_name("issuer")
        .handshake_endpoint("https://issuer.example.com/aitp/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "issuer".into(),
            issuer: None,
            public_key: Some(aitp::core::base64url::encode(
                &issuer.verifying_key().to_bytes(),
            )),
        })
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .build()
        .unwrap();

    let server = HandshakeServer::new(
        AitpSigningKey::from_seed(&[0x42; 32]),
        manifest,
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    .with_revocation_producer(Arc::new(StaticProducer(snapshot)));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    println!("issuer listening on http://127.0.0.1:{port}");
    tokio::spawn(async move {
        axum::serve(listener, server.router()).await.ok();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let base: url::Url = format!("http://127.0.0.1:{port}/").parse().unwrap();
    let cache = RevocationCache::new(HttpRevocationProvider { base }, RevocationPolicy::default());

    let revoked = cache
        .is_revoked(&revoked_jti, issuer.aid(), Timestamp::now())
        .expect("revoked check");
    println!("revoked-jti check       → {revoked:5}  (in deny list)");
    assert!(revoked, "expected revoked-jti to read as revoked");

    let other = Uuid::new_v4();
    let unknown = cache
        .is_revoked(&other, issuer.aid(), Timestamp::now())
        .expect("unknown check");
    println!("unknown-jti check       → {unknown:5}  (not in deny list)");
    assert!(!unknown, "expected unknown-jti to read as not revoked");

    println!("demo OK");
}
