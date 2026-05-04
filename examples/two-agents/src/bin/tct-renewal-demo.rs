//! TCT renewal demo (P15).
//!
//! Spawns an issuer agent serving `POST /aitp/handshake/renew`, mints
//! an initial TCT in-process, and exercises the renewal endpoint via
//! `aitp::facade::renew_tct`. Asserts the new TCT has a fresh JTI and
//! a refreshed expiry.
//!
//! ```sh
//! cargo run -p aitp-example-two-agents --bin tct-renewal-demo
//! ```

use aitp::core::Timestamp;
use aitp::crypto::AitpSigningKey;
use aitp::facade::{renew_tct, TctStore};
use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp::tct::{TctBuilder, TctEnvelope};
use aitp::transport::HandshakeServer;
use tokio::net::TcpListener;

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

#[tokio::main]
async fn main() {
    let issuer = AitpSigningKey::from_seed(&[0x60; 32]);
    let holder = AitpSigningKey::from_seed(&[0x61; 32]);
    let now = Timestamp::now();

    // Initial TCT minted in-process — pretend it came from a prior
    // handshake.
    let initial = TctBuilder::new(&issuer)
        .subject(holder.aid().clone())
        .audience(holder.aid().clone())
        .grants(["demo.echo"])
        .ttl_secs(60)
        .subject_pubkey(holder.verifying_key())
        .issued_at(now)
        .build()
        .expect("mint initial TCT");

    let store = TctStore::default();
    store.insert(TctEnvelope {
        tct: initial.clone(),
    });

    // Stand up the issuer's handshake server (it serves /aitp/handshake/renew).
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
        .ttl_secs(86_400)
        .build()
        .unwrap();

    let server = HandshakeServer::new(
        AitpSigningKey::from_seed(&[0x60; 32]),
        manifest,
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    println!("issuer listening on http://127.0.0.1:{port}");
    tokio::spawn(async move {
        axum::serve(listener, server.router()).await.ok();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Holder side: drive `renew_tct` against the issuer's renew endpoint.
    let endpoint: url::Url = format!("http://127.0.0.1:{port}/aitp/handshake/")
        .parse()
        .unwrap();
    let current = store
        .get(holder.aid())
        .or_else(|| {
            Some(TctEnvelope {
                tct: initial.clone(),
            })
        })
        .unwrap();
    let renewed = renew_tct(&holder, current, &endpoint)
        .await
        .expect("renew_tct round-trip");
    assert_ne!(renewed.tct.jti, initial.jti, "JTI must rotate on renewal");
    assert_eq!(
        renewed.tct.subject, initial.subject,
        "subject must be preserved across renewal"
    );
    assert_eq!(
        renewed.tct.grants, initial.grants,
        "grants must be preserved across renewal"
    );
    assert!(
        renewed.tct.expires_at.0 > initial.expires_at.0,
        "renewed TCT must have a fresher expiry"
    );

    println!("initial JTI    {}", initial.jti);
    println!("renewed JTI    {}", renewed.tct.jti);
    println!("initial expiry {}", initial.expires_at.0);
    println!("renewed expiry {}", renewed.tct.expires_at.0);
    println!("demo OK");
}
