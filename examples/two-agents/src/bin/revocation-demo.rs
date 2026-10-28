//! Revocation demo (P15.5).
//!
//! Spawns an issuer agent that publishes a signed revocation list
//! at `/.well-known/aitp-revocation-list`, then a consumer that fetches
//! the snapshot with a `RevocationFetcher` and asks it for the status of
//! two `jti`s. Demonstrates
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
//! revoked-jti check       → Revoked  (in deny list)
//! unknown-jti check       → Clear    (not in deny list)
//! demo OK
//! ```

use aitp::core::{BoxFuture, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp::tct::{
    sign_revocation_list, RevocationEntry, RevocationList, RevocationListEnvelope, RevocationQuery,
    RevocationStatus,
};
use aitp::transport::{
    HandshakeServer, RevocationError, RevocationFetcher, RevocationListProducer, RevocationPolicy,
    REVOCATION_LIST_PATH,
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
    fn current(&self) -> BoxFuture<'_, Result<RevocationListEnvelope, RevocationError>> {
        Box::pin(std::future::ready(Ok(self.0.clone())))
    }
}

#[tokio::main]
async fn main() {
    let issuer = AitpSigningKey::from_seed(&[0x42; 32]);
    let now = Timestamp::now();
    let revoked_jti = Uuid::new_v4();

    let snapshot = sign_revocation_list(
        RevocationList::new(
            issuer.aid().clone(),
            now,
            Timestamp(now.0 + 3600),
            vec![RevocationEntry::new(revoked_jti, now).with_reason("compromised")],
        ),
        &issuer,
    )
    .expect("sign snapshot");

    let manifest = ManifestBuilder::new(&issuer)
        .display_name("issuer")
        .handshake_endpoint("https://issuer.example.com/aitp/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityHintKind::PinnedKey, "issuer").with_public_key(
                aitp::core::base64url::encode(
                    &issuer
                        .verifying_key()
                        .try_to_ed25519_bytes()
                        .expect("key was constructed as Ed25519, never P-256"),
                ),
            ),
        )
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        // RFC-AITP-0005 §11: a TCT issuer MUST advertise its ListRevoked
        // URL inside the signed Manifest.
        .revocation_list_uri(
            "https://issuer.example.com/.well-known/aitp-revocation-list"
                .parse()
                .unwrap(),
        )
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
        server.serve(listener).await.ok();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // The consumer reads the list from the issuer's listener. A real
    // consumer takes the URL from the issuer's verified Manifest.
    let list_uri = format!("http://127.0.0.1:{port}{REVOCATION_LIST_PATH}");
    let fetcher =
        RevocationFetcher::new(RevocationPolicy::default()).with_insecure_localhost_dangerous();
    let now = Timestamp::now();
    let prepared = fetcher.prepare(issuer.aid(), Some(&list_uri), now).await;

    let revoked = prepared
        .decide(&RevocationQuery::new(issuer.aid(), &revoked_jti, now))
        .expect("revoked check");
    println!(
        "revoked-jti check       → {:8} (in deny list)",
        format!("{revoked:?}")
    );
    assert_eq!(revoked, RevocationStatus::Revoked);

    let other = Uuid::new_v4();
    let unknown = prepared
        .decide(&RevocationQuery::new(issuer.aid(), &other, now))
        .expect("unknown check");
    println!(
        "unknown-jti check       → {:8} (not in deny list)",
        format!("{unknown:?}")
    );
    assert_eq!(unknown, RevocationStatus::Clear);

    println!("demo OK");
}
