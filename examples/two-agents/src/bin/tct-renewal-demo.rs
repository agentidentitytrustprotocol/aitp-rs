//! TCT renewal demo (P15).
//!
//! Spawns an issuer agent whose Manifest advertises
//! `rfc-aitp-0005.renew_uri` (RFC-AITP-0013 §2), hosting the handshake
//! routes, the Manifest and `aitp_experimental::renewal::RenewalServer`
//! on one listener. Mints an initial TCT in-process and renews it with
//! `aitp_experimental::renewal::renew_tct_with_insecure_localhost`, which
//! reads that URL from the Manifest. Asserts the new TCT has a fresh JTI
//! and a refreshed expiry.
//!
//! ```sh
//! cargo run -p aitp-example-two-agents --bin tct-renewal-demo \
//!     --features experimental-renewal
//! ```

use aitp::core::nonce_store::InMemoryNonceStore;
use aitp::core::Timestamp;
use aitp::crypto::AitpSigningKey;
use aitp::facade::TctStore;
use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp::tct::{
    sign_revocation_list, verify_tct, RevocationList, RevocationListEnvelope, TctBuilder,
    TctVerifyContext,
};
use aitp::transport::{HandshakeServer, ManifestServer, RevocationListProducer};
use aitp_experimental::renewal::{renew_tct_with_insecure_localhost, RenewalServer, RENEW_URI_EXT};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

/// The issuer's revocation list: signed once, empty.
struct EmptyList(RevocationListEnvelope);
impl RevocationListProducer for EmptyList {
    fn current(
        &self,
    ) -> aitp::core::BoxFuture<'_, Result<RevocationListEnvelope, aitp::transport::RevocationError>>
    {
        Box::pin(std::future::ready(Ok(self.0.clone())))
    }
}

#[tokio::main]
async fn main() {
    let issuer = AitpSigningKey::from_ed25519_seed(&[0x60; 32]);
    let holder = AitpSigningKey::from_ed25519_seed(&[0x61; 32]);
    let now = Timestamp::now();

    // Initial TCT minted in-process — pretend it came from a prior
    // handshake. `build()` returns the compact JWS plus a companion
    // grant voucher.
    let initial = TctBuilder::new(&issuer)
        .subject(holder.aid().clone())
        .audience(holder.aid().clone())
        .grants(["demo.echo"])
        .ttl(std::time::Duration::from_secs(60))
        .subject_pubkey(holder.verifying_key())
        .issued_at(now)
        .build()
        .expect("mint initial TCT");

    // The holder verifies what it receives before storing it — the
    // store is keyed by the issuer's AID.
    let initial_verified = verify_tct(
        &initial.token,
        &TctVerifyContext::builder(holder.aid(), issuer.aid(), Timestamp::now())
            .revocation(aitp::tct::RevocationSource::FailOpen)
            .skip_manifest_expiry_cap_dangerous()
            .build()
            .expect("both decisions are made"),
    )
    .expect("initial TCT verifies");

    let store = TctStore::default();
    store.insert(initial_verified.clone(), initial.voucher.clone());

    // Stand up the issuer's handshake server. Its Manifest advertises the
    // renewal endpoint; the server mounts the route at that path.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let renew_uri = format!("http://127.0.0.1:{port}/aitp/handshake/renew");
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
        .ttl(std::time::Duration::from_secs(86_400))
        .extension(RENEW_URI_EXT, renew_uri.into())
        .build()
        .unwrap();

    // One revocation producer for both servers.
    let list = sign_revocation_list(
        RevocationList::new(issuer.aid().clone(), now, Timestamp(now.0 + 3600), vec![]),
        &issuer,
    )
    .expect("sign revocation list");
    let revocation: Arc<dyn RevocationListProducer> = Arc::new(EmptyList(list));
    let handshake = HandshakeServer::new(
        AitpSigningKey::from_ed25519_seed(&[0x60; 32]),
        manifest.clone(),
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    .with_revocation_producer(revocation.clone());
    let renewal = RenewalServer::new(
        Arc::new(AitpSigningKey::from_ed25519_seed(&[0x60; 32])),
        manifest.clone(),
        revocation,
        Arc::new(InMemoryNonceStore::default()),
    )
    .expect("signer matches the Manifest");
    let app = handshake
        .into_router()
        .merge(ManifestServer::new(manifest.clone()).into_router())
        .merge(renewal.router().expect("Manifest advertises renew_uri"));

    println!("issuer listening on http://127.0.0.1:{port}");
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .ok();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Holder side: drive `renew_tct_with_insecure_localhost` (loopback demo) against the endpoint the issuer's
    // (already verified) Manifest advertises, presenting the
    // currently-held TCT compact JWS.
    let current = store.get(issuer.aid()).expect("stored TCT");
    let renewed = renew_tct_with_insecure_localhost(&holder, current.token().to_owned(), &manifest)
        .await
        .expect("renew_tct round-trip");

    // `renew_tct` has already checked the issuer's signed response and
    // verified the renewed TCT (RFC-AITP-0013 §6.1); stash it (and its
    // fresh voucher) back into the store.
    let renewed_verified = renewed.tct;
    store.insert(renewed_verified.clone(), renewed.grant_voucher.clone());

    let old = &initial_verified.claims();
    let new = &renewed_verified.claims();
    assert_ne!(new.jti, old.jti, "JTI must rotate on renewal");
    assert_eq!(new.sub, old.sub, "subject must be preserved across renewal");
    assert_eq!(
        new.grants, old.grants,
        "grants must be preserved across renewal"
    );
    assert!(
        new.exp.0 > old.exp.0,
        "renewed TCT must have a fresher expiry"
    );

    println!("initial JTI    {}", old.jti);
    println!("renewed JTI    {}", new.jti);
    println!("initial expiry {}", old.exp.0);
    println!("renewed expiry {}", new.exp.0);
    println!("demo OK");
}
