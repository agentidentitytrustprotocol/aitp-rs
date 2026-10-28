//! The `HandshakeServer` awaits `JwksResolver::prefetch` for an OIDC
//! initiator's issuer before the synchronous `Responder::on_hello`, whose
//! `resolve` call then answers from what the prefetch stored.

#![cfg(all(feature = "http-client", feature = "http-server"))]

#[path = "handshake_fixtures/mod.rs"]
mod fixtures;

use aitp::core::{BoxFuture, MessageType, RawUrl, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::envelope::sign_envelope_with;
use aitp::handshake::{
    Initiator, JwkPublicKey, JwksResolver, PeerConfig, PresentedIdentity, ResolveError,
    StaticPinnedKeyStore,
};
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use aitp::transport::HandshakeServer;
use fixtures::mock_oidc::MockOidcIssuer;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use uuid::Uuid;

/// Holds no keys until `prefetch` loads them (when `serves` is set).
struct PrefetchOnly {
    issuer: url::Url,
    keys: Vec<JwkPublicKey>,
    serves: bool,
    loaded: Mutex<Option<Vec<JwkPublicKey>>>,
    prefetches: Arc<AtomicUsize>,
}

impl JwksResolver for PrefetchOnly {
    fn resolve(&self, issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        match &*self.loaded.lock() {
            Some(keys) if issuer == &self.issuer => Ok(keys.clone()),
            _ => Err(ResolveError::NetworkError("not prefetched".into())),
        }
    }

    fn prefetch<'a>(&'a self, issuer: &'a url::Url) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.prefetches.fetch_add(1, Ordering::Relaxed);
            if self.serves && issuer == &self.issuer {
                *self.loaded.lock() = Some(self.keys.clone());
            }
        })
    }
}

fn manifest(key: &AitpSigningKey, name: &str, issuer: &url::Url) -> Manifest {
    ManifestBuilder::new(key)
        .display_name(name)
        .handshake_endpoint(
            format!("https://{name}.example.com/aitp/handshake")
                .parse()
                .unwrap(),
        )
        .identity_hint(
            IdentityHint::new(IdentityHintKind::Oidc, name)
                .with_issuer(RawUrl::from(issuer.clone())),
        )
        .accept_trust_anchor(issuer.clone())
        .accept_identity_type("oidc")
        .offer("demo.echo")
        .build()
        .unwrap()
}

/// POST an OIDC MUTUAL_HELLO from alice to a bob whose resolver serves
/// keys only after a prefetch when `serves`; return the response status,
/// its body and the prefetch count.
async fn hello(serves: bool) -> (u16, serde_json::Value, usize) {
    let idp = MockOidcIssuer::new("https://idp.example.com", "kid-1", [0xC0; 32]);
    let alice = AitpSigningKey::from_seed(&[0xA7; 32]);
    let bob = AitpSigningKey::from_seed(&[0xB7; 32]);
    let alice_manifest = manifest(&alice, "alice", &idp.issuer);
    let bob_manifest = manifest(&bob, "bob", &idp.issuer);

    let prefetches = Arc::new(AtomicUsize::new(0));
    let resolver = PrefetchOnly {
        issuer: idp.issuer.clone(),
        keys: vec![idp.as_jwk()],
        serves,
        loaded: Mutex::new(None),
        prefetches: prefetches.clone(),
    };
    let server = HandshakeServer::new(
        AitpSigningKey::from_seed(&[0xB7; 32]),
        bob_manifest,
        vec![RawUrl::from(idp.issuer.clone())],
        resolver,
        vec!["demo.echo".into()],
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        server.serve(listener).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let no_keys = StaticPinnedKeyStore::new([]);
    let unused = PrefetchOnly {
        issuer: idp.issuer.clone(),
        keys: vec![],
        serves: false,
        loaded: Mutex::new(None),
        prefetches: Arc::new(AtomicUsize::new(0)),
    };
    let now = Timestamp::now();
    let cfg = PeerConfig::new(
        &alice,
        &alice_manifest,
        &unused,
        &no_keys,
        aitp::tct::RevocationSource::FailOpen,
        now,
    );
    let mid = Uuid::new_v4();
    let (_initiator, mut payload) = Initiator::start(
        &cfg,
        PresentedIdentity::Oidc {
            issuer: idp.issuer.clone(),
            subject: "alice".into(),
            proof_jwt: String::new(),
        },
        bob.aid(),
        &mid,
        now,
        vec!["demo.echo".into()],
    )
    .unwrap();
    let jkt = alice.verifying_key().to_jwk_thumbprint().unwrap();
    payload.identity.proof =
        idp.mint_aitp_jwt("alice", bob.aid().as_str(), &payload.pop_nonce, &jkt, now.0);
    let envelope = sign_envelope_with(
        &alice,
        MessageType::MutualHello,
        serde_json::to_value(&payload).unwrap(),
        mid,
        now,
    )
    .unwrap();
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/aitp/handshake/hello"))
        .json(&envelope)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, body, prefetches.load(Ordering::Relaxed))
}

#[tokio::test]
async fn oidc_hello_resolves_keys_the_server_prefetched() {
    let (status, body, prefetches) = hello(true).await;
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(prefetches, 1);
}

#[tokio::test]
async fn unresolved_issuer_keys_are_key_resolution_failed() {
    let (status, body, prefetches) = hello(false).await;
    assert_eq!(prefetches, 1);
    assert_eq!(status, 400, "body: {body}");
    assert!(
        body.to_string().contains("KEY_RESOLUTION_FAILED"),
        "body: {body}"
    );
}
