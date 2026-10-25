//! `aitp::facade::renew_tct` renews only at the issuer's advertised
//! `rfc-aitp-0005.renew_uri` and never probes a guessed path
//! (RFC-AITP-0004 §8.1, issue #196).

#![cfg(all(feature = "experimental-renewal", feature = "http-server"))]

use aitp::core::{base64url, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::facade::{renew_tct, renew_tct_with_insecure_localhost, FacadeError};
use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError};
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use aitp::tct::TctBuilder;
use aitp::transport::{HandshakeServer, RENEW_URI_EXT};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn manifest(issuer: &AitpSigningKey, renew_uri: Option<String>) -> Manifest {
    let mut b = ManifestBuilder::new(issuer)
        .display_name("issuer")
        .handshake_endpoint("https://issuer.example/aitp/handshake/".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "issuer".into(),
            issuer: None,
            public_key: Some(base64url::encode(
                &issuer.verifying_key().try_to_ed25519_bytes().unwrap(),
            )),
        })
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .ttl_secs(86_400);
    if let Some(uri) = renew_uri {
        b = b.extension(RENEW_URI_EXT, uri.into());
    }
    b.build().unwrap()
}

fn held_tct(issuer: &AitpSigningKey, holder: &AitpSigningKey) -> String {
    TctBuilder::new(issuer)
        .subject(holder.aid().clone())
        .audience(holder.aid().clone())
        .grants(["demo.echo"])
        .ttl_secs(600)
        .subject_pubkey(holder.verifying_key())
        .issued_at(Timestamp::now())
        .build()
        .unwrap()
        .token
}

#[tokio::test]
async fn renews_at_the_advertised_uri() {
    let issuer = AitpSigningKey::from_seed(&[0x60; 32]);
    let holder = AitpSigningKey::from_seed(&[0x61; 32]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // A non-default path: only reading the Manifest finds it.
    let m = manifest(
        &issuer,
        Some(format!("http://127.0.0.1:{port}/somewhere/else/renew")),
    );
    let server = HandshakeServer::new(
        AitpSigningKey::from_seed(&[0x60; 32]),
        m.clone(),
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    );
    tokio::spawn(async move { axum::serve(listener, server.router()).await.ok() });

    let renewed = renew_tct_with_insecure_localhost(&holder, held_tct(&issuer, &holder), &m)
        .await
        .expect("renewal at the advertised URI");
    assert!(!renewed.tct.is_empty());

    // Each `renew_tct` call draws a fresh nonce, so the replay guard
    // does not trip on a legitimate second renewal.
    renew_tct_with_insecure_localhost(&holder, held_tct(&issuer, &holder), &m)
        .await
        .expect("fresh nonce renews again");
}

#[tokio::test]
async fn no_renew_uri_means_no_request() {
    let issuer = AitpSigningKey::from_seed(&[0x62; 32]);
    let holder = AitpSigningKey::from_seed(&[0x63; 32]);

    // Count every request that reaches the issuer's host.
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let app = axum::Router::new().fallback(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        async { "" }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });

    // The handshake endpoint points at the live host, but nothing
    // advertises a renewal endpoint.
    let m = ManifestBuilder::new(&issuer)
        .display_name("issuer")
        .handshake_endpoint(
            format!("http://127.0.0.1:{port}/aitp/handshake/")
                .parse()
                .unwrap(),
        )
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "issuer".into(),
            issuer: None,
            public_key: Some(base64url::encode(
                &issuer.verifying_key().try_to_ed25519_bytes().unwrap(),
            )),
        })
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .build()
        .unwrap();
    let err = renew_tct_with_insecure_localhost(&holder, held_tct(&issuer, &holder), &m)
        .await
        .unwrap_err();
    assert!(
        matches!(err, FacadeError::RenewalNotAdvertised),
        "got {err:?}"
    );

    // Non-HTTPS (non-loopback) URIs are not usable either.
    let m = manifest(&issuer, Some("http://issuer.example/renew".into()));
    let err = renew_tct_with_insecure_localhost(&holder, held_tct(&issuer, &holder), &m)
        .await
        .unwrap_err();
    assert!(
        matches!(err, FacadeError::RenewalNotAdvertised),
        "got {err:?}"
    );

    // A loopback `http` URI needs the explicit local-development opt-in.
    let m = manifest(&issuer, Some(format!("http://127.0.0.1:{port}/renew")));
    let err = renew_tct(&holder, held_tct(&issuer, &holder), &m)
        .await
        .unwrap_err();
    assert!(
        matches!(err, FacadeError::RenewalNotAdvertised),
        "got {err:?}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0, "no guessed path probed");
}
