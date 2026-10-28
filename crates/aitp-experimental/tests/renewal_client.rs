//! `renewal::renew_tct` renews only at the issuer's advertised
//! `rfc-aitp-0005.renew_uri` and never probes a guessed path
//! (RFC-AITP-0013 §2).

use aitp::core::nonce_store::InMemoryNonceStore;
use aitp::core::{base64url, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::handshake::IdentityKind;
use aitp::manifest::{IdentityHint, Manifest, ManifestBuilder};
use aitp::tct::{sign_revocation_list, RevocationList, RevocationListEnvelope, TctBuilder};
use aitp::transport::RevocationListProducer;
use aitp_experimental::renewal::{
    renew_tct, renew_tct_with_insecure_localhost, RenewClientError, RenewalServer, RENEW_URI_EXT,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;

struct StaticProducer(RevocationListEnvelope);
impl RevocationListProducer for StaticProducer {
    fn current(
        &self,
    ) -> aitp::core::BoxFuture<'_, Result<RevocationListEnvelope, aitp::transport::RevocationError>>
    {
        Box::pin(std::future::ready(Ok(self.0.clone())))
    }
}

/// Serve `seed`'s renewal endpoint for `m` on `listener`.
fn spawn_renewal(seed: [u8; 32], m: &Manifest, listener: TcpListener) {
    let key = AitpSigningKey::from_ed25519_seed(&seed);
    let now = Timestamp::now();
    let list = sign_revocation_list(
        RevocationList::new(key.aid().clone(), now, Timestamp(now.0 + 3600), vec![]),
        &key,
    )
    .unwrap();
    let app = RenewalServer::new(
        Arc::new(key),
        m.clone(),
        Arc::new(StaticProducer(list)),
        Arc::new(InMemoryNonceStore::default()),
    )
    .unwrap()
    .router()
    .unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .ok()
    });
}

fn manifest(issuer: &AitpSigningKey, renew_uri: Option<String>) -> Manifest {
    let mut b = ManifestBuilder::new(issuer)
        .display_name("issuer")
        .handshake_endpoint("https://issuer.example/aitp/handshake/".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityKind::PinnedKey, "issuer").with_public_key(
                base64url::encode(&issuer.verifying_key().try_to_ed25519_bytes().unwrap()),
            ),
        )
        .accept_identity_type(aitp::handshake::IdentityKind::PinnedKey)
        .offer("demo.echo")
        .ttl(std::time::Duration::from_secs(86_400));
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
        .ttl(std::time::Duration::from_secs(600))
        .subject_pubkey(holder.verifying_key())
        .issued_at(Timestamp::now())
        .build()
        .unwrap()
        .token
}

#[tokio::test]
async fn renews_at_the_advertised_uri() {
    let issuer = AitpSigningKey::from_ed25519_seed(&[0x60; 32]);
    let holder = AitpSigningKey::from_ed25519_seed(&[0x61; 32]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // A non-default path: only reading the Manifest finds it.
    let m = manifest(
        &issuer,
        Some(format!("http://127.0.0.1:{port}/somewhere/else/renew")),
    );
    spawn_renewal([0x60; 32], &m, listener);

    let renewed = renew_tct_with_insecure_localhost(&holder, held_tct(&issuer, &holder), &m)
        .await
        .expect("renewal at the advertised URI");
    // The response was a signed `tct` envelope from the issuer whose
    // renewed TCT is addressed to the holder (RFC-AITP-0013 §6.1).
    assert_eq!(&renewed.tct.claims().sub, holder.aid());
    assert_eq!(&renewed.tct.claims().iss, issuer.aid());

    // Each `renew_tct` call draws a fresh nonce, so the replay guard
    // does not trip on a legitimate second renewal.
    renew_tct_with_insecure_localhost(&holder, held_tct(&issuer, &holder), &m)
        .await
        .expect("fresh nonce renews again");
}

#[tokio::test]
async fn no_renew_uri_means_no_request() {
    let issuer = AitpSigningKey::from_ed25519_seed(&[0x62; 32]);
    let holder = AitpSigningKey::from_ed25519_seed(&[0x63; 32]);

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
        .identity_hint(
            IdentityHint::new(IdentityKind::PinnedKey, "issuer").with_public_key(
                base64url::encode(&issuer.verifying_key().try_to_ed25519_bytes().unwrap()),
            ),
        )
        .accept_identity_type(aitp::handshake::IdentityKind::PinnedKey)
        .offer("demo.echo")
        .build()
        .unwrap();
    let err = renew_tct_with_insecure_localhost(&holder, held_tct(&issuer, &holder), &m)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RenewClientError::NotAdvertised),
        "got {err:?}"
    );

    // Non-HTTPS (non-loopback) URIs are not usable either.
    let m = manifest(&issuer, Some("http://issuer.example/renew".into()));
    let err = renew_tct_with_insecure_localhost(&holder, held_tct(&issuer, &holder), &m)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RenewClientError::NotAdvertised),
        "got {err:?}"
    );

    // A loopback `http` URI needs the explicit local-development opt-in.
    let m = manifest(&issuer, Some(format!("http://127.0.0.1:{port}/renew")));
    let err = renew_tct(&holder, held_tct(&issuer, &holder), &m)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RenewClientError::NotAdvertised),
        "got {err:?}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0, "no guessed path probed");
}

/// An issuer refusal arrives as a signed `error` envelope with a 4xx
/// status; the client surfaces its code (RFC-AITP-0013 §6.1).
#[tokio::test]
async fn refusal_is_surfaced_with_its_code() {
    use aitp::core::ErrorCode;
    use aitp_experimental::renewal::RenewalResponseError;

    let issuer = AitpSigningKey::from_ed25519_seed(&[0x64; 32]);
    let holder = AitpSigningKey::from_ed25519_seed(&[0x65; 32]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let m = manifest(&issuer, Some(format!("http://127.0.0.1:{port}/renew")));
    spawn_renewal([0x64; 32], &m, listener);

    // A TCT carrying only a grant the Manifest no longer offers.
    let withdrawn = TctBuilder::new(&issuer)
        .subject(holder.aid().clone())
        .audience(holder.aid().clone())
        .grants(["legacy.cap"])
        .ttl(std::time::Duration::from_secs(600))
        .subject_pubkey(holder.verifying_key())
        .issued_at(Timestamp::now())
        .build()
        .unwrap()
        .token;
    let err = renew_tct_with_insecure_localhost(&holder, withdrawn, &m)
        .await
        .unwrap_err();
    match err {
        RenewClientError::Response(RenewalResponseError::Refused { code, .. }) => {
            assert_eq!(code, ErrorCode::PolicyViolation)
        }
        other => panic!("got {other:?}"),
    }
}
