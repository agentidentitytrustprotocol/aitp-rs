//! Compile probe: the facade handshake future, the server futures and
//! the configuration types an application shares across tasks are
//! `Send`, and the shared ones `Sync`. A regression fails to compile.

#![cfg(all(feature = "http-client", feature = "http-server"))]

use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError};

fn assert_send<T: Send>(_: &T) {}
fn assert_send_sync<T: Send + Sync>() {}

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

#[allow(dead_code)]
fn handshake_future_is_send(cfg: aitp::facade::InitiatorConfig<'static>) {
    assert_send(&aitp::facade::run_initiator_handshake(cfg));
}

#[allow(dead_code)]
fn serve_future_is_send(
    server: aitp::transport::HandshakeServer<NoOpResolver>,
    listener: tokio::net::TcpListener,
) {
    assert_send(&server.serve(listener));
}

#[test]
fn shared_configuration_is_send_and_sync() {
    assert_send_sync::<aitp::facade::InitiatorConfig<'static>>();
    assert_send_sync::<aitp::facade::IdentityMode>();
    assert_send_sync::<aitp::facade::TrustMode<'static>>();
    assert_send_sync::<aitp::handshake::PeerConfig<'static>>();
    assert_send_sync::<aitp::handshake::IdentityVerifyContext<'static>>();
    assert_send_sync::<aitp::handshake::OidcMintError>();
    assert_send_sync::<Box<aitp::handshake::OidcMintJwtFn>>();
    assert_send_sync::<&'static dyn JwksResolver>();
    assert_send_sync::<aitp::tct::TctVerifyContext<'static>>();
    assert_send_sync::<aitp::delegation::DelegationVerifyContext<'static>>();
    assert_send_sync::<aitp::transport::HandshakeServer<NoOpResolver>>();
}
