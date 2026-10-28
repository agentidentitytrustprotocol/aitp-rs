//! `IdentityVerifier`: identity types `aitp` does not verify itself are
//! verified by the verifier attached to `PeerConfig`, and rejected with
//! `INCOMPATIBLE_IDENTITY_TYPE` when none handles them (RFC-AITP-0002
//! §6.6).

use std::sync::atomic::{AtomicUsize, Ordering};

use aitp::__private::bootstrap_verify_peer;
use aitp::core::{AitpEnvelope, ErrorCode, MessageType, Timestamp};
use aitp::crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp::handshake::{
    HandshakeError, IdentityDescriptor, IdentityKind, IdentityVerifier, IdentityVerifyContext,
    IdentityVerifyError, JwkPublicKey, JwksResolver, PeerConfig, ResolveError,
    StaticPinnedKeyStore, VerifiedIdentity,
};
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use aitp::tct::RevocationSource;
use serde_json::json;
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);
const SPIFFE_ID: &str = "spiffe://prod.example.com/ns/payments/sa/agent";
const NONCE: &str = "bQ88kiChryTKduskLXSCNg";

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

fn proved_spiffe_id() -> Result<VerifiedIdentity, IdentityVerifyError> {
    Ok(VerifiedIdentity::new(IdentityKind::Spiffe, SPIFFE_ID))
}

/// A verifier that counts its calls and answers with `outcome`.
struct Fake {
    handles: bool,
    outcome: fn() -> Result<VerifiedIdentity, IdentityVerifyError>,
    calls: AtomicUsize,
    seen: std::sync::Mutex<Option<String>>,
}

impl Fake {
    fn new(handles: bool, outcome: fn() -> Result<VerifiedIdentity, IdentityVerifyError>) -> Self {
        Self {
            handles,
            outcome,
            calls: AtomicUsize::new(0),
            seen: Default::default(),
        }
    }
}

impl IdentityVerifier for Fake {
    fn handles(&self, _kind: IdentityKind) -> bool {
        self.handles
    }
    fn verify(
        &self,
        identity: &IdentityDescriptor,
        ctx: &IdentityVerifyContext<'_>,
    ) -> Result<VerifiedIdentity, IdentityVerifyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(identity.subject, SPIFFE_ID);
        assert_eq!(ctx.sender_aid, &ctx.peer_manifest.aid);
        assert_eq!(ctx.pop_nonce, NONCE);
        assert_eq!(ctx.now, NOW);
        *self.seen.lock().unwrap() = Some(ctx.receiver_aid.as_str().to_owned());
        (self.outcome)()
    }
}

fn manifest(key: &AitpSigningKey, hint: IdentityHint, accepted: &str) -> Manifest {
    ManifestBuilder::new(key)
        .display_name("peer")
        .handshake_endpoint("https://peer.example.com/handshake".parse().unwrap())
        .identity_hint(hint)
        .accept_identity_type(accepted)
        .offer("demo.echo")
        .published_at(NOW)
        .build()
        .unwrap()
}

fn spiffe_manifest(key: &AitpSigningKey) -> Manifest {
    manifest(
        key,
        IdentityHint::new(IdentityHintKind::Spiffe, SPIFFE_ID),
        "spiffe",
    )
}

fn spiffe_identity() -> IdentityDescriptor {
    serde_json::from_value(json!({
        "type": "spiffe", "subject": SPIFFE_ID, "svid_type": "jwt-svid", "proof": "x.y.z",
    }))
    .unwrap()
}

fn envelope(sender: &AitpSigningKey) -> AitpEnvelope {
    AitpEnvelope::unsigned(
        sender.aid().clone(),
        MessageType::MutualHello,
        json!({}),
        Uuid::new_v4(),
        NOW,
    )
}

/// Runs `bootstrap_verify_peer` for a `spiffe` peer, with `verifier`
/// attached when given.
fn verify_spiffe_peer(
    verifier: Option<&dyn IdentityVerifier>,
) -> Result<AitpVerifyingKey, HandshakeError> {
    let me = AitpSigningKey::from_seed(&[0x11; 32]);
    let peer = AitpSigningKey::from_seed(&[0x12; 32]);
    let my_manifest = spiffe_manifest(&me);
    let peer_manifest = spiffe_manifest(&peer);
    let store = StaticPinnedKeyStore::new([]);
    let mut cfg = PeerConfig::new(
        &me,
        &my_manifest,
        &NoOpResolver,
        &store,
        RevocationSource::FailOpen,
        NOW,
    );
    if let Some(v) = verifier {
        cfg = cfg.with_identity_verifier(v);
    }
    bootstrap_verify_peer(
        &envelope(&peer),
        &peer_manifest,
        &spiffe_identity(),
        NONCE,
        &cfg,
    )
}

#[test]
fn without_a_verifier_spiffe_is_incompatible() {
    let err = verify_spiffe_peer(None).unwrap_err();
    assert_eq!(err.error_code(), ErrorCode::IncompatibleIdentityType);
}

#[test]
fn a_verifier_that_does_not_handle_the_kind_is_not_called() {
    let fake = Fake::new(false, proved_spiffe_id);
    let err = verify_spiffe_peer(Some(&fake)).unwrap_err();
    assert_eq!(err.error_code(), ErrorCode::IncompatibleIdentityType);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_verifier_identity_error_is_identity_failed() {
    let fake = Fake::new(true, || {
        Err(IdentityVerifyError::Rejected("bad svid".into()))
    });
    let err = verify_spiffe_peer(Some(&fake)).unwrap_err();
    assert_eq!(err.error_code(), ErrorCode::IdentityFailed);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn a_verifier_key_resolution_error_passes_through() {
    let fake = Fake::new(true, || {
        Err(IdentityVerifyError::KeyUnavailable(
            "bundle endpoint unreachable".into(),
        ))
    });
    let err = verify_spiffe_peer(Some(&fake)).unwrap_err();
    assert_eq!(err.error_code(), ErrorCode::KeyResolutionFailed);
}

#[test]
fn a_verifier_proving_another_identity_is_identity_failed() {
    let fake = Fake::new(true, || {
        Ok(VerifiedIdentity::new(
            IdentityKind::Spiffe,
            "spiffe://prod.example.com/other",
        ))
    });
    let err = verify_spiffe_peer(Some(&fake)).unwrap_err();
    assert_eq!(err.error_code(), ErrorCode::IdentityFailed);
    let fake = Fake::new(true, || {
        Ok(VerifiedIdentity::new(IdentityKind::Oidc, SPIFFE_ID))
    });
    let err = verify_spiffe_peer(Some(&fake)).unwrap_err();
    assert_eq!(err.error_code(), ErrorCode::IdentityFailed);
}

#[test]
fn on_success_the_peer_key_is_the_sender_aid_key() {
    let fake = Fake::new(true, proved_spiffe_id);
    let key = verify_spiffe_peer(Some(&fake)).unwrap();
    let peer = AitpSigningKey::from_seed(&[0x12; 32]);
    assert_eq!(key, AitpVerifyingKey::from_aid(peer.aid()).unwrap());
    let me = AitpSigningKey::from_seed(&[0x11; 32]);
    assert_eq!(
        fake.seen.lock().unwrap().as_deref(),
        Some(me.aid().as_str())
    );
}

#[test]
fn the_verifier_is_never_called_for_native_kinds() {
    let fake = Fake::new(true, proved_spiffe_id);
    let me = AitpSigningKey::from_seed(&[0x11; 32]);
    let peer = AitpSigningKey::from_seed(&[0x12; 32]);
    let my_manifest = spiffe_manifest(&me);
    let store = StaticPinnedKeyStore::new([]);
    let cfg = PeerConfig::new(
        &me,
        &my_manifest,
        &NoOpResolver,
        &store,
        RevocationSource::FailOpen,
        NOW,
    )
    .with_identity_verifier(&fake);

    // pinned_key: the key is not in the (empty) store.
    let pk = aitp::core::base64url::encode(&peer.verifying_key().try_to_ed25519_bytes().unwrap());
    let pinned_manifest = manifest(
        &peer,
        IdentityHint::new(IdentityHintKind::PinnedKey, "peer").with_public_key(pk.clone()),
        "pinned_key",
    );
    let pinned: IdentityDescriptor = serde_json::from_value(json!({
        "type": "pinned_key", "subject": "peer", "public_key": pk, "proof": "x",
    }))
    .unwrap();
    let err = bootstrap_verify_peer(&envelope(&peer), &pinned_manifest, &pinned, NONCE, &cfg)
        .unwrap_err();
    assert_eq!(err.error_code(), ErrorCode::IdentityFailed);

    // oidc: the issuer is not a trust anchor.
    let issuer = "https://issuer.example.com";
    let oidc_manifest = manifest(
        &peer,
        IdentityHint::new(IdentityHintKind::Oidc, "peer").with_issuer(issuer.into()),
        "oidc",
    );
    let oidc: IdentityDescriptor = serde_json::from_value(json!({
        "type": "oidc", "subject": "peer", "issuer": issuer, "proof": "a.b.c",
    }))
    .unwrap();
    let err =
        bootstrap_verify_peer(&envelope(&peer), &oidc_manifest, &oidc, NONCE, &cfg).unwrap_err();
    assert_eq!(err.error_code(), ErrorCode::IncompatibleTrustAnchors);

    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}
