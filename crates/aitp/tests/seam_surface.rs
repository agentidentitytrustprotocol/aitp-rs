//! The embedded admission seam: what a service that admits agents with
//! pinned keys and self-attestations, and runs no AITP HTTP stack, uses
//! from `aitp`.
//!
//! Built with `--no-default-features --features pinned-admission` (the
//! `features` CI job runs every feature alone), so a seam item that moves
//! behind another feature fails here. `scripts/check-dep-surface.sh`
//! checks that this build carries no HTTP stack. Every item is used
//! through public constructors only, so the test keeps compiling when
//! the types become `#[non_exhaustive]`.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use aitp::core::nonce_store::{
    ConsumeOutcome, IssuedNonce, Nonce, NonceStore, NonceStoreError, NONCE_LEN,
};
use aitp::core::{
    base64url, ids, Aid, AidAlgorithm, BoxFuture, CheckedJson, ExtensionsMap, RawUrl, Timestamp,
};
use aitp::crypto::testing::{p256_high_s_twin, MockKmsSigner, MockOutput};
use aitp::crypto::{
    check_public_key, jws, sign_raw, AitpSigner, AitpSigningKey, AitpVerifyingKey, AsyncAitpSigner,
    CryptoError, Digest32, Signature,
};
use aitp::handshake::admission::{
    AdmissionError, ChallengeRateLimiter, ChallengeSource, TokenBucketLimiter, MAX_NONCE_TTL,
};
use aitp::handshake::identity_pinned::PINNED_KEY_PROOF_DOMAIN;
use aitp::handshake::{
    pinned_key_proof_input, sign_pinned_key_proof, verify_pinned_key, IdentityDescriptor,
    IdentityKind, PinnedKeyVerifyContext, StaticPinnedKeyStore, SubjectBinding,
};
use aitp::tct::{
    verify_attestation, verify_tct, AttestationVerifyContext, TctBuilder, TctError,
    TctVerifyContext, ATTESTATION_GRANT,
};
use serde_json::{json, Map, Value};
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_711_900_000);
const STATEMENT_KEY: &str = "com.example.seam";

/// Drive a future that never waits on I/O. The seam has no runtime.
fn ready<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("the future waited"),
    }
}

fn ed25519(seed: u8) -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&[seed; 32])
}

fn p256(seed: u8) -> AitpSigningKey {
    AitpSigningKey::from_p256_seed(&[seed; 32]).unwrap()
}

fn statement() -> Map<String, Value> {
    json!({STATEMENT_KEY: {"statement": "seam attestation"}})
        .as_object()
        .unwrap()
        .clone()
}

fn attestation_ctx<'a>(issuer: &'a Aid, key: &'a str) -> AttestationVerifyContext<'a> {
    AttestationVerifyContext::builder(issuer, key, NOW)
        .waive_manifest_cap_issuer_has_no_manifest()
        .accept_unchecked_revocation_dangerous()
        .build()
        .unwrap()
}

/// An embedder's mapping of a TCT failure to its own refusal reasons.
fn refusal(err: &TctError) -> &'static str {
    match err {
        TctError::Crypto(CryptoError::Signer(e)) if e.is_transient() => "retry",
        TctError::Crypto(_) | TctError::SignatureInvalid => "bad-signature",
        TctError::IssuerMismatch => "wrong-issuer",
        TctError::AttestationStatementMissing(_) => "no-statement",
        _ => "refused",
    }
}

/// An embedder's own nonce store, behind the `NonceStore` trait.
#[derive(Default)]
struct MapNonceStore(Mutex<HashMap<Nonce, IssuedNonce>>);

impl NonceStore for MapNonceStore {
    fn issue<'a>(&'a self, issued: &'a IssuedNonce) -> BoxFuture<'a, Result<(), NonceStoreError>> {
        Box::pin(async move {
            let mut map = self.0.lock().unwrap();
            if map.contains_key(&issued.nonce) {
                return Err(NonceStoreError::Duplicate);
            }
            map.insert(issued.nonce, issued.clone());
            Ok(())
        })
    }

    fn consume<'a>(
        &'a self,
        nonce: &'a Nonce,
        verifier: &'a Aid,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<ConsumeOutcome, NonceStoreError>> {
        Box::pin(async move {
            Ok(match self.0.lock().unwrap().remove(nonce) {
                Some(n) if &n.verifier != verifier => ConsumeOutcome::Unknown,
                Some(n) if now.0 >= n.expires_at.0 => ConsumeOutcome::Expired,
                Some(_) => ConsumeOutcome::Consumed,
                None => ConsumeOutcome::Unknown,
            })
        })
    }
}

#[test]
fn core_items() {
    let key = ed25519(1);
    let aid: &Aid = key.aid();
    assert_eq!(aid.algorithm(), AidAlgorithm::Ed25519);
    assert_eq!(Aid::parse(aid.as_str()).unwrap(), *aid);
    assert_eq!(
        base64url::decode_strict(&base64url::encode(b"seam")).unwrap(),
        b"seam"
    );
    assert_eq!(
        RawUrl::new("https://idp.example.com").as_str(),
        "https://idp.example.com"
    );

    let mut ext = ExtensionsMap::new();
    ext.insert(STATEMENT_KEY, json!(1));
    assert_eq!(ext.get(STATEMENT_KEY), Some(&json!(1)));

    assert!(CheckedJson::from_slice(br#"{"a":1}"#).is_ok());
    let _duplicate_key: aitp::core::CheckedJsonError =
        CheckedJson::from_slice(br#"{"a":1,"a":2}"#).unwrap_err();

    let derived = ids::derived_v4("com.example.seam", b"record-1").unwrap();
    assert_eq!(ids::parse_v4(&derived.to_string()).unwrap(), derived);
    assert!(ids::parse_v4("01890a5d-ac96-774b-bcce-b302099a8057").is_err());
}

#[test]
fn nonce_store_contract() {
    let store = MapNonceStore::default();
    let verifier = ed25519(1).aid().clone();
    let nonce: Nonce = [7; NONCE_LEN];
    let issued = IssuedNonce::new(
        nonce,
        verifier.clone(),
        "10.0.0.1",
        NOW,
        Timestamp(NOW.0 + 60),
    );
    let dyn_store: &dyn NonceStore = &store;

    ready(dyn_store.issue(&issued)).unwrap();
    assert!(matches!(
        ready(dyn_store.issue(&issued)),
        Err(NonceStoreError::Duplicate)
    ));
    assert_eq!(
        ready(dyn_store.consume(&nonce, &verifier, NOW)).unwrap(),
        ConsumeOutcome::Consumed
    );
    assert_eq!(
        ready(dyn_store.consume(&nonce, &verifier, NOW)).unwrap(),
        ConsumeOutcome::Unknown
    );
}

#[test]
fn crypto_items() {
    let msg = b"seam message";
    for key in [ed25519(2), p256(3)] {
        let sig = sign_raw(&key, msg).unwrap();
        key.verifying_key().verify_raw(msg, &sig).unwrap();
        check_public_key(&key).unwrap();
        let async_pk: AitpVerifyingKey = ready(AsyncAitpSigner::public_key(&key)).unwrap();
        assert_eq!(async_pk, AitpSigner::public_key(&key).unwrap());
        let boxed: BoxFuture<'_, _> = Box::pin(AsyncAitpSigner::public_key(&key));
        assert_eq!(ready(boxed).unwrap(), async_pk);
    }

    // A KMS signer returning DER: normalised to low-S JOSE `R || S`.
    let kms = MockKmsSigner::new(p256(4)).output(MockOutput::Der);
    let sig = sign_raw(&kms, msg).unwrap();
    let vk = AitpVerifyingKey::from_aid(AitpSigner::aid(&kms)).unwrap();
    vk.verify_raw(msg, &sig).unwrap();
    assert!(
        vk.verify_raw(msg, &p256_high_s_twin(sig)).is_err(),
        "high-S must not verify"
    );

    let digest = Digest32::sha256(msg);
    assert_eq!(digest, Digest32::from_bytes(*digest.as_bytes()));
    assert!(Signature::parse("not-a-signature").is_err());
}

#[test]
fn a_transient_signer_failure_surfaces_through_tct_issuance() {
    let kms = MockKmsSigner::new(ed25519(5)).fail_transient(1, None);
    let err = TctBuilder::new(&kms)
        .self_attestation()
        .ext(statement())
        .issued_at(NOW)
        .build()
        .unwrap_err();
    assert_eq!(refusal(&err), "retry", "{err:?}");
    assert_eq!(kms.calls(), 1);
}

#[test]
fn self_attestation_round_trip_and_rejections() {
    let issuer = p256(6);
    let issued = TctBuilder::new(&issuer)
        .self_attestation()
        .ext(statement())
        .issued_at(NOW)
        .build()
        .unwrap();
    assert_eq!(issued.claims.grants, [ATTESTATION_GRANT]);

    let v =
        verify_attestation(&issued.token, &attestation_ctx(issuer.aid(), STATEMENT_KEY)).unwrap();
    assert_eq!(v.statement, json!({"statement": "seam attestation"}));

    let err =
        verify_attestation(&issued.token, &attestation_ctx(issuer.aid(), "org.other")).unwrap_err();
    assert!(
        matches!(&err, TctError::AttestationStatementMissing(k) if k == "org.other"),
        "{err:?}"
    );
    assert_eq!(refusal(&err), "no-statement");

    // Genuinely signed by `issuer`, but claiming another `iss`.
    let mut claims = serde_json::to_value(&issued.claims).unwrap();
    claims["iss"] = json!(p256(7).aid());
    let spoofed = jws::sign_compact(&issuer, jws::TYP_TCT, &claims).unwrap();
    let err =
        verify_attestation(&spoofed, &attestation_ctx(issuer.aid(), STATEMENT_KEY)).unwrap_err();
    assert_eq!(refusal(&err), "wrong-issuer", "{err:?}");

    let (head, sig) = issued.token.rsplit_once('.').unwrap();
    let flipped = if sig.starts_with('A') { "B" } else { "A" };
    let tampered = format!("{head}.{flipped}{}", &sig[1..]);
    let err =
        verify_attestation(&tampered, &attestation_ctx(issuer.aid(), STATEMENT_KEY)).unwrap_err();
    assert_eq!(refusal(&err), "bad-signature", "{err:?}");

    // An attestation confers nothing in the grant context.
    let ctx = TctVerifyContext::builder(issuer.aid(), issuer.aid(), NOW)
        .accept_unchecked_revocation_dangerous()
        .skip_manifest_expiry_cap_dangerous()
        .build()
        .unwrap();
    assert!(verify_tct(&issued.token, &ctx).is_err());
}

/// The bytes `TctBuilder::self_attestation` signs for a fixed key, clock
/// and `jti`. A change here breaks every stored attestation.
#[test]
fn self_attestation_golden_bytes() {
    let token = TctBuilder::new(&ed25519(8))
        .self_attestation()
        .ext(statement())
        .ttl_secs(3_600)
        .derived_jti("com.example.seam", b"golden")
        .issued_at(NOW)
        .build()
        .unwrap()
        .token;
    assert_eq!(token, GOLDEN_ATTESTATION);
}

/// Generated with the aitp-tct 0.23.0 code before the crates collapsed.
const GOLDEN_ATTESTATION: &str = concat!(
    "eyJhbGciOiJFZERTQSIsInR5cCI6ImFpdHAtdGN0K2p3dCJ9.",
    "eyJhdWQiOiJhaWQ6cHVia2V5OkU1ajJMRzBhUlh4UnVtcExYejI5TDJuOHFUSVdJWTNJbVg1QmE5Rjlr",
    "OG8iLCJjbmYiOnsiamt0IjoiRTkxNlhUakpDSzgydkFpYkVHR2hCM2xEVjd3QU52bExmeGlDTlRxZm9f",
    "YyJ9LCJleHAiOjE3MTE5MDM2MDAsImV4dCI6eyJjb20uZXhhbXBsZS5zZWFtIjp7InN0YXRlbWVudCI6",
    "InNlYW0gYXR0ZXN0YXRpb24ifX0sImdyYW50cyI6WyJhaXRwLmF0dGVzdGF0aW9uIl0sImlhdCI6MTcx",
    "MTkwMDAwMCwiaXNzIjoiYWlkOnB1YmtleTpFNWoyTEcwYVJYeFJ1bXBMWHoyOUwybjhxVElXSVkzSW1Y",
    "NUJhOUY5azhvIiwianRpIjoiZTNiYjg2YWItN2JlYy00ZDQ1LTliZjMtNmIzOGQ3MTIwZGUzIiwic3Vi",
    "IjoiYWlkOnB1YmtleTpFNWoyTEcwYVJYeFJ1bXBMWHoyOUwybjhxVElXSVkzSW1YNUJhOUY5azhvIiwi",
    "dmVyIjoiYWl0cC8wLjMifQ",
    ".URp0SLSAo6VBUIQ3lYdg-GK5zg-IBqpteuo5WjSRrS6YRZpzcKIWSDgOQSvMXBMSvIEPwyJ8aRYgVK7w6PC6Bg",
);

#[test]
fn pinned_key_proof_round_trip() {
    let sender = ed25519(9);
    let receiver = ed25519(10).aid().clone();
    let message_id = Uuid::from_u128(0x5eed);
    let pop_nonce = base64url::encode(&[3; 16]);

    let input =
        pinned_key_proof_input(sender.aid(), &receiver, &message_id, NOW, &pop_nonce).unwrap();
    assert!(input.starts_with(PINNED_KEY_PROOF_DOMAIN));

    let proof = sign_pinned_key_proof(
        &sender,
        sender.aid(),
        &receiver,
        &message_id,
        NOW,
        &pop_nonce,
    )
    .unwrap();
    let vk = sender.verifying_key();
    vk.verify_jcs(
        &Digest32::sha256(&input),
        &Signature::parse(&proof).unwrap(),
    )
    .unwrap();

    let descriptor = IdentityDescriptor::pinned_key(
        sender.aid().as_str(),
        base64url::encode(&vk.to_compressed()),
        proof,
    );
    assert_eq!(descriptor.kind, IdentityKind::PinnedKey);
    let store: StaticPinnedKeyStore = [vk].into_iter().collect();
    let ctx = PinnedKeyVerifyContext::new(sender.aid(), &receiver, &message_id, NOW, &pop_nonce)
        .with_subject(SubjectBinding::SenderAid);
    let verified = verify_pinned_key(&descriptor, &ctx, &store).unwrap();
    assert_eq!(verified.aid, *sender.aid());

    let unpinned = StaticPinnedKeyStore::default();
    assert!(verify_pinned_key(&descriptor, &ctx, &unpinned).is_err());
}

#[test]
fn admission_items() {
    let limiter = TokenBucketLimiter::new(1, 1.0);
    let limiter: &dyn ChallengeRateLimiter = &limiter;
    let source = ChallengeSource::ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(limiter.check(&source).is_ok());
    assert!(
        limiter.check(&source).is_err(),
        "the bucket holds one token"
    );

    assert!(MAX_NONCE_TTL.as_secs() > 0);
    let err = AdmissionError::Replay;
    assert_eq!(err.code(), Some("REPLAY_DETECTED"));
    assert_eq!(
        err.http_status(),
        None,
        "a replay is an envelope error, not an HTTP refusal"
    );
}
