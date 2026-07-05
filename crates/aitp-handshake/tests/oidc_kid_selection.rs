//! `verify_oidc` JWK-selection branch (RFC-AITP-0002 §2.2).
//!
//! The verifier picks the JWKS key by `kid`, with a single-key fallback
//! when the JWT carries no `kid`. Key rotation makes this a live
//! attack/robustness surface: a JWT for a rotated-out key, or a no-`kid`
//! JWT against a multi-key JWKS, must NOT be verified against the wrong
//! key — it must fail selection cleanly. These tests pin each branch.

mod fixtures;

use aitp_core::{Aid, RawUrl};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp_handshake::{
    verify_oidc, HandshakeError, IdentityDescriptor, IdentityKind, JwkPublicKey, JwksResolver,
    OidcVerifyContext, ResolveError,
};
use fixtures::mock_oidc::MockOidcIssuer;
use url::Url;

const NOW: i64 = 1_700_000_000;
const ISSUER: &str = "https://idp.example.com";

/// Resolver returning a fixed key list for the one trusted issuer.
struct MultiKeyResolver {
    issuer: Url,
    keys: Vec<JwkPublicKey>,
}

impl JwksResolver for MultiKeyResolver {
    fn resolve(&self, issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        if issuer == &self.issuer {
            Ok(self
                .keys
                .iter()
                .map(|k| JwkPublicKey {
                    kid: k.kid.clone(),
                    alg: k.alg,
                    key: k.key.clone(),
                })
                .collect())
        } else {
            Err(ResolveError::NotTrusted(issuer.clone()))
        }
    }
}

fn subject_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0x51; 32])
}

fn audience() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0x52; 32])
}

fn jkt_of(key: &AitpSigningKey) -> String {
    AitpVerifyingKey::from_aid(key.aid())
        .unwrap()
        .to_jwk_thumbprint()
        .unwrap()
}

fn descriptor(proof: String) -> IdentityDescriptor {
    IdentityDescriptor {
        kind: IdentityKind::Oidc,
        issuer: Some(ISSUER.parse().unwrap()),
        subject: "sender".into(),
        proof,
        public_key: None,
    }
}

fn ctx<'a>(
    resolver: &'a dyn JwksResolver,
    audience_aid: &'a Aid,
    subject_aid: &'a Aid,
    nonce: &'a str,
    anchors: &'a [RawUrl],
) -> OidcVerifyContext<'a> {
    OidcVerifyContext {
        expected_audience: audience_aid,
        expected_nonce: nonce,
        trust_anchors: anchors,
        jwks_resolver: resolver,
        subject_aid,
        iat_tolerance_secs: 300,
        now_unix_secs: NOW,
    }
}

/// No `kid` on the JWT + exactly one JWKS key ⇒ the fallback selects
/// that key and verification succeeds end-to-end.
#[test]
fn no_kid_single_key_fallback_verifies() {
    let issuer = MockOidcIssuer::new(ISSUER, "kid-A", [0xC1; 32]);
    let sub = subject_key();
    let aud = audience();
    let nonce = "NONCE-nokid-single-01";

    let jwt = issuer.mint_jwt_no_kid(serde_json::json!({
        "iss": ISSUER,
        "sub": "sender",
        "aud": aud.aid().as_str(),
        "iat": NOW,
        "exp": NOW + 3600,
        "nonce": nonce,
        "cnf": { "jkt": jkt_of(&sub) },
    }));

    let resolver = MultiKeyResolver {
        issuer: ISSUER.parse().unwrap(),
        keys: vec![issuer.as_jwk_no_kid()],
    };
    let anchors: Vec<RawUrl> = vec![ISSUER.parse().unwrap()];
    let d = descriptor(jwt);
    verify_oidc(&d, &ctx(&resolver, aud.aid(), sub.aid(), nonce, &anchors))
        .expect("no-kid single-key fallback should verify");
}

/// No `kid` on the JWT + TWO JWKS keys ⇒ the fallback MUST NOT fire; the
/// verifier cannot know which key to use, so selection fails cleanly
/// (it must never silently pick one).
#[test]
fn no_kid_multiple_keys_rejected() {
    let issuer = MockOidcIssuer::new(ISSUER, "kid-A", [0xC1; 32]);
    let other = MockOidcIssuer::new(ISSUER, "kid-B", [0xC2; 32]);
    let sub = subject_key();
    let aud = audience();
    let nonce = "NONCE-nokid-multi-01";

    let jwt = issuer.mint_jwt_no_kid(serde_json::json!({
        "iss": ISSUER,
        "sub": "sender",
        "aud": aud.aid().as_str(),
        "iat": NOW,
        "exp": NOW + 3600,
        "nonce": nonce,
        "cnf": { "jkt": jkt_of(&sub) },
    }));

    // Two keys with DISTINCT concrete kids: a no-kid JWT matches neither
    // by kid, and the single-key fallback does not fire (len == 2), so
    // selection must fail rather than silently pick one.
    let resolver = MultiKeyResolver {
        issuer: ISSUER.parse().unwrap(),
        keys: vec![issuer.as_jwk(), other.as_jwk()],
    };
    let anchors: Vec<RawUrl> = vec![ISSUER.parse().unwrap()];
    let d = descriptor(jwt);
    let err = verify_oidc(&d, &ctx(&resolver, aud.aid(), sub.aid(), nonce, &anchors)).unwrap_err();
    assert!(
        matches!(err, HandshakeError::Identity(ref s) if s.contains("no matching JWK")),
        "no-kid + multi-key must fail selection, got {err:?}"
    );
}

/// A JWT naming a `kid` the JWKS no longer serves (rotated out) MUST be
/// rejected — the verifier must not fall back to some other key.
#[test]
fn kid_not_in_jwks_rejected_even_with_single_key() {
    // JWT signed by an issuer advertising `kid-OLD`, but the JWKS only
    // serves `kid-NEW` (rotation).
    let old = MockOidcIssuer::new(ISSUER, "kid-OLD", [0xC1; 32]);
    let new = MockOidcIssuer::new(ISSUER, "kid-NEW", [0xC3; 32]);
    let sub = subject_key();
    let aud = audience();
    let nonce = "NONCE-rotated-01";

    let jwt = old.mint_jwt(serde_json::json!({
        "iss": ISSUER,
        "sub": "sender",
        "aud": aud.aid().as_str(),
        "iat": NOW,
        "exp": NOW + 3600,
        "nonce": nonce,
        "cnf": { "jkt": jkt_of(&sub) },
    }));

    // Only the NEW key is served — and it has a concrete kid, so the
    // no-kid single-key fallback does not apply to a kid-bearing JWT.
    let resolver = MultiKeyResolver {
        issuer: ISSUER.parse().unwrap(),
        keys: vec![new.as_jwk()],
    };
    let anchors: Vec<RawUrl> = vec![ISSUER.parse().unwrap()];
    let d = descriptor(jwt);
    let err = verify_oidc(&d, &ctx(&resolver, aud.aid(), sub.aid(), nonce, &anchors)).unwrap_err();
    assert!(
        matches!(err, HandshakeError::Identity(ref s) if s.contains("no matching JWK")),
        "rotated-out kid must fail selection, got {err:?}"
    );
}
