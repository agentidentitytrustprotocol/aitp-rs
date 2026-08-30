//! `verify_oidc` issuer-key-resolution error mapping (RFC-AITP-0001
//! §5.4.3, RFC-AITP-0007 §3).
//!
//! The issuer's key being unresolvable at all (JWKS fetch failed, or
//! resolution succeeded but produced zero candidate keys) is a
//! distinct, *retryable* failure mode from a resolved-but-non-matching
//! key (bad `kid`/`alg`) or an invalid proof. The former MUST map to
//! `HandshakeError::KeyResolutionFailed` (wire code
//! `KEY_RESOLUTION_FAILED`); the latter stays
//! `HandshakeError::Identity` (wire code `IDENTITY_FAILED`).

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

/// A resolver that always fails to reach the issuer's JWKS endpoint —
/// simulates the JWKS fetch/network-failure case from RFC-AITP-0007 §3.
struct FailingResolver {
    issuer: Url,
}

impl JwksResolver for FailingResolver {
    fn resolve(&self, issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        if issuer == &self.issuer {
            Err(ResolveError::NetworkError(
                "connection to JWKS endpoint timed out".into(),
            ))
        } else {
            Err(ResolveError::NotTrusted(issuer.clone()))
        }
    }
}

/// A resolver that reaches the issuer successfully but has zero keys
/// on file for it — e.g. no pinned/well-known fallback entry exists.
struct EmptyResolver {
    issuer: Url,
}

impl JwksResolver for EmptyResolver {
    fn resolve(&self, issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        if issuer == &self.issuer {
            Ok(vec![])
        } else {
            Err(ResolveError::NotTrusted(issuer.clone()))
        }
    }
}

/// Resolver returning a fixed, non-empty key list for the issuer —
/// used for the regression case where candidates exist but the
/// token's `kid` doesn't match any of them.
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

fn mint_valid_jwt(
    issuer: &MockOidcIssuer,
    sub: &AitpSigningKey,
    aud: &AitpSigningKey,
    nonce: &str,
) -> String {
    issuer.mint_jwt(serde_json::json!({
        "iss": ISSUER,
        "sub": "sender",
        "aud": aud.aid().as_str(),
        "iat": NOW,
        "exp": NOW + 3600,
        "nonce": nonce,
        "cnf": { "jkt": jkt_of(sub) },
    }))
}

/// The JWKS resolver returns a hard error (network failure, malformed
/// body, etc.) — the issuer's key could not be reached at all. Must
/// surface as the retryable `KeyResolutionFailed`, not `Identity`.
#[test]
fn resolver_error_maps_to_key_resolution_failed() {
    let issuer = MockOidcIssuer::new(ISSUER, "kid-A", [0xC1; 32]);
    let sub = subject_key();
    let aud = audience();
    let nonce = "NONCE-resolve-err-01";

    let jwt = mint_valid_jwt(&issuer, &sub, &aud, nonce);

    let resolver = FailingResolver {
        issuer: ISSUER.parse().unwrap(),
    };
    let anchors: Vec<RawUrl> = vec![ISSUER.parse().unwrap()];
    let d = descriptor(jwt);
    let err = verify_oidc(&d, &ctx(&resolver, aud.aid(), sub.aid(), nonce, &anchors)).unwrap_err();
    match &err {
        HandshakeError::KeyResolutionFailed { issuer, reason } => {
            assert_eq!(issuer, ISSUER);
            assert!(
                reason.contains("timed out"),
                "reason should carry the underlying ResolveError, got {reason:?}"
            );
        }
        other => panic!("expected KeyResolutionFailed, got {other:?}"),
    }
}

/// The resolver reaches the issuer but has zero candidate keys on
/// file for it. This is "no key available" in effect, so it gets the
/// same retryable treatment as an outright resolver error.
#[test]
fn zero_candidates_maps_to_key_resolution_failed() {
    let issuer = MockOidcIssuer::new(ISSUER, "kid-A", [0xC1; 32]);
    let sub = subject_key();
    let aud = audience();
    let nonce = "NONCE-empty-01";

    let jwt = mint_valid_jwt(&issuer, &sub, &aud, nonce);

    let resolver = EmptyResolver {
        issuer: ISSUER.parse().unwrap(),
    };
    let anchors: Vec<RawUrl> = vec![ISSUER.parse().unwrap()];
    let d = descriptor(jwt);
    let err = verify_oidc(&d, &ctx(&resolver, aud.aid(), sub.aid(), nonce, &anchors)).unwrap_err();
    assert!(
        matches!(err, HandshakeError::KeyResolutionFailed { ref issuer, .. } if issuer == ISSUER),
        "zero resolved candidates must be KeyResolutionFailed, got {err:?}"
    );
}

/// Regression: candidates DO exist for the issuer, but none match the
/// token's `kid`. This remains `Identity` (not retryable) — the proof
/// itself is what's wrong, not the resolution process. Overcorrecting
/// this into `KeyResolutionFailed` would make an attacker-controlled
/// `kid` field retry-bait.
#[test]
fn kid_mismatch_with_candidates_present_stays_identity() {
    let old = MockOidcIssuer::new(ISSUER, "kid-OLD", [0xC1; 32]);
    let new = MockOidcIssuer::new(ISSUER, "kid-NEW", [0xC3; 32]);
    let sub = subject_key();
    let aud = audience();
    let nonce = "NONCE-kid-mismatch-01";

    let jwt = mint_valid_jwt(&old, &sub, &aud, nonce);

    // Only the NEW key is served — a concrete (non-empty) candidate
    // set exists, it just doesn't contain a match for the JWT's kid.
    let resolver = MultiKeyResolver {
        issuer: ISSUER.parse().unwrap(),
        keys: vec![new.as_jwk()],
    };
    let anchors: Vec<RawUrl> = vec![ISSUER.parse().unwrap()];
    let d = descriptor(jwt);
    let err = verify_oidc(&d, &ctx(&resolver, aud.aid(), sub.aid(), nonce, &anchors)).unwrap_err();
    assert!(
        matches!(err, HandshakeError::Identity(ref s) if s.contains("no matching JWK")),
        "kid mismatch with non-empty candidates must stay Identity, got {err:?}"
    );
}
