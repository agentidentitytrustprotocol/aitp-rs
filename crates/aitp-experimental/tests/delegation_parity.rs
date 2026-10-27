//! A single-hop delegation (RFC-AITP-0006) verifies the same way under
//! the stable `aitp::delegation::verify_delegation` and the multi-hop
//! `verify_chained_delegation`: the same claims on success, the same
//! `DelegationError` variant on failure.

use aitp::core::{Aid, Timestamp};
use aitp::crypto::{jws, AitpSigningKey};
use aitp::delegation::{
    verify_delegation, DelegationBuilder, DelegationError, DelegationRevocation,
    VerifyDelegationContext,
};
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder};
use aitp::tct::TctBuilder;
use aitp_experimental::delegation::{
    verify_chained_delegation, ChainedDelegationError, VerifyChainContext,
};

const NOW: Timestamp = Timestamp(1_700_000_000);

fn a() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xA2; 32])
}
fn b() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xB2; 32])
}
fn c() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xC2; 32])
}

fn manifests() -> Vec<Manifest> {
    vec![ManifestBuilder::new(&b())
        .handshake_endpoint("https://agent.example.com/aitp/handshake".parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityHintKind::Oidc, "agent")
                .with_issuer("https://idp.example.com".parse().unwrap()),
        )
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .published_at(NOW)
        .ttl_secs(86_400)
        .build()
        .unwrap()]
}

fn token(scope: &[&str], ttl: i64) -> String {
    let voucher = TctBuilder::new(&a())
        .subject(b().aid().clone())
        .audience(b().aid().clone())
        .grants(["read_data", "write_data"])
        .ttl_secs(7200)
        .subject_pubkey(b().verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
        .voucher
        .unwrap();
    DelegationBuilder::new(&b(), &voucher)
        .unwrap()
        .delegatee(c().aid().clone())
        .scope(scope.iter().copied())
        .ttl_secs(ttl)
        .now(NOW)
        .build()
        .unwrap()
}

/// Verify `token` with both verifiers as `verifier` at `now`, and return
/// the stable verifier's outcome after checking the two agree.
fn both(token: &str, verifier: &Aid, now: Timestamp) -> Result<Vec<String>, String> {
    let manifests = manifests();
    let stable = verify_delegation(
        token,
        &VerifyDelegationContext::new(verifier, now, DelegationRevocation::FailOpen)
            .with_issuer_manifests(&manifests),
    );
    let chained = verify_chained_delegation(
        token,
        &VerifyChainContext::new(verifier, now, DelegationRevocation::FailOpen)
            .with_issuer_manifests(&manifests),
    );
    match (stable, chained) {
        (Ok(s), Ok(c)) => {
            assert_eq!(s.token, c.token);
            assert_eq!(
                (&s.claims.iss, &s.claims.sub, &s.claims.aud),
                (&c.claims.iss, &c.claims.sub, &c.claims.aud)
            );
            assert_eq!(
                (&s.claims.scope, s.claims.exp),
                (&c.claims.scope, c.claims.exp)
            );
            assert_eq!(s.claims.cnf.jkt, c.claims.cnf.jkt);
            assert_eq!(s.voucher, c.voucher);
            Ok(s.claims.scope)
        }
        (Err(s), Err(ChainedDelegationError::Delegation(c))) => {
            assert_eq!(
                std::mem::discriminant(&s),
                std::mem::discriminant(&c),
                "stable {s:?} vs chained {c:?}"
            );
            Err(format!("{s:?}"))
        }
        (s, c) => panic!("verifiers disagree: stable {s:?}, chained {c:?}"),
    }
}

#[test]
fn single_hop_verifies_identically() {
    let scope = both(
        &token(&["read_data"], 600),
        a().aid(),
        Timestamp(NOW.0 + 60),
    )
    .unwrap();
    assert_eq!(scope, vec!["read_data".to_string()]);
}

#[test]
fn single_hop_rejections_agree() {
    let t = token(&["read_data"], 600);
    // Expired.
    both(&t, a().aid(), Timestamp(NOW.0 + 3600)).unwrap_err();
    // Wrong verifier: the voucher was not issued by it.
    both(&t, c().aid(), Timestamp(NOW.0 + 60)).unwrap_err();
    // Bad signature.
    let payload = jws::decode_payload_unverified(&t).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    let forged = jws::sign_compact(&c(), jws::TYP_DELEGATION, &claims).unwrap();
    let err = both(&forged, a().aid(), Timestamp(NOW.0 + 60)).unwrap_err();
    assert_eq!(err, format!("{:?}", DelegationError::InvalidSignature));
}
