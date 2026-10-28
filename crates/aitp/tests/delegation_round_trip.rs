//! End-to-end single-hop delegation: A issues B a TCT + voucher; B
//! delegates a subset to C; A verifies — plus the RFC-AITP-0006 §4
//! rejection matrix.

use aitp::core::{Aid, Timestamp, PROTOCOL_VERSION};
use aitp::crypto::{jws, AitpSigningKey, CryptoError};
use aitp::delegation::{
    verify_delegation, DelegationBuilder, DelegationError, DelegationVerifyContext,
};
use aitp::manifest::{Manifest, ManifestError};
use aitp::tct::{
    RevocationQuery, RevocationSource, RevocationStatus, RevocationUnavailable, TctBuilder,
};
use std::collections::HashMap;
use std::sync::OnceLock;
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

#[path = "delegation_common/mod.rs"]
mod common;

/// B's published Manifest: the single-hop delegator's key source
/// (RFC-AITP-0006 §4 step 1).
fn issuer_manifests() -> &'static Vec<Manifest> {
    static MANIFESTS: OnceLock<Vec<Manifest>> = OnceLock::new();
    MANIFESTS.get_or_init(|| vec![common::manifest_for(&b(), NOW)])
}

fn verify_ctx(verifier: &Aid, now: Timestamp) -> DelegationVerifyContext<'_> {
    common::verify_ctx(verifier, now, issuer_manifests())
}

fn a() -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&[0xA1; 32])
}
fn b() -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&[0xB1; 32])
}
fn c() -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&[0xC1; 32])
}

/// A → B: TCT + voucher with two grants, 2h TTL.
fn voucher_for_b() -> String {
    TctBuilder::new(&a())
        .subject(b().aid().clone())
        .audience(b().aid().clone())
        .grants(["read_data", "write_data"])
        .ttl(std::time::Duration::from_secs(7200))
        .subject_pubkey(b().verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
        .voucher()
        .unwrap()
        .to_string()
}

/// B → C: delegate `read_data`, 1h TTL.
fn delegate_to_c(voucher: &str) -> String {
    DelegationBuilder::new(&b(), voucher)
        .unwrap()
        .delegatee(c().aid().clone())
        .scope(["read_data"])
        .ttl(std::time::Duration::from_secs(3600))
        .now(NOW)
        .build()
        .unwrap()
        .into_parts()
        .token
}

#[test]
fn happy_path_round_trip() {
    let token = delegate_to_c(&voucher_for_b());
    let a_key = a();
    let ctx = verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60));
    let verified = verify_delegation(&token, &ctx).expect("delegation verifies");
    assert_eq!(verified.claims().iss, *b().aid());
    assert_eq!(verified.claims().sub, *c().aid());
    assert_eq!(verified.claims().scope, vec!["read_data".to_string()]);
    assert_eq!(verified.claims().ver, PROTOCOL_VERSION);
    assert_eq!(verified.voucher().sub, *b().aid());
    assert_eq!(verified.voucher().grants.len(), 2);
}

#[test]
fn issued_delegation_carries_the_claims_its_token_signs() {
    let voucher = voucher_for_b();
    let issued = DelegationBuilder::new(&b(), &voucher)
        .unwrap()
        .delegatee(c().aid().clone())
        .scope(["read_data"])
        .now(NOW)
        .build()
        .unwrap();
    let a_key = a();
    let ctx = verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60));
    let verified = verify_delegation(issued.token(), &ctx).unwrap();
    assert_eq!(verified.claims(), issued.claims());
    assert_eq!(issued.claims().voucher.as_deref(), Some(voucher.as_str()));
    let parts = issued.clone().into_parts();
    assert_eq!(parts.token, issued.token());
    assert_eq!(&parts.claims, issued.claims());
}

#[test]
fn builder_rejects_voucher_for_someone_else() {
    // C cannot delegate against B's voucher.
    let voucher = voucher_for_b();
    let b_key = c();
    let err = match DelegationBuilder::new(&b_key, &voucher) {
        Err(e) => e,
        Ok(_) => panic!("voucher for B must not be usable by C"),
    };
    assert!(matches!(err, DelegationError::InvalidVoucher));
}

#[test]
fn builder_rejects_scope_outside_voucher() {
    let err = DelegationBuilder::new(&b(), &voucher_for_b())
        .unwrap()
        .delegatee(c().aid().clone())
        .scope(["admin"])
        .now(NOW)
        .build()
        .unwrap_err();
    assert!(matches!(err, DelegationError::ScopeExceeded));
}

#[test]
fn builder_rejects_self_delegation() {
    let err = DelegationBuilder::new(&b(), &voucher_for_b())
        .unwrap()
        .delegatee(b().aid().clone())
        .scope(["read_data"])
        .now(NOW)
        .build()
        .unwrap_err();
    assert!(matches!(err, DelegationError::SelfDelegation));
}

#[test]
fn builder_caps_expiry_at_voucher() {
    let token = DelegationBuilder::new(&b(), &voucher_for_b())
        .unwrap()
        .delegatee(c().aid().clone())
        .scope(["read_data"])
        .ttl(std::time::Duration::from_secs(999_999)) // way past the voucher's 2h
        .now(NOW)
        .build()
        .unwrap()
        .into_parts()
        .token;
    let a_key = a();
    let ctx = verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60));
    let verified = verify_delegation(&token, &ctx).unwrap();
    assert_eq!(
        verified.claims().exp.0,
        NOW.0 + 7200,
        "capped at voucher exp"
    );
}

#[test]
fn missing_voucher_rejected() {
    // Hand-mint a single-hop token with no voucher claim.
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 3600,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint_sha256().unwrap() },
    });
    let token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    let ctx = verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60));
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::InvalidVoucher
    ));
}

#[test]
fn voucher_issued_by_third_party_rejected() {
    // B embeds a voucher minted by some other agent (not the verifier):
    // verification under A's own key fails.
    let mallory = AitpSigningKey::from_ed25519_seed(&[0xD1; 32]);
    let foreign_voucher = TctBuilder::new(&mallory)
        .subject(b().aid().clone())
        .audience(b().aid().clone())
        .grants(["read_data"])
        .ttl(std::time::Duration::from_secs(7200))
        .subject_pubkey(b().verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
        .into_parts()
        .voucher
        .unwrap();
    // Hand-mint with aud = A (the builder would derive aud from the
    // foreign voucher's issuer and die on the audience check instead).
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 600,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint_sha256().unwrap() },
        "voucher": foreign_voucher,
    });
    let token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    let ctx = verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60));
    let err = verify_delegation(&token, &ctx).unwrap_err();
    // Dies verifying the voucher signature under A's own key.
    assert!(
        matches!(
            err,
            DelegationError::InvalidVoucher
                | DelegationError::Crypto(CryptoError::SignatureInvalid)
        ),
        "got {err:?}"
    );
}

#[test]
fn voucher_subject_mismatch_rejected() {
    // B's voucher embedded in a token issued by Mallory:
    // voucher.sub != outer iss (RFC-AITP-0006 §4 step 4).
    let mallory = AitpSigningKey::from_ed25519_seed(&[0xD2; 32]);
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": mallory.aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 600,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint_sha256().unwrap() },
        "voucher": voucher_for_b(),
    });
    let token = jws::sign_compact(&mallory, jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    // Mallory publishes a valid Manifest, so the check under test is reached.
    let manifests = vec![common::manifest_for(&mallory, NOW)];
    let ctx = common::verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60), &manifests);
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::InvalidVoucher
    ));
}

#[test]
fn audience_mismatch_rejected() {
    let token = delegate_to_c(&voucher_for_b());
    let other = AitpSigningKey::from_ed25519_seed(&[0xD3; 32]);
    let ctx = verify_ctx(other.aid(), Timestamp(NOW.0 + 60));
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::AudienceMismatch
    ));
}

#[test]
fn expired_delegation_rejected() {
    let token = delegate_to_c(&voucher_for_b());
    let a_key = a();
    let ctx = verify_ctx(a_key.aid(), Timestamp(NOW.0 + 4000));
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::Expired
    ));
}

#[test]
fn exp_beyond_voucher_rejected() {
    // Hand-mint exp > voucher.exp (the builder would cap it).
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 7200 + 1,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint_sha256().unwrap() },
        "voucher": voucher_for_b(),
    });
    let token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    let ctx = verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60));
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::Expired
    ));
}

#[test]
fn scope_exceeding_voucher_rejected() {
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data", "admin"],
        "exp": NOW.0 + 600,
        "cnf": { "jkt": c().verifying_key().to_jwk_thumbprint_sha256().unwrap() },
        "voucher": voucher_for_b(),
    });
    let token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    let ctx = verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60));
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::ScopeExceeded
    ));
}

#[test]
fn forged_cnf_jkt_rejected() {
    let rogue = AitpSigningKey::from_ed25519_seed(&[0xD4; 32]);
    let claims = serde_json::json!({
        "ver": PROTOCOL_VERSION,
        "iss": b().aid(),
        "sub": c().aid(),
        "aud": a().aid(),
        "scope": ["read_data"],
        "exp": NOW.0 + 600,
        // jkt of a different key than sub encodes
        "cnf": { "jkt": rogue.verifying_key().to_jwk_thumbprint_sha256().unwrap() },
        "voucher": voucher_for_b(),
    });
    let token = jws::sign_compact(&b(), jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    let ctx = verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60));
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::CnfMalformed
    ));
}

#[test]
fn revoked_source_tct_rejected() {
    let voucher = voucher_for_b();
    let payload = jws::decode_payload_unverified(&voucher).unwrap();
    let voucher_claims: aitp::tct::GrantVoucherClaims = serde_json::from_slice(&payload).unwrap();
    let src = voucher_claims.src_jti;
    let token = delegate_to_c(&voucher);
    let revoked = move |q: &RevocationQuery<'_>| {
        Ok(if *q.jti == src {
            RevocationStatus::Revoked
        } else {
            RevocationStatus::Clear
        })
    };
    let a_key = a();
    let mut ctx = verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60));
    ctx.revocation = RevocationSource::Check(&revoked);
    assert!(matches!(
        verify_delegation(&token, &ctx).unwrap_err(),
        DelegationError::SourceTctRevoked
    ));
}

/// RS1.2: a source that cannot determine status fails closed with a
/// reason distinct from an actually revoked source TCT.
#[test]
fn unavailable_revocation_source_fails_closed() {
    let token = delegate_to_c(&voucher_for_b());
    let unavailable = |_: &RevocationQuery<'_>| Err(RevocationUnavailable::new("no snapshot"));
    let a_key = a();
    let mut ctx = verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60));
    ctx.revocation = RevocationSource::Check(&unavailable);
    let err = verify_delegation(&token, &ctx).unwrap_err();
    assert!(
        matches!(&err, DelegationError::RevocationUnavailable(r) if r.to_string() == "revocation source unavailable: no snapshot"),
        "got {err:?}"
    );
    assert_eq!(
        err.to_string(),
        "revocation source unavailable: no snapshot"
    );
}

#[test]
fn tampered_token_rejected() {
    let mut token = delegate_to_c(&voucher_for_b());
    let last = token.pop().unwrap();
    token.push(if last == 'A' { 'B' } else { 'A' });
    let a_key = a();
    let ctx = verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60));
    let err = verify_delegation(&token, &ctx).unwrap_err();
    // A flipped final character fails either as a bad signature or as
    // non-canonical base64 in the signature segment — both refusals.
    assert!(
        matches!(
            err,
            DelegationError::InvalidSignature
                | DelegationError::Crypto(CryptoError::JwsMalformed(_))
        ),
        "got {err:?}"
    );
}

#[test]
fn tct_presented_as_delegation_rejected() {
    let issued = TctBuilder::new(&a())
        .subject(b().aid().clone())
        .audience(b().aid().clone())
        .grants(["read_data"])
        .ttl(std::time::Duration::from_secs(7200))
        .subject_pubkey(b().verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap();
    let a_key = a();
    let ctx = verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60));
    let err = verify_delegation(issued.token(), &ctx).unwrap_err();
    // `peek_claims` now has a typ-first gate (D7 / issue #140 follow-up),
    // mirroring `aitp::tct::verify_tct`/`verify_voucher`'s established
    // `peek_header_typ` pattern: the TCT's header `typ` (`aitp-tct+jwt`)
    // is peeked and compared against the expected delegation typ
    // (`aitp-delegation+jwt`) before the claim-set check or strict
    // deserialize ever runs, so the outcome is deterministically
    // `TypMismatch` — matching `aitp-verifier-py`'s ordering (typ ahead
    // of unknown-fields) and closing a real cross-impl divergence.
    assert!(
        matches!(
            err,
            DelegationError::Crypto(CryptoError::TypMismatch { .. })
        ),
        "got {err:?}"
    );
}

/// Re-sign B's delegation to C after `edit` changes its claims.
fn resigned_delegation(
    edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) -> String {
    let token = delegate_to_c(&voucher_for_b());
    let payload = jws::decode_payload_unverified(&token).unwrap();
    let mut claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    edit(claims.as_object_mut().unwrap());
    jws::sign_compact(&b(), jws::TYP_DELEGATION, &claims).unwrap()
}

#[test]
fn jti_and_chain_hash_rejected_as_malformed() {
    // RFC-AITP-0011 §1.1: `jti` and `chain_hash` are outside the
    // RFC-AITP-0006 §2 claim set; the value is never inspected.
    let a_key = a();
    let ctx = verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60));
    for (member, value) in [
        ("jti", serde_json::json!(Uuid::new_v4())),
        ("jti", serde_json::json!("not-a-uuid")),
        ("chain_hash", serde_json::json!("AAAA")),
    ] {
        let token = resigned_delegation(|c| {
            c.insert(member.into(), value.clone());
        });
        assert!(
            matches!(
                verify_delegation(&token, &ctx).unwrap_err(),
                DelegationError::ClaimsMalformed(_)
            ),
            "{member}: {value}"
        );
    }
}

#[test]
fn chain_rejected_before_other_claim_checks() {
    // RFC-AITP-0006 §4 multi-hop guard: a `chain` claim is a structural
    // rejection ahead of every other claim check.
    let a_key = a();
    let ctx = verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60));
    let edits: [fn(&mut serde_json::Map<String, serde_json::Value>); 4] = [
        |c| {
            c.insert("chain".into(), serde_json::json!(["x"]));
        },
        |c| {
            c.insert("chain".into(), serde_json::json!([]));
        },
        |c| {
            c.insert("chain".into(), serde_json::json!(["x"]));
            c.insert("jti".into(), serde_json::json!("not-a-uuid"));
        },
        |c| {
            c.insert("chain".into(), serde_json::json!(["x"]));
            c.insert("scope".into(), serde_json::json!(7));
        },
    ];
    for edit in edits {
        let token = resigned_delegation(edit);
        assert!(matches!(
            verify_delegation(&token, &ctx).unwrap_err(),
            DelegationError::MultihopNotSupported
        ));
    }
}

// ─────────────── issuer key from the issuer's Manifest ───────────────
// RFC-AITP-0006 §4 step 1: the outer signature verifies against B's
// public key "resolved from the `iss` AID via B's Manifest", not merely
// the key the AID encodes. A missing or unusable Manifest is
// KEY_RESOLUTION_FAILED (RFC-AITP-0007 §1).

/// Unwrap a `KeyResolutionFailed` for B and return its cause.
fn key_resolution_cause(err: DelegationError) -> ManifestError {
    match err {
        DelegationError::KeyResolutionFailed { issuer, source } => {
            assert_eq!(issuer, *b().aid());
            source
        }
        other => panic!("expected KeyResolutionFailed, got {other:?}"),
    }
}

#[test]
fn verifies_under_issuer_manifest_key() {
    let token = delegate_to_c(&voucher_for_b());
    let a_key = a();
    // Unrelated Manifests alongside B's do not get in the way.
    let manifests = vec![
        common::manifest_for(&c(), NOW),
        common::manifest_for(&b(), NOW),
    ];
    let ctx = common::verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60), &manifests);
    let verified = verify_delegation(&token, &ctx).expect("verifies under B's Manifest key");
    assert_eq!(verified.claims().iss, *b().aid());
}

#[test]
fn no_manifest_source_rejected() {
    // No source configured fails closed: the AID-embedded key alone
    // MUST NOT verify the token.
    let token = delegate_to_c(&voucher_for_b());
    let a_key = a();
    let ctx = DelegationVerifyContext::new(
        a_key.aid(),
        Timestamp(NOW.0 + 60),
        RevocationSource::FailOpen,
    );
    let cause = key_resolution_cause(verify_delegation(&token, &ctx).unwrap_err());
    assert!(matches!(cause, ManifestError::NotFound), "got {cause:?}");
}

#[test]
fn issuer_manifest_missing_rejected() {
    // A source is configured, but it holds no Manifest for B.
    let token = delegate_to_c(&voucher_for_b());
    let a_key = a();
    let manifests = vec![common::manifest_for(&c(), NOW)];
    let ctx = common::verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60), &manifests);
    let cause = key_resolution_cause(verify_delegation(&token, &ctx).unwrap_err());
    assert!(matches!(cause, ManifestError::NotFound), "got {cause:?}");
}

#[test]
fn key_not_designated_by_issuer_manifest_rejected() {
    // The token is signed by the key B's AID encodes, but the Manifest
    // served for B designates a different (rotated, RFC-AITP-0003 §8.1)
    // key.
    let token = delegate_to_c(&voucher_for_b());
    let rotated_b = AitpSigningKey::from_ed25519_seed(&[0xB2; 32]);
    let resolver: HashMap<Aid, Manifest> =
        HashMap::from([(b().aid().clone(), common::manifest_for(&rotated_b, NOW))]);
    let a_key = a();
    let ctx = DelegationVerifyContext::new(
        a_key.aid(),
        Timestamp(NOW.0 + 60),
        RevocationSource::FailOpen,
    )
    .with_issuer_manifests(&resolver);
    let cause = key_resolution_cause(verify_delegation(&token, &ctx).unwrap_err());
    assert!(matches!(cause, ManifestError::AidMismatch), "got {cause:?}");
}

#[test]
fn issuer_manifest_must_verify() {
    let token = delegate_to_c(&voucher_for_b());
    let a_key = a();
    // Forged: B's Manifest body altered after signing.
    let mut forged = common::manifest_for(&b(), NOW);
    forged.display_name = Some("not what B signed".into());
    let manifests = vec![forged];
    let ctx = common::verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60), &manifests);
    let cause = key_resolution_cause(verify_delegation(&token, &ctx).unwrap_err());
    assert!(
        matches!(cause, ManifestError::SignatureInvalid),
        "got {cause:?}"
    );
    // Expired: B's Manifest lapsed before the verification time.
    let manifests = vec![common::manifest_for(&b(), NOW)];
    let ctx = common::verify_ctx(a_key.aid(), Timestamp(NOW.0 + 86_401), &manifests);
    let cause = key_resolution_cause(verify_delegation(&token, &ctx).unwrap_err());
    assert!(matches!(cause, ManifestError::Expired), "got {cause:?}");
}

#[test]
fn signed_by_key_other_than_issuer_manifest_key_is_invalid_signature() {
    // B's Manifest resolves, but the token claiming `iss = B` was signed
    // by someone else: DELEGATION_INVALID_SIGNATURE.
    let payload = jws::decode_payload_unverified(&delegate_to_c(&voucher_for_b())).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    let mallory = AitpSigningKey::from_ed25519_seed(&[0xE1; 32]);
    let forged = jws::sign_compact(&mallory, jws::TYP_DELEGATION, &claims).unwrap();
    let a_key = a();
    let err =
        verify_delegation(&forged, &verify_ctx(a_key.aid(), Timestamp(NOW.0 + 60))).unwrap_err();
    assert!(
        matches!(err, DelegationError::InvalidSignature),
        "got {err:?}"
    );
}
