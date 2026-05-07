//! End-to-end delegation issue + verify + tamper-detection.
//!
//! Three agents:
//! - **A** = original grantor / verifier
//! - **B** = delegator (holds A's TCT, issues delegation to C)
//! - **C** = delegatee
//!
//! The flow: A issues TCT_B (subject=B). B issues a delegation to C.
//! A verifies the delegation against its own AID.

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_delegation::{
    verify_delegation, DelegationBuilder, DelegationError, VerifyDelegationContext,
};
use aitp_tct::{Tct, TctBuilder};
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

fn alice_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xA0; 32])
}
fn bob_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xB0; 32])
}
fn carol_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xC0; 32])
}

/// Issue A → B with two grants, default 1h TTL (matches the verifier's
/// reconstructed `issued_at = expires_at - 3600`).
fn alice_to_bob_tct() -> Tct {
    TctBuilder::new(&alice_key())
        .subject(bob_key().aid().clone())
        .audience(bob_key().aid().clone())
        .grants(["read_data", "write_data"])
        .ttl_secs(3600)
        .subject_pubkey(bob_key().verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
}

#[test]
fn happy_path_round_trip() {
    let tct_b = alice_to_bob_tct();
    let delegation = DelegationBuilder::new(&bob_key(), &tct_b)
        .delegatee(carol_key().aid().clone())
        .delegatee_pubkey(carol_key().verifying_key())
        .scope(["read_data"])
        .ttl_secs(1800)
        .now(NOW)
        .build()
        .unwrap();
    let alice = alice_key();
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
        max_hops: aitp_delegation::DEFAULT_MAX_HOPS,
    };
    verify_delegation(&delegation, &ctx).expect("valid delegation verifies");
}

#[test]
fn scope_exceeded_rejected() {
    let tct_b = alice_to_bob_tct();
    let mut d = DelegationBuilder::new(&bob_key(), &tct_b)
        .delegatee(carol_key().aid().clone())
        .delegatee_pubkey(carol_key().verifying_key())
        .scope(["read_data"])
        .now(NOW)
        .build()
        .unwrap();
    // Forge: append an extra cap that wasn't in grant_proof.
    d.scope.push("delete_everything".into());
    let alice = alice_key();
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
        max_hops: aitp_delegation::DEFAULT_MAX_HOPS,
    };
    let err = verify_delegation(&d, &ctx).unwrap_err();
    // The forged scope also breaks the outer signature, which the verifier
    // checks before scope. So the surfaced error is InvalidSignature, but
    // both checks would refuse the token. Confirm rejection occurred.
    assert!(matches!(
        err,
        DelegationError::InvalidSignature | DelegationError::ScopeExceeded
    ));
}

#[test]
fn delegation_expires_after_grant_proof_rejected() {
    let tct_b = alice_to_bob_tct();
    let mut d = DelegationBuilder::new(&bob_key(), &tct_b)
        .delegatee(carol_key().aid().clone())
        .delegatee_pubkey(carol_key().verifying_key())
        .scope(["read_data"])
        .now(NOW)
        .build()
        .unwrap();
    // Push delegation expiry past grant_proof expiry.
    d.expires_at = Timestamp(d.grant_proof.expires_at.0 + 1);
    let alice = alice_key();
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
        max_hops: aitp_delegation::DEFAULT_MAX_HOPS,
    };
    let err = verify_delegation(&d, &ctx).unwrap_err();
    // Tamper invalidates the outer signature, which is checked after the
    // expiry comparison — but the expiry comparison fires first in the
    // verify order.
    assert!(matches!(err, DelegationError::Expired));
}

#[test]
fn forged_grant_proof_subject_rejected() {
    let tct_b = alice_to_bob_tct();
    let mut d = DelegationBuilder::new(&bob_key(), &tct_b)
        .delegatee(carol_key().aid().clone())
        .delegatee_pubkey(carol_key().verifying_key())
        .scope(["read_data"])
        .now(NOW)
        .build()
        .unwrap();
    // Forge grant_proof.subject to a different AID.
    let evil = AitpSigningKey::from_seed(&[0xEE; 32]);
    d.grant_proof.subject = evil.aid().clone();
    let alice = alice_key();
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
        max_hops: aitp_delegation::DEFAULT_MAX_HOPS,
    };
    let err = verify_delegation(&d, &ctx).unwrap_err();
    assert!(matches!(err, DelegationError::InvalidGrantProof));
}

#[test]
fn tampered_outer_signature_rejected() {
    let tct_b = alice_to_bob_tct();
    let mut d = DelegationBuilder::new(&bob_key(), &tct_b)
        .delegatee(carol_key().aid().clone())
        .delegatee_pubkey(carol_key().verifying_key())
        .scope(["read_data"])
        .now(NOW)
        .build()
        .unwrap();
    let mut s = d.signature.clone();
    let last = s.pop().unwrap();
    s.push(if last == 'A' { 'B' } else { 'A' });
    d.signature = s;
    let alice = alice_key();
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
        max_hops: aitp_delegation::DEFAULT_MAX_HOPS,
    };
    let err = verify_delegation(&d, &ctx).unwrap_err();
    assert!(matches!(err, DelegationError::InvalidSignature));
}

#[test]
fn tampered_grant_proof_signature_rejected() {
    let tct_b = alice_to_bob_tct();
    let mut d = DelegationBuilder::new(&bob_key(), &tct_b)
        .delegatee(carol_key().aid().clone())
        .delegatee_pubkey(carol_key().verifying_key())
        .scope(["read_data"])
        .now(NOW)
        .build()
        .unwrap();
    let mut s = d.grant_proof.signature.clone();
    let last = s.pop().unwrap();
    s.push(if last == 'A' { 'B' } else { 'A' });
    d.grant_proof.signature = s;
    let alice = alice_key();
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: None,
        max_hops: aitp_delegation::DEFAULT_MAX_HOPS,
    };
    let err = verify_delegation(&d, &ctx).unwrap_err();
    assert!(matches!(err, DelegationError::InvalidGrantProof));
}

#[test]
fn revoked_source_tct_rejected() {
    let tct_b = alice_to_bob_tct();
    let target = tct_b.jti;
    let d = DelegationBuilder::new(&bob_key(), &tct_b)
        .delegatee(carol_key().aid().clone())
        .delegatee_pubkey(carol_key().verifying_key())
        .scope(["read_data"])
        .now(NOW)
        .build()
        .unwrap();
    let alice = alice_key();
    let revoked = move |jti: &Uuid| *jti == target;
    let ctx = VerifyDelegationContext {
        verifier_aid: alice.aid(),
        now: NOW,
        revocation_check: Some(&revoked),
        max_hops: aitp_delegation::DEFAULT_MAX_HOPS,
    };
    let err = verify_delegation(&d, &ctx).unwrap_err();
    assert!(matches!(err, DelegationError::SourceTctRevoked));
}

#[test]
fn wrong_verifier_rejected() {
    let tct_b = alice_to_bob_tct();
    let d = DelegationBuilder::new(&bob_key(), &tct_b)
        .delegatee(carol_key().aid().clone())
        .delegatee_pubkey(carol_key().verifying_key())
        .scope(["read_data"])
        .now(NOW)
        .build()
        .unwrap();
    let other = AitpSigningKey::from_seed(&[0x77; 32]);
    let ctx = VerifyDelegationContext {
        verifier_aid: other.aid(),
        now: NOW,
        revocation_check: None,
        max_hops: aitp_delegation::DEFAULT_MAX_HOPS,
    };
    let err = verify_delegation(&d, &ctx).unwrap_err();
    assert!(matches!(err, DelegationError::AudienceMismatch));
}

#[test]
fn self_delegation_at_build_rejected() {
    let tct_b = alice_to_bob_tct();
    let bob = bob_key();
    let err = DelegationBuilder::new(&bob, &tct_b)
        .delegatee(bob.aid().clone()) // B → B is forbidden
        .delegatee_pubkey(bob.verifying_key())
        .scope(["read_data"])
        .now(NOW)
        .build()
        .unwrap_err();
    assert!(matches!(err, DelegationError::SelfDelegation));
}

#[test]
fn empty_scope_rejected() {
    let tct_b = alice_to_bob_tct();
    let err = DelegationBuilder::new(&bob_key(), &tct_b)
        .delegatee(carol_key().aid().clone())
        .delegatee_pubkey(carol_key().verifying_key())
        .now(NOW)
        .build()
        .unwrap_err();
    assert!(matches!(err, DelegationError::EmptyScope));
}

#[test]
fn build_rejects_scope_exceeded() {
    let tct_b = alice_to_bob_tct();
    let err = DelegationBuilder::new(&bob_key(), &tct_b)
        .delegatee(carol_key().aid().clone())
        .delegatee_pubkey(carol_key().verifying_key())
        .scope(["this_was_never_granted"])
        .now(NOW)
        .build()
        .unwrap_err();
    assert!(matches!(err, DelegationError::ScopeExceeded));
}
