//! Property tests for single-hop delegation attenuation invariants
//! (RFC-AITP-0006 §4).
//!
//! The core delegation guarantee is that a delegate can only ever
//! receive a **subset** of the grants the voucher carries, and that a
//! verified delegation's expiry never exceeds the voucher's. These
//! invariants must hold for arbitrary grant sets and scopes, not just
//! the hand-picked round-trip cases — so we drive them with proptest.

use std::collections::BTreeSet;

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_delegation::{
    verify_delegation, DelegationBuilder, DelegationError, VerifyDelegationContext,
};
use aitp_tct::TctBuilder;
use proptest::prelude::*;

const NOW: Timestamp = Timestamp(1_700_000_000);

fn a() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xA1; 32])
}
fn b() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xB1; 32])
}
fn c() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xC1; 32])
}

/// A → B voucher carrying `grants`, 2h TTL.
fn voucher_for_b(grants: &BTreeSet<String>) -> String {
    TctBuilder::new(&a())
        .subject(b().aid().clone())
        .audience(b().aid().clone())
        .grants(grants.iter().cloned())
        .ttl_secs(7200)
        .subject_pubkey(b().verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
        .voucher
        .unwrap()
}

/// Non-empty grant tokens from a small alphabet so subsets/supersets
/// overlap meaningfully across cases.
fn grant() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "read", "write", "delete", "admin", "list", "share", "exec", "audit",
    ])
    .prop_map(String::from)
}

fn grant_set(max: usize) -> impl Strategy<Value = BTreeSet<String>> {
    prop::collection::btree_set(grant(), 1..=max)
}

proptest! {
    /// Any scope that is a subset of the voucher grants verifies, and
    /// the verified scope is exactly what was requested.
    #[test]
    fn subset_scope_always_verifies(
        grants in grant_set(8),
        // A fraction to pick a subset from the sorted grant vec.
        picks in prop::collection::vec(any::<bool>(), 8),
    ) {
        let grant_vec: Vec<String> = grants.iter().cloned().collect();
        let scope: BTreeSet<String> = grant_vec
            .iter()
            .zip(picks.iter().cycle())
            .filter(|(_, &keep)| keep)
            .map(|(g, _)| g.clone())
            .collect();
        // A delegation must carry at least one grant.
        prop_assume!(!scope.is_empty());

        let voucher = voucher_for_b(&grants);
        let token = DelegationBuilder::new(&b(), &voucher)
            .unwrap()
            .delegatee(c().aid().clone())
            .scope(scope.iter().cloned())
            .ttl_secs(3600)
            .now(NOW)
            .build()
            .expect("subset scope must build");

        let a_key = a();
        let ctx = VerifyDelegationContext::new(a_key.aid(), Timestamp(NOW.0 + 60));
        let verified = verify_delegation(&token, &ctx).expect("subset delegation verifies");
        let got: BTreeSet<String> = verified.claims.scope.into_iter().collect();
        prop_assert_eq!(got, scope);
    }

    /// Any scope containing a grant NOT in the voucher is rejected at
    /// build time — there is no way to widen grants through delegation.
    #[test]
    fn superset_scope_always_rejected(
        grants in grant_set(6),
        extra in grant(),
    ) {
        prop_assume!(!grants.contains(&extra));
        let voucher = voucher_for_b(&grants);

        // scope = all voucher grants + one extra the voucher lacks.
        let mut scope: Vec<String> = grants.iter().cloned().collect();
        scope.push(extra);

        let result = DelegationBuilder::new(&b(), &voucher)
            .unwrap()
            .delegatee(c().aid().clone())
            .scope(scope)
            .now(NOW)
            .build();
        prop_assert!(matches!(result, Err(DelegationError::ScopeExceeded)));
    }

    /// A verified delegation's expiry never exceeds the voucher's
    /// expiry, regardless of the requested TTL (monotonic attenuation
    /// of lifetime).
    #[test]
    fn delegation_expiry_never_exceeds_voucher(
        grants in grant_set(4),
        ttl in 1i64..100_000,
    ) {
        let voucher = voucher_for_b(&grants);
        let scope: Vec<String> = grants.iter().take(1).cloned().collect();
        let token = DelegationBuilder::new(&b(), &voucher)
            .unwrap()
            .delegatee(c().aid().clone())
            .scope(scope)
            .ttl_secs(ttl)
            .now(NOW)
            .build()
            .expect("single-grant delegation builds");

        // Verify at issuance time NOW: the delegation is valid for
        // [NOW, NOW+ttl] with ttl >= 1, so NOW is always inside the
        // window regardless of the (possibly tiny) sampled ttl.
        let a_key = a();
        let ctx = VerifyDelegationContext::new(a_key.aid(), NOW);
        let verified = verify_delegation(&token, &ctx).expect("delegation verifies");
        // Voucher TTL is 7200s from NOW; delegation exp must not exceed it.
        prop_assert!(verified.claims.exp.0 <= NOW.0 + 7200);
    }
}
