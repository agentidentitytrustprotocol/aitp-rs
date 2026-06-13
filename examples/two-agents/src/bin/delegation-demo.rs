//! Single-hop delegation demo (RFC-AITP-0006).
//!
//! Three parties:
//!   - **A** (grantor) issues a TCT to **B** granting `demo.read` + `demo.write`.
//!   - **B** (delegator) delegates a *subset* (`demo.read`) to **C**.
//!   - **A** (verifier) checks C's delegation token before honoring it.
//!
//! The delegation token carries A's original grant verbatim (`grant_proof`),
//! so A can confirm — offline, from C's token alone — that the authority
//! chain A→B→C is intact and that C's scope never exceeds what A gave B.
//!
//! ```sh
//! cargo run -p aitp-example-two-agents --bin delegation-demo
//! ```

use aitp::core::Timestamp;
use aitp::crypto::AitpSigningKey;
use aitp::delegation::{verify_delegation, DelegationBuilder, VerifyDelegationContext};
use aitp::tct::TctBuilder;

fn main() {
    println!("aitp-rs delegation demo — single-hop (RFC-AITP-0006)\n");

    let a = AitpSigningKey::from_seed(&[0xA1; 32]); // grantor
    let b = AitpSigningKey::from_seed(&[0xB2; 32]); // delegator
    let c = AitpSigningKey::from_seed(&[0xC3; 32]); // delegatee
    println!("A (grantor):   {}", a.aid());
    println!("B (delegator): {}", b.aid());
    println!("C (delegatee): {}\n", c.aid());

    let now = Timestamp::now();

    // ── A → B: issue a TCT granting two capabilities ───────────────────
    let a_to_b = TctBuilder::new(&a)
        .subject(b.aid().clone())
        .audience(b.aid().clone()) // v0.1: audience == subject
        .grants(["demo.read", "demo.write"])
        .subject_pubkey(b.verifying_key())
        .issued_at(now)
        .ttl_secs(3600)
        .build()
        .expect("A issues TCT to B");
    println!("A → B: TCT granting {:?}", a_to_b.grants);

    // ── B → C: delegate a subset (demo.read only) ──────────────────────
    let b_to_c = DelegationBuilder::new(&b, &a_to_b)
        .delegatee(c.aid().clone())
        .delegatee_pubkey(c.verifying_key())
        .scope(["demo.read"])
        .now(now)
        .ttl_secs(1800)
        .build()
        .expect("B delegates demo.read to C");
    println!("B → C: delegation scoped to {:?}\n", b_to_c.scope);

    // ── A verifies C's delegation token ────────────────────────────────
    let ctx = VerifyDelegationContext::new(a.aid(), now);
    match verify_delegation(&b_to_c, &ctx) {
        Ok(tok) => println!(
            "A verifies C's token:  ✓ valid — C may exercise {:?} on A",
            tok.scope
        ),
        Err(e) => panic!("expected valid delegation, got {e}"),
    }

    // ── Negative 1: B cannot delegate authority it was never granted ───
    // The builder enforces `scope ⊆ held_tct.grants` at issuance time, so
    // an over-broad delegation never even mints.
    let over_broad = DelegationBuilder::new(&b, &a_to_b)
        .delegatee(c.aid().clone())
        .delegatee_pubkey(c.verifying_key())
        .scope(["demo.admin"]) // never granted to B
        .now(now)
        .build();
    match over_broad {
        Err(e) => println!("B over-broad delegation: ✓ rejected at issuance ({e})"),
        Ok(_) => panic!("builder should reject scope it was never granted"),
    }

    // ── Negative 2: only the grantor (A) may verify ────────────────────
    // The token binds `audience == delegator == A`. Anyone else verifying
    // it — here C tries — is rejected.
    let wrong_ctx = VerifyDelegationContext::new(c.aid(), now);
    match verify_delegation(&b_to_c, &wrong_ctx) {
        Err(e) => println!("Non-grantor verify:    ✓ rejected ({e})"),
        Ok(_) => panic!("only the grantor A should be able to verify this token"),
    }

    println!("\ndemo OK");
}
