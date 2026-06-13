//! Single-hop delegation demo (RFC-AITP-0006).
//!
//! Three parties:
//!   - **A** (grantor) issues B a TCT granting `demo.read` + `demo.write`,
//!     plus a companion **grant voucher** (RFC-AITP-0005 §8) — A's signed,
//!     standalone statement of what it granted B. In a real deployment B
//!     receives both in the handshake commit payload
//!     ([`CompletedHandshake::grant_voucher`](aitp::handshake::CompletedHandshake) /
//!     [`SessionContext::grant_voucher`](aitp::facade::SessionContext)).
//!   - **B** (delegator) delegates a *subset* (`demo.read`) to **C**,
//!     rooting the delegation in that voucher — not in B's held TCT.
//!   - **A** (verifier) checks C's delegation token before honoring it.
//!
//! The delegation token is an opaque compact JWS that embeds A's voucher
//! verbatim, so A can confirm — offline, from C's token alone — that the
//! authority chain A→B→C is intact and that C's scope never exceeds what
//! A gave B. (In v0.1 this took reconstructing a `grant_proof` from B's
//! TCT; in v0.2 the embedded voucher *is* the proof.)
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
    // `build()` mints the TCT *and* the companion grant voucher; both
    // travel to B in the handshake commit payload.
    let a_to_b = TctBuilder::new(&a)
        .subject(b.aid().clone())
        .audience(b.aid().clone()) // v0.2: audience == subject
        .grants(["demo.read", "demo.write"])
        .subject_pubkey(b.verifying_key())
        .issued_at(now)
        .ttl_secs(3600)
        .build()
        .expect("A issues TCT to B");
    println!(
        "A → B: TCT granting {:?} (+ grant voucher)",
        a_to_b.claims.grants
    );
    let voucher = a_to_b
        .voucher
        .as_deref()
        .expect("voucher minted by default");

    // ── B → C: delegate a subset (demo.read only) ──────────────────────
    // B delegates against A's voucher; the voucher is embedded verbatim
    // in the resulting token. The result is an opaque compact JWS string
    // that C presents to A.
    let b_to_c = DelegationBuilder::new(&b, voucher)
        .expect("voucher entitles B to delegate")
        .delegatee(c.aid().clone())
        .scope(["demo.read"])
        .now(now)
        .ttl_secs(1800)
        .build()
        .expect("B delegates demo.read to C");
    println!("B → C: delegation token minted (scope [\"demo.read\"])\n");

    // ── A verifies C's delegation token ────────────────────────────────
    let ctx = VerifyDelegationContext::new(a.aid(), now);
    match verify_delegation(&b_to_c, &ctx) {
        Ok(v) => println!(
            "A verifies C's token:  ✓ valid — C may exercise {:?} on A",
            v.claims.scope
        ),
        Err(e) => panic!("expected valid delegation, got {e}"),
    }

    // ── Negative 1: B cannot delegate authority it was never granted ───
    // The builder enforces `scope ⊆ voucher.grants` at issuance time, so
    // an over-broad delegation never even mints.
    let over_broad = DelegationBuilder::new(&b, voucher)
        .expect("voucher entitles B to delegate")
        .delegatee(c.aid().clone())
        .scope(["demo.admin"]) // never granted to B
        .now(now)
        .build();
    match over_broad {
        Err(e) => println!("B over-broad delegation: ✓ rejected at issuance ({e})"),
        Ok(_) => panic!("builder should reject scope it was never granted"),
    }

    // ── Negative 2: only the grantor (A) may verify ────────────────────
    // The token binds `aud == voucher issuer == A`. Anyone else verifying
    // it — here C tries — is rejected.
    let wrong_ctx = VerifyDelegationContext::new(c.aid(), now);
    match verify_delegation(&b_to_c, &wrong_ctx) {
        Err(e) => println!("Non-grantor verify:    ✓ rejected ({e})"),
        Ok(_) => panic!("only the grantor A should be able to verify this token"),
    }

    println!("\ndemo OK");
}
