#![no_main]

//! Fuzz target: compact-JWS verification (`aitp_crypto::jws::verify_compact`).
//!
//! The JWS profile is the load-bearing anti-forgery boundary
//! (RFC-AITP-0001 §5.4.5): strict 3-segment parse, exact `{alg, typ}`
//! header, AID-pinned `alg`, signature over transmitted bytes. This
//! target drives arbitrary bytes through it against both an Ed25519 and
//! a P-256 signer AID. Any panic / OOM / unbounded recursion is a
//! finding; a well-formed rejection (`Err`) is the expected outcome for
//! essentially all inputs.

use libfuzzer_sys::fuzz_target;

use aitp_crypto::{jws, AitpSigningKey};

fuzz_target!(|data: &[u8]| {
    // Fixed, deterministic signer AIDs — one per suite — so the target
    // exercises the alg-pinning branch for both.
    let ed_aid = AitpSigningKey::from_ed25519_seed(&[7u8; 32]).aid().clone();
    let p256_aid = AitpSigningKey::from_p256_seed(&[5u8; 32])
        .expect("fixed P-256 seed is valid")
        .aid()
        .clone();

    let token = String::from_utf8_lossy(data);

    // Both the canonical TCT typ and a deliberately-wrong typ, so the
    // typ-mismatch branch is reachable too.
    for typ in [jws::TYP_TCT, "aitp-delegation+jwt", "wrong+jwt"] {
        let _ = jws::verify_compact(&ed_aid, typ, &token);
        let _ = jws::verify_compact(&p256_aid, typ, &token);
    }
});
