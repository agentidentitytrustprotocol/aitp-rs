#![no_main]

//! Fuzz target: delegation verification (`aitp_delegation::verify_delegation`).
//!
//! Drives arbitrary bytes as a candidate delegation compact-JWS through
//! both the single-hop default (`max_hops = 0`, RFC-AITP-0006) and the
//! multi-hop chain path (`max_hops > 0`, RFC-AITP-0011: chain assembly,
//! chain-hash recompute, per-hop continuity, scope subsetting, jti
//! uniqueness). The multi-hop path is the highest-complexity verifier in
//! the codebase; any panic there is a finding.

use libfuzzer_sys::fuzz_target;

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_delegation::{verify_delegation, VerifyDelegationContext};

fuzz_target!(|data: &[u8]| {
    // First byte selects the hop budget so both the single-hop
    // structural-reject path and the multi-hop assembly path are
    // exercised; the rest is the candidate token.
    let (max_hops, token_bytes) = match data.split_first() {
        Some((&b, rest)) => ((b % 6) as usize, rest),
        None => (0, data),
    };
    let verifier = AitpSigningKey::from_ed25519_seed(&[3u8; 32]).aid().clone();
    let token = String::from_utf8_lossy(token_bytes);

    let ctx = VerifyDelegationContext::new(&verifier, Timestamp::now()).with_max_hops(max_hops);
    let _ = verify_delegation(&token, &ctx);
});
