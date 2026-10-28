#![no_main]

//! Fuzz target: delegation verification.
//!
//! Drives arbitrary bytes as a candidate delegation compact-JWS through
//! the stable single-hop verifier (`aitp::delegation::verify_delegation`,
//! RFC-AITP-0006) and the multi-hop verifier
//! (`aitp_experimental::delegation::verify_chained_delegation`,
//! RFC-AITP-0011: chain assembly, chain-hash recompute, per-hop
//! continuity, scope subsetting, jti uniqueness). The multi-hop path is
//! the highest-complexity verifier in the codebase; any panic there is a
//! finding.

use libfuzzer_sys::fuzz_target;

use aitp::core::Timestamp;
use aitp::crypto::AitpSigningKey;
use aitp::delegation::{verify_delegation, VerifyDelegationContext};
use aitp::tct::RevocationSource;
use aitp_experimental::delegation::{verify_chained_delegation, VerifyChainContext};

fuzz_target!(|data: &[u8]| {
    // First byte selects the multi-hop budget so both the structural
    // reject path and the multi-hop assembly path are exercised; the
    // rest is the candidate token.
    let (max_delegation_hops, token_bytes) = match data.split_first() {
        Some((&b, rest)) => ((b % 6) as usize, rest),
        None => (0, data),
    };
    let verifier = AitpSigningKey::from_ed25519_seed(&[3u8; 32]).aid().clone();
    let token = String::from_utf8_lossy(token_bytes);
    let now = Timestamp::now();

    let ctx = VerifyDelegationContext::new(&verifier, now, RevocationSource::FailOpen);
    let _ = verify_delegation(&token, &ctx);

    let ctx = VerifyChainContext::new(&verifier, now, RevocationSource::FailOpen)
        .with_max_delegation_hops(max_delegation_hops);
    let _ = verify_chained_delegation(&token, &ctx);
});
