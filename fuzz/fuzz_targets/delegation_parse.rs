#![no_main]

//! Fuzz target: DelegationToken JSON parsing.
//!
//! Includes multi-hop tokens (RFC-AITP-0011) since the new optional
//! `chain` and `chain_hash` fields widen the parser surface.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<aitp_delegation::DelegationToken>(data);
});
