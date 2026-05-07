#![no_main]

//! Fuzz target: AitpEnvelope JSON parsing.
//!
//! Drives `serde_json::from_slice::<AitpEnvelope>` over arbitrary
//! bytes. Any panic, OOM, or unbounded recursion is a finding —
//! envelope parsing is the first thing every untrusted byte stream
//! hits, so it must be robust against malformed input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<aitp_core::AitpEnvelope>(data);
});
