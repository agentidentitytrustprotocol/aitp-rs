#![no_main]

//! Fuzz target: Manifest JSON parsing.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<aitp_manifest::Manifest>(data);
});
