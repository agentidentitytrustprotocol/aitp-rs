#![no_main]

//! Fuzz target: JCS canonicalization (`aitp_core::jcs::canonicalize`).
//!
//! JCS (RFC 8785) canonicalization underpins the embedded-signature
//! profile (envelopes, Manifests, revocation snapshots). This target
//! parses arbitrary bytes as JSON and canonicalizes them, hunting for
//! panics on exotic numbers, deep nesting, duplicate keys, and unusual
//! string escapes. A canonicalization that returns `Err` (e.g. on
//! non-finite numbers) is fine; a panic or hang is a finding.

use libfuzzer_sys::fuzz_target;

use aitp_core::jcs;

fuzz_target!(|data: &[u8]| {
    // Parsing as a serde_json::Value first mirrors how canonicalization
    // is reached in practice (parse → canonicalize the parsed value).
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = jcs::canonicalize(&value);
    }
});
