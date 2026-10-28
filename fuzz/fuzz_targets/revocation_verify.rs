#![no_main]

//! Fuzz target: signed revocation-list parsing + verification
//! (`aitp::tct::verify_revocation_list`).
//!
//! Revocation snapshots are JCS-signed (RFC-AITP-0008). This target
//! parses arbitrary bytes as a `RevocationListEnvelope` and, when they
//! parse, runs verification against a fixed issuer — exercising the
//! signature-before-lookup ordering and the empty-list handling. Any
//! panic is a finding.

use libfuzzer_sys::fuzz_target;

use aitp::core::Timestamp;
use aitp::crypto::AitpSigningKey;
use aitp::tct::{verify_revocation_list, RevocationListEnvelope, RevocationListVerifyContext};

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = serde_json::from_slice::<RevocationListEnvelope>(data) {
        let issuer = AitpSigningKey::from_ed25519_seed(&[9u8; 32]).aid().clone();
        let ctx = RevocationListVerifyContext::new(&issuer, Timestamp::now());
        let _ = verify_revocation_list(&envelope, &ctx);
    }
});
