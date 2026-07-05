#![no_main]

//! Fuzz target: TCT verification (`aitp_tct::verify_tct`).
//!
//! Drives arbitrary bytes as a candidate TCT compact-JWS string through
//! the full 9-step verification order (RFC-AITP-0005 §7.2): parse → typ
//! → alg-pin → signature → claim validation (`ver`/`iss`/`aud`/`exp`/
//! `iat`/`grants`/`cnf`). Any panic is a finding; garbage input must
//! always return `Err`.

use libfuzzer_sys::fuzz_target;

use aitp_crypto::AitpSigningKey;
use aitp_tct::{verify_tct, TctVerifyContext};

fuzz_target!(|data: &[u8]| {
    let audience = AitpSigningKey::from_ed25519_seed(&[1u8; 32]).aid().clone();
    let issuer = AitpSigningKey::from_ed25519_seed(&[2u8; 32]).aid().clone();

    let token = String::from_utf8_lossy(data);
    let ctx = TctVerifyContext::now(&audience, &issuer);
    let _ = verify_tct(&token, &ctx);

    // Also exercise the self-issued shape (aud == iss == sub), which
    // takes a different path through the audience/self-binding checks.
    let ctx_self = TctVerifyContext::now(&issuer, &issuer);
    let _ = verify_tct(&token, &ctx_self);
});
