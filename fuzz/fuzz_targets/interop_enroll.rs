#![no_main]

//! Fuzz target: the interop peer's `POST /enroll` body
//! (`aitp serve --interop`, crates/aitp-cli/src/enrol.rs).
//!
//! The endpoint is open to anyone on the internet, so parsing must never
//! panic. A body that parses also has its signature checked against a
//! fixed peer AID, the way the server does before consuming the nonce.

use libfuzzer_sys::fuzz_target;

#[allow(dead_code, unexpected_cfgs)]
#[path = "../../crates/aitp-cli/src/enrol.rs"]
mod enrol;

const PEER_AID: &str = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = enrol::parse_enroll(data) {
        let peer = aitp::core::Aid::parse(PEER_AID).expect("valid AID");
        let digest = enrol::signing_digest(&req.aid, &peer, &req.nonce);
        let _ = req.key.verify_jcs(&digest, &req.signature);
    }
});
