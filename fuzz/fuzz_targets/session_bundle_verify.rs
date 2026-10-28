#![no_main]

//! Fuzz target: Session Trust Bundle parsing and verification
//! (RFC-AITP-0010, feature `experimental-session-bundle`).
//!
//! The input goes through `CheckedJson`, both wire parsers (the bare
//! and the transport-wrapped form), and then `verify_session_bundle`.
//! The coordinator key comes from the `coordinator` AID
//! (`UnverifiedAidDangerous`) so that a parsed bundle reaches the outer
//! signature and per-participant TCT checks without a Manifest. Every
//! path must return, never panic.

use aitp::core::{Aid, CheckedJson, Timestamp};
use aitp_experimental::session_bundle::{
    parse_session_bundle_envelope, parse_session_bundle_wire, verify_session_bundle,
    CoordinatorKeySource, SessionBundleVerifyContext,
};
use libfuzzer_sys::fuzz_target;

// kat-keypair-002, the receiving participant in fixtures bundle-001..008.
const VERIFIER: &str = "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
const NOW: i64 = 1_711_900_000;

fuzz_target!(|data: &[u8]| {
    let Ok(checked) = CheckedJson::from_slice(data) else {
        return;
    };
    let verifier = Aid::parse(VERIFIER).expect("valid AID");
    let revoked = |_: &uuid::Uuid| false;
    let ctx = SessionBundleVerifyContext {
        verifier_aid: &verifier,
        now: Timestamp(NOW),
        revocation_check: Some(&revoked),
        coordinator_key: CoordinatorKeySource::UnverifiedAidDangerous,
    };
    for bundle in [
        parse_session_bundle_wire(&checked),
        parse_session_bundle_envelope(&checked),
    ]
    .into_iter()
    .flatten()
    {
        let _ = verify_session_bundle(&bundle, &ctx);
    }
});
