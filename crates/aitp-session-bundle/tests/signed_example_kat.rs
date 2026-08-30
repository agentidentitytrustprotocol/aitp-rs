//! Known-answer test for the vendored `signed-examples/session-bundle/`
//! artifact, distinct from `tests/kat.rs`'s `kat-session-bundle-001`
//! (which pins raw signing bytes) and from `xcheck_committed.rs`'s
//! `aitp-verifier-py`-minted fixture. This one is `aitp-rs`'s own
//! reference-minted example: coordinator `kat-keypair-001` issuing a
//! single-participant bundle to `kat-keypair-002`.
//!
//! Follows the vendored-fixture-loading pattern used by sibling crates
//! (e.g. `crates/aitp-tct/tests/kat.rs`): read the file at its path under
//! `tests/schemas/`, at runtime, so drift in the vendored copy is caught
//! here rather than assumed away.

use aitp_core::{Aid, Timestamp};
use aitp_session_bundle::{parse_session_bundle_wire, verify_session_bundle, BundleOutcome};
use serde_json::Value;
use std::path::PathBuf;

fn fixture() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .join(
            "tests/schemas/known-answer/signed-examples/session-bundle/kat-keypair-001-bundle.json",
        );
    let raw = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("read vendored signed example {path:?}: {e}"));
    serde_json::from_slice(&raw).expect("vendored fixture is valid JSON")
}

// kat-keypair-002 (RFC-AITP-0001 §5.3 known-answer keypairs) -- the
// sole participant in this fixture.
fn participant_aid() -> Aid {
    Aid::parse("aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg").unwrap()
}

#[test]
fn kat_keypair_001_bundle_parses_and_verifies() {
    let fixture = fixture();
    let body = fixture
        .get("session_bundle")
        .expect("fixture carries the signed bundle body under `session_bundle`")
        .clone();

    // Read it the way the adapter does: through the wire-form parser,
    // wrapped in the transport envelope.
    let wire = serde_json::json!({ "session_bundle": body });
    let bundle =
        parse_session_bundle_wire(&wire).expect("vendored bundle parses as valid wire form");

    let verifier_aid = participant_aid();
    let ctx = aitp_session_bundle::VerifySessionBundleContext {
        verifier_aid: &verifier_aid,
        now: Timestamp(1_711_900_100),
        revocation_check: None,
    };
    match verify_session_bundle(&bundle, &ctx) {
        Ok(BundleOutcome::Clear { active_aids }) => {
            assert!(
                active_aids.contains(&verifier_aid),
                "verifying participant must be in the active set"
            );
            assert_eq!(active_aids.len(), 1, "fixture has exactly one participant");
        }
        other => panic!("vendored kat-keypair-001 bundle must verify clean, got {other:?}"),
    }
}
