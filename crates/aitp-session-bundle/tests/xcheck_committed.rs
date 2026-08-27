//! Cross-implementation acceptance, reverse direction: a session bundle
//! minted by `aitp-verifier-py`'s own minter, verified by `aitp-rs`.
//!
//! `tools/mint-signed-examples/src/bin/xcheck_mint.rs` + `scripts/xcheck-verify.py`
//! cover the forward direction (aitp-rs mints, aitp-verifier-py verifies). Until
//! now the bundle had no reverse direction: only the revocation snapshot did,
//! via the spec's committed example. This closes that gap for the bundle.
//!
//! The fixture (`tests/xcheck-fixtures/session-bundle/kat-keypair-001-bundle.json`)
//! was minted independently by `aitp-verifier-py`'s `aitp_verifier/minter.py`
//! (`_mint_bundle`, via `mint_input`) — see the sibling README for exact
//! provenance and regeneration instructions. It is verified here **as
//! committed**: nothing is re-minted or re-signed on the Rust side. Re-minting
//! is precisely what let the wrapped-vs-inner divergence hide for a full
//! release: each stack signed under its own convention and verified its own
//! output.

use aitp_core::{Aid, Timestamp};
use aitp_session_bundle::{verify_session_bundle, BundleOutcome, VerifySessionBundleContext};
use serde_json::Value;
use std::path::PathBuf;

fn fixture() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .join("tests/xcheck-fixtures/session-bundle/kat-keypair-001-bundle.json");
    let raw = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("read committed aitp-verifier-py bundle {path:?}: {e}"));
    serde_json::from_slice(&raw).expect("committed fixture is valid JSON")
}

// kat-keypair-002 (RFC-AITP-0001 §5.3 known-answer keypairs) — the receiving
// participant in the fixture's `bundle-001-success` input.
fn receiving_participant_aid() -> Aid {
    Aid::parse("aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg").unwrap()
}

// The reference clock the fixture was minted under (spec's `NOW` for signed
// examples), +100s -- matching bundle-001-success.json's `input.now`.
fn reference_now() -> Timestamp {
    Timestamp(1_711_900_100)
}

#[test]
fn aitp_verifier_py_committed_bundle_verifies() {
    let envelope = fixture();
    // The wire envelope is `{"session_bundle": {<inner body incl.
    // signature>}}` -- unwrap exactly the one transport key, matching how
    // `aitp-rs-adapter::verify_session_bundle_op` reads the wire form.
    let body = envelope
        .get("session_bundle")
        .expect("envelope carries the transport-wrapped body")
        .clone();
    let bundle: aitp_session_bundle::SessionTrustBundle =
        serde_json::from_value(body).expect("aitp-verifier-py-minted bundle deserializes");

    let verifier_aid = receiving_participant_aid();
    let ctx = VerifySessionBundleContext {
        verifier_aid: &verifier_aid,
        now: reference_now(),
        revocation_check: None,
    };
    match verify_session_bundle(&bundle, &ctx) {
        Ok(BundleOutcome::Clear { active_aids }) => {
            assert!(
                active_aids.contains(&verifier_aid),
                "verifying participant must be in the active set"
            );
        }
        other => panic!("committed aitp-verifier-py bundle must verify clean, got {other:?}"),
    }
}

/// The committed bundle must NOT verify when reframed into the pre-spec-fix
/// sibling shape (`signature` as a sibling of the `{"session_bundle": ...}`
/// wrapper, absent from the inner body) -- the shape `xcheck_mint.rs` used to
/// emit to accommodate an older `aitp-verifier-py` reading, and the shape
/// RFC-AITP-0010 §3 no longer permits (spec commit `45b5ef978e13`).
///
/// The positive test alone pins nothing: an implementation that accepted
/// either placement would pass it while leaving the wire convention
/// undetermined. `SessionTrustBundle::signature` is a required member of the
/// inner body (`#[serde(deny_unknown_fields)]`, no `Option`), so reading the
/// sibling shape at the same wire position a conformant reader uses fails
/// structurally -- there is no digest to even attempt.
#[test]
fn aitp_verifier_py_committed_bundle_rejects_the_sibling_shape() {
    let envelope = fixture();
    let mut body = envelope
        .get("session_bundle")
        .expect("envelope carries the transport-wrapped body")
        .clone();
    let signature = body
        .as_object_mut()
        .expect("body is an object")
        .remove("signature")
        .expect("committed bundle carries a signature");

    // Reframe as the old sibling shape: `{"session_bundle": <body sans
    // signature>, "signature": <sig>}`.
    let sibling = serde_json::json!({ "session_bundle": body, "signature": signature });

    // Read it the same way a conformant reader does: unwrap the single
    // `session_bundle` transport key and deserialize what's inside.
    let inner = sibling
        .get("session_bundle")
        .expect("sibling envelope still carries the wrapper key")
        .clone();
    let result: Result<aitp_session_bundle::SessionTrustBundle, _> = serde_json::from_value(inner);
    assert!(
        result.is_err(),
        "sibling-shaped bundle (signature outside the inner body) must not \
         deserialize as a valid SessionTrustBundle -- RFC-AITP-0010 §3 places \
         `signature` inside the body"
    );
}
