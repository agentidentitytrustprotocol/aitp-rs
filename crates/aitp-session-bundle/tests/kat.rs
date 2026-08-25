//! Known-answer test for `kat-session-bundle-001`.
//!
//! Nothing in this workspace pinned this vector before — its
//! `coordinator_signature_b64url` appeared in zero `.rs` files, so the
//! session bundle had no canonical-bytes test, no signature test and no
//! negative test of any kind. It was the least-covered of the three
//! JCS-profile artifacts and the one whose signing view was wrong.
//!
//! Every expectation here is read from the vendored spec file at runtime.

use aitp_core::{jcs, Aid};
use aitp_crypto::{AitpVerifyingKey, Signature};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const VECTOR_ID: &str = "kat-session-bundle-001";

fn vendored(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .join("tests/schemas")
        .join(rel)
}

fn vector() -> Value {
    let kat: Value =
        serde_json::from_slice(&std::fs::read(vendored("known-answer/jcs-sha256.json")).unwrap())
            .unwrap();
    kat["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .find(|v| v["id"].as_str() == Some(VECTOR_ID))
        .unwrap_or_else(|| panic!("{VECTOR_ID} missing from jcs-sha256.json"))
        .clone()
}

/// The pinned coordinator signature must verify over the pinned canonical
/// bytes of the **inner** bundle body.
#[test]
fn pinned_coordinator_signature_verifies_over_inner_body() {
    let v = vector();
    assert_eq!(
        v["signing_input"].as_str(),
        Some("body"),
        "{VECTOR_ID}: must declare signing_input=body (RFC-AITP-0010 §3)"
    );

    let body = &v["object"];
    assert!(
        body.get("session_bundle").is_none(),
        "{VECTOR_ID}: `object` must be the inner body, not the transport wrapper"
    );

    let canonical = jcs::canonicalize(body).expect("canonicalize");
    assert_eq!(
        hex::encode(&canonical),
        v["jcs_canonical_hex"].as_str().unwrap(),
        "{VECTOR_ID}: canonical bytes diverge from the spec"
    );

    let coordinator = body["coordinator"].as_str().expect("coordinator aid");
    let key = AitpVerifyingKey::from_aid(&Aid::parse(coordinator).expect("aid parses"))
        .expect("coordinator key");
    let sig = Signature::parse(v["coordinator_signature_b64url"].as_str().unwrap())
        .expect("pinned signature parses");

    key.verify(&Sha256::digest(&canonical), &sig)
        .expect("pinned coordinator signature must verify over the inner body");
}

/// ...and must NOT verify over the wrapped form.
///
/// A signature valid under both shapes pins no convention at all. This is
/// the assertion that would have caught the original divergence on day one.
#[test]
fn pinned_coordinator_signature_rejects_the_wrapped_form() {
    let v = vector();
    let wrapped = json!({ "session_bundle": v["object"].clone() });
    let canonical = jcs::canonicalize(&wrapped).expect("canonicalize wrapped");

    let coordinator = v["object"]["coordinator"].as_str().unwrap();
    let key = AitpVerifyingKey::from_aid(&Aid::parse(coordinator).unwrap()).unwrap();
    let sig = Signature::parse(v["coordinator_signature_b64url"].as_str().unwrap()).unwrap();

    assert!(
        key.verify(&Sha256::digest(&canonical), &sig).is_err(),
        "{VECTOR_ID}: signature verified over the WRAPPED form — the transport \
         wrapper is being signed (RFC-AITP-0001 §5.4.1)"
    );
}
