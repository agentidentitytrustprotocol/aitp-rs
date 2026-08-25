//! Negative KAT for the manifest — the **control** artifact.
//!
//! The manifest already signed the inner body before the wrapped-vs-inner
//! migration, and its signed example was byte-unchanged by spec commit
//! `5f8e588`. That makes it the control case: it proves the migration did
//! not overshoot. But "already correct" was asserted by no negative test,
//! so nothing prevented it from drifting the other way. This adds the
//! missing half.

use aitp_core::{jcs, Aid};
use aitp_crypto::{AitpVerifyingKey, Signature};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn vendored(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .join("tests/schemas")
        .join(rel)
}

/// The committed manifest signed example must verify over the body minus
/// `signature`, and must NOT verify over the `{"manifest": …}` wrapper.
///
/// Note the manifest's `signature` is a **member** of the body (unlike the
/// revocation snapshot's, which is a sibling), so the exclusion happens
/// from within — RFC-AITP-0003 §6.1.
#[test]
fn committed_manifest_example_signs_the_inner_body_only() {
    let raw = std::fs::read(vendored(
        "known-answer/signed-examples/manifest/kat-keypair-001-manifest.json",
    ))
    .expect("read committed manifest example");
    let value: Value = serde_json::from_slice(&raw).unwrap();
    // The committed file is transport-wrapped: `{"manifest": {…}}` with
    // `_kat_input` as a minting companion. The wrapper is routing metadata,
    // never signed — take the inner body.
    let mut obj = value["manifest"]
        .as_object()
        .expect("committed example is wrapped in `manifest`")
        .clone();

    let signature = obj
        .remove("signature")
        .and_then(|v| v.as_str().map(String::from))
        .expect("manifest example carries a signature");
    let aid = obj["aid"].as_str().expect("manifest aid").to_string();

    // Positive: body minus `signature`.
    let body = Value::Object(obj.clone());
    let canonical = jcs::canonicalize(&body).expect("canonicalize");
    let key = AitpVerifyingKey::from_aid(&Aid::parse(&aid).expect("aid parses")).unwrap();
    let sig = Signature::parse(&signature).expect("signature parses");
    key.verify(&Sha256::digest(&canonical), &sig)
        .expect("committed manifest example must verify over the inner body");

    // Negative: the wrapped form must not verify.
    let wrapped = json!({ "manifest": body });
    let wrapped_canonical = jcs::canonicalize(&wrapped).expect("canonicalize wrapped");
    assert!(
        key.verify(&Sha256::digest(&wrapped_canonical), &sig)
            .is_err(),
        "manifest signature verified over the WRAPPED form — the transport \
         wrapper is being signed (RFC-AITP-0001 §5.4.1, RFC-AITP-0003 §6.1)"
    );
}
