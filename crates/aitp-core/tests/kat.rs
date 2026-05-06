//! Known-answer tests for JCS canonicalization + SHA-256 against the
//! spec's pinned vectors at `tests/schemas/known-answer/jcs-sha256.json`.
//!
//! Each vector pins a JSON object (a signed AITP artifact body, with the
//! signature field omitted) plus the canonical JCS bytes (hex) and the
//! SHA-256 digest of those bytes. Implementations must produce
//! byte-identical canonical output and digests.

use aitp_core::jcs;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn signing_input<'a>(object: &'a Value, expected_canonical_hex: &str) -> &'a Value {
    let Some(map) = object.as_object() else {
        return object;
    };
    if map.len() != 1 {
        return object;
    }
    let (key, inner) = map.iter().next().unwrap();
    let wrapped_prefix = format!("\"{key}\"");
    let wrapped_prefix_hex = hex::encode(wrapped_prefix.as_bytes());
    let starts_at = expected_canonical_hex.find(&wrapped_prefix_hex);
    if matches!(starts_at, Some(2)) {
        object
    } else {
        inner
    }
}

fn kat_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("tests/schemas/known-answer/jcs-sha256.json")
}

#[test]
fn jcs_sha256_kat() {
    let kat: Value =
        serde_json::from_slice(&std::fs::read(kat_path()).expect("read kat")).expect("parse kat");
    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty(), "jcs-sha256.json has no vectors");

    for v in vectors {
        let id = v["id"].as_str().unwrap();
        // jcs-sha256.json mixes two vector kinds: canonical-form
        // vectors (have `object` + `jcs_canonical_hex`) and
        // signing-input vectors (e.g. kat-manifest-pop-001, which
        // pins the unified `sha256(base64url_decode(x))` PoP input).
        // Only the canonical-form entries are exercised here.
        if v.get("object").is_none() || v.get("jcs_canonical_hex").is_none() {
            continue;
        }
        let object = v["object"].clone();
        let expected_canonical_hex = v["jcs_canonical_hex"].as_str().unwrap();
        let expected_sha256_hex = v["sha256_hex"].as_str().unwrap();
        let expected_len = v["jcs_canonical_len_bytes"].as_u64().unwrap() as usize;

        // Spec KAT vectors come in two shapes:
        //   (a) `object` = the artifact wrapped in its type label
        //       (e.g. `{"manifest": {...}}`) and canonical bytes match
        //       that wrapped form.
        //   (b) `object` = same wrapped form, but canonical bytes are
        //       the *inner signing body* — i.e. the value without the
        //       wrapper. RFC-AITP-0010/0011 vectors (multi-hop chain,
        //       session bundle) use this shape because the signature
        //       is computed over the inner body.
        // Detect by comparing against the wrapper key: if the
        // canonical hex starts with `{"<wrapper_key>"` we use the
        // wrapped form; otherwise unwrap once.
        let signing_input = signing_input(&object, expected_canonical_hex);
        let actual = jcs::canonicalize(signing_input).expect("canonicalize");
        assert_eq!(
            actual.len(),
            expected_len,
            "{id}: canonical byte length mismatch (got {} want {})",
            actual.len(),
            expected_len,
        );
        let actual_hex = hex::encode(&actual);
        assert_eq!(
            actual_hex, expected_canonical_hex,
            "{id}: JCS canonical bytes mismatch — implementation produces different canonical form than the spec"
        );

        let digest = Sha256::digest(&actual);
        let actual_sha256_hex = hex::encode(digest);
        assert_eq!(
            actual_sha256_hex, expected_sha256_hex,
            "{id}: SHA-256 of canonical bytes mismatch"
        );
    }
}
