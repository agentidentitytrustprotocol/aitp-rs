//! Known-answer tests for JCS canonicalization + SHA-256 against the
//! spec's pinned vectors at `tests/schemas/known-answer/jcs-sha256.json`.
//!
//! Each vector pins a JSON object — the **inner artifact body**, with the
//! signature omitted — plus the canonical JCS bytes (hex) and their
//! SHA-256 digest. Implementations must produce byte-identical output.
//!
//! # Why this file asserts instead of infers
//!
//! This harness previously chose *which shape to canonicalize* by
//! searching for the wrapper key inside the pinned answer hex — deriving
//! the question from the answer. It therefore agreed with whatever shape
//! a vector happened to carry and could not fail in either direction.
//! That is how the spec's (then wrong) wrapped vectors and `aitp-rs`'s
//! wrapped signing views validated each other for a full release.
//!
//! The rule is not negotiable and is not inferred here: per
//! RFC-AITP-0001 §5.4.1, the artifact-naming key is transport routing
//! metadata and is **never part of the signing bytes**. RFC-AITP-0003
//! §6.1 (manifest), RFC-AITP-0008 §1.5 (revocation) and RFC-AITP-0010 §3
//! (session bundle) each restate it for their artifact. So every
//! JCS-profile vector MUST declare `signing_input: "body"`, and this file
//! hard-codes that expectation rather than echoing the file's own claim
//! back at it.

use aitp_core::jcs;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// The JCS-profile artifact vectors and the transport wrapper key each
/// one must **not** be canonicalized inside of.
///
/// Hard-coded on purpose: a future vector that flips its own
/// `signing_input` to `"envelope"` must fail this suite, not silently
/// redefine the convention. A vector may not self-certify a
/// non-conformant signing input.
const JCS_ARTIFACT_VECTORS: &[(&str, &str)] = &[
    ("kat-manifest-001", "manifest"),
    ("kat-revocation-001", "revocation_list"),
    ("kat-session-bundle-001", "session_bundle"),
];

/// The vectors in `jcs-sha256.json` that are deliberately NOT
/// canonical-form vectors, and so carry no `object`/`jcs_canonical_hex`.
///
/// This is an allowlist rather than a `continue` on missing members, so
/// that dropping `object` from a real vector — or adding a new vector
/// upstream — cannot silently remove it from coverage. Skipping on
/// absence lets the file decide what gets tested; an allowlist keeps that
/// decision here.
const NON_CANONICAL_VECTORS: &[&str] = &[
    "kat-manifest-pop-001",
    "kat-multihop-chain-001",
    "kat-multihop-truncation-001",
];

/// Members every canonical-form vector must carry. Absence is a failure,
/// never a skip.
const REQUIRED_PAYLOAD: &[&str] = &[
    "object",
    "jcs_canonical_hex",
    "jcs_canonical_len_bytes",
    "sha256_hex",
    "sha256_b64url",
];

fn kat_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("tests/schemas/known-answer/jcs-sha256.json")
}

fn load_vectors() -> Vec<Value> {
    let kat: Value =
        serde_json::from_slice(&std::fs::read(kat_path()).expect("read kat")).expect("parse kat");
    let vectors = kat["vectors"].as_array().expect("vectors array").clone();
    assert!(!vectors.is_empty(), "jcs-sha256.json has no vectors");
    vectors
}

#[test]
fn jcs_sha256_kat() {
    let vectors = load_vectors();

    for v in &vectors {
        let id = v["id"].as_str().unwrap();
        // jcs-sha256.json mixes two vector kinds: canonical-form vectors
        // (`object` + `jcs_canonical_hex`) and signing-input vectors
        // (e.g. kat-manifest-pop-001, which pins the unified
        // `sha256(base64url_decode(x))` PoP input). Only the former are
        // exercised here — but which is which is decided by the allowlist
        // above, NOT by whether the members happen to be present. A vector
        // that lost its `object` must go red, not quietly stop being tested.
        if NON_CANONICAL_VECTORS.contains(&id) {
            continue;
        }
        for member in REQUIRED_PAYLOAD {
            assert!(
                v.get(member).is_some(),
                "{id}: canonical-form vector is missing `{member}`; add it to \
                 NON_CANONICAL_VECTORS if it is genuinely not one"
            );
        }

        // A vector that pins canonical bytes without declaring what they
        // are the canonicalization *of* is unfalsifiable. Fail loudly —
        // never fall back to a default shape, which is what made the old
        // helper adaptive.
        let declared = v
            .get("signing_input")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "{id}: pins canonical bytes but does not declare `signing_input`; \
                 refusing to guess the signing shape"
                )
            });
        assert_eq!(
            declared, "body",
            "{id}: JCS-profile vectors sign the inner artifact body \
             (RFC-AITP-0001 §5.4.1); `{declared}` is not a conformant signing input"
        );

        let object = &v["object"];
        let expected_canonical_hex = v["jcs_canonical_hex"].as_str().unwrap();
        let expected_sha256_hex = v["sha256_hex"].as_str().unwrap();
        let expected_len = v["jcs_canonical_len_bytes"].as_u64().unwrap() as usize;

        // `signing_input: "body"` means `object` IS the body — canonicalize
        // it as-is. No unwrapping, no sniffing.
        let actual = jcs::canonicalize(object).expect("canonicalize");
        assert_eq!(
            actual.len(),
            expected_len,
            "{id}: canonical byte length mismatch (got {} want {expected_len})",
            actual.len(),
        );
        assert_eq!(
            hex::encode(&actual),
            expected_canonical_hex,
            "{id}: JCS canonical bytes mismatch — implementation produces a \
             different canonical form than the spec"
        );
        let digest = Sha256::digest(&actual);
        assert_eq!(
            hex::encode(digest),
            expected_sha256_hex,
            "{id}: SHA-256 of canonical bytes mismatch"
        );
        // `sha256_b64url` is pinned on every canonical vector and was
        // asserted by no test in the workspace — free coverage of the
        // same digest in the encoding the wire actually carries.
        assert_eq!(
            aitp_core::base64url::encode(digest.as_slice()),
            v["sha256_b64url"].as_str().unwrap(),
            "{id}: base64url SHA-256 mismatch"
        );
    }
}

/// Every JCS-profile artifact vector must be present, declare
/// `signing_input: "body"`, and carry an already-unwrapped `object`.
///
/// Presence is asserted explicitly: a vector deleted from the file would
/// otherwise just reduce the number of assertions `jcs_sha256_kat` makes,
/// silently.
#[test]
fn jcs_artifact_vectors_are_present_and_declare_body() {
    let vectors = load_vectors();
    let ids: BTreeSet<&str> = vectors.iter().filter_map(|v| v["id"].as_str()).collect();

    for (id, wrapper) in JCS_ARTIFACT_VECTORS {
        assert!(
            ids.contains(id),
            "{id}: JCS-profile vector missing from jcs-sha256.json"
        );
        let v = vectors
            .iter()
            .find(|v| v["id"].as_str() == Some(*id))
            .unwrap();

        assert_eq!(
            v["signing_input"].as_str(),
            Some("body"),
            "{id}: must declare signing_input=body"
        );
        // Assert the payload members exist before asserting anything about
        // them: `Value::Null.get(...)` returns `None`, so a vector that lost
        // its `object` would satisfy the wrapper check vacuously and drop
        // every byte/digest assertion without going red.
        for member in REQUIRED_PAYLOAD {
            assert!(
                v.get(member).is_some(),
                "{id}: JCS-profile vector is missing `{member}`"
            );
        }
        assert!(
            v["object"].get(wrapper).is_none(),
            "{id}: `object` still carries the `{wrapper}` transport wrapper; \
             with signing_input=body it must be the inner artifact body"
        );
    }
}

/// The negative direction: the pinned canonical bytes must NOT be the
/// canonicalization of the **wrapped** form.
///
/// This is the second of two independent defences against a re-wrap. If a
/// vector is re-wrapped wholesale (`object` wrapped too), the wrapper-key
/// assertion in `jcs_artifact_vectors_are_present_and_declare_body` catches
/// it. If instead only the pinned bytes are swapped to the wrapped form
/// while `object` stays inner, that assertion passes and *this* one fires.
/// Both mutations were verified to go red; neither check subsumes the other.
#[test]
fn pinned_bytes_are_not_the_wrapped_form() {
    let vectors = load_vectors();

    for (id, wrapper) in JCS_ARTIFACT_VECTORS {
        let v = vectors
            .iter()
            .find(|v| v["id"].as_str() == Some(*id))
            .unwrap_or_else(|| panic!("{id}: vector missing"));

        let wrapped = json!({ *wrapper: v["object"].clone() });
        let wrapped_hex = hex::encode(jcs::canonicalize(&wrapped).expect("canonicalize wrapped"));
        let pinned_hex = v["jcs_canonical_hex"]
            .as_str()
            .unwrap_or_else(|| panic!("{id}: missing `jcs_canonical_hex`"));

        assert_ne!(
            wrapped_hex, pinned_hex,
            "{id}: pinned canonical bytes equal JCS of the wrapped \
             `{{\"{wrapper}\": ...}}` form — the transport wrapper is being signed"
        );
    }
}
