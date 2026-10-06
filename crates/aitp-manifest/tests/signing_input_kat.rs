//! Production-funnel regression coverage for the manifest signing input
//! (issue #147) — the manifest is the **control** artifact: it already
//! signed the inner body before the wrapped-vs-inner migration, and its
//! signed example was byte-unchanged by spec commit `5f8e588`. That made it
//! easy to assume "already correct" needed no test of its own. It did:
//! flipping BOTH `ManifestBuilder::build`'s and `verify_manifest`'s signing
//! derivation to canonicalize the wrapped `{"manifest": …}` form instead of
//! the inner body used to pass `cargo test -p aitp-manifest` completely
//! green but for one incidental failure — `round_trip.rs`'s
//! `extensions_present_but_empty_now_verifies_end_to_end`, which happens to
//! hand-sign the inner body with raw primitives before calling the real
//! `verify_manifest`, but exists to pin `extensions:{}` presence semantics,
//! not the wrapper convention, and isn't checked against a committed
//! fixture. No test in this crate deliberately drove the real sign+verify
//! funnel against a fixed, committed fixture — only this file's own
//! raw-primitive check below, which never calls into `aitp_manifest` at
//! all.

use aitp_core::{jcs, Aid, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey, Signature};
use aitp_manifest::{
    parse_manifest_wire, verify_manifest, IdentityHint, IdentityHintKind, ManifestBuilder,
    ManifestError, VerifyManifestContext,
};
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

/// The AID pinned for a KAT keypair, read from the vendored `keypairs.json`
/// rather than derived from the artifact under test — mirrors
/// `crates/aitp-tct/src/revocation.rs`'s `kat_keypair_aid` helper.
fn kat_keypair_aid(id: &str) -> Aid {
    let kp: Value =
        serde_json::from_slice(&std::fs::read(vendored("known-answer/keypairs.json")).unwrap())
            .unwrap();
    let aid = kp["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .find(|v| v["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("keypair {id} missing from keypairs.json"))["aid"]
        .as_str()
        .unwrap_or_else(|| panic!("keypair {id} has no `aid`"))
        .to_owned();
    Aid::parse(&aid).expect("pinned AID parses")
}

/// Production-path positive: the committed manifest example verifies
/// through the real `parse_manifest_wire` + `verify_manifest` funnel, not
/// hand-rolled primitives.
///
/// This is the test that actually catches issue #147's regression:
/// flipping the shared signing-view derivation (`ManifestSigningView::from`
/// / `manifest_signing_bytes`, `crates/aitp-manifest/src/builder.rs`) to
/// canonicalize the wrapped form makes THIS test fail, because the
/// committed signature is a fixed artifact of the real, correct convention
/// — unlike a freshly-minted round-trip (e.g. `round_trip.rs`'s
/// `happy_path_round_trip`), which stays self-consistent under a symmetric
/// flip of both the sign and verify sides.
#[test]
fn committed_manifest_example_verifies_via_verify_manifest() {
    let raw = std::fs::read(vendored(
        "known-answer/signed-examples/manifest/kat-keypair-001-manifest.json",
    ))
    .expect("read committed manifest example");
    let mut value: Value = serde_json::from_slice(&raw).unwrap();
    // `_kat_input` is a minting companion, never part of the wire object.
    // `parse_manifest_wire`'s wrapper-member check requires the wrapper's
    // member set to be exactly `["manifest"]`, so this must be stripped
    // before parsing (mirrors `crates/aitp-tct/src/revocation.rs`'s
    // committed-fixture tests, which strip the same sibling first).
    value
        .as_object_mut()
        .expect("committed example is a JSON object")
        .remove("_kat_input");

    let manifest = parse_manifest_wire(&value)
        .expect("committed example parses via the real wire-parsing entry point");

    // Fixture validity window is [1_711_900_000, 1_711_986_400) — same
    // pinned `now` `crates/aitp-cli/tests/cli.rs`'s
    // `manifest_verify_ok_within_validity_window` already uses.
    let ctx = VerifyManifestContext {
        now: Timestamp(1_711_900_500),
    };
    verify_manifest(&manifest, &ctx)
        .expect("committed spec signed example must verify as committed");

    // Fixture-integrity guard: confirm the committed file still represents
    // the keypair it claims to, independent of the artifact's own `aid`
    // field. This is not closing a tautology in `verify_manifest` itself
    // (which has no separate `expected_issuer` parameter to make
    // tautological, unlike `verify_revocation_list` — the manifest's `aid`
    // is simultaneously the claimed identity and the verification key
    // source, by design) — just a check that the committed file hasn't
    // silently drifted to a different signing key.
    assert_eq!(
        manifest.aid,
        kat_keypair_aid("kat-keypair-001"),
        "committed manifest example's aid no longer matches kat-keypair-001"
    );
}

/// The committed manifest signed example must verify over the body minus
/// `signature`, and must NOT verify over the `{"manifest": …}` wrapper.
///
/// Note the manifest's `signature` is a **member** of the body (unlike the
/// revocation snapshot's, which is a sibling), so the exclusion happens
/// from within — RFC-AITP-0003 §6.1. Raw-primitive check, independent of
/// any `aitp_manifest` code path — still the only assertion pinning the
/// committed artifact's actual on-disk convention regardless of what any
/// code path does with it.
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

/// A manifest signed over the wrapped `{"manifest": …}` form must be
/// rejected by the real `verify_manifest`, independent of any committed
/// fixture.
///
/// This is the test that would catch the regression even with no committed
/// fixture at all — it exercises `verify_manifest`'s canonicalization
/// directly against a signature deliberately computed the wrong way.
/// Building the wrapped canonicalization by hand (not via
/// `ManifestSigningView`'s `Serialize` impl or `manifest_signing_bytes`) is
/// deliberate: using the function under test to construct its own
/// adversarial input would make this test unable to fail no matter what
/// that function does.
#[test]
fn wrapped_signed_manifest_is_rejected_by_verify_manifest() {
    const PUBLISHED_AT: i64 = 1_700_000_000;
    let key = AitpSigningKey::from_seed(&[9u8; 32]);

    let mut manifest = ManifestBuilder::new(&key)
        .handshake_endpoint(
            "https://a.example.com/handshake"
                .parse()
                .expect("valid URL"),
        )
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::Oidc,
            subject: "agent-a".into(),
            issuer: Some(
                "https://idp.example.com"
                    .parse::<url::Url>()
                    .expect("valid URL")
                    .into(),
            ),
            public_key: None,
        })
        .accept_trust_anchor("https://idp.example.com".parse().expect("valid URL"))
        .offer("demo.echo")
        .published_at(Timestamp(PUBLISHED_AT))
        .ttl_secs(3600)
        .build()
        .expect("builder produces a well-formed manifest");

    // Re-sign over the WRAPPED form, deliberately, replacing the real
    // signature `build()` produced — mirrors
    // `crates/aitp-tct/src/revocation.rs`'s `wrapped_signed_snapshot_is_rejected`.
    let mut body = serde_json::to_value(&manifest).expect("manifest serializes");
    body.as_object_mut()
        .expect("manifest serializes to an object")
        .remove("signature");
    let wrapped = json!({ "manifest": body });
    let wrapped_canonical = jcs::canonicalize(&wrapped).expect("canonicalize wrapped");
    let wrong_signature = key.sign(&Sha256::digest(&wrapped_canonical));
    manifest.signature = wrong_signature.into_string();

    let ctx = VerifyManifestContext {
        now: Timestamp(PUBLISHED_AT + 100),
    };
    let result = verify_manifest(&manifest, &ctx);
    assert!(
        matches!(result, Err(ManifestError::SignatureInvalid)),
        "a manifest signed over the wrapped form must be rejected with \
         SignatureInvalid, got {result:?}"
    );
}
