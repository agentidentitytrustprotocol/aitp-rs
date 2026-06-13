//! Sanity-check that the minted signed examples actually verify
//! cryptographically. The schema test in the spec repo confirms shape;
//! this confirms the signatures are real.

use aitp_core::{Aid, Timestamp};
use aitp_manifest::{verify_manifest, Manifest, VerifyManifestContext};
use aitp_tct::{
    verify_revocation_list, verify_tct, verify_voucher, RevocationListEnvelope, TctVerifyContext,
    VerifyRevocationListContext,
};
use std::path::PathBuf;

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .parent()
        .unwrap()
        .join("agentidentitytrustprotocol/schemas/conformance/known-answer/signed-examples")
}

/// Returns `None` when the sibling spec repo is not present (e.g.,
/// in CI where we don't check it out). Tests treat that as a graceful
/// skip rather than a failure — these tests verify *previously
/// minted* output, so when the spec repo is missing there's nothing
/// to verify.
fn try_load(rel: &str) -> Option<serde_json::Value> {
    let path = examples_dir().join(rel);
    if !path.exists() {
        eprintln!(
            "skip: {} not present (sibling spec repo not checked out — \
             run `cargo run -p mint-signed-examples` against a sibling \
             agentidentitytrustprotocol checkout to populate it)",
            path.display()
        );
        return None;
    }
    Some(serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap())
}

fn fixed_now() -> Timestamp {
    // The minting tool pins issued/published_at to 1_711_900_000.
    // Verify at 100s after issuance — well within all the pinned TTLs.
    Timestamp(1_711_900_100)
}

fn kat_001_aid() -> Aid {
    Aid::parse("aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik").unwrap()
}

fn kat_002_aid() -> Aid {
    Aid::parse("aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg").unwrap()
}

#[test]
fn minted_manifest_verifies() {
    let Some(v) = try_load("manifest/kat-keypair-001-manifest.json") else {
        return;
    };
    let m: Manifest = serde_json::from_value(v["manifest"].clone()).unwrap();
    verify_manifest(&m, &VerifyManifestContext { now: fixed_now() })
        .expect("minted manifest verifies");
}

#[test]
fn minted_tct_verifies() {
    let Some(v) = try_load("tct/kat-keypair-001-issues-002.json") else {
        return;
    };
    let token = v["tct_token"].as_str().expect("tct_token string");
    // Holder receipt: subject == audience == kat-keypair-002.
    let expected_audience = kat_002_aid();
    let issuer = kat_001_aid();
    let ctx = TctVerifyContext {
        expected_audience: &expected_audience,
        issuer: &issuer,
        now: fixed_now(),
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    let verified = verify_tct(token, &ctx).expect("minted TCT verifies");
    assert_eq!(
        serde_json::to_value(&verified.claims).unwrap(),
        v["decoded_claims"],
        "decoded_claims companion diverges from the token payload"
    );
}

#[test]
fn minted_grant_voucher_verifies() {
    let Some(v) = try_load("grant-voucher/kat-voucher-001.json") else {
        return;
    };
    let token = v["voucher_token"].as_str().expect("voucher_token string");
    let claims = verify_voucher(token, &kat_001_aid()).expect("minted voucher verifies");
    assert_eq!(claims.sub, kat_002_aid());
    assert_eq!(
        serde_json::to_value(&claims).unwrap(),
        v["decoded_claims"],
        "decoded_claims companion diverges from the token payload"
    );
}

#[test]
fn minted_delegation_verifies() {
    let Some(v) = try_load("delegation/single-hop-001-002-003.json") else {
        return;
    };
    let token = v["delegation_token"].as_str().expect("delegation_token");
    // Verifier is the original grantor / voucher issuer (A = kat-keypair-001).
    let verifier_aid = kat_001_aid();
    let ctx = aitp_delegation::VerifyDelegationContext::new(&verifier_aid, fixed_now());
    let verified =
        aitp_delegation::verify_delegation(token, &ctx).expect("minted delegation verifies");
    assert_eq!(
        serde_json::to_value(&verified.claims).unwrap(),
        v["decoded_claims"],
        "decoded_claims companion diverges from the token payload"
    );
}

#[test]
fn minted_revocation_snapshot_verifies() {
    let Some(mut v) = try_load("revocation/kat-keypair-001-snapshot.json") else {
        return;
    };
    v.as_object_mut().unwrap().remove("_kat_input");
    let env: RevocationListEnvelope = serde_json::from_value(v).unwrap();
    let issuer = env.revocation_list.issuer.clone();
    let ctx = VerifyRevocationListContext {
        expected_issuer: &issuer,
        now: fixed_now(),
    };
    verify_revocation_list(&env, &ctx).expect("minted revocation snapshot verifies");
}
