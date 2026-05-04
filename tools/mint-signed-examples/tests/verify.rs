//! Sanity-check that the minted signed examples actually verify
//! cryptographically. The schema test in the spec repo confirms shape;
//! this confirms the signatures are real.

use aitp_core::{Aid, Timestamp};
use aitp_crypto::AitpVerifyingKey;
use aitp_manifest::{verify_manifest, Manifest, VerifyManifestContext};
use aitp_tct::{
    verify_revocation_list, verify_tct, RevocationListEnvelope, Tct, TctVerifyContext,
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

fn load(rel: &str) -> serde_json::Value {
    let path = examples_dir().join(rel);
    if !path.exists() {
        panic!(
            "expected example at {} — run `cargo run -p mint-signed-examples` first",
            path.display()
        );
    }
    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
}

fn fixed_now() -> Timestamp {
    // The minting tool pins issued/published_at to 1_711_900_000.
    // Verify at 100s after issuance — well within all the pinned TTLs.
    Timestamp(1_711_900_100)
}

#[test]
fn minted_manifest_verifies() {
    let mut v = load("manifest/kat-keypair-001-manifest.json");
    v.as_object_mut().unwrap().remove("_kat_input");
    let m: Manifest = serde_json::from_value(v["manifest"].clone()).unwrap();
    verify_manifest(&m, &VerifyManifestContext { now: fixed_now() })
        .expect("minted manifest verifies");
}

#[test]
fn minted_tct_verifies() {
    let mut v = load("tct/kat-keypair-001-issues-002.json");
    v.as_object_mut().unwrap().remove("_kat_input");
    let tct: Tct = serde_json::from_value(v["tct"].clone()).unwrap();
    let issuer_pk = AitpVerifyingKey::from_aid(&tct.issuer).unwrap();
    let expected_audience = tct.subject.clone();
    let ctx = TctVerifyContext {
        expected_audience: &expected_audience,
        issuer_pubkey: &issuer_pk,
        now: fixed_now(),
        revocation_check: None,
    };
    verify_tct(&tct, &ctx).expect("minted TCT verifies");
}

#[test]
fn minted_delegation_verifies() {
    let mut v = load("delegation/single-hop-001-002-003.json");
    v.as_object_mut().unwrap().remove("_kat_input");
    let token: aitp_delegation::DelegationToken =
        serde_json::from_value(v["delegation"].clone()).unwrap();
    // Verifier is the original grantor (A = kat-keypair-001).
    let verifier_aid =
        Aid::parse("aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik").unwrap();
    let ctx = aitp_delegation::VerifyDelegationContext {
        verifier_aid: &verifier_aid,
        now: fixed_now(),
        revocation_check: None,
    };
    aitp_delegation::verify_delegation(&token, &ctx).expect("minted delegation verifies");
}

#[test]
fn minted_revocation_snapshot_verifies() {
    let mut v = load("revocation/kat-keypair-001-snapshot.json");
    v.as_object_mut().unwrap().remove("_kat_input");
    let env: RevocationListEnvelope = serde_json::from_value(v).unwrap();
    let issuer = env.revocation_list.issuer.clone();
    let ctx = VerifyRevocationListContext {
        expected_issuer: &issuer,
        now: fixed_now(),
    };
    verify_revocation_list(&env, &ctx).expect("minted revocation snapshot verifies");
}
