//! Drift firewall: freshly minted delegation claims MUST validate
//! against the spec schema vendored at
//! `tests/schemas/aitp-delegation.schema.json` (which models the
//! decoded JWS payload).

use aitp_core::Timestamp;
use aitp_crypto::{jws, AitpSigningKey};
use aitp_delegation::{DelegationBuilder, DELEGATION_CLAIMS_MEMBERS};
use aitp_tct::TctBuilder;
use boon::{Compiler, Schemas};
use std::collections::BTreeSet;
use std::path::PathBuf;
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_700_000_000);

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("tests/schemas/aitp-delegation.schema.json")
}

fn validate(value: &serde_json::Value) -> Result<(), String> {
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
    let schema_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(schema_path()).expect("read schema"))
            .expect("parse schema");
    let url = format!("file://{}", schema_path().display());
    compiler
        .add_resource(&url, schema_json)
        .map_err(|e| e.to_string())?;
    let id = compiler
        .compile(&url, &mut schemas)
        .map_err(|e| e.to_string())?;
    schemas.validate(value, id).map_err(|e| e.to_string())
}

fn decoded_claims(token: &str) -> serde_json::Value {
    serde_json::from_slice(&jws::decode_payload_unverified(token).unwrap()).unwrap()
}

#[test]
fn minted_single_hop_claims_validate() {
    let a = AitpSigningKey::from_seed(&[0xA1; 32]);
    let b = AitpSigningKey::from_seed(&[0xB1; 32]);
    let c = AitpSigningKey::from_seed(&[0xC1; 32]);
    let voucher = TctBuilder::new(&a)
        .subject(b.aid().clone())
        .audience(b.aid().clone())
        .grants(["read_data"])
        .ttl_secs(7200)
        .subject_pubkey(b.verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
        .voucher
        .unwrap();
    let token = DelegationBuilder::new(&b, &voucher)
        .unwrap()
        .delegatee(c.aid().clone())
        .scope(["read_data"])
        .now(NOW)
        .build()
        .unwrap();
    if let Err(e) = validate(&decoded_claims(&token)) {
        panic!("single-hop delegation claims failed schema validation:\n{e}");
    }
}

#[test]
fn minted_multihop_claims_validate() {
    let a = AitpSigningKey::from_seed(&[0xA1; 32]);
    let b = AitpSigningKey::from_seed(&[0xB1; 32]);
    let c = AitpSigningKey::from_seed(&[0xC1; 32]);
    let d = AitpSigningKey::from_seed(&[0xD1; 32]);
    let voucher = TctBuilder::new(&a)
        .subject(b.aid().clone())
        .audience(b.aid().clone())
        .grants(["read_data"])
        .ttl_secs(7200)
        .subject_pubkey(b.verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
        .voucher
        .unwrap();
    let h1 = DelegationBuilder::new(&b, &voucher)
        .unwrap()
        .delegatee(c.aid().clone())
        .scope(["read_data"])
        .ttl_secs(6000)
        .now(NOW)
        .jti(Uuid::new_v4())
        .build()
        .unwrap();
    let outer = DelegationBuilder::extending(&c, &h1)
        .unwrap()
        .delegatee(d.aid().clone())
        .scope(["read_data"])
        .ttl_secs(3000)
        .now(NOW)
        .jti(Uuid::new_v4())
        .build()
        .unwrap();
    if let Err(e) = validate(&decoded_claims(&outer)) {
        panic!("multi-hop delegation claims failed schema validation:\n{e}");
    }
}

/// Drift firewall (RFC-AITP-0001 §7): `DELEGATION_CLAIMS_MEMBERS`, the
/// member set the unverified-peek claim-set check enforces in
/// `verify_delegation`/`DelegationBuilder`, must equal the vendored
/// `aitp-delegation.schema.json`'s declared member set. Like the TCT and
/// grant-voucher schemas, this compact-JWS-profile schema validates the
/// decoded claims object directly, so its `properties` sit at the top
/// level — no `properties.<wrapper>.properties` nesting.
#[test]
fn delegation_claims_members_matches_vendored_schema_properties() {
    let schema_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(schema_path()).expect("read vendored schema"))
            .expect("parse vendored delegation schema");

    let schema_properties: BTreeSet<String> = schema_json["properties"]
        .as_object()
        .expect("schema has a top-level `properties` object")
        .keys()
        .cloned()
        .collect();

    let rust_members: BTreeSet<String> = DELEGATION_CLAIMS_MEMBERS
        .iter()
        .map(|s| s.to_string())
        .collect();

    assert_eq!(
        rust_members, schema_properties,
        "DELEGATION_CLAIMS_MEMBERS has drifted from \
         tests/schemas/aitp-delegation.schema.json's top-level `properties` keys"
    );
}
