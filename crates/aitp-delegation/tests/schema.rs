//! Drift firewall: freshly minted delegation claims MUST validate
//! against the spec schema vendored at
//! `tests/schemas/aitp-delegation.schema.json` (which models the
//! decoded JWS payload).

use aitp_core::Timestamp;
use aitp_crypto::{jws, AitpSigningKey};
use aitp_delegation::DelegationBuilder;
use aitp_tct::TctBuilder;
use boon::{Compiler, Schemas};
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
