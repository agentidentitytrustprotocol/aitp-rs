//! Drift firewall: a fresh `DelegationEnvelope` MUST validate against the
//! AITP delegation JSON Schema vendored under
//! `tests/schemas/aitp-delegation.schema.json`.

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_delegation::{DelegationBuilder, DelegationEnvelope};
use aitp_tct::{Tct, TctBuilder};
use boon::{Compiler, Schemas};
use std::path::PathBuf;

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
    let path = schema_path();
    let schema_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read schema")).expect("parse schema");
    let url = format!("file://{}", path.display());
    compiler
        .add_resource(&url, schema_json)
        .map_err(|e| e.to_string())?;
    let id = compiler
        .compile(&url, &mut schemas)
        .map_err(|e| e.to_string())?;
    schemas.validate(value, id).map_err(|e| e.to_string())
}

fn alice_to_bob_tct() -> Tct {
    let alice = AitpSigningKey::from_seed(&[0xA0; 32]);
    let bob = AitpSigningKey::from_seed(&[0xB0; 32]);
    TctBuilder::new(&alice)
        .subject(bob.aid().clone())
        .audience(bob.aid().clone())
        .grants(["read_data", "write_data"])
        .ttl_secs(3600)
        .subject_pubkey(bob.verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
}

#[test]
fn populated_delegation_envelope_validates() {
    let bob = AitpSigningKey::from_seed(&[0xB0; 32]);
    let carol = AitpSigningKey::from_seed(&[0xC0; 32]);
    let tct_b = alice_to_bob_tct();

    let delegation = DelegationBuilder::new(&bob, &tct_b)
        .delegatee(carol.aid().clone())
        .delegatee_pubkey(carol.verifying_key())
        .scope(["read_data"])
        .ttl_secs(1800)
        .now(NOW)
        .build()
        .unwrap();
    let env = DelegationEnvelope { delegation };
    let value = serde_json::to_value(&env).unwrap();
    if let Err(e) = validate(&value) {
        panic!("Delegation envelope failed schema validation:\n{e}");
    }
}
