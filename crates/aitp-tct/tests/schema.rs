//! Drift firewall: a fresh `TctEnvelope` MUST validate against the
//! AITP TCT JSON Schema vendored under `tests/schemas/aitp-tct.schema.json`.

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_tct::{sign_revocation_list, RevocationEntry, RevocationList, TctBuilder, TctEnvelope};
use boon::{Compiler, Schemas};
use std::path::PathBuf;
use uuid::Uuid;

fn schema_path() -> PathBuf {
    schema_path_for("aitp-tct.schema.json")
}

fn schema_path_for(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("tests/schemas")
        .join(name)
}

fn validate(value: &serde_json::Value) -> Result<(), String> {
    validate_against(value, schema_path())
}

fn validate_against(value: &serde_json::Value, path: PathBuf) -> Result<(), String> {
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
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

#[test]
fn populated_tct_envelope_validates() {
    let issuer = AitpSigningKey::from_seed(&[0xA0; 32]);
    let subject = AitpSigningKey::from_seed(&[0xB0; 32]);
    let tct = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["demo.echo", "demo.respond"])
        .ttl_secs(3600)
        .subject_pubkey(subject.verifying_key())
        .issued_at(Timestamp(1_700_000_000))
        .build()
        .unwrap();
    let env = TctEnvelope { tct };
    let value = serde_json::to_value(&env).unwrap();
    if let Err(e) = validate(&value) {
        panic!("TCT envelope failed schema validation:\n{e}");
    }
}

#[test]
fn tct_with_unknown_field_rejected() {
    let issuer = AitpSigningKey::from_seed(&[0xA0; 32]);
    let subject = AitpSigningKey::from_seed(&[0xB0; 32]);
    let tct = TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["demo.echo"])
        .ttl_secs(3600)
        .subject_pubkey(subject.verifying_key())
        .issued_at(Timestamp(1_700_000_000))
        .build()
        .unwrap();
    let env = TctEnvelope { tct };
    let mut value = serde_json::to_value(&env).unwrap();
    value["tct"]
        .as_object_mut()
        .unwrap()
        .insert("rogue".into(), serde_json::json!("nope"));
    let err = validate(&value).expect_err("schema must reject unknown TCT field");
    assert!(
        err.contains("rogue") || err.contains("additionalProperties"),
        "unexpected error: {err}"
    );
}

#[test]
fn signed_revocation_list_validates_against_spec_schema() {
    let issuer = AitpSigningKey::from_seed(&[0xA0; 32]);
    let body = RevocationList {
        version: "aitp/0.1".into(),
        issuer: issuer.aid().clone(),
        published_at: Timestamp(1_700_000_000),
        expires_at: Timestamp(1_700_003_600),
        entries: vec![RevocationEntry {
            jti: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            revoked_at: Timestamp(1_700_001_000),
            reason: None,
        }],
    };
    let env = sign_revocation_list(body, &issuer).unwrap();
    let value = serde_json::to_value(&env).unwrap();
    if let Err(e) = validate_against(&value, schema_path_for("aitp-revocation-list.schema.json")) {
        panic!("Signed revocation list failed schema validation:\n{e}");
    }
}

#[test]
fn empty_entries_revocation_list_validates() {
    let issuer = AitpSigningKey::from_seed(&[0xA0; 32]);
    let body = RevocationList {
        version: "aitp/0.1".into(),
        issuer: issuer.aid().clone(),
        published_at: Timestamp(1_700_000_000),
        expires_at: Timestamp(1_700_003_600),
        entries: vec![],
    };
    let env = sign_revocation_list(body, &issuer).unwrap();
    let value = serde_json::to_value(&env).unwrap();
    if let Err(e) = validate_against(&value, schema_path_for("aitp-revocation-list.schema.json")) {
        panic!("Empty-entries revocation list failed schema validation:\n{e}");
    }
}
