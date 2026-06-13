//! Drift firewall: freshly minted artifacts MUST validate against the
//! spec JSON Schemas vendored under `tests/schemas/`.
//!
//! In v0.2 the TCT and grant-voucher schemas validate the **decoded
//! claims object** (the wire form is an opaque compact JWS string).

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_tct::{sign_revocation_list, RevocationEntry, RevocationList, TctBuilder};
use boon::{Compiler, Schemas};
use std::path::PathBuf;
use uuid::Uuid;

fn schema_path_for(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("tests/schemas")
        .join(name)
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

fn issue() -> aitp_tct::IssuedTct {
    let issuer = AitpSigningKey::from_seed(&[0xA0; 32]);
    let subject = AitpSigningKey::from_seed(&[0xB0; 32]);
    TctBuilder::new(&issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["demo.echo", "demo.respond"])
        .ttl_secs(3600)
        .subject_pubkey(subject.verifying_key())
        .issued_at(Timestamp(1_700_000_000))
        .build()
        .unwrap()
}

#[test]
fn minted_tct_claims_validate() {
    let issued = issue();
    let value = serde_json::to_value(&issued.claims).unwrap();
    if let Err(e) = validate_against(&value, schema_path_for("aitp-tct.schema.json")) {
        panic!("TCT claims failed schema validation:\n{e}");
    }
}

#[test]
fn tct_claims_with_unknown_field_rejected() {
    let issued = issue();
    let mut value = serde_json::to_value(&issued.claims).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("rogue".into(), serde_json::json!("nope"));
    let err = validate_against(&value, schema_path_for("aitp-tct.schema.json"))
        .expect_err("schema must reject unknown TCT claim");
    assert!(
        err.contains("rogue") || err.contains("additionalProperties"),
        "unexpected error: {err}"
    );
}

#[test]
fn minted_voucher_claims_validate() {
    let issued = issue();
    let voucher_token = issued.voucher.as_deref().unwrap();
    let payload = aitp_crypto::jws::decode_payload_unverified(voucher_token).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    if let Err(e) = validate_against(&value, schema_path_for("aitp-grant-voucher.schema.json")) {
        panic!("grant-voucher claims failed schema validation:\n{e}");
    }
}

#[test]
fn minted_tokens_match_compact_jws_pattern() {
    // The wire form everywhere a token embeds in JSON: exactly three
    // non-empty base64url segments.
    let issued = issue();
    let re = regex_lite();
    for token in [issued.token.as_str(), issued.voucher.as_deref().unwrap()] {
        assert!(
            re(token),
            "token does not match CompactJws pattern: {token}"
        );
    }
}

/// Minimal local check mirroring the schema's CompactJws `pattern`
/// (`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`).
fn regex_lite() -> impl Fn(&str) -> bool {
    |s: &str| {
        let parts: Vec<&str> = s.split('.').collect();
        parts.len() == 3
            && parts.iter().all(|p| {
                !p.is_empty()
                    && p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
    }
}

#[test]
fn signed_revocation_list_validates_against_spec_schema() {
    let issuer = AitpSigningKey::from_seed(&[0xA0; 32]);
    let body = RevocationList {
        version: "aitp/0.2".into(),
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
        version: "aitp/0.2".into(),
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
