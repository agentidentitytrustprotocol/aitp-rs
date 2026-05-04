//! Drift firewall: serialize a fully-populated Manifest and validate the
//! result against the AITP JSON Schema vendored under
//! `tests/schemas/aitp-manifest.schema.json`.
//!
//! This catches the class of drift that prompted the alpha.2 RFC-alignment
//! work — fields appearing in the Rust types but not in the schema, or
//! vice versa. The schema sets `additionalProperties: false`, so any
//! extra field on the wire fails validation here.

use aitp_core::ExtensionsMap;
use aitp_crypto::AitpSigningKey;
use aitp_manifest::{IdentityHint, IdentityHintKind, ManifestBuilder, ManifestEnvelope};
use boon::{Compiler, Schemas};
use std::path::PathBuf;

fn schema_path() -> PathBuf {
    // crate dir → workspace root → tests/schemas/
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf();
    workspace_root.join("tests/schemas/aitp-manifest.schema.json")
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

fn populated_manifest() -> aitp_manifest::Manifest {
    let key = AitpSigningKey::from_seed(&[0xAA; 32]);
    ManifestBuilder::new(&key)
        .display_name("alice")
        .handshake_endpoint("https://a.example.com/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "alice".into(),
            issuer: None,
            public_key: Some(aitp_core::base64url::encode(
                &key.verifying_key().to_bytes(),
            )),
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .require("demo.respond")
        .extension(
            "vendor.example/feature",
            serde_json::json!({"enabled": true}),
        )
        .ttl_secs(3600)
        .build()
        .unwrap()
}

#[test]
fn populated_manifest_validates_against_spec_schema() {
    let env = ManifestEnvelope {
        manifest: populated_manifest(),
    };
    let value = serde_json::to_value(&env).unwrap();
    if let Err(e) = validate(&value) {
        panic!("Manifest envelope failed schema validation:\n{e}");
    }
}

#[test]
fn minimal_manifest_validates_against_spec_schema() {
    // The smallest manifest the builder will produce — only required
    // fields, no display_name, no extensions, no required_peer_capabilities.
    let key = AitpSigningKey::from_seed(&[0xAB; 32]);
    let mut m = ManifestBuilder::new(&key)
        .handshake_endpoint("https://a.example.com/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::Oidc,
            subject: "agent-a".into(),
            issuer: Some("https://idp.example.com".parse().unwrap()),
            public_key: None,
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .offer("demo.echo")
        .build()
        .unwrap();
    // Belt-and-braces: clear extensions to confirm the empty-map path
    // also validates (it should be skipped from serialization entirely).
    m.extensions = ExtensionsMap::new();
    let env = ManifestEnvelope { manifest: m };
    let value = serde_json::to_value(&env).unwrap();
    if let Err(e) = validate(&value) {
        panic!("Minimal Manifest envelope failed schema validation:\n{e}");
    }
}

#[test]
fn manifest_with_legacy_description_is_rejected_by_schema() {
    // Direct guard against D-1 regression: even if someone sneaks the
    // `description` field back into the wire bytes, the spec schema will
    // refuse it.
    let env = ManifestEnvelope {
        manifest: populated_manifest(),
    };
    let mut value = serde_json::to_value(&env).unwrap();
    value["manifest"]
        .as_object_mut()
        .unwrap()
        .insert("description".into(), serde_json::json!("oops"));
    let err = validate(&value).expect_err("schema must reject legacy description field");
    assert!(
        err.contains("description") || err.contains("additionalProperties"),
        "unexpected error: {err}"
    );
}
