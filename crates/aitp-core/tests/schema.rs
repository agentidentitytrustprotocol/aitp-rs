//! Drift firewall: `AITP_ENVELOPE_MEMBERS` must equal the top-level
//! `properties` key set of the vendored `aitp-envelope.schema.json`.
//!
//! This anchors the hand-maintained member list used by
//! `parse_envelope_wire`'s RFC-AITP-0001 §7 member-set check to the actual
//! spec schema, rather than to the Rust struct — the schema is the
//! stronger anchor and is itself kept in sync with the pinned spec commit
//! by the `vendored schemas in sync` CI job.

use aitp_core::AITP_ENVELOPE_MEMBERS;
use std::collections::BTreeSet;
use std::path::PathBuf;

fn schema_path() -> PathBuf {
    // crate dir -> workspace root -> tests/schemas/
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf();
    workspace_root.join("tests/schemas/aitp-envelope.schema.json")
}

#[test]
fn envelope_members_matches_vendored_schema_properties() {
    let path = schema_path();
    let schema_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read vendored envelope schema"))
            .expect("parse vendored envelope schema");

    let schema_properties: BTreeSet<String> = schema_json["properties"]
        .as_object()
        .expect("schema has a top-level `properties` object")
        .keys()
        .cloned()
        .collect();

    let rust_members: BTreeSet<String> = AITP_ENVELOPE_MEMBERS
        .iter()
        .map(|s| s.to_string())
        .collect();

    assert_eq!(
        rust_members, schema_properties,
        "AITP_ENVELOPE_MEMBERS has drifted from tests/schemas/aitp-envelope.schema.json's \
         `properties` keys"
    );
}
