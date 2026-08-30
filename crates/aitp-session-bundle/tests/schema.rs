//! Drift firewall (RFC-AITP-0001 §7): `SESSION_BUNDLE_MEMBERS`, the
//! member set `parse_session_bundle_wire`'s body-level check enforces,
//! must equal the vendored schema's declared member set for the inner
//! `session_bundle` object — not a hand-maintained list that could
//! silently diverge from the spec.

use aitp_session_bundle::SESSION_BUNDLE_MEMBERS;
use std::collections::BTreeSet;
use std::path::PathBuf;

fn schema_path() -> PathBuf {
    // crate dir → workspace root → tests/schemas/
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("tests/schemas/aitp-session-bundle.schema.json")
}

#[test]
fn session_bundle_members_matches_vendored_schema_properties() {
    let path = schema_path();
    let schema_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read vendored session-bundle schema"))
            .expect("parse vendored session-bundle schema");

    let schema_properties: BTreeSet<String> = schema_json["properties"]["session_bundle"]
        ["properties"]
        .as_object()
        .expect("schema has a `properties.session_bundle.properties` object")
        .keys()
        .cloned()
        .collect();

    let rust_members: BTreeSet<String> = SESSION_BUNDLE_MEMBERS
        .iter()
        .map(|s| s.to_string())
        .collect();

    assert_eq!(
        rust_members, schema_properties,
        "SESSION_BUNDLE_MEMBERS has drifted from \
         tests/schemas/aitp-session-bundle.schema.json's \
         `properties.session_bundle.properties` keys"
    );
}
