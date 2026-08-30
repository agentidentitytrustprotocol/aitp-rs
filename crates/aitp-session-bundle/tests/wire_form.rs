//! `parse_session_bundle_wire` — the Session Trust Bundle transport
//! envelope (RFC-AITP-0010 §3), covered as a public-API integration test
//! separately from `src/wire.rs`'s in-crate unit tests.

use aitp_session_bundle::{parse_session_bundle_wire, SessionBundleError};
use serde_json::json;

fn valid_body() -> serde_json::Value {
    json!({
        "version": "aitp/0.2",
        "session_id": "00000000-0000-4000-8000-000000000000",
        "coordinator": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
        "issued_at": 1_700_000_000,
        "expires_at": 1_700_010_000,
        "participants": [],
        "signature": "A".repeat(86),
    })
}

#[test]
fn wrapped_with_signature_inside_is_ok() {
    let wire = json!({ "session_bundle": valid_body() });
    assert!(parse_session_bundle_wire(&wire).is_ok());
}

#[test]
fn bare_body_is_ok() {
    assert!(parse_session_bundle_wire(&valid_body()).is_ok());
}

/// `bundle-004-signature-sibling-rejected`: `signature` as a SIBLING of
/// the `{"session_bundle": …}` wrapper, absent from the inner body.
#[test]
fn sibling_signature_shape_is_wire_form_invalid() {
    let mut body = valid_body();
    let signature = body.as_object_mut().unwrap().remove("signature").unwrap();
    let wire = json!({ "session_bundle": body, "signature": signature });
    assert!(matches!(
        parse_session_bundle_wire(&wire),
        Err(SessionBundleError::WireFormInvalid(_))
    ));
}

#[test]
fn wrapper_with_unexpected_sibling_key_is_wire_form_invalid() {
    let wire = json!({ "session_bundle": valid_body(), "extensions_leak": {} });
    assert!(matches!(
        parse_session_bundle_wire(&wire),
        Err(SessionBundleError::WireFormInvalid(_))
    ));
}

#[test]
fn bare_body_missing_signature_with_no_sibling_is_wire_form_invalid() {
    let mut body = valid_body();
    body.as_object_mut().unwrap().remove("signature");
    assert!(matches!(
        parse_session_bundle_wire(&body),
        Err(SessionBundleError::WireFormInvalid(_))
    ));
}

/// `bundle-006-unknown-field-rejected`: an unknown member of the INNER
/// body — not a wrapper sibling, not inside `extensions` — is the
/// body-level `UnknownField` class, distinct from every
/// `WireFormInvalid` case above.
#[test]
fn unknown_inner_body_member_is_unknown_field() {
    let mut body = valid_body();
    body.as_object_mut()
        .unwrap()
        .insert("coordinator_note".into(), json!("primary-region"));
    let wire = json!({ "session_bundle": body });
    match parse_session_bundle_wire(&wire) {
        Err(SessionBundleError::UnknownField(field)) => assert_eq!(field, "coordinator_note"),
        other => panic!("expected UnknownField(\"coordinator_note\"), got {other:?}"),
    }
}
