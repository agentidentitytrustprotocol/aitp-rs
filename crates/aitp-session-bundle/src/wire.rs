//! Wire-form parsing for the Session Trust Bundle transport envelope
//! (RFC-AITP-0010 §3, §5).

use crate::error::SessionBundleError;
use crate::types::{SessionBundleEnvelope, SessionTrustBundle, SESSION_BUNDLE_MEMBERS};
use aitp_core::{check_members, from_serde_error};
use serde_json::Value;

/// Full member set of the `{"session_bundle": {...}}` transport
/// wrapper. Per RFC-AITP-0010 §3 the wrapper is `additionalProperties:
/// false`: no member besides `session_bundle` is ever permitted, not
/// even in a future schema revision, since the wrapper's sole purpose
/// is to carry the signed body.
const SESSION_BUNDLE_ENVELOPE_MEMBERS: &[&str] = &["session_bundle"];

/// Parse a session bundle from its on-the-wire JSON.
///
/// Accepts the spec transport envelope `{"session_bundle": {<body incl.
/// `signature`>}}` and, for internal callers that never wrap, a bare
/// body. This function is where RFC-AITP-0010's two DISTINCT failure
/// classes are told apart, by WHERE a violation occurs:
///
/// - **Wrapper-level** (§3): when a `{"session_bundle": …}` wrapper is
///   present, its member set MUST be exactly `{session_bundle}`. Any
///   sibling member — notably the pre-erratum shape where `signature`
///   sat OUTSIDE the wrapped body — is a wire-FORM defect:
///   [`SessionBundleError::WireFormInvalid`], which the error-code
///   mapping surfaces as `SESSION_BUNDLE_INVALID`.
/// - **Body-level** (§5): once the wrapper shape (if any) is confirmed
///   valid, the inner body's member set is checked against
///   [`SESSION_BUNDLE_MEMBERS`]. A member outside that set is not a wire
///   defect — the wrapper/no-wrapper shape was correct — but an unknown
///   member of the signed artifact itself:
///   [`SessionBundleError::UnknownField`], the **core** `UNKNOWN_FIELD`
///   code (RFC-AITP-0001 §7), even though the session-bundle artifact
///   is itself draft. This check runs before any cryptographic work,
///   including the coordinator key resolution used to verify the outer
///   signature (RFC-AITP-0010 §5 step 5) — a bundle with an unknown body
///   member is rejected without ever deriving that key.
/// - Once both member-set checks pass, the value is typed-deserialized.
///   A residual `#[serde(deny_unknown_fields)]` error at that point can
///   only come from a NESTED closed object (a `participants[]` entry);
///   [`from_serde_error`] recovers the offending field name so it, too,
///   reports [`SessionBundleError::UnknownField`] rather than a generic
///   parse failure.
///
/// The bare-body path (no wrapper, used by internal callers) applies the
/// SAME body-level member-set check as the wrapped form, so the two
/// entry points never disagree about what a valid body looks like.
pub fn parse_session_bundle_wire(value: &Value) -> Result<SessionTrustBundle, SessionBundleError> {
    if value.get("session_bundle").is_some() {
        check_members(
            "SessionBundleEnvelope",
            value,
            SESSION_BUNDLE_ENVELOPE_MEMBERS,
        )
        .map_err(|e| {
            SessionBundleError::WireFormInvalid(format!(
                "transport envelope: unknown field `{}` (RFC-AITP-0010 §3 places \
                 `signature` inside the signed body, never beside the wrapper)",
                e.field
            ))
        })?;

        let body = value.get("session_bundle").expect("checked above");
        check_members("SessionTrustBundle", body, SESSION_BUNDLE_MEMBERS)
            .map_err(|e| SessionBundleError::UnknownField(e.field))?;

        let env: SessionBundleEnvelope = serde_json::from_value(value.clone()).map_err(|e| {
            if let Some(field) = from_serde_error(&e) {
                SessionBundleError::UnknownField(field)
            } else {
                SessionBundleError::WireFormInvalid(format!("transport envelope: {e}"))
            }
        })?;
        Ok(env.session_bundle)
    } else {
        check_members("SessionTrustBundle", value, SESSION_BUNDLE_MEMBERS)
            .map_err(|e| SessionBundleError::UnknownField(e.field))?;

        serde_json::from_value(value.clone()).map_err(|e| {
            if let Some(field) = from_serde_error(&e) {
                SessionBundleError::UnknownField(field)
            } else {
                SessionBundleError::WireFormInvalid(format!("bundle body: {e}"))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_body() -> Value {
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
    fn wrapped_with_signature_inside_parses() {
        let wire = json!({ "session_bundle": valid_body() });
        assert!(parse_session_bundle_wire(&wire).is_ok());
    }

    #[test]
    fn bare_body_parses() {
        assert!(parse_session_bundle_wire(&valid_body()).is_ok());
    }

    #[test]
    fn sibling_signature_is_rejected() {
        let mut body = valid_body();
        let signature = body.as_object_mut().unwrap().remove("signature").unwrap();
        let wire = json!({ "session_bundle": body, "signature": signature });
        assert!(matches!(
            parse_session_bundle_wire(&wire),
            Err(SessionBundleError::WireFormInvalid(_))
        ));
    }

    #[test]
    fn unexpected_sibling_key_is_rejected() {
        let wire = json!({ "session_bundle": valid_body(), "extra": "nope" });
        assert!(matches!(
            parse_session_bundle_wire(&wire),
            Err(SessionBundleError::WireFormInvalid(_))
        ));
    }

    #[test]
    fn bare_body_missing_signature_is_rejected() {
        let mut body = valid_body();
        body.as_object_mut().unwrap().remove("signature");
        assert!(matches!(
            parse_session_bundle_wire(&body),
            Err(SessionBundleError::WireFormInvalid(_))
        ));
    }

    /// `bundle-006-unknown-field-rejected`: an unknown member of the
    /// INNER body (not inside `extensions`, not a wrapper sibling) is a
    /// body-level defect, distinct from the wrapper-level
    /// `WireFormInvalid` cases above.
    #[test]
    fn unknown_body_member_is_unknown_field() {
        let mut body = valid_body();
        body.as_object_mut()
            .unwrap()
            .insert("coordinator_note".into(), json!("primary-region"));
        let wire = json!({ "session_bundle": body });
        match parse_session_bundle_wire(&wire) {
            Err(SessionBundleError::UnknownField(field)) => {
                assert_eq!(field, "coordinator_note")
            }
            other => panic!("expected UnknownField(\"coordinator_note\"), got {other:?}"),
        }
    }

    /// Same body-level defect via the bare-body entry point: the two
    /// entry points must not disagree about what a valid body looks
    /// like.
    #[test]
    fn unknown_bare_body_member_is_unknown_field() {
        let mut body = valid_body();
        body.as_object_mut()
            .unwrap()
            .insert("rogue".into(), json!(1));
        match parse_session_bundle_wire(&body) {
            Err(SessionBundleError::UnknownField(field)) => assert_eq!(field, "rogue"),
            other => panic!("expected UnknownField(\"rogue\"), got {other:?}"),
        }
    }

    /// A member inside `extensions` is never inspected — the MUST-ignore
    /// half of RFC-AITP-0001 §7 — even though the body-level member-set
    /// check now runs (`bundle-005-extensions-accepted`'s ignore-half
    /// guard, at the wire-parsing layer rather than full verification).
    #[test]
    fn extensions_contents_are_never_treated_as_unknown_members() {
        let mut body = valid_body();
        body.as_object_mut()
            .unwrap()
            .insert("extensions".into(), json!({ "tee": { "platform": "sgx" } }));
        let wire = json!({ "session_bundle": body });
        assert!(parse_session_bundle_wire(&wire).is_ok());
    }

    /// A nested closed object (`participants[]` entry) with an unknown
    /// member is not caught by the top-level [`SESSION_BUNDLE_MEMBERS`]
    /// check — that only inspects the body's own keys — but the residual
    /// `deny_unknown_fields` error from `ParticipantEntry` is still
    /// recovered via `from_serde_error` and reported as `UnknownField`,
    /// never a generic parse failure.
    #[test]
    fn unknown_participant_entry_member_is_unknown_field_via_from_serde_error() {
        let mut body = valid_body();
        body["participants"] = json!([{
            "aid": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "tct": "a.b.c",
            "rogue": "nope",
        }]);
        let wire = json!({ "session_bundle": body });
        match parse_session_bundle_wire(&wire) {
            Err(SessionBundleError::UnknownField(field)) => assert_eq!(field, "rogue"),
            other => panic!("expected UnknownField(\"rogue\"), got {other:?}"),
        }
    }

    /// The security property RFC-AITP-0010 §5 places this check for: even
    /// a bundle whose `coordinator` is not a resolvable AID at all is
    /// rejected on its unknown body member BEFORE anything downstream
    /// would attempt to interpret — let alone resolve — that field. The
    /// member-set check operates purely on the raw JSON key set, so it
    /// never reaches, parses, or resolves `coordinator`.
    #[test]
    fn unknown_body_member_is_rejected_before_coordinator_key_resolution() {
        let mut body = valid_body();
        // Not a well-formed AID at all — if this were ever parsed or a
        // key derived from it, that would panic or error with something
        // other than UnknownField. It never gets that far.
        body["coordinator"] = json!("not-an-aid-and-not-even-attempted");
        body.as_object_mut()
            .unwrap()
            .insert("rogue".into(), json!("nope"));
        let wire = json!({ "session_bundle": body });
        match parse_session_bundle_wire(&wire) {
            Err(SessionBundleError::UnknownField(field)) => assert_eq!(field, "rogue"),
            other => panic!(
                "expected the unknown-member check to short-circuit before `coordinator` is \
                 ever interpreted, got {other:?}"
            ),
        }
    }
}
