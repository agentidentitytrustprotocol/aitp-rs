//! Unknown-member detection per RFC-AITP-0001 §7.
//!
//! §7 requires every schema-defined JSON object to reject members outside
//! its declared member set, while members *inside* a declared extension
//! namespace (e.g. `extensions`) are never inspected — the MUST-ignore half
//! of §7 is structural, not a policy choice made here.
//!
//! This module gives that rejection a name: [`check_members`] performs the
//! top-level member-set check directly against a [`serde_json::Value`], and
//! [`from_serde_error`] recovers the offending field name from a residual
//! `#[serde(deny_unknown_fields)]` failure raised by a *nested* closed
//! object (one this module never got a chance to check directly because it
//! lives inside a typed struct rather than a raw `Value`).

use std::collections::BTreeSet;

/// The offending member and the object it was found on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown field `{field}` in `{object}`")]
pub struct UnknownField {
    /// Name of the JSON member that was not in the object's declared
    /// member set.
    pub field: String,
    /// Name of the object the member was found on (for diagnostics only —
    /// not part of the wire format).
    pub object: &'static str,
}

/// Top-level member-set check (RFC-AITP-0001 §7).
///
/// `allowed` is the object's full schema-defined member set, INCLUDING the
/// extension-namespace key itself (e.g. `"extensions"`). Contents of that
/// namespace are never inspected — the MUST-ignore half of §7 is
/// structural here, not a policy: this function only ever looks at the
/// top-level keys of `value`.
///
/// Returns `Ok(())` if `value` is not a JSON object. "Not an object" is a
/// different defect, already owned by the existing typed deserialization
/// path, and must not be reclassified as `UNKNOWN_FIELD` here.
pub fn check_members(
    object: &'static str,
    value: &serde_json::Value,
    allowed: &[&str],
) -> Result<(), UnknownField> {
    let Some(map) = value.as_object() else {
        return Ok(());
    };
    let allowed: BTreeSet<&str> = allowed.iter().copied().collect();
    for key in map.keys() {
        if !allowed.contains(key.as_str()) {
            return Err(UnknownField {
                field: key.clone(),
                object,
            });
        }
    }
    Ok(())
}

/// Recover the offending field name from a residual serde
/// `deny_unknown_fields` failure raised by a NESTED closed object.
///
/// `serde`'s unknown-field error always begins with the literal prefix
/// `` unknown field `<name>` `` regardless of how many fields the target
/// struct declares (or none at all). This parses that prefix.
///
/// Returns `None` for anything else — a missing-field error, a type
/// mismatch, or (should serde's wording ever change) an unknown-field
/// error whose message no longer matches this shape. This is a documented
/// degradation path, never a gate: callers that get `None` here simply
/// fall back to their pre-existing error code, they never silently accept
/// the input.
pub fn from_serde_error(e: &serde_json::Error) -> Option<String> {
    let msg = e.to_string();
    let rest = msg.strip_prefix("unknown field `")?;
    let end = rest.find('`')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;

    // ---- check_members --------------------------------------------------

    #[test]
    fn allows_known_members_and_ignores_extension_namespace_contents() {
        let v = json!({"a": 1, "extensions": {"junk": 1}});
        assert_eq!(check_members("x", &v, &["a", "extensions"]), Ok(()));
    }

    #[test]
    fn rejects_a_member_outside_the_allowed_set() {
        let v = json!({"a": 1, "b": 2});
        let err = check_members("x", &v, &["a"]).unwrap_err();
        assert_eq!(err.field, "b");
        assert_eq!(err.object, "x");
    }

    #[test]
    fn does_not_recurse_into_the_extension_namespace() {
        // An arbitrary junk key nested inside `extensions` must never be
        // reported: contents of the namespace are never inspected.
        let v = json!({
            "extensions": {
                "junk_key_of_any_shape": {"deeply": {"nested": true}},
            }
        });
        assert_eq!(check_members("x", &v, &["extensions"]), Ok(()));
    }

    #[test]
    fn non_object_value_is_ok() {
        assert_eq!(check_members("x", &json!("a string"), &["a"]), Ok(()));
        assert_eq!(check_members("x", &json!(null), &["a"]), Ok(()));
        assert_eq!(check_members("x", &json!(42), &["a"]), Ok(()));
        assert_eq!(check_members("x", &json!([1, 2, 3]), &["a"]), Ok(()));
    }

    #[test]
    fn empty_object_with_no_allowed_members_is_ok() {
        assert_eq!(check_members("x", &json!({}), &[]), Ok(()));
    }

    // ---- from_serde_error -------------------------------------------------

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Closed {
        #[allow(dead_code)]
        a: i64,
    }

    #[test]
    fn recovers_field_name_from_unknown_field_error() {
        let err = serde_json::from_str::<Closed>(r#"{"a":1,"zzz":2}"#).unwrap_err();
        assert_eq!(from_serde_error(&err), Some("zzz".to_string()));
    }

    #[test]
    fn returns_none_for_missing_field_error() {
        let err = serde_json::from_str::<Closed>(r#"{}"#).unwrap_err();
        assert_eq!(from_serde_error(&err), None);
    }

    #[test]
    fn returns_none_for_type_mismatch_error() {
        let err = serde_json::from_str::<Closed>(r#"{"a":"not a number"}"#).unwrap_err();
        assert_eq!(from_serde_error(&err), None);
    }
}
