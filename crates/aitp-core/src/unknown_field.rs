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
//!
//! A third function, [`reject_duplicate_keys`], guards the step that runs
//! *before* either of the above: every `parse_*_wire` entry point in this
//! workspace inspects a member set by first producing a
//! [`serde_json::Value`] from the wire bytes. `Value`'s object
//! representation is last-write-wins on a duplicate JSON key — by the time
//! a `Value` exists, RFC-AITP-0001 §5.4.5's duplicate-key rejection is
//! already impossible to perform. [`reject_duplicate_keys`] operates on the
//! raw bytes instead, before any `Value` is built.

use std::collections::{BTreeSet, HashSet};

use serde::de::{DeserializeSeed, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};

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

/// Detects a duplicate key anywhere in a JSON document's object structure
/// (recursively, at every nesting level) directly from raw bytes/text —
/// deliberately BEFORE any `serde_json::Value` exists. `Value`'s map
/// representation is last-write-wins on a duplicate key (RFC-AITP-0001
/// §5.4.5 requires the opposite), so parsing to `Value` first — which
/// [`check_members`] and every `parse_*_wire` function in this workspace
/// must do to inspect a member set ahead of a typed deserialize — silently
/// forfeits serde-derive's usual automatic duplicate-field rejection.
/// Every entry point that begins a wire parse by producing a `Value` MUST
/// call this against the ORIGINAL bytes first.
///
/// Returns `Ok(())` when `bytes` is not a JSON object at all (a bare
/// scalar, array-of-scalars, etc.) — rejecting a non-object top level is a
/// different defect, owned by the caller's existing typed deserialize, not
/// this function's job. It also returns `Ok(())` for a malformed-but-not-
/// object top level such as a bare array, matching [`check_members`]'s own
/// "not an object is not this function's problem" contract; a genuine JSON
/// syntax error surfaces as `Err` with serde_json's own diagnostic text,
/// which every call site maps to the same malformed/parse-failure class it
/// already uses for a `Value` parse failure, so pre-empting that parse
/// with this check never changes behavior for non-duplicate-key input.
pub fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), String> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    Deserializer::deserialize_any(&mut de, DuplicateKeyChecker).map_err(|e| e.to_string())
}

/// A `Visitor`/`DeserializeSeed` that walks a JSON document purely to
/// detect a duplicate object key, at any nesting level. It never collects
/// or returns any of the document's actual values — "look but don't
/// collect".
#[derive(Clone, Copy)]
struct DuplicateKeyChecker;

impl<'de> DeserializeSeed<'de> for DuplicateKeyChecker {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for DuplicateKeyChecker {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen: HashSet<String> = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom(format!("duplicate field `{key}`")));
            }
            map.next_value_seed(DuplicateKeyChecker)?;
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element_seed(DuplicateKeyChecker)?.is_some() {}
        Ok(())
    }

    fn visit_bool<E>(self, _v: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _v: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_i128<E>(self, _v: i128) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _v: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u128<E>(self, _v: u128) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _v: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _v: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_bytes<E>(self, _v: &[u8]) -> Result<(), E> {
        Ok(())
    }

    fn visit_char<E>(self, _v: char) -> Result<(), E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
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

    // ---- reject_duplicate_keys --------------------------------------------

    #[test]
    fn rejects_duplicate_key_at_top_level() {
        let bytes = br#"{"version":"aitp/0.2","version":"aitp/0.3"}"#;
        let err = reject_duplicate_keys(bytes).unwrap_err();
        assert!(err.contains("duplicate field `version`"), "got: {err}");
    }

    #[test]
    fn rejects_duplicate_key_in_nested_object() {
        let bytes = br#"{"a": {"x": 1, "x": 2}}"#;
        let err = reject_duplicate_keys(bytes).unwrap_err();
        assert!(err.contains("duplicate field `x`"), "got: {err}");
    }

    #[test]
    fn rejects_duplicate_key_in_object_nested_inside_array() {
        let bytes = br#"{"entries": [{"jti": "a"}, {"x":1,"x":2}]}"#;
        let err = reject_duplicate_keys(bytes).unwrap_err();
        assert!(err.contains("duplicate field `x`"), "got: {err}");
    }

    #[test]
    fn rejects_duplicate_key_several_levels_deep_inside_arrays_and_objects() {
        // entries[] -> object -> nested object -> duplicate.
        let bytes = br#"{"entries": [{"cnf": {"jkt": "a", "jkt": "b"}}]}"#;
        let err = reject_duplicate_keys(bytes).unwrap_err();
        assert!(err.contains("duplicate field `jkt`"), "got: {err}");
    }

    #[test]
    fn accepts_document_with_no_duplicates_at_any_level() {
        let bytes = br#"{
            "version": "aitp/0.2",
            "sender": {"agent_id": "aid:pubkey:abc"},
            "entries": [
                {"jti": "a", "cnf": {"jkt": "x"}},
                {"jti": "b", "cnf": {"jkt": "y"}}
            ],
            "extensions": {"com.example/foo": {"a": 1, "b": 2}}
        }"#;
        assert_eq!(reject_duplicate_keys(bytes), Ok(()));
    }

    #[test]
    fn bare_scalar_top_level_is_ok_not_this_functions_job() {
        assert_eq!(reject_duplicate_keys(b"42"), Ok(()));
        assert_eq!(reject_duplicate_keys(b"\"a string\""), Ok(()));
        assert_eq!(reject_duplicate_keys(b"null"), Ok(()));
        assert_eq!(reject_duplicate_keys(b"true"), Ok(()));
        assert_eq!(reject_duplicate_keys(b"[1,2,3]"), Ok(()));
    }

    #[test]
    fn malformed_non_duplicate_json_still_errs_but_not_as_a_duplicate() {
        // Not this function's headline job, but it must not panic, and
        // must not misreport a plain syntax error as a duplicate field.
        let err = reject_duplicate_keys(b"{not json").unwrap_err();
        assert!(!err.contains("duplicate field"), "got: {err}");
    }

    /// A real, deeply-nested signed fixture (session bundle: top-level
    /// object, `participants[]` array of objects) round-trips cleanly
    /// with no false positive.
    #[test]
    fn realistic_signed_fixture_has_no_false_positive() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root")
            .join("tests/schemas/known-answer/signed-examples/session-bundle/kat-keypair-001-bundle.json");
        let bytes = std::fs::read(&path).unwrap_or_else(|e| {
            panic!("read {}: {e}", path.display());
        });
        assert_eq!(reject_duplicate_keys(&bytes), Ok(()));
    }
}
