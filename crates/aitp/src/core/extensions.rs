//! Forward-compatible extension fields.
//!
//! Per RFC-AITP-0001 §7, every signed object reserves an `extensions` slot.
//! Unknown JSON fields _outside_ `extensions` MUST be rejected (because
//! signature canonicalization depends on the exact field set). Unknown keys
//! _inside_ `extensions` MUST be ignored.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A map of vendor-namespaced extension values.
///
/// Keys SHOULD use a reverse-DNS-style prefix (e.g. `vendor.example/feature`)
/// to avoid collisions across implementations. The map preserves insertion
/// order for stable canonicalization.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExtensionsMap(BTreeMap<String, serde_json::Value>);

impl ExtensionsMap {
    /// Construct an empty extensions map.
    pub fn new() -> Self {
        Self::default()
    }

    /// True if no extensions are set.
    ///
    /// Callers embedding this map in a signed struct MUST wrap the field
    /// as `Option<ExtensionsMap>` with
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]`, NOT
    /// `skip_serializing_if = "ExtensionsMap::is_empty"` on a bare
    /// (non-`Option`) field — the latter conflates an absent `extensions`
    /// member with a present-but-empty `"extensions":{}`, which are
    /// different canonical bytes and therefore different signatures
    /// (RFC-AITP-0001 §5.4.1). See `docs/jcs.md` for the full rationale
    /// and the list of types that follow this pattern. This method exists
    /// for callers that only need to check emptiness directly, not as a
    /// `skip_serializing_if` target.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Insert a key/value pair.
    pub fn insert(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.0.insert(key.into(), value);
    }

    /// True if `key` is set.
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    /// Get a value by key.
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.0.get(key)
    }

    /// Iterate over key/value pairs in canonical (sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &serde_json::Value)> {
        self.0.iter()
    }
}

impl From<serde_json::Map<String, serde_json::Value>> for ExtensionsMap {
    fn from(map: serde_json::Map<String, serde_json::Value>) -> Self {
        map.into_iter().collect()
    }
}

impl<K: Into<String>> FromIterator<(K, serde_json::Value)> for ExtensionsMap {
    fn from_iter<I: IntoIterator<Item = (K, serde_json::Value)>>(iter: I) -> Self {
        Self(iter.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Holder {
        #[serde(default, skip_serializing_if = "ExtensionsMap::is_empty")]
        extensions: ExtensionsMap,
    }

    #[test]
    fn empty_is_empty() {
        let m = ExtensionsMap::new();
        assert!(m.is_empty());
    }

    #[test]
    fn after_insert_not_empty() {
        let mut m = ExtensionsMap::new();
        m.insert("vendor.example/foo", json!({"x": 1}));
        assert!(!m.is_empty());
        assert_eq!(m.get("vendor.example/foo"), Some(&json!({"x": 1})));
    }

    #[test]
    fn round_trip_with_extension() {
        let mut m = ExtensionsMap::new();
        m.insert("vendor.example/foo", json!({"x": 1}));
        let h = Holder { extensions: m };
        let s = serde_json::to_string(&h).unwrap();
        assert!(s.contains("vendor.example/foo"));
        let back: Holder = serde_json::from_str(&s).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn empty_extensions_omitted_from_canonical_json() {
        let h = Holder {
            extensions: ExtensionsMap::new(),
        };
        let s = serde_json::to_string(&h).unwrap();
        // skip_serializing_if drops the field entirely when empty.
        assert_eq!(s, "{}");
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct OptHolder {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ext: Option<ExtensionsMap>,
    }

    #[test]
    fn unknown_members_round_trip_byte_identically_through_jcs() {
        let raw = json!({"ext": {
            "org.example.z": {"b": [1, 2.5, "x", null], "a": {"nested": true}},
            "com.example.a": "caf\u{e9}",
        }});
        let parsed: OptHolder = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(
            crate::core::jcs::canonicalize_serializable(&parsed).unwrap(),
            crate::core::jcs::canonicalize_serializable(&raw).unwrap()
        );
    }

    #[test]
    fn absent_and_empty_canonicalize_differently() {
        let absent: OptHolder = serde_json::from_value(json!({})).unwrap();
        let empty: OptHolder = serde_json::from_value(json!({"ext": {}})).unwrap();
        let jcs = |h: &OptHolder| crate::core::jcs::canonicalize_serializable(h).unwrap();
        assert_eq!(jcs(&absent), b"{}");
        assert_eq!(jcs(&empty), br#"{"ext":{}}"#);
    }

    #[test]
    fn from_map_and_collect_agree() {
        let map = json!({"a": 1, "b": 2}).as_object().unwrap().clone();
        let collected: ExtensionsMap = [("a", json!(1)), ("b", json!(2))].into_iter().collect();
        assert_eq!(ExtensionsMap::from(map), collected);
        assert!(collected.contains_key("a"));
        assert!(!collected.contains_key("c"));
    }

    #[test]
    fn keys_iterate_in_sorted_order() {
        let mut m = ExtensionsMap::new();
        m.insert("z", json!(1));
        m.insert("a", json!(2));
        m.insert("m", json!(3));
        let order: Vec<_> = m.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(order, vec!["a", "m", "z"]);
    }
}
