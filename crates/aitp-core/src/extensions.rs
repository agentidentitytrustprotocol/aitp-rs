//! Forward-compatible extension fields.
//!
//! Per RFC-AITP-0001 §6, every signed object reserves an `extensions` slot.
//! Unknown JSON fields _outside_ `extensions` MUST be rejected (because
//! signature canonicalization depends on the exact field set). Unknown keys
//! _inside_ `extensions` MAY be ignored.

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
    /// Used with `#[serde(skip_serializing_if = "ExtensionsMap::is_empty")]`
    /// so that empty extensions are omitted from canonical JSON entirely
    /// rather than serialized as `"extensions":{}` — this matters for
    /// signature interop.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Insert a key/value pair.
    pub fn insert(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.0.insert(key.into(), value);
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
