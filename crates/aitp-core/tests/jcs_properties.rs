//! JCS property tests.
//!
//! Three properties hold for every JSON value (within the reachable input
//! space — proptest generates bounded trees):
//!
//! - **Idempotence** — canonicalize(parse(canonicalize(x))) == canonicalize(x)
//! - **Order invariance** — same key/value pairs in different input order
//!   produce the same canonical form
//! - **Whitespace-free** — output never contains space, tab, newline, or
//!   carriage return

use proptest::prelude::*;
use serde_json::Value;

/// A bounded JSON value generator.
///
/// String contents intentionally exclude whitespace so the
/// `whitespace_free` property check can scan the *entire* canonical output
/// without having to distinguish "whitespace inside a JSON string"
/// (legitimate, preserved by JCS) from "whitespace between tokens"
/// (forbidden by JCS).
fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i32>().prop_map(|n| Value::from(n as i64)),
        "[a-zA-Z0-9_-]{0,16}".prop_map(Value::from),
    ];
    leaf.prop_recursive(4, 16, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::hash_map("[a-z]{1,6}", inner, 0..6)
                .prop_map(|m| { Value::Object(m.into_iter().collect()) })
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        .. ProptestConfig::default()
    })]

    /// Round-tripping through parse + re-canonicalize is a no-op.
    #[test]
    fn idempotence(v in arb_json()) {
        let c1 = aitp_core::jcs::canonicalize(&v).unwrap();
        let parsed: Value = serde_json::from_slice(&c1).unwrap();
        let c2 = aitp_core::jcs::canonicalize(&parsed).unwrap();
        prop_assert_eq!(c1, c2);
    }

    /// Output contains no whitespace between tokens.
    ///
    /// `arb_json` does not produce strings that contain whitespace, so we
    /// can blanket-check the entire canonical output for raw whitespace
    /// bytes; JSON-string-internal whitespace is intentionally out of
    /// scope of this generator.
    #[test]
    fn whitespace_free(v in arb_json()) {
        let c = aitp_core::jcs::canonicalize(&v).unwrap();
        for &b in &c {
            prop_assert!(
                b != b' ' && b != b'\t' && b != b'\n' && b != b'\r',
                "whitespace byte 0x{:02x} in canonical output",
                b,
            );
        }
    }

    /// Two object literals with the same keys/values in different orders
    /// produce the same canonical form.
    #[test]
    fn order_invariance(
        keys in proptest::collection::vec("[a-z]{1,4}", 1..8),
        vals in proptest::collection::vec(any::<i32>(), 1..8),
    ) {
        // Build two objects with the same data but different insertion order.
        let n = keys.len().min(vals.len());
        let pairs: Vec<(String, i64)> = keys.iter().take(n).cloned().zip(vals.iter().take(n).map(|v| *v as i64)).collect();
        let dedup: std::collections::BTreeMap<String, i64> = pairs.into_iter().collect();
        let mut as_vec: Vec<(String, i64)> = dedup.into_iter().collect();

        let mut o1 = serde_json::Map::new();
        for (k, v) in &as_vec {
            o1.insert(k.clone(), Value::from(*v));
        }
        as_vec.reverse();
        let mut o2 = serde_json::Map::new();
        for (k, v) in &as_vec {
            o2.insert(k.clone(), Value::from(*v));
        }

        let c1 = aitp_core::jcs::canonicalize(&Value::Object(o1)).unwrap();
        let c2 = aitp_core::jcs::canonicalize(&Value::Object(o2)).unwrap();
        prop_assert_eq!(c1, c2);
    }
}
