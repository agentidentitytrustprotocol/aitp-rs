//! JCS standard vectors per `docs/jcs.md`.
//!
//! These are the vectors every conformant AITP implementation MUST agree on.
//! Adding a vector is encouraged; deleting one is not.

use serde_json::Value;

struct Vector {
    name: &'static str,
    input: &'static str,
    expected: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        name: "empty_object",
        input: r#"{}"#,
        expected: r#"{}"#,
    },
    Vector {
        name: "empty_array",
        input: r#"[]"#,
        expected: r#"[]"#,
    },
    Vector {
        name: "key_ordering_simple",
        input: r#"{"b":1,"a":2}"#,
        expected: r#"{"a":2,"b":1}"#,
    },
    Vector {
        name: "no_whitespace",
        input: r#"{ "a" :   1 ,  "b" :  2 }"#,
        expected: r#"{"a":1,"b":2}"#,
    },
    Vector {
        name: "number_integer",
        input: r#"{"x":42}"#,
        expected: r#"{"x":42}"#,
    },
    Vector {
        name: "number_no_trailing_zeros",
        input: r#"{"x":1.0}"#,
        expected: r#"{"x":1}"#,
    },
    Vector {
        name: "number_negative_zero",
        input: r#"{"x":-0}"#,
        expected: r#"{"x":0}"#,
    },
    Vector {
        name: "string_unicode_literal",
        input: r#"{"x":"café"}"#,
        expected: r#"{"x":"café"}"#,
    },
    Vector {
        name: "string_control_char_escaped",
        // Raw control bytes in JSON are illegal; they must be \uXXXX-escaped.
        // JCS preserves the lowercase \uXXXX form for chars < U+0020.
        input: "{\"x\":\"\\u0001\"}",
        expected: "{\"x\":\"\\u0001\"}",
    },
    Vector {
        name: "string_forward_slash_not_escaped",
        input: r#"{"x":"/"}"#,
        expected: r#"{"x":"/"}"#,
    },
    Vector {
        name: "nested_objects",
        input: r#"{"b":{"d":1,"c":2},"a":{}}"#,
        expected: r#"{"a":{},"b":{"c":2,"d":1}}"#,
    },
    Vector {
        name: "array_preserves_order",
        input: r#"{"x":[3,1,2]}"#,
        expected: r#"{"x":[3,1,2]}"#,
    },
    Vector {
        name: "boolean_and_null",
        input: r#"{"a":true,"b":false,"c":null}"#,
        expected: r#"{"a":true,"b":false,"c":null}"#,
    },
    Vector {
        name: "deeply_nested",
        input: r#"{"a":{"b":{"c":{"d":[1,2,3]}}}}"#,
        expected: r#"{"a":{"b":{"c":{"d":[1,2,3]}}}}"#,
    },
    Vector {
        name: "string_with_quotes_and_backslash",
        input: r#"{"x":"a\"b\\c"}"#,
        expected: r#"{"x":"a\"b\\c"}"#,
    },
    Vector {
        name: "empty_string_value",
        input: r#"{"x":""}"#,
        expected: r#"{"x":""}"#,
    },
    Vector {
        name: "key_with_unicode",
        input: r#"{"é":1,"a":2}"#,
        // 'é' (U+00E9) sorts AFTER 'a' (U+0061) in UTF-16 code-unit order.
        expected: r#"{"a":2,"é":1}"#,
    },
    Vector {
        name: "many_object_keys",
        input: r#"{"z":1,"y":2,"x":3,"w":4,"v":5,"u":6,"t":7,"s":8}"#,
        expected: r#"{"s":8,"t":7,"u":6,"v":5,"w":4,"x":3,"y":2,"z":1}"#,
    },
    Vector {
        name: "negative_integer",
        input: r#"{"x":-42}"#,
        expected: r#"{"x":-42}"#,
    },
    Vector {
        name: "zero",
        input: r#"{"x":0}"#,
        expected: r#"{"x":0}"#,
    },
    Vector {
        name: "array_of_objects",
        input: r#"[{"b":1,"a":2},{"d":3,"c":4}]"#,
        expected: r#"[{"a":2,"b":1},{"c":4,"d":3}]"#,
    },
    Vector {
        name: "tab_in_string_escaped",
        input: r#"{"x":"a\tb"}"#,
        expected: r#"{"x":"a\tb"}"#,
    },
    Vector {
        name: "newline_in_string_escaped",
        input: r#"{"x":"a\nb"}"#,
        expected: r#"{"x":"a\nb"}"#,
    },
];

#[test]
fn jcs_standard_vectors() {
    let mut failures = Vec::new();
    for v in VECTORS {
        let value: Value = match serde_json::from_str(v.input) {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!("{}: invalid input JSON: {}", v.name, e));
                continue;
            }
        };
        let canonical = match aitp_core::jcs::canonicalize(&value) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{}: canonicalize failed: {}", v.name, e));
                continue;
            }
        };
        let actual = std::str::from_utf8(&canonical).unwrap();
        if actual != v.expected {
            failures.push(format!(
                "{}: expected `{}` got `{}`",
                v.name, v.expected, actual
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// Surrogate-pair key ordering — known broken in `serde_jcs` 0.1.
///
/// RFC 8785 §3.2.3 specifies UTF-16 code-unit ordering for object keys.
/// One key is BMP (U+FB03 = `ﬃ`, single 16-bit code unit 0xFB03) and the
/// other is astral (U+1D11E = `𝄞`, surrogate pair starting with high-
/// surrogate 0xD834). Correct JCS emits `𝄞` first (0xD834 < 0xFB03 in
/// UTF-16). `serde_jcs` 0.1 sorted by UTF-8 byte order and got this
/// wrong; 0.2 fixed it.
#[test]
fn jcs_surrogate_pair_ordering() {
    let v: Value = serde_json::from_str(r#"{"𝄞":1,"ﬃ":2}"#).unwrap();
    let canonical = aitp_core::jcs::canonicalize(&v).unwrap();
    let actual = std::str::from_utf8(&canonical).unwrap();
    assert_eq!(actual, r#"{"𝄞":1,"ﬃ":2}"#);
}

/// `canonicalize_and_hash` is the standard signing input — verify it returns
/// 32 bytes of SHA-256 over the canonical JSON.
#[test]
fn canonicalize_and_hash_is_32_bytes_of_sha256() {
    use sha2::{Digest, Sha256};
    let v = serde_json::json!({"b": 1, "a": 2});
    let h = aitp_core::jcs::canonicalize_and_hash(&v).unwrap();
    let canonical = aitp_core::jcs::canonicalize(&v).unwrap();
    let expected: [u8; 32] = Sha256::digest(&canonical).into();
    assert_eq!(h, expected);
}
