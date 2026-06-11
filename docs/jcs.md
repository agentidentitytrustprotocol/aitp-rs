# JSON Canonicalization (JCS)

AITP signatures are computed over RFC 8785 JCS canonical JSON. Two
implementations that disagree on canonicalization will produce mutually
unverifiable signatures. This document captures the test strategy and the
edge cases we know are dangerous.

## Why JCS is hard

JCS sounds like "serialize JSON deterministically." The reality is a list of
edge cases that are easy to get wrong and silent when you do:

1. **Number formatting.** `1.0` vs `1` vs `1.00`. JCS pins this to
   ECMAScript's `Number.prototype.toString`.
2. **Unicode escaping.** `"é"` vs `"\u00e9"` vs `"\u00E9"`. JCS uses the
   literal character when possible; lowercase hex when escaping is required.
3. **Key ordering.** Lexicographic by UTF-16 code unit — not UTF-8 bytes,
   not codepoint. Affects strings with surrogate pairs.
4. **Whitespace.** Zero whitespace anywhere.
5. **Floating-point precision.** ECMAScript's algorithm produces the
   shortest string that round-trips to the same IEEE 754 double.
6. **Integer/float distinction.** `1` and `1.0` produce the same canonical
   form (`1`), because that's what ECMAScript would produce.
7. **Negative zero.** `-0` becomes `0`.
8. **NaN and Infinity.** Forbidden; canonicalization MUST error.
9. **Duplicate keys.** RFC 8259 leaves this undefined; JCS rejects.
10. **String escapes.** Only `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, and
    `\uXXXX` for control characters and forced escapes. Forward slash is
    NOT escaped.
11. **Surrogate pairs.** Astral characters use their UTF-16 surrogate pair
    representation in sort order.
12. **Empty objects and arrays.** Exactly `{}` and `[]`, no whitespace.

A naive `serde_json::to_string` with `sort_keys` solves about 4 of these.
We need all 12.

## Strategy: depend on `serde_jcs`, vet with test vectors

We use the [`serde_jcs`](https://crates.io/crates/serde_jcs) crate as the
backing implementation. It's based on the JCS reference and handles the
ECMAScript number formatting via `ryu`. We keep our public API
(`aitp_core::jcs::canonicalize`) thin enough to fork the backing
implementation later if needed.

The contract we offer to the rest of the workspace is:

> Two AITP implementations passing the same test vectors will produce
> byte-identical signatures.

So our investment is in the **test vectors**, not the JCS implementation.

## Test vectors, three layers

### Layer 1: JCS standard vectors (`tests/jcs_standard_vectors.rs`)

Imported from RFC 8785 plus hand-constructed cases for every edge condition
above. Examples:

| Name | Input | Expected |
|---|---|---|
| `empty_object` | `{}` | `{}` |
| `empty_array` | `[]` | `[]` |
| `key_ordering_simple` | `{"b":1,"a":2}` | `{"a":2,"b":1}` |
| `no_whitespace` | `{ "a" : 1 }` | `{"a":1}` |
| `number_no_trailing_zeros` | `{"x":1.0}` | `{"x":1}` |
| `number_negative_zero` | `{"x":-0}` | `{"x":0}` |
| `string_unicode_literal` | `{"x":"café"}` | `{"x":"café"}` |
| `string_control_char_escaped` | `{"x":"\u0001"}` | `{"x":"\u0001"}` |
| `string_forward_slash_not_escaped` | `{"x":"/"}` | `{"x":"/"}` |
| `key_ordering_utf16_surrogates` | `{"𝄞":1,"ﬃ":2}` | `{"ﬃ":2,"𝄞":1}` |
| `nested_objects` | `{"b":{"d":1,"c":2},"a":{}}` | `{"a":{},"b":{"c":2,"d":1}}` |
| `array_preserves_order` | `{"x":[3,1,2]}` | `{"x":[3,1,2]}` |

**Discipline: never delete a test vector.** New edge cases are added; old
ones stay forever.

### Layer 2: AITP signing vectors (`crates/aitp-core/tests/kat.rs`)

Take a known wire object, canonicalize it, hash it, and assert against a
known-answer hash **pinned in the spec**, not against our own output.

```rust
let canonical = jcs::canonicalize(&tct)?;
let hash = sha256(&canonical);
assert_eq!(hex::encode(hash), "<value pinned in the spec's jcs-sha256 KAT>");
```

This is the test that catches drift across implementations. The spec now
publishes these known-answer hashes — vendored into
`tests/schemas/known-answer/jcs-sha256.json` and pinned by commit SHA in
`tests/schemas/SPEC_VERSION`, with the `spec-schemas` CI job failing on
any drift. So every conformant implementation must produce the same
hashes; this is no longer a de-facto value captured from our own
reference run.

We pin this for all four signed types: TCT, Manifest, delegation token,
and revocation snapshot (the revocation KAT is checked separately in
`crates/aitp-tct/src/revocation.rs`).

### Layer 3: Property tests (`tests/jcs_properties.rs`)

Three properties:

- **Idempotence:** `canonicalize(parse(canonicalize(x))) == canonicalize(x)`.
- **Order invariance:** the same keys in different input order produce the
  same canonical form.
- **Whitespace-free:** the output never contains spaces, tabs, or newlines.

Run with `proptest`. Property tests are slow (thousands of cases); CI runs
them in `--release`.

## What JCS does NOT solve

JCS canonicalizes the JSON it's given. It doesn't define what JSON to feed
it. These are responsibilities of the protocol layer:

**Consistent serialization.** Always serialize empty `extensions` as either
omitted or `{}` — pick one. We pick: omit. Every protocol crate uses
`#[serde(default, skip_serializing_if = "ExtensionsMap::is_empty")]`.

**No floats in protocol fields.** Timestamps are `i64`. UUIDs are strings.
We never let a protocol field round-trip through `f64`.

**Signed-object viewing.** When signing, we serialize a "view" struct that
omits the `signature` field. After signing, we set the field on the full
struct. This pattern repeats for every signed type (Manifest, TCT,
delegation token, revocation snapshot). See the `SignedTctView` pattern in
`crates/aitp-tct/src/builder.rs`.

## Why we may fork `serde_jcs` later

Risks with our current dependency:

- Low-traffic crate; bugs may surface slowly.
- Maintenance status uncertain.
- Number formatting depends on `ryu`, which is solid but external.

If we hit a correctness issue we can't fix upstream, we vendor `serde_jcs`
into the workspace as `crates/aitp-jcs/`. Our public API
(`aitp_core::jcs::canonicalize`) does not change.
