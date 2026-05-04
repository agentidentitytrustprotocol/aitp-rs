# Phase 1 — `aitp-core` Foundations

You are working on the `aitp-rs` Rust reference implementation of the
Agent Identity & Trust Protocol. This is Phase 1 of a 6-phase build plan.

**Your goal in this phase:** make `aitp-core` actually work. Implement
every primitive in the crate, write thorough tests, get the crate to
"green CI" status standalone. Other crates depend on `aitp-core`, so
quality here pays dividends everywhere else.

---

## Required reading (in order, before touching anything)

1. `docs/design/00-architecture.md` — why `aitp-core` is a separate crate
   with no I/O and no crypto
2. `docs/design/01-jcs.md` — the JCS strategy and test vector approach
3. `docs/design/PENDING.md` — task IDs you're closing this phase
4. `phase-0-report.md` (in repo root) — what was found in pre-flight
5. Every file in `crates/aitp-core/src/` — current scaffold

---

## Global rules

[All 12 global rules from `_global-rules.md` apply. Repeating the
critical ones here for emphasis:]

1. **Wire-format invariants are non-negotiable.** Every wire-format
   struct MUST have `#[serde(deny_unknown_fields)]`. Every
   `extensions: ExtensionsMap` MUST have
   `#[serde(default, skip_serializing_if = "ExtensionsMap::is_empty")]`.

2. **Tests come with the code, not after.** Each task's "done" includes
   its tests.

3. **No new dependencies** without writing a `BLOCKED-*` entry first.

4. **STOP if a JCS test vector fails against `serde_jcs`.** Do not
   modify the vector to match the implementation. The vectors come from
   RFC 8785 and `docs/design/01-jcs.md`.

5. **Stop at the phase boundary.** Do not begin Phase 2.

---

## Tasks

Work through these in order. Each builds on the previous. Each task ends
with green tests for that task before moving to the next.

### 1.1 — Implement `Aid` (IMPL-005)

File: `crates/aitp-core/src/aid.rs`

Implement the four `todo!()` functions:

- **`Aid::parse(s: &str) -> Result<Self, AidParseError>`**
  - MUST start with `aid:`
  - Method MUST be `pubkey` (anything else: `UnsupportedMethod`)
  - Identifier MUST be exactly 43 chars (anything else: `WrongLength`)
  - Identifier MUST contain only `[A-Za-z0-9_-]` (anything else: `InvalidChars`)
  - Identifier MUST NOT contain `=` padding (caught by `InvalidChars`)

- **`Aid::from_ed25519(pubkey: &[u8; 32]) -> Self`**
  - Encode with `base64ct::Base64UrlUnpadded`
  - Prepend `"aid:pubkey:"`
  - Result is exactly 43 chars in the identifier component

- **`Aid::to_ed25519_bytes(&self) -> [u8; 32]`**
  - Decode the identifier with `Base64UrlUnpadded`
  - Always succeeds for an `Aid` constructed via `parse` or `from_ed25519`
    (since both validate). If decoding somehow fails, panic with a clear
    message — this would indicate corruption of the `Aid`'s string

Tests in `mod tests`:
- Round-trip: `Aid::from_ed25519(&[0x42u8; 32]).to_ed25519_bytes() == [0x42u8; 32]`
- `Aid::parse("aid:pubkey:11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")` succeeds
- Rejects: missing scheme, `aid:did:...`, 42-char identifier, 44-char identifier,
  identifier with `=`, identifier with `/`, identifier with space
- Serde round-trip through `serde_json::to_string` and `from_str`
- `AidParseError` variants are constructed correctly for each rejection case

### 1.2 — Implement strict `base64url` (IMPL-009)

File: `crates/aitp-core/src/base64url.rs`

Implement `decode_strict`:
- Reject any `=` in input → `Base64UrlError::PaddingNotAllowed`
- Use `Base64UrlUnpadded::decode_vec`
- Map decoder errors to `Base64UrlError::InvalidChar`

Tests:
- Encode then decode round-trips for: empty bytes, 32-byte key, 64-byte sig
- `decode_strict("AA==")` → `PaddingNotAllowed`
- `decode_strict("AA")` → succeeds (1 byte)
- `decode_strict("!@#")` → `InvalidChar`
- `decode_strict_exact::<32>` rejects 33-byte input

### 1.3 — Verify `Timestamp` (IMPL-006)

File: `crates/aitp-core/src/time.rs` — already implemented in scaffold.

Verify:
- The existing tests pass
- Add one more test: `Timestamp::now()` returns a value within ±5
  seconds of `Utc::now().timestamp()` (sanity check)
- Confirm serde uses `#[serde(transparent)]` and serializes as a JSON
  number, NOT a string

### 1.4 — Verify `ExtensionsMap` (IMPL-008)

File: `crates/aitp-core/src/extensions.rs` — already implemented.

Add tests:
- Empty map's `is_empty()` returns true
- After insert, `is_empty()` returns false
- Serde round-trip for `{"vendor.example/foo": {"x": 1}}`
- When wrapped in a struct with
  `#[serde(skip_serializing_if = "ExtensionsMap::is_empty")]`, an empty
  map produces output without the field

### 1.5 — Round-trip `AitpEnvelope` (IMPL-007)

File: `crates/aitp-core/src/envelope.rs` — types already exist.

Add a `mod tests` with a JSON round-trip:
- Construct an envelope with all 8 message types (one test per type)
- Serialize to JSON, parse back, assert equality
- Verify `deny_unknown_fields` rejects an envelope with an extra
  top-level field
- Verify `deny_unknown_fields` is set on `Sender` too

### 1.6 — Wire JCS (IMPL-010)

File: `crates/aitp-core/src/jcs.rs`

The scaffold already wraps `serde_jcs`. Verify the wrappers work and add
the `canonicalize_and_hash` function (already present, just confirm).

Quick smoke-test in `mod tests`:
- Empty object `{}` canonicalizes to `b"{}"`
- `{"b":1,"a":2}` canonicalizes to `b"{\"a\":2,\"b\":1}"`
- `canonicalize_and_hash` returns 32 bytes

The full vector suite comes in 1.7.

### 1.7 — JCS standard test vectors (IMPL-011)

Create `crates/aitp-core/tests/jcs_standard_vectors.rs`.

Implement the vectors from `docs/design/01-jcs.md`. Use a struct table
pattern:

```rust
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
    // ... at least the 12 categories from the design doc
];

#[test]
fn jcs_standard_vectors() {
    for v in VECTORS {
        let value: serde_json::Value = serde_json::from_str(v.input)
            .unwrap_or_else(|e| panic!("vector {}: invalid input: {}", v.name, e));
        let canonical = aitp_core::jcs::canonicalize(&value)
            .unwrap_or_else(|e| panic!("vector {}: canonicalize failed: {}", v.name, e));
        let actual = std::str::from_utf8(&canonical).unwrap();
        assert_eq!(actual, v.expected, "vector {}", v.name);
    }
}
```

Required vector categories (at minimum):
- empty_object, empty_array
- key_ordering_simple, no_whitespace
- number_integer, number_no_trailing_zeros, number_negative_zero
- string_unicode_literal, string_control_char_escaped, string_forward_slash_not_escaped
- key_ordering_utf16_surrogates
- nested_objects, array_preserves_order

If any vector fails: STOP. Write a `BLOCKED-JCS-*` entry in PENDING.md.
Do NOT modify the vector to match the implementation.

### 1.8 — JCS property tests (IMPL-012)

Create `crates/aitp-core/tests/jcs_properties.rs` using `proptest`.

Three properties:
- **Idempotence:** canonicalize(parse(canonicalize(x))) == canonicalize(x)
- **Order invariance:** same keys+values in different order → same output
- **Whitespace-free:** output never contains space, tab, or newline

Limit recursion depth (4) and node count (16) so the property tests
finish in reasonable time. Run them as part of `cargo test`.

### 1.9 — Error code coverage (IMPL-014)

File: `crates/aitp-core/src/error.rs` — `ErrorCode` enum already exists.

Add tests in `mod tests`:
- For each variant, serialize with serde_json, parse back, assert equality
- Pin the wire string for at least 5 representative variants:
  - `ErrorCode::AudienceMismatch` ↔ `"AUDIENCE_MISMATCH"`
  - `ErrorCode::TctExpired` ↔ `"TCT_EXPIRED"`
  - `ErrorCode::ManifestSignatureInvalid` ↔ `"MANIFEST_SIGNATURE_INVALID"`
  - `ErrorCode::ReplayDetected` ↔ `"REPLAY_DETECTED"`
  - `ErrorCode::SourceTctRevoked` ↔ `"SOURCE_TCT_REVOKED"`

These pinned tests are the contract with the AITP spec's error code
registry. If `serde(rename_all = "SCREAMING_SNAKE_CASE")` ever produces
the wrong wire form, these tests catch it.

---

## Format, lint, and CI

Before declaring this phase done:

```sh
cargo fmt --all
cargo clippy -p aitp-core --all-targets -- -D warnings
cargo test -p aitp-core
```

All three must succeed. Clippy emits zero warnings on `aitp-core`.

---

## Update PENDING.md

In `docs/design/PENDING.md`, check off:
- IMPL-005 (Aid)
- IMPL-006 (Timestamp — verify, scaffold already had it)
- IMPL-007 (AitpEnvelope — verify and add round-trip tests)
- IMPL-008 (ExtensionsMap — verify and add tests)
- IMPL-009 (base64url)
- IMPL-010 (JCS wrapper)
- IMPL-011 (JCS standard vectors)
- IMPL-012 (JCS property tests)
- IMPL-014 (ErrorCode coverage)

Note that IMPL-013 (AITP signing known-answer tests) remains BLOCKED
on SPEC-005 (the AITP spec needs to publish reference hashes). Add a
note under IMPL-013: `BLOCKED-SPEC-005`.

---

## Phase report

Write `phase-1-report.md` in the repo root:

```markdown
# Phase 1 Report

## Tasks completed
- IMPL-005, 006, 007, 008, 009, 010, 011, 012, 014

## Tasks blocked
- IMPL-013 — blocked on SPEC-005 (spec-side known-answer hashes)

## Test counts
- aitp-core unit tests: <count>
- jcs_standard_vectors.rs: <count> vectors
- jcs_properties.rs: <count> properties

## Coverage notes
- <anything you noticed about edge cases worth flagging>

## Remaining todo!() in aitp-core
- <should be zero or near-zero. List any that remain and why>

## Things the human reviewer should look at
- The pinned wire strings in `error.rs` tests — is the casing right?
- The JCS standard vectors — do they match RFC 8785 expectations?
- <other notes>
```

---

## Success gate

This phase is done when:
- `cargo test -p aitp-core` passes 100% of non-`#[ignore]` tests
- `cargo clippy -p aitp-core --all-targets -- -D warnings` is clean
- `cargo doc -p aitp-core --no-deps` produces no warnings
- `phase-1-report.md` is written
- `docs/design/PENDING.md` is updated
- A git commit (or branch) captures the work cleanly

## Stop here

Do not begin Phase 2. Wait for human review.
