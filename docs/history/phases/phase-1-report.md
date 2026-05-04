# Phase 1 Report

## Tasks completed

- IMPL-005, 006, 007, 008, 009, 010, 011, 012, 014.

## Tasks blocked

- **IMPL-013** — Blocked on `SPEC-005` (the AITP spec needs to publish JCS
  signing-input known-answer hashes for TCT/Manifest/delegation/revocation
  before this implementation can pin them).
- **BLOCKED-JCS-SURROGATE** (new) — `serde_jcs` 0.1 sorts object keys by
  UTF-8 byte order, not UTF-16 code-unit order. The astral-vs-BMP key
  ordering vector is `#[ignore]`'d. See `docs/design/PENDING.md`.

## Spec deviations corrected in the scaffold during this phase

| Symbol | Before (scaffold) | After (this phase) | Source of truth |
|---|---|---|---|
| `AitpEnvelope.extensions` | Present (`ExtensionsMap`) | Removed (schema forbids; `additionalProperties: false`) | `schemas/json/aitp-envelope.schema.json`, RFC-AITP-0001 §5.1 |
| Envelope signing input | Implied JCS-of-whole-envelope | Pipe-formatted `mid|ts|aid|hex(sha256(jcs(payload)))` then SHA-256 | RFC-AITP-0001 §5.4 |
| `MessageType` wire forms | Inferred via serde rename | Explicit `as_wire_str()` and pinned tests | RFC-AITP-0001 §5.2 |

## Test counts

| Suite | Count |
|---|---|
| `aitp-core` unit tests | 33 |
| `tests/jcs_standard_vectors.rs` | 24 vectors + 1 `canonicalize_and_hash` test + 1 `#[ignore]`'d surrogate test |
| `tests/jcs_properties.rs` | 3 properties (idempotence, order-invariance, whitespace-free), 64 cases each |
| Total active tests for `aitp-core` | **39** |

## Coverage notes

- Every concrete `AitpError` variant has either a pinned wire-string test
  or a round-trip-through-JSON test (32 variants total).
- `Aid` is exercised on the happy path, on every individual rejection
  branch, and on serde round-trip via `try_from`/`into`.
- `base64url` is exercised on round-trip through arbitrary lengths plus
  every error variant.
- `Timestamp` is exercised on freshness, ordering, and verifies the wire
  form is a JSON integer (not a string).
- `ExtensionsMap` is exercised on serde round-trip and on the
  `skip_serializing_if` empty-omission contract.

## Remaining `todo!()` in `aitp-core`

Zero. Every public function has a real implementation.

## Assumptions (non-obvious choices)

1. **`hex` is now a runtime dependency of `aitp-core`** (was dev-only). It
   is needed by `envelope_signing_input` for the
   `hex(sha256(JCS(payload)))` step in the envelope signing recipe. It is
   already in workspace deps; no new crate added.
2. **Envelope signing input is a `Vec<u8>` of the pipe-formatted ASCII
   string**, not a JSON object. RFC-AITP-0001 §5.4 specifies the literal
   `+` concatenation; we serialize via `format!`.
3. **`UUID` rendering inside the signing input** uses `Uuid`'s
   `Display`/`fmt::Debug` (hyphenated lowercase) per the schema's regex.
4. **Surrogate-pair test vector kept but `#[ignore]`'d** rather than
   deleted, so a future serde_jcs upgrade trips a visible test failure
   when the upstream bug gets fixed.
5. **The `extensions` field on the envelope was removed** even though
   RFC-AITP-0001 §7 reserves an `extensions` slot for "every signed
   object" — the schema explicitly disallows additional fields on the
   envelope, so the spec text and the schema disagree. This implementation
   follows the schema (no top-level extensions on the envelope; payloads
   already carry their own extension slots).

## Things the human reviewer should look at

1. The pinned `MessageType` wire strings in `envelope.rs::tests` and the
   pinned `ErrorCode` strings in `error.rs::tests`. Drift here breaks
   interop silently.
2. The chosen "envelope signing input" byte format. RFC-AITP-0001 §5.4
   shows a pseudocode formula; this implementation realizes it literally
   as `format!("{}|{}|{}|{}", mid, ts.0, aid, hex)` followed by `sha256`
   and Ed25519 sign. Spec authors should confirm that
   `Timestamp::Display` (decimal integer) and `Aid::as_str()` (full
   `aid:pubkey:...`) are the intended forms.
3. The decision in `extensions` removal on the envelope — should the spec
   text in §7 be amended to acknowledge the schema's stricter form?
4. JCS property test bounds (`cases: 64`, depth 4, breadth 8). Increasing
   these is cheap if the test runtime is acceptable.

## Next phase

Phase 2 (`aitp-crypto`) — already partially landed in Phase 0 (Ed25519
keys, JWK thumbprint, `Signature::parse`). Phase 2 will add the integration
test file (sign/verify round-trip, wrong-key, mutated-message,
empty-message, long-message, reproducibility) and switch verification to
`verify_strict`.
