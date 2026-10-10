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
9. **Duplicate keys.** RFC 8259 leaves this undefined. JCS input must be
   I-JSON, which forbids duplicate names. See below for where `aitp-rs`
   enforces this.
10. **String escapes.** Only `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, and
    `\uXXXX` for control characters and forced escapes. Forward slash is
    NOT escaped.
11. **Surrogate pairs.** Astral characters use their UTF-16 surrogate pair
    representation in sort order.
12. **Empty objects and arrays.** Exactly `{}` and `[]`, no whitespace.

A naive `serde_json::to_string` with `sort_keys` solves about 4 of these.
We need all 12. The canonicalizer handles 11 of them.

Duplicate keys are not handled in `aitp_core::jcs`. The canonicalizer
takes an already-parsed `serde_json::Value`, and by then `serde_json` has
silently kept the last of any duplicate keys. `JcsError::DuplicateKey` is
never constructed. Duplicates are rejected earlier, from the raw bytes, by
`aitp_core::reject_duplicate_keys` (`crates/aitp-core/src/unknown_field.rs`).
That check runs at the wire-parse entry points, before any `Value`
exists:

- the JWS claim parsers in `aitp-tct` and `aitp-delegation`
- HTTP request and response parsing in `aitp-transport-http`
- the session-bundle builder, on each participant TCT's claims
- the NDJSON adapter

[RFC-AITP-0001 §5.4.5](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md#545-compact-jws-profile-portable-trust-artifacts)
requires this check for JWS payloads. The language bindings reach it for TCT
claims (they call `aitp_tct::verify_tct`), but their manifest, revocation,
bundle and envelope entry points bypass the hardened wire parsers
([#152](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/152)).

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

<a id="layer-1-jcs-standard-vectors-testsjcs_standard_vectorsrs"></a>

### Layer 1: JCS standard vectors (`crates/aitp-core/tests/jcs_standard_vectors.rs`)

Hand-constructed cases for the edge conditions above. They are not copied
from RFC 8785's examples. The `VECTORS` table, run by
`jcs_standard_vectors`, includes:

| Name | Input | Expected |
|---|---|---|
| `empty_object` | `{}` | `{}` |
| `empty_array` | `[]` | `[]` |
| `key_ordering_simple` | `{"b":1,"a":2}` | `{"a":2,"b":1}` |
| `no_whitespace` | `{ "a" :   1 ,  "b" :  2 }` | `{"a":1,"b":2}` |
| `number_no_trailing_zeros` | `{"x":1.0}` | `{"x":1}` |
| `number_negative_zero` | `{"x":-0}` | `{"x":0}` |
| `string_unicode_literal` | `{"x":"café"}` | `{"x":"café"}` |
| `string_control_char_escaped` | `{"x":"\u0001"}` | `{"x":"\u0001"}` |
| `string_forward_slash_not_escaped` | `{"x":"/"}` | `{"x":"/"}` |
| `nested_objects` | `{"b":{"d":1,"c":2},"a":{}}` | `{"a":{},"b":{"c":2,"d":1}}` |
| `array_preserves_order` | `{"x":[3,1,2]}` | `{"x":[3,1,2]}` |
| `key_with_unicode` | `{"é":1,"a":2}` | `{"a":2,"é":1}` |

UTF-16 surrogate ordering has its own test, `jcs_surrogate_pair_ordering`.
It feeds in `{"𝄞":1,"ﬃ":2}` and expects the same order back:
`{"𝄞":1,"ﬃ":2}`. `𝄞` (U+1D11E) starts with the high surrogate 0xD834,
and that sorts before `ﬃ` (U+FB03, 0xFB03). Sorting by code point or by
UTF-8 bytes gets this wrong.

**Discipline: never delete a test vector.** New edge cases are added; old
ones stay forever.

### Layer 2: AITP signing vectors (`crates/aitp-core/tests/kat.rs`)

Take a known wire object, canonicalize it, hash it, and assert against a
known-answer hash **pinned in the spec**, not against our own output.

```rust
let canonical = jcs::canonicalize(&manifest)?;
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

### What gets fed to the canonicalizer

Getting the bytes right is only half the problem; the other half is
canonicalizing the **right JSON**. The rule is one sentence, and it has
been normative since v0.2:

> The signing input is the **inner artifact body**. The artifact-naming
> key (`{"revocation_list": …}`, `{"session_bundle": …}`, `{"manifest": …}`)
> is routing metadata for the transport and is **never** part of the
> signing bytes.

The rule is in
[RFC-AITP-0001 §5.4.1](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md#541-signing-input-jcs-profile).
Each artifact's RFC restates it: RFC-AITP-0003 §6.1, RFC-AITP-0008 §1.5
and RFC-AITP-0010 §3. The same section also explains when `signature` is
a member of the body and when it sits beside it. Mixing up the two
placements is the easiest way to get this wrong:

| Artifact | Where `signature` lives | Signing input |
|---|---|---|
| Manifest | a **member** of the body | body **minus** `signature` |
| Session bundle | a **member** of the body | body **minus** `signature` |
| Revocation snapshot | a **sibling** of the wrapped body | the body **as-is** — nothing to strip |

The session-bundle placement is settled. An erratum in RFC-AITP-0010 §3
corrected the schema and the `bundle-*` fixtures to the placement the RFC
always specified: `signature` is a member of the inner body. `aitp-rs` rejects the old sibling shape,
`{"session_bundle": …, "signature": …}`, with `SESSION_BUNDLE_INVALID`
(`parse_session_bundle_wire` in `crates/aitp-session-bundle/src/wire.rs`;
fixture `bundle-004`). That parser still accepts a bare, unwrapped body
for internal callers. The HTTP server exposes that path; see
[#195](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/195).

Each artifact has exactly one function that defines its signing input.
The signer, the verifier and the known-answer test all go through it:

- `manifest_signing_bytes` (`crates/aitp-manifest/src/builder.rs`)
- `revocation_signing_bytes` (`crates/aitp-tct/src/revocation.rs`)
- `bundle_signing_bytes` (`crates/aitp-session-bundle/src/builder.rs`)

Reconstructing the signing input at a call site is how a signer and
its own verifier drift apart.

Do not document one artifact's convention by pointing at another's. A
comment reading "same convention as the revocation snapshot" is what
turned one misread vector into two divergent artifacts: the code was
corrected and the pointer left behind. State the rule and cite the RFC.

In **AITP v0.2** JCS only governs the protocol-internal artifacts, so we
pin the jcs-sha256 KAT for the **JCS-profile** types: Manifest,
revocation snapshot and session bundle. Vectors for all three declare
`signing_input: "body"`, and `crates/aitp-core/tests/kat.rs` asserts that
declaration rather than inferring the shape — see
[testing.md](testing.md) for why that distinction matters. The v0.1 TCT and delegation JCS
vectors are **retired** — those artifacts are now compact JWS strings
(RFC-AITP-0001 §5.4.5) verified over their exact transmitted bytes, not
over a canonicalized form; their known-answer vectors live under
`known-answer/signed-examples/` instead. See
[architecture.md](architecture.md#the-two-signing-profiles) for the
profile boundary.

<a id="layer-3-property-tests-testsjcs_propertiesrs"></a>

### Layer 3: Property tests (`crates/aitp-core/tests/jcs_properties.rs`)

Three properties:

- **Idempotence:** `canonicalize(parse(canonicalize(x))) == canonicalize(x)`.
- **Order invariance:** the same keys in different input order produce the
  same canonical form.
- **Whitespace-free:** the output never contains spaces, tabs, or newlines.

They run under `proptest` with 64 cases per property, set by
`ProptestConfig` in the file. CI runs them as part of the ordinary
`cargo nextest run --workspace --all-features` in the `test` job, which is
a debug build, not `--release`.

## What JCS does NOT solve

JCS canonicalizes the JSON it's given. It doesn't define what JSON to feed
it. These are responsibilities of the protocol layer:

**Presence-sensitive serialization.** Absent and present-but-empty
`extensions` MUST NOT collapse onto the same wire shape or the two round
trips would canonicalize to different bytes for the same logical value —
or worse, silently normalize one into the other and invalidate a
signature. Every `extensions` field across the protocol crates
(`AitpEnvelope`, `Manifest`, `RevocationList`, `SessionTrustBundle`, the
four handshake payloads, and the `IdentityDescriptor` nested inside the
`mutual_hello` / `mutual_hello_ack` payloads) is therefore modeled as
`Option<ExtensionsMap>`
with
`#[serde(default, skip_serializing_if = "Option::is_none")]`: `None` omits
the key entirely, `Some(ExtensionsMap::new())` serializes as
`"extensions":{}`, and deserialization preserves the distinction rather
than folding both into one Rust value. See RFC-AITP-0001 §5.4.1 (the
"Optional-array round-trip" note) and §7.

**No floats in protocol fields.** Timestamps are `i64`. UUIDs are strings.
We never let a protocol field round-trip through `f64`.

**Signed-object viewing.** When signing a **JCS-profile** object, we
serialize a "view" struct that omits the `signature` field. After signing,
we set the field on the full struct. This pattern repeats for every
JCS-profile signed type (Manifest, revocation snapshot, the session-bundle
outer signature). The compact-JWS artifacts (TCT, grant voucher, delegation
token) do **not** use this pattern — they have no embedded `signature`
field; the signature is the third compact-JWS segment, computed over the
`header.payload` bytes (see `crates/aitp-tct/src/` for the JWS minting
path).

## Why we may fork `serde_jcs` later

Risks with our current dependency:

- Low-traffic crate; bugs may surface slowly.
- Maintenance status uncertain.
- Number formatting depends on `ryu`, which is solid but external.

If we hit a correctness issue we can't fix upstream, we vendor `serde_jcs`
into the workspace as `crates/aitp-jcs/`. Our public API
(`aitp_core::jcs::canonicalize`) does not change.
