# Phase 3a Report — `aitp-manifest`

## Tasks completed

- IMPL-020 (type round-trips, including ManifestEnvelope HTTP wrapper)
- IMPL-021 (ManifestBuilder with full required-field + identity-hint validation)
- IMPL-022 (verify_manifest in the spec-mandated order)

## IMPL-023 (spec-example test) — still open

The spec ships a `examples/manifest/agent-b-manifest.json` whose AID is the
literal placeholder string `aid:pubkey:worker_pubkey_AID_v01_placeholder_wwwwwwwww`
and whose signatures are placeholder strings. Loading it succeeds but
`verify_manifest` rejects it (PoP fails on the placeholder signature). This
is not a Rust-side bug — the spec example does not contain real crypto and
isn't intended to pass verification. Tracking under `BLOCKED-SPEC-EXAMPLE`
in `docs/design/PENDING.md`.

## Test counts

| Suite | Count |
|---|---|
| unit `mod tests` | 6 |
| `tests/round_trip.rs` | 11 |

All 17 tests pass. Doctest in `builder.rs` is `#[ignore]`d because it
documents intended call-site shape and would require an importable
`AitpSigningKey` instance to compile — keeping it informative rather than
runnable.

## Decisions in this phase

1. **View-struct signing pattern.** `ManifestSigningView<'a>` mirrors
   every public field of `Manifest` *except* `signature`, with the same
   `skip_serializing_if` rules. It is `pub(crate)` so the verifier can
   reuse it. Issuer signs JCS(view) → SHA-256 → Ed25519; verifier
   reconstructs the view from a parsed Manifest and re-signs the same
   bytes. As long as the two views' field orders, names, and skip rules
   stay in sync (and JCS canonicalization is deterministic), bytes
   match.
2. **`published_at` override** is exposed on the builder for tests and
   fixed-clock issuance. Production callers should not pass it; the
   builder defaults to `Timestamp::now()`.
3. **Default Manifest TTL** is **24 hours** (`DEFAULT_MANIFEST_TTL_SECS`),
   per RFC-AITP-0003 §8 ("≤ 24 hours" rotation window).
4. **HTTP wrapper struct.** `ManifestEnvelope { manifest: Manifest }`
   captures the `{"manifest": {...}}` form RFC-AITP-0003 §6.1 specifies
   for the well-known endpoint. Keeping it separate from `Manifest`
   prevents accidentally hashing the wrapper as part of the signing
   input.
5. **Error code mapping.** `MANIFEST_VERSION_UNKNOWN`, `MANIFEST_EXPIRED`,
   `MANIFEST_POP_FAILED`, `MANIFEST_SIGNATURE_INVALID` all map 1-1 to the
   error-codes registry. A new variant `IdentityHintMalformed` covers
   step 5 of §5; the wire mapping is `IDENTITY_FAILED`.

## Verification order check

The implementation in `verifier.rs` runs:
1. version → `VersionUnknown`
2. expiry → `Expired`
3. PoP → `PopFailed`
4. outer signature → `SignatureInvalid`
5. identity-hint shape → `IdentityHintMalformed`

This matches RFC-AITP-0003 §5 1:1.

## Things the human reviewer should look at

1. The `ManifestSigningView` field order. It is the implicit byte
   contract for cross-impl interop. Compare it to RFC-AITP-0003 §2 and to
   `schemas/json/aitp-manifest.schema.json`'s `properties` declaration
   order — but note that JCS canonicalization sorts keys lex, so field
   order in the Rust struct is irrelevant to the bytes; what matters is
   field NAMES and skip rules.
2. The choice to keep `extensions` as a Manifest field even though the
   AITP spec text and schema currently treat it as an obvious slot. The
   Manifest schema explicitly *allows* `extensions` (it appears in the
   `properties` table, not in `additionalProperties: false`'s exclusion
   list).
3. The PoP challenge generator — uses `OsRng` and produces a 16-byte
   challenge → 22-char base64url-unpadded, matching the schema's pattern
   `^[A-Za-z0-9_-]{22}$`.
