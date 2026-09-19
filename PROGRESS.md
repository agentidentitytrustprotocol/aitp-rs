# Progress — issue #144 (`MANIFEST_INVALID` / `REVOCATION_SNAPSHOT_*` / identity `extensions`)

Plan: `plans/manifest-revocation-error-codes.md`. Tracking issue: #144. Spec commit:
`ea22c710f50bc74c6331dcc1983a0ec6fa82a0de` (spec PR #42).
Upstream: spec `5063c08ed994d6da71292ce9f0f99812462be997` → `ea22c710f50bc74c6331dcc1983a0ec6fa82a0de`.

## Branch state (read this before touching anything)

- `deps/spec-ea22c710f50b` (PR #145) has one commit, `cf23ca5`, branched from `7e338b6`
  (pre-PR #141) — **behind `main`'s tip `9f887dd`**. PR #145's two red CI checks
  (`vendored schemas in sync`, `conformance fixtures`) are this stale-base problem, not a real
  defect in the bump itself. Phase 0 rebases and re-syncs properly.
- aitp-rs vendors **only** `schemas/json/*.schema.json` and
  `schemas/conformance/known-answer/**` (`scripts/sync-schemas.sh:41-64`). Conformance
  fixtures themselves are read live from the sibling spec checkout, resolved via
  `tests/schemas/SPEC_VERSION` (CI: `.github/workflows/ci.yml:395-404`; local minting:
  `tools/mint-conformance-fixtures/src/main.rs:488-492` via `$AITP_SPEC_DIR`, default
  `../agentidentitytrustprotocol`). `man-006`/`rev-007`/`rev-008`/`id-008`/`id-009` do not
  exist anywhere in this repo's tree.
- Sibling spec repo, checked out at `ea22c71` (ahead of the pin — do not treat as this repo's
  current state, only as ground truth for what the bump will bring):
  `/Users/Shared/agentIdenitytrustprotocol/agentidentitytrustprotocol`.
- Only one vendored schema file actually changes at `ea22c71`:
  `tests/schemas/aitp-mutual-handshake.schema.json` (+30 lines: `$defs.IdentityDescriptor`
  gains `extensions`, a `public_key` pattern, and
  `then.not.required:["public_key"]`). `aitp-identity.schema.json` (the canonical file) is
  byte-unchanged in this commit — it already had both.

## The error-code registry (spec `ea22c71`)

- `registries/error-codes.md:22-64` — new "Structural rejection" section, normative
  per-artifact table (`:32-42`): Manifest → `MANIFEST_INVALID` (new), Revocation snapshot →
  `REVOCATION_SNAPSHOT_INVALID` (new), TCT/voucher/delegation → their existing signature-
  family codes (**unchanged, deliberately**), Identity descriptor → `IDENTITY_FAILED`
  (existing, unchanged).
- New `## Revocation codes (RFC-AITP-0008)` section, `:158-177` — first revocation-specific
  family in the registry; adds `REVOCATION_SNAPSHOT_INVALID` and
  `REVOCATION_SNAPSHOT_SIGNATURE_INVALID`.
- RFC-AITP-0008 §3.1 gains a blockquote confirming `TCT_REVOKED` under `fail_closed` for a
  stale/unreachable snapshot is **unchanged** — a stale snapshot is absent, not invalid.

## `aitp-core` — where the 3 new `ErrorCode` variants go (Phase 1)

- `crates/aitp-core/src/error.rs:58-206` — `ErrorCode` enum, `#[non_exhaustive]` (`:60`),
  `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]` (`:59`) is the **only** wire mapping — no
  `Display`/`as_str`/`FromStr`.
  - `ManifestInvalid` → insert after `ManifestVersionUnknown` (`:95`).
  - `RevocationSnapshotInvalid`, `RevocationSnapshotSignatureInvalid` → new section after
    `TctExpiresAfterManifest` (`:166`), before `// ── Session Bundle ──` (`:168`).
- Three coupled sites, same file, must move together:
  - `pinned_wire_strings`' `cases` table, `:216-325`.
  - `assert_every_variant_named`'s exhaustive or-pattern, `:338-391` — **no `_` arm**, compile
    error if a variant is added without a row here. This is the hard gate.
  - `assert_eq!(cases.len(), 50, ...)`, `:405-409` → `53`.
- `AitpError` (`:18-48`) is a separate, vestigial enum — nothing constructs it, not relevant.
- No file in this repo enumerates the error-code registry for humans (the authoritative list
  is the spec repo's `registries/error-codes.md`, not vendored here). `docs/conformance.md`'s
  fixture table (`:390-416`) is the closest thing and is what Phase 6 updates.

## Manifest — structural vs. signature (Phase 2)

- `crates/aitp-manifest/src/verifier.rs:168-190` `parse_manifest_wire` — structural path.
  Member-set violations → `ManifestError::UnknownField` (`:174`, `:181`); residual
  `serde_json::from_value` failure (missing REQUIRED member, wrong type) →
  `ManifestError::Malformed` (`:187`).
- `crates/aitp-manifest/src/verifier.rs:49-111` `verify_manifest` — signature path. Outer
  Ed25519/P-256 check `:95-99` → `SignatureInvalid`; PoP check `:104-111` → `PopFailed`.
  **The comment at `:68-75` (issue #144 cited "line 71") is about sig-before-PoP check
  *ordering* for fixture `mh-002`, NOT a structural-failure mapping — do not "fix" it.**
- `crates/aitp-manifest/src/error.rs:6-56` `ManifestError`, `#[non_exhaustive]` — full variant
  list, no `impl From<ManifestError> for ErrorCode` anywhere in the workspace. Two independent
  hand-written mapping tables (no shared conversion):
  - `crates/aitp-rs-adapter/src/lib.rs:1259-1285` `manifest_error_code` — **already mostly
    correct**; only `Malformed(_) => "INVALID_ENVELOPE"` (`:1281`) needs to become
    `"MANIFEST_INVALID"`. `AidMismatch => "MANIFEST_SIGNATURE_INVALID"` (`:1268`) is
    deliberate, tested (`lib.rs:3489` area), leave alone.
  - `crates/aitp-transport-http/src/server.rs:1238-1277` `handshake_error_code` — **the real
    defect**. `:1257` `HE::Manifest(_) => ErrorCode::ManifestSignatureInvalid` collapses ALL
    12 `ManifestError` variants (not just structural-vs-signature) — production HTTP
    handshakes today misreport `Expired`/`PopFailed`/`VersionUnknown`/`UnknownField` manifests
    as signature failures. Precedent to copy: `HE::Tct(tct_err)` arm at `:1251-1256`, two
    lines above, already does correct per-variant splitting.
  - `types.rs:94-95` — `Manifest.signature` is body-level (last struct member), confirms
    JCS-profile "signature inside the signed body" framing.
- `crates/aitp-manifest/tests/pop_kat.rs:168-174`, `round_trip.rs:101-108` — both already
  accept `PopFailed | SignatureInvalid`, unaffected by this phase; only the stale prose
  (`pop_kat.rs:125-132`, `round_trip.rs:95-100`) might need a wording check, not a logic
  change.
- Fixture/runner mechanics: CI job `.github/workflows/ci.yml:386-428` →
  `crates/aitp-conformance/src/fixture/loader.rs:21` loads fixtures →
  `runner/executor.rs:308-331` `run_single` → adapter dispatch
  (`crates/aitp-rs-adapter/src/lib.rs:141` `"verify_manifest"`) → `parse_manifest_wire` then
  `verify_manifest` → `manifest_error_code`. String-compare assertion:
  `crates/aitp-conformance/src/runner/executor.rs:374-381`.

## Revocation snapshot — structural vs. signature (Phase 3)

- `crates/aitp-tct/src/revocation.rs:166-184` `parse_revocation_snapshot_wire` — structural.
  Member-set → `TctError::UnknownField` (`:170,174,179`); residual deserialize failure (e.g.
  missing `published_at`, `rev-007`'s shape) → `TctError::ClaimsMalformed` (`:181`).
- `crates/aitp-tct/src/revocation.rs:203-226` `verify_revocation_list` — signature. The actual
  Ed25519 check is `:221-224`; failure → `TctError::SignatureInvalid`.
- `crates/aitp-tct/src/error.rs:6-81` `TctError`, `#[non_exhaustive]` — no revocation-specific
  variant exists; `ClaimsMalformed`'s doc comment (`:49-52`) is written about JWS claims, not
  JCS bodies — Phase 3 adds a clarifying line, doesn't rename.
- Mapping (again no `From` impl, hand-written):
  - `crates/aitp-rs-adapter/src/lib.rs:1442-1475` `tct_error_code` — the one the conformance
    corpus actually drives. `ClaimsMalformed(_) => "INVALID_ENVELOPE"` (`:1458`, **not**
    signature-borrowed, contrary to the issue's framing); `SignatureInvalid => …
    "TCT_SIGNATURE_INVALID"` (`:1446`, **the real borrowed-code defect**);
    `IssuerMismatch => "TCT_SIGNATURE_INVALID"` (`:1450`, left alone, see plan's Open
    Questions #2). **Do not retarget this function** — it's shared with real `tct-*`
    fixtures. Add a sibling `revocation_error_code` instead.
  - `crates/aitp-transport-http/src/server.rs:1252-1255` — `TctError → ErrorCode`, but only
    reachable via `HandshakeError::Tct`, never from the standalone revocation-snapshot path.
    Not touched by this plan.
- `verify_revocation_snapshot_op`, `crates/aitp-rs-adapter/src/lib.rs:2623-2689` — the op
  fixtures actually call; parse at `:2632-2636`, verify at `:2652-2661`. `TCT_REVOKED` for a
  stale snapshot under `fail_closed` is a **separate, hardcoded literal at `:2676`**,
  structurally independent of `tct_error_code`/`revocation_error_code` — `rev-001` is
  unaffected by this phase.
- Two more call sites reusing the same (to-be-forked) mapping: `verify_tct_op`'s
  `issuer_revocation_list.snapshot` (`lib.rs:1376-1393`); delegation's
  `revocation_snapshots[]` (`lib.rs:1644-1652`). Plan applies `revocation_error_code` to both
  (Open Question #1, decided).
- `crates/aitp-transport-http/src/revocation.rs:103-138` `RevocationError` — already splits
  structural/signature at its own mapping site (`:365-371`) for the **client-side cache**
  path, but is `pub`, **not** `#[non_exhaustive]` (unlike every sibling error enum), and is
  **never mapped to `ErrorCode` anywhere**. Real gap, deliberately out of scope (Open
  Question #3) — adding a variant here would trip `cargo-semver-checks` as major for no
  fixture-passing benefit.
- No existing test anywhere covers the structural-failure case for a revocation snapshot —
  `rev-007`'s shape is new coverage. Existing adapter test to update:
  `crates/aitp-rs-adapter/src/lib.rs:3729-3751`
  (`verify_revocation_snapshot_tampered_signature_is_not_unknown_field`, currently asserts
  `"TCT_SIGNATURE_INVALID"` at `:3750`).

## Identity descriptor (Phase 4) and OIDC minting (Phase 5)

- `crates/aitp-handshake/src/identity.rs:26-44` `IdentityDescriptor` — flat struct
  (`type`/`issuer`/`subject`/`proof`/`public_key`), `deny_unknown_fields` (`:27`), **no
  `extensions` field**. Lives in `aitp-handshake`, not `aitp-core`; no `aitp-identity` crate
  exists.
- `crates/aitp-handshake/src/identity_oidc.rs:88-96` — the OIDC/`public_key` exclusivity rule
  (`id-008`'s concern) is **already enforced in Rust**, first check in `verify_oidc`, tested
  at `crates/aitp-handshake/tests/p1_p8_regressions.rs:194-232`. Phase 4 needs no change here.
- `crates/aitp-handshake/src/payloads.rs:382-402`
  `nested_identity_still_rejects_extensions_field` — doc comment (`:373-381`) explicitly
  documents this test's own expiry the moment `extensions` is added. Flip it, don't just
  delete it.
- `identity_oidc.rs:88-218` `verify_oidc` — full check order (18 steps) read in full; see the
  plan's Phase 5 approach section for the claim set a minted JWT needs
  (`iss`/`sub`/`aud`/`nonce`/`exp`/`iat`/`cnf.jkt`). Resolver trait: `JwksResolver`
  (`identity_oidc.rs:17-20`), synchronous, takes `&Url` → `Vec<JwkPublicKey>`.
- `crates/aitp-rs-adapter/src/lib.rs:829` — `NoOpResolver` (impl at `:1192-1197`), always
  resolves zero keys. Fixed constant; nothing reads resolver config from fixture `params`.
- **No fixture in the `id-*` corpus has ever minted a real, verifiable OIDC JWT.**
  `id-001`–`id-007` are failure fixtures with unminted placeholder proofs that die before
  reaching key resolution (steps 1-6 of the 18); `id-008` similarly never reaches JWT parsing
  (`public_key` check fires first). `id-009` (`success`) is the first fixture that actually
  needs this machinery to work.
- **`__VALID_JWT__` is used by five fixtures, not just `id-009`** — also `mh-002`, `mh-003`,
  `mh-005`. A full trace of the check sequence (adapter checks `lib.rs:710-1029` →
  `bootstrap_verify_peer` `state_machine.rs:426-486` → `verify_manifest` → `verify_oidc`)
  confirmed all four non-`id-009` fixtures are caught by checks that strictly precede JWT
  parsing (manifest outer-signature failure for `mh-002`, manifest PoP failure for `mh-003`, a
  root-level adapter nonce guard at `lib.rs:941-949` for `mh-005` — distinct from
  `verify_oidc`'s own nonce check — and the `public_key` exclusivity check for `id-008`), so
  minting a real JWT for all five is safe; only `id-009` needs the JWT to actually verify. See
  the plan's Phase 5 for the full per-fixture trace and the substitution design (one-object-
  level sibling reads — `identity.issuer`/`identity.subject`/`payload.pop_nonce`/
  `payload.manifest.aid` — cover everything except `aud`, which has no uniform fixture-level
  source and needs an explicit fallback).
- Reference minting implementation to port from (test-only, unreachable from
  `aitp-conformance` as a module — port the logic, ~25 lines):
  `crates/aitp-handshake/tests/fixtures/mock_oidc.rs:30-128` (`MockOidcIssuer`, fixed Ed25519
  seed, `mint_jwt`/`mint_aitp_jwt`). Claim template reference:
  `crates/aitp-handshake/tests/oidc_key_resolution.rs:128-143`.
- `crates/aitp-conformance/src/fixture/placeholder.rs:568-581` `is_jws_placeholder` — closed
  list, does not include `__VALID_JWT__`; falls through to
  `RUNNER_UNKNOWN_PLACEHOLDER___VALID_JWT__` sentinel (`:564`) today.
- KAT key precedent to mirror (AID-keyed, duplicated between the two crates already, no shared
  module — confirmed via `Cargo.toml` dependency direction in both crates):
  `placeholder.rs:771-798` (`kat_seed_for_aid`/`kat_key_for_aid`) and
  `crates/aitp-rs-adapter/src/lib.rs:690-704`.
- id-009's fixture JSON carries no extra field (no inlined JWKS/signing key) — grepped the
  whole spec corpus, zero hits for `jwks|issuer_public_key|signing_key|issuer_jwk`.
  `trust_anchors` is hardcoded in the adapter at `lib.rs:852-856` to three URLs including
  `https://auth.openai.com` (id-009's issuer) — already satisfies `verify_oidc` check #3.

## Conformance harness architecture (relevant to Phase 5's design)

- **Correction (post-verification):** `aitp-conformance` *does* optionally depend on
  `aitp-rs-adapter` (path dependency behind the `in-process` feature,
  `crates/aitp-conformance/Cargo.toml`) — a shared KAT-registry module is not architecturally
  blocked. It's just not usable for the default *subprocess* build (what CI actually runs,
  `.github/workflows/ci.yml:422-426`), and Phase 5 needs exactly one key pair — not worth new
  shared plumbing for that alone. The existing AID-keyed KAT registry this pattern mirrors has
  already drifted regardless: `placeholder.rs:771-785` knows four AIDs,
  `crates/aitp-rs-adapter/src/lib.rs:690-704` (not `:690` exactly — starts at `:691`) knows
  only three.
- Two adapter drive modes, same dispatcher: in-process
  (`crates/aitp-conformance/src/adapter/in_process.rs:76`, feature-gated) and subprocess NDJSON
  (what CI actually uses, `.github/workflows/ci.yml:422-426`).
- The only minter↔adapter contract is the per-op `params` JSON (fixture `input` minus
  `operation`) plus two unprompted Tier-D ops (`set_clock`, `set_features`) and per-fixture
  `preconditions` forwarding (`crates/aitp-conformance/src/runner/executor.rs:181-306`). No
  side channel exists for injecting extra trust material today.

## House style reference for Phase 6 doc edits

- `CHANGELOG.md:8-27` — `[Unreleased] / ### Added`, existing `UNKNOWN_FIELD` entry is the
  template (issue link, spec PR link, what changed, why, what stays the same).
- `docs/conformance.md:389-416` — "Core fixtures (required for v0.2)" table, one row per
  RFC/topic grouping with a prose "Notes" cell in the same terse citation style as the
  existing `man-004`/`man-005`, `rev-005`/`rev-006` sentences.
- `.github/workflows/ci.yml:417-419` — hardcoded fixture-count comment, currently "62 pass /
  0 fail / 2 skip of 64 fixtures" at the `5063c08` pin; Phase 6 replaces with the real number
  observed after all other phases land.
