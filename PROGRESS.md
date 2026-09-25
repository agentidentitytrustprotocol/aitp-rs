# Progress — issue #144 (`MANIFEST_INVALID` / `REVOCATION_SNAPSHOT_*` / identity `extensions`)

Plan: `plans/manifest-revocation-error-codes.md`. Tracking issue: #144. Spec commit:
`ea22c710f50bc74c6331dcc1983a0ec6fa82a0de` (spec PR #42).
Upstream: spec `5063c08ed994d6da71292ce9f0f99812462be997` → `ea22c710f50bc74c6331dcc1983a0ec6fa82a0de`.

## Checkpoint trail

- **Phase 0** — DONE, 2026-09-19. Verifier: Opus, 1 round, **PASS**, 0 gaps (3 minor
  non-blocking notes, all closed by this checkpoint: plan status flip, this file's
  "ahead of the pin" line, and the not-yet-done force-push noted below). Commits:
  `eddc5d2` (rebase onto `main`), `aa669ce` (vendor `tests/schemas/SPEC_VERSION` +
  `tests/schemas/aitp-mutual-handshake.schema.json`). Files touched: those two plus this
  file and the plan. Real observed conformance count: **63 passed, 4 failed, 2 skipped of
  69** — failures exactly at `id-009`/`man-006`/`rev-007`/`rev-008` (Phases 1-5's targets),
  `id-008` and everything pre-existing green. Verifier re-ran both the "vendored schemas in
  sync" check and the full conformance run independently (via a git worktree, since the
  sibling spec repo was mid-use by a concurrent lane at verification time) and reproduced
  identical results, plus the spec's own 59-check known-answer verifier, all passing.
  Outstanding from Phase 0: branch history was rewritten by the rebase, so
  `deps/spec-ea22c710f50b` needs a force-push to `origin` at ship time (not done — `/ship`'s
  job, no push has occurred this session). No `ASSUMPTIONS.md` entries — mechanical phase,
  no ambiguous judgment calls. What's next: Phase 1 (add the three `ErrorCode` variants to
  `aitp-core`).
- **Phase 1** — DONE, 2026-09-19. Verifier: Opus, 2 rounds. Round 1: **GAPS** — inserting the
  three new variants mid-enum shifted every later variant's implicit discriminant on this
  `#[repr]`-less fieldless enum, tripping `cargo-semver-checks`'s
  `enum_no_repr_variant_discriminant_changed` lint as **major** (a required CI check) —
  the plan's Phase 1 AC3 had wrongly assumed any `#[non_exhaustive]` addition is
  automatically minor; plus a wrong RFC citation (`0002`→`0003`) and a doc-comment
  contradicting the registry's `UNKNOWN_FIELD`-wins carve-out. Fixed by moving all three
  variants to the enum's tail (after `SessionBundleInvalid`) instead of their originally
  planned mid-enum sections, and correcting both doc comments to mirror the registry's exact
  wording. Round 2: **PASS**, 0 gaps (one new non-blocking doc-wording nit, deferred to
  Phase 6 per the verifier's own call). Commits: `21466ee` (initial), `734cccd` (gap fixes).
  Files touched: `crates/aitp-core/src/error.rs` only, plus this file and the plan.
  `cargo semver-checks --baseline-rev main -p aitp-core` now reports no semver update
  required. No `ASSUMPTIONS.md` entries — the semver-placement question had a single
  empirically-verified correct answer, not an ambiguous judgment call. What's next: Phase 2
  (manifest structural-vs-signature codes in the adapter + HTTP transport).
- **Phase 2** — DONE, 2026-09-19. Verifier: Opus, 1 round, **PASS**, 0 gaps. Commit:
  `777133a`. Files touched: `crates/aitp-rs-adapter/src/lib.rs` (one-line `Malformed(_)` arm
  fix + one new test assertion), `crates/aitp-transport-http/src/server.rs`
  (`handshake_error_code`'s `HE::Manifest(_)` collapse replaced with a per-variant match, plus
  the previously-missing `HE::GrantOverflow` arm; two new tests), plus this file and the plan.
  Verifier independently re-ran the full fixture corpus in an isolated worktree of the pinned
  spec commit (without disturbing the sibling checkout, which is mid-use by a concurrent
  lane): `64 passed, 3 failed, 2 skipped of 69`, `man-006`/`man-004` both green, remaining
  failures exactly `id-009`/`rev-007`/`rev-008`. `cargo semver-checks` clean for both crates.
  No `ASSUMPTIONS.md` entries — the `IncompatibleIdentityType`→`IdentityFailed` call was
  already a recorded plan decision (Open Question 5), not a new ambiguous one. What's next:
  Phase 3 (revocation snapshot codes).
- **Phase 3** — DONE, 2026-09-19. Verifier: Opus, 1 round, **PASS**, 0 gaps. Commit:
  `62e0b5e`. Files touched: `crates/aitp-rs-adapter/src/lib.rs` (new sibling
  `revocation_error_code` function + 4 call-site updates + 1 new test), `crates/aitp-tct/src/error.rs`
  (doc-only `ClaimsMalformed` addition), plus this file and the plan. Verifier independently
  confirmed `tct_error_code` has zero changed lines (true sibling, not a retarget) and that
  the two embedded call sites genuinely swallow their verify-half error (so
  `REVOCATION_SNAPSHOT_SIGNATURE_INVALID` is reachable only via the standalone op — a claim
  re-derived from the current code, not just repeated from the plan). Fixture re-run in an
  isolated worktree: `66 passed, 1 failed, 2 skipped of 69`, only `id-009` remaining.
  `cargo semver-checks` clean for `aitp-tct`. No `ASSUMPTIONS.md` entries — the
  `IssuerMismatch` non-change was already a recorded plan decision (Edge cases note, same
  class as Phase 2's `AidMismatch`), not a new ambiguous one. What's next: Phase 4 (identity
  descriptor `extensions` slot).
- **Phase 4** — DONE, 2026-09-19. Verifier: Opus, 1 round, **PASS**, 0 gaps. Commit:
  `decba91`. Files touched: `crates/aitp-handshake/src/identity.rs` (new field),
  `state_machine.rs`/`identity_pinned.rs`/`payloads.rs` and 3 integration test files (16
  `IdentityDescriptor` construction sites updated — every literal in the workspace, forced by
  the compiler since the struct has no `#[non_exhaustive]`/`Default`), plus this file and the
  plan. Verifier independently confirmed AC4's exact-one-semver-flag claim and empirically
  proved the `id-009` failure-reason shift (`UNKNOWN_FIELD`→`IDENTITY_FAILED`) by building
  both this commit and its parent in separate worktrees and diffing real output, not
  inference. `identity_oidc.rs` confirmed untouched by the whole branch so far (`git diff
  main...HEAD -- .../identity_oidc.rs` empty) — Phase 5's file to touch next. No
  `ASSUMPTIONS.md` entries. What's next: Phase 5 (OIDC test-issuer KAT key / real JWT
  minting).
- **Phase 5** — DONE, 2026-09-19. Verifier: Opus, 1 round, **PASS**, 0 gaps (3 minor
  non-blocking notes, see below). Commit: `8ba29cf`. Files touched:
  `crates/aitp-conformance/src/fixture/placeholder.rs` (new `__VALID_JWT__` substitution pass
  — `substitute_valid_jwt`/`substitute_valid_jwt_at`/`mint_identity_jwt_if_present` — plus
  `mint_oidc_jwt`, `OIDC_TEST_ISSUER_SEED`/`OIDC_TEST_ADAPTER_FALLBACK_AUD`, a `materialize`
  exclusion so `__VALID_JWT__` isn't caught by the unknown-placeholder sentinel, and 3 new
  unit tests), `crates/aitp-rs-adapter/src/lib.rs` (`NoOpResolver` → `OidcTestIssuerResolver`
  resolving one real JWK for `https://auth.openai.com`, matching `OIDC_TEST_ISSUER_SEED`
  constants, and a new `oidc_test_issuer_tests` module, 2 tests), plus this file and the plan.
  Verifier independently built the parent commit in a separate isolated worktree and diffed
  real conformance output (not inference) to prove `id-009` flipped fail→pass; also
  mutation-tested AC4 by swapping the mint/sign pass order in a throwaway worktree and
  confirming the ordering test actually fails when the order regresses. Fixture re-run in two
  independent isolated worktrees: **67 passed, 0 failed, 2 skipped of 69** — `id-009` now
  passing, `mh-002`/`mh-003`/`mh-005`/`id-008` holding their exact pre-Phase-5 codes. Full
  workspace suite: 725 passed, 0 failed, 5 ignored. `cargo fmt --check`/`clippy -D warnings`
  clean on both touched crates. Three non-blocking verifier notes (all accepted as-is, no code
  change): (1) the plan's AC1 predicted `id-009`'s pre-Phase-5 failure as
  `KEY_RESOLUTION_FAILED`; actual observed baseline is `IDENTITY_FAILED` (the literal
  placeholder string fails JWT parsing before key resolution) — plan-text-only inaccuracy,
  corrected in the plan's Phase 5 section; (2) the minted `aud` fallback mirrors only the
  adapter's hardcoded fallback AID, not its `tct.aud` peek — inert, no current `__VALID_JWT__`
  fixture carries a `tct` in its payload; (3) a `__VALID_JWT__` living in a Sequence input's
  shared `context` rather than a step's own params would mint before the step-level `self_aid`
  merge — also inert, no current fixture exercises it. No `ASSUMPTIONS.md` entries — the
  plan's Approach section was directly implementable with no ambiguous judgment call. What's
  next: Phase 6 (Docs, CHANGELOG, and CI expectation refresh) — the last phase.
- **Phase 6** — DONE, 2026-09-19. Verifier: Opus, 2 rounds. Round 1: **GAPS** — two minor
  doc-wording inaccuracies introduced by this phase's own new text: `CHANGELOG.md`'s
  `### Fixed` entry double-counted `Malformed` among the "already-registered code" classes
  (should be six of seven, not seven, since `Malformed` is the one getting the *new* code);
  `docs/jcs.md` overclaimed `IdentityDescriptor` nests inside all four handshake payloads
  when it's only two (`MutualHelloPayload`/`MutualHelloAckPayload` — the commit payloads have
  no `identity` field). Round 2: **PASS**, both confirmed closed against the live text and
  re-checked against the code (the six/seven split verified true against
  `server.rs:1262-1284` and `main`'s pre-existing `ErrorCode` variants; the payload-nesting
  claim verified true against `payloads.rs`). Commits: `d8b46bc` (initial), `56dc5c8` (gap
  fixes). Files touched exactly per the plan's Files list, no scope creep: `CHANGELOG.md`
  (new `[Unreleased]`/`### Added` entry for the three codes + `extensions`, a `### Fixed`
  entry for the HTTP-transport behavior change, and a correction to the now-stale "pending
  next spec bump" claim), `docs/conformance.md` (fixture-table rows for
  `man-006`/`rev-007`/`rev-008`/`id-008`/`id-009`), `.github/workflows/ci.yml` (fixture-count
  comment `62/0/2 of 64` → `67/0/2 of 69`, the real measured number, not hand-computed), plus
  three deferred doc fixes from earlier phases' verifiers (`aitp-core`'s `ManifestInvalid` doc
  wording, `server.rs`'s `IncompatibleIdentityType` arm comment cross-referencing Open
  Question 5, `docs/jcs.md`'s `Option<ExtensionsMap>` type list). Both round-1-touched `.rs`
  files confirmed comment-only (byte-identical to their parent commit with comments
  stripped) — no logic slipped in under a docs phase. All 3 acceptance criteria independently
  measured, not assumed: conformance corpus re-run confirms `67 passed, 0 failed, 2 skipped
  of 69`; full workspace suite `725 passed, 0 failed, 5 ignored`; `fmt --check`/clippy clean.
  No `ASSUMPTIONS.md` entries. **This was the plan's last phase** — what's next: the
  `/implement` Finalization pass (whole-feature tests, integration tests across phase seams,
  one final cumulative Opus verification pass) before anything ships.
- **Finalization pass** — DONE, 2026-09-19. Whole-workspace `cargo build`/`test --all-features`
  (725 passed, 0 failed, 5 ignored) and `fmt --all --check` re-confirmed clean; conformance
  corpus re-confirmed `67 passed, 0 failed, 2 skipped of 69`. An isolated-worktree empirical
  check proved the Phase 4→Phase 5 dependency is real (reverting Phase 4's commit alone while
  keeping Phase 5's code drops `id-009` to failing, 66/1/2) — not just claimed by the plan.
  `cargo semver-checks` re-confirmed exactly the one expected major break
  (`aitp-handshake`'s `IdentityDescriptor.extensions`, `constructible_struct_adds_field`),
  consistent across every check this session. Verifier: Opus, cumulative whole-branch review
  (all 6 phases as one unit, not phase-by-phase) — **GAPS**, all documentation-accuracy, zero
  code defects: (1, blocking) `CHANGELOG.md`'s `IdentityDescriptor.extensions` entry didn't
  disclose the semver-major break; (2, blocking) `docs/conformance.md`'s headline fixture
  count was stale (64) against `ci.yml`'s already-updated 69; (3–8, minor) CHANGELOG
  overclaims/underclaims — HTTP-transport reachability scoped to only 4 of 7 `ManifestError`
  classes (traced `state_machine.rs:441`'s `bootstrap_verify_peer` → `verify_manifest`, never
  `parse_manifest_wire`), `IncompatibleIdentityType`'s mapping softened to "closest registered
  code", the "replaces a signature-family code" headline rescoped (only
  `REVOCATION_SNAPSHOT_SIGNATURE_INVALID` truly does), a missing note that both
  `REVOCATION_SNAPSHOT_*` codes are reachable only via the unpublished adapter today (plan's
  Open Question 3), and a missing CHANGELOG entry for Phase 5's `NoOpResolver` →
  `OidcTestIssuerResolver` fix. Round 2 (fresh Opus, given the itemized gap list): **GAPS** —
  7/8 confirmed closed against the live text and re-traced code citations; item 2 found only
  half-fixed (the headline was right but the same file's separate "v0.2 conformance matrix"
  Summary table three paragraphs down still said `53`/`64`, contradicting both the headline
  and this branch's own already-updated per-RFC detail table below it). Round 3 (fresh Opus,
  scoped to just that one remaining item): **PASS** — independently re-summed the detail
  table's per-RFC rows (58) and cross-checked against the pinned fixture corpus directly
  (58 `required_for_v0_2: true` of 69 total). Commits: `fdd6dc6` (7 of 8 items),
  `45d52de` (the 8th). Files touched: `CHANGELOG.md`, `docs/conformance.md` only — no code.
  No `ASSUMPTIONS.md` entries. **This closes `/implement`'s phase loop + Finalization pass for
  issue #144.** What's next: `/ship` (opening/updating PR #145) was not requested this session
  and is a deliberately separate, not-yet-authorized step per the plan's Branch strategy
  section — do not initiate it without explicit direction.
- **`/ship`** — authorized 2026-09-20. Local gates green: build/clippy/fmt clean,
  `cargo test --workspace --all-features` 725 passed/0 failed/5 ignored, conformance corpus
  67 passed/0 failed/2 skipped of 69 (CI's exact invocation, matching `ci.yml`'s documented
  expectation). Ship-gate verifier: fresh Opus, full `git diff main...HEAD` (all 19 files) —
  **PASS**, no blocking gaps; independently re-derived all 5 Open Questions from code rather
  than trusting the plan text, spot-checked doc claims against source, confirmed
  `ASSUMPTIONS.md`/`DECISIONS.md` untouched by this plan. Flagged two pre-existing (not
  introduced by this branch) imprecisions in `docs/conformance.md`'s Summary table
  (`del-004`'s SKIP row and the "2 skip" attribution) — not blocking, same shape existed at
  the old 64-fixture counts. **pushed `deps/spec-ea22c710f50b` `5a4ded3`** (force-with-lease;
  Phase 0 rebased the branch's original single bot commit `cf23ca5` onto `main`'s current tip,
  so the remote history diverged and required a force-push — expected and plan-documented, not
  an accident). Updates PR #145 in place. `cargo-semver-checks` is expected to show red on this
  PR (the single disclosed `constructible_struct_adds_field` on `IdentityDescriptor` — matches
  precedent PR #141, which merged with the same check red); confirm on the CI run that it's
  *exactly* that one finding before treating a non-green rollup as mergeable.
- **CI run 1** (`5a4ded3`) surfaced two *unplanned* required-check failures, unrelated to
  issue #144: `cargo-audit`/`cargo-deny` both red on `RUSTSEC-2026-0285` (rustls TLS 1.3
  handshake-message validation bug, published 2026-09-14 — after this branch's work started)
  plus a yanked `wnaf 0.14.0` (transitive via `aitp-crypto`'s `p256` dep). Confirmed via
  `git diff main...HEAD -- Cargo.lock` that this branch's diff never touched `Cargo.lock` —
  genuine environment drift, not a regression from this PR's changes. Fixed with a narrow,
  tested `cargo update -p rustls -p wnaf` (0.23.43→0.23.45, 0.14.0→0.14.1, both within
  existing `Cargo.toml` ranges, zero source changes) — commit `8f07149`. `bindings cargo-deny`
  also failed (a `--config` CLI-arg incompatibility, unrelated) but is **not** a required
  check, left alone.
- **CI run 2** (`8f07149`) — `cargo-audit`/`cargo-deny` now green. Only two checks red:
  `cargo-semver-checks` (required — confirmed via job log: every crate but `aitp-handshake`
  reports "no semver update required"; `aitp-handshake` shows exactly one finding,
  `constructible_struct_adds_field` on `IdentityDescriptor.extensions` at
  `identity.rs:52` — the single disclosed break, nothing else) and `bindings cargo-deny`
  (not required, pre-existing unrelated CLI issue). `gh pr view 145` reports
  `mergeStateStatus: BLOCKED`, `mergeable: MERGEABLE` — no conflicts, blocked purely by the
  required `cargo-semver-checks` check, identical to PR #141's situation (merged there by a
  human admin override, `merged_by: ajit-zer07`). **`/ship` stops here per its own
  guardrail** ("do not try to bypass branch protection") — ready to merge, needs a manual
  admin override of `cargo-semver-checks` from a repo admin. PR:
  https://github.com/agentidentitytrustprotocol/aitp-rs/pull/145

## Branch state (read this before touching anything)

- `deps/spec-ea22c710f50b` (PR #145) originally had one commit, `cf23ca5`, branched from
  `7e338b6` (pre-PR #141) — behind `main`'s tip `9f887dd`, which is why PR #145's two red CI
  checks (`vendored schemas in sync`, `conformance fixtures`) were red: a stale-base problem,
  not a real defect in the bump itself. Phase 0 rebased and re-synced properly; the branch now
  has 20 feature/doc commits on top of `main`'s `9f887dd`, force-pushed to `origin` at `5a4ded3`
  (see Checkpoint trail).
- aitp-rs vendors **only** `schemas/json/*.schema.json` and
  `schemas/conformance/known-answer/**` (`scripts/sync-schemas.sh:41-64`). Conformance
  fixtures themselves are read live from the sibling spec checkout, resolved via
  `tests/schemas/SPEC_VERSION` (CI: `.github/workflows/ci.yml:395-404`; local minting:
  `tools/mint-conformance-fixtures/src/main.rs:488-492` via `$AITP_SPEC_DIR`, default
  `../agentidentitytrustprotocol`). `man-006`/`rev-007`/`rev-008`/`id-008`/`id-009` do not
  exist anywhere in this repo's tree.
- Sibling spec repo (ground truth for what the bump brings, restored after Phase 0's vendor
  step — do not assume its checkout still sits at `ea22c71`, another concurrent lane in this
  workspace has since moved it to a different branch):
  `/Users/Shared/agentIdenitytrustprotocol/agentidentitytrustprotocol`. `ea22c71` **is now
  this repo's own pin** (`tests/schemas/SPEC_VERSION`), not just a future target.
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

- `crates/aitp-core/src/error.rs` — `ErrorCode` enum, `#[non_exhaustive]`,
  `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]` is the **only** wire mapping — no
  `Display`/`as_str`/`FromStr`. **DONE (Phase 1).** `ManifestInvalid`, `RevocationSnapshotInvalid`,
  `RevocationSnapshotSignatureInvalid` all live at the **tail of the enum**, after
  `SessionBundleInvalid` — NOT mid-enum after `ManifestVersionUnknown`/`TctExpiresAfterManifest`
  as originally planned. That placement was rejected by Phase 1's verification gate: this is a
  `#[repr]`-less fieldless enum, so a mid-enum insertion shifts every later variant's implicit
  discriminant and trips `cargo-semver-checks` as major. Any later phase reasoning about "where
  a new `ErrorCode` variant should go" should default to the tail, not its conceptually-grouped
  section, unless a variant is added at the very end of the enum's current range anyway.
- Three coupled sites, same file, already updated together for these three variants — pattern
  to repeat if a later phase ever adds another variant:
  - `pinned_wire_strings`' `cases` table.
  - `assert_every_variant_named`'s exhaustive or-pattern — **no `_` arm**, compile error if a
    variant is added without a row here. This is the hard gate.
  - `assert_eq!(cases.len(), 53, ...)`.
- `AitpError` (`:18-48`) is a separate, vestigial enum — nothing constructs it, not relevant.
- No file in this repo enumerates the error-code registry for humans (the authoritative list
  is the spec repo's `registries/error-codes.md`, not vendored here). `docs/conformance.md`'s
  fixture table (`:390-416`) is the closest thing and is what Phase 6 updates.

## Manifest — structural vs. signature (Phase 2) — DONE

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
  - `crates/aitp-rs-adapter/src/lib.rs` `manifest_error_code` — **DONE**: `Malformed(_)` now
    maps to `"MANIFEST_INVALID"`. `AidMismatch => "MANIFEST_SIGNATURE_INVALID"` and
    `MissingField(_) => "INVALID_ENVELOPE"` left deliberately unchanged, per plan.
  - `crates/aitp-transport-http/src/server.rs` `handshake_error_code` — **DONE**: the
    `HE::Manifest(_)` collapse replaced with a per-variant match (mirroring the `HE::Tct`
    precedent), fixing a real production bug — HTTP handshakes no longer misreport
    `Expired`/`PopFailed`/`VersionUnknown`/`UnknownField` manifests as signature failures.
    `HE::GrantOverflow` also gained its own arm (adjacent one-line fix, was falling to the
    catch-all as `InvalidEnvelope`).
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

## Revocation snapshot — structural vs. signature (Phase 3) — DONE

- `crates/aitp-tct/src/revocation.rs:166-184` `parse_revocation_snapshot_wire` — structural.
  Member-set → `TctError::UnknownField` (`:170,174,179`); residual deserialize failure (e.g.
  missing `published_at`, `rev-007`'s shape) → `TctError::ClaimsMalformed` (`:181`).
- `crates/aitp-tct/src/revocation.rs:203-226` `verify_revocation_list` — signature. The actual
  Ed25519 check is `:221-224`; failure → `TctError::SignatureInvalid`.
- `crates/aitp-tct/src/error.rs:6-81` `TctError`, `#[non_exhaustive]` — no revocation-specific
  variant exists; `ClaimsMalformed`'s doc comment (`:49-52`) is written about JWS claims, not
  JCS bodies — Phase 3 adds a clarifying line, doesn't rename.
- Mapping (again no `From` impl, hand-written):
  - `crates/aitp-rs-adapter/src/lib.rs` `tct_error_code` — **unchanged (DONE, deliberately
    left alone)**, still shared with real `tct-*` fixtures. `IssuerMismatch =>
    "TCT_SIGNATURE_INVALID"` stays, per plan's Open Questions #2.
  - `crates/aitp-rs-adapter/src/lib.rs` `revocation_error_code` (new, sibling of
    `tct_error_code`, right after it) — **DONE**: overrides `ClaimsMalformed(_)` →
    `"REVOCATION_SNAPSHOT_INVALID"` and `SignatureInvalid` → `"REVOCATION_SNAPSHOT_SIGNATURE_INVALID"`,
    falls through to `tct_error_code` for everything else.
  - `crates/aitp-transport-http/src/server.rs:1252-1255` — `TctError → ErrorCode`, but only
    reachable via `HandshakeError::Tct`, never from the standalone revocation-snapshot path.
    Not touched by this plan.
- `verify_revocation_snapshot_op` — **DONE**: both error sites (parse, verify) now use
  `revocation_error_code`. `TCT_REVOKED` for a stale snapshot under `fail_closed` remains a
  separate, untouched hardcoded literal — `rev-001` unaffected, confirmed still green.
- Two more call sites, both switched to `revocation_error_code` (parse-half only — **DONE**):
  `verify_tct_op`'s `issuer_revocation_list.snapshot`; delegation's `revocation_snapshots[]`.
  Verify-half errors at both sites are swallowed (not propagated), so
  `REVOCATION_SNAPSHOT_SIGNATURE_INVALID` is reachable only through the standalone op —
  confirmed against the current code by Phase 3's verifier, not just asserted by the plan.
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

## Identity descriptor (Phase 4 — DONE) and OIDC minting (Phase 5)

- `crates/aitp-handshake/src/identity.rs` `IdentityDescriptor` — **DONE**: gained
  `extensions: Option<ExtensionsMap>`, same shape as the four payload structs.
  `deny_unknown_fields` stays on. 16 construction sites workspace-wide updated (compiler-
  forced, no `#[non_exhaustive]`/`Default` on this struct).
- `crates/aitp-handshake/src/identity_oidc.rs:88-96` — the OIDC/`public_key` exclusivity rule
  (`id-008`'s concern) is **already enforced in Rust**, first check in `verify_oidc`, tested
  at `crates/aitp-handshake/tests/p1_p8_regressions.rs:194-232`. Confirmed untouched by Phase
  4 (and by the whole branch so far) — still Phase 5's file to touch, not before.
- `crates/aitp-handshake/src/payloads.rs` — **DONE**: renamed/inverted to
  `nested_identity_now_accepts_extensions_field`; companion
  `nested_identity_omits_extensions_when_absent` added.
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

# Progress — issue #148 (cross-impl coverage for the committed manifest fixture)

Plan: `plans/cross-impl-manifest-coverage.md`. Tracking issue: #148 (mostly stale — D9/PR#141
already covers the freshly-minted half). No spec bump, no Rust-side change, no public API.

## Repo map

- `scripts/xcheck-verify.py` — the main file Phase 1 touches (`.github/workflows/ci.yml`'s
  path filter is the other, see below). `DEFAULT_COMMITTED`/`--committed`
  (`:66-70`, `:104-109`, revocation-only before this plan), `check()`/`check_rejects()`
  helpers (`:78-99`), existing manifest checks (`:159-170`, both freshly-minted), Direction
  (b) narration (`:297-308`, print-only, doesn't semantically fit the new checks),
  byte-identity block (`:314-323`, revocation-only, the closest existing "committed fixture"
  precedent in spirit).
- `tools/mint-signed-examples/src/bin/xcheck_mint.rs:123-168` — manifest minting (D9); confirmed
  this plan needs zero changes here.
- `.github/workflows/ci.yml` — `changes` job (`:43-62` post-fix, filter list `:54-62`,
  `scripts/**`/`tools/**` now present — Phase 1 fixed the part of issue #150's path-filter
  gap that this plan's own PR depended on) and `xcheck` job (`:430-476`, job id `xcheck`,
  display name `cross-impl acceptance (aitp-verifier-py)`, pin file
  `tests/AITP_VERIFIER_PY_VERSION` read at `:442`).
- `tests/AITP_VERIFIER_PY_VERSION` — pinned SHA `c5ecb604441f041e734f610b5f372299c97dfcda`
  (stale relative to aitp-verifier-py `main`, tracked separately as issue #149; confirmed this
  plan's fix works correctly at the current pin, no bump needed).
- `tests/schemas/known-answer/signed-examples/manifest/kat-keypair-001-manifest.json` — the
  committed fixture this plan cross-checks; same file `plans/manifest-signing-regression-coverage.md`
  (issue #147) pins on the Rust side — the code changes are disjoint files, but both plans add
  a `CHANGELOG.md` bullet under the same `[Unreleased]` → `### Added` section (trivial
  merge-conflict risk, not disjoint there); order still doesn't matter either way.
- `/Users/Shared/agentIdenitytrustprotocol/aitp-verifier-py` — sibling checkout (read-only for
  this plan). `aitp_verifier/manifest.py` at the pinned SHA (read directly via
  `git show <sha>:aitp_verifier/manifest.py`) is the source of the exact primitives
  (`parse_aid`, `b64url_decode`, `sha256`, `canonicalize`, `decode_tagged_signature`) Phase 1's
  negative check reuses.
- `DECISIONS.md:158-173` (D9) and `ASSUMPTIONS.md:162-191` — existing, already-closed records
  of the freshly-minted half's fix; not touched by this plan (see Open Questions #3).
- `plans/cross-repo/aitp-verifier-py-post-0.12.0-sync.md` — a pre-existing, unrelated
  cross-repo plan (spec-drift `signing_input` companion-field bug in aitp-verifier-py's own
  pytest suite). Confirmed no overlap: different files, different repo-side, different bug.

## Checkpoint trail

- Plan drafted 2026-09-25. Research: one Opus subagent (confirmed script structure, CI filter
  gap, fixture shape) plus a direct read of `scripts/xcheck-verify.py` in full and
  `aitp_verifier/manifest.py` at the pinned SHA to ground the negative check's exact API
  surface before committing to the phase design (avoided relying on the subagent's
  un-cited API sketch). Plan review: 1 round, REVISE, all 6 findings applied (AC2's inverted
  observable, the CI path-filter self-defeat, the `python3.11` requirement, and 3 smaller
  fixes) — see plan's own "Plan review" section.
- Phase 1 implemented 2026-09-25 in git worktree `aitp-rs-148` (branch
  `chore/cross-impl-manifest-coverage`, isolated from #147's concurrent work in the main
  checkout): `scripts/xcheck-verify.py` gained `DEFAULT_COMMITTED_MANIFEST` +
  `--committed-manifest`, a positive check (committed manifest fixture verifies via
  `aitp-verifier-py`'s real `verify_manifest`) and a negative check (same signature must not
  verify over the wrapped `{"manifest": ...}` form, reusing `verify_manifest`'s own internal
  primitives, no re-signing); `.github/workflows/ci.yml`'s `changes` job `rust` filter gained
  `'scripts/**'`/`'tools/**'` so this plan's own PR doesn't skip the `xcheck` check it depends
  on. Local: Docker-minted `xcheck-mint` output piped into `python3.11 scripts/xcheck-verify.py`
  (pinned `aitp-verifier-py` @ `c5ecb604...` in a scratch venv) — both new checks `ok`, exit 0;
  AC2's reversed-mutation probe confirmed to `FAIL` exactly as the plan states;
  `py_compile` clean. Fresh-Opus verify: **PASS** (independently reproduced AC1/AC2 from a
  clean venv, confirmed the pinned-vs-ahead-of-pin package distinction via
  `direct_url.json`, confirmed the `ImportError` guard is real via a stub-package probe, and
  confirmed the positive check is non-vacuous by tampering individual signed fields). 3
  non-blocking repo-map citation nits fixed in a follow-up commit (see plan's Phase 1 status
  note).
- Phase 2 implemented 2026-09-25 (same branch): `CHANGELOG.md` entry added under
  `[Unreleased]` → `### Added`, referencing issue #148, noting issue #150's path-filter gap
  is partially closed by this PR. Comments on issues #148 and #150 to be posted via `gh` at
  ship time (communication, not a merge gate). This closes both phases of issue #148's plan.
- Ship-gate: fresh-Opus full-diff verify **PASS** (3 non-blocking doc nits, fixed in
  `ec71123`). pushed chore/cross-impl-manifest-coverage ec711232f846dab3213b6a916a7386f66bca1a9a
- PR #180 opened: https://github.com/agentidentitytrustprotocol/aitp-rs/pull/180

# Progress — issue #147 (manifest signing-input regression coverage)

Plan: `plans/manifest-signing-regression-coverage.md`. Tracking issue: #147. No spec bump,
no cross-repo work, no public API change (`ManifestSigningView`/`manifest_signing_bytes` are
both `pub(crate)`).

## Repo map

- `crates/aitp-manifest/src/builder.rs` — `ManifestBuilder::build()` (`:182`), inline
  signing-bytes construction (`:238-257`, the sign-side half of the gap),
  `ManifestSigningView` def (`pub(crate)`, `:339-360`), existing `#[cfg(test)] mod tests`
  (`:371` onward). Phase 1 adds `manifest_signing_bytes` here; Phase 3 adds a KAT test to the
  existing `mod tests`.
- `crates/aitp-manifest/src/verifier.rs` — `verify_manifest()` (`:49-137`, verify-side half of
  the gap at `:76-92`), `parse_manifest_wire()` (`:168-190`, the wrapper-detecting public entry
  point Phase 2's Test A should route through instead of a bare `serde_json::from_value`).
- `crates/aitp-manifest/src/error.rs` — `ManifestError` (`#[non_exhaustive]`), `Malformed`
  and `SignatureInvalid` variants already exist; no new variant needed for this plan.
- `crates/aitp-manifest/src/types.rs` — `Manifest`, `MANIFEST_MEMBERS`, `IdentityHint`,
  `ManifestPop` — all `pub` fields, no new dependency needed to construct one in a test.
- `crates/aitp-manifest/tests/signing_input_kat.rs` — the file the issue names; confirmed
  self-referential (no `aitp_manifest` import at all). Phase 2 rewrites it.
- `crates/aitp-manifest/tests/round_trip.rs` — 20 existing tests, all against freshly-minted
  manifests (none against the committed fixture); PR #168 added
  `parse_manifest_wire_missing_required_field_is_malformed_not_unknown_field` (`:406`) here as
  the closest existing precedent for this plan's approach. Not otherwise touched by this plan.
- `crates/aitp-cli/tests/cli.rs:220-241` — `manifest_verify_ok_within_validity_window`, the
  one existing test (subprocess, wrong crate/altitude) that currently catches the issue's
  regression. Not modified — stays as an additional CLI-surface check.
- `tests/schemas/known-answer/signed-examples/manifest/kat-keypair-001-manifest.json` — the
  committed fixture Phase 2 pins against. `aid = aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik`,
  `published_at: 1711900000`, `expires_at: 1711986400`.
- `tests/schemas/known-answer/jcs-sha256.json` → `kat-manifest-001` — the spec-pinned
  canonical-bytes vector Phase 3 pins against (623 bytes, `signing_input: "body"`). Currently
  only consumed raw (no production code path) by `crates/aitp-core/tests/kat.rs:40`.
- `tests/schemas/known-answer/keypairs.json` — `kat-keypair-001` vector, read by the
  `kat_keypair_aid()` helper Phase 2 copies from `crates/aitp-tct/src/revocation.rs:354-368`.
- **Precedent to mirror**, all already on `main`: `crates/aitp-tct/src/revocation.rs:105-126`
  (`revocation_signing_bytes`, Phase 1's model), `:392-433` (`rfc_kat_canonical_bytes_match`,
  Phase 3's model), `:435-523` (three-test committed-fixture pattern, Phase 2's model);
  `crates/aitp-session-bundle/src/builder.rs:168-274` (`bundle_signing_bytes` +
  `production_signing_bytes_match_the_pinned_vector`, Phase 1 and Phase 3's other model);
  `crates/aitp-transport-http/src/revocation.rs:676-698` (PR #168's own regression-test style
  — positive assertion paired with a negative ruling out the mis-classification).

## Checkpoint trail

- Plan drafted 2026-09-25. Research: two parallel Opus subagents (manifest funnel +
  revocation/PR#168 pattern), plus direct reads of `builder.rs`, `verifier.rs`, `types.rs`,
  `error.rs`, `signing_input_kat.rs`, `revocation.rs:340-524`, and `jcs-sha256.json`'s
  `kat-manifest-001` vector to ground Phase 3's exact field shapes before committing to the
  phase design. Plan review: 2 rounds, both REVISE, all findings applied — see plan's own
  "Plan review" section.
- Phase 1 implemented 2026-09-25 on branch `chore/manifest-signing-regression-coverage`:
  `impl From<&Manifest> for ManifestSigningView` + `manifest_signing_bytes` added to
  `builder.rs`; `build()` reordered to construct the `Manifest` first (placeholder
  `signature`), derive the view, sign, then splice in the real signature;
  `verifier.rs`'s hand-built 14-field view replaced with `ManifestSigningView::from(manifest)`,
  dead `aitp_core::jcs` import removed. Local: 47/47 `aitp-manifest` + 14/14 `aitp-cli` green,
  clippy `-D warnings` clean. Fresh-Opus verify: **PASS** (see plan's Phase 1 status note).
  Committed as its own commit, separate from Phase 2's test file.
- Phase 2 implemented 2026-09-25 (same branch): `signing_input_kat.rs` rewritten with
  `kat_keypair_aid()` helper, Test A (`committed_manifest_example_verifies_via_verify_manifest`),
  Test B kept as-is, Test C (`wrapped_signed_manifest_is_rejected_by_verify_manifest`). Local:
  3/3 new-file tests green, `aitp-manifest` crate total now 49, workspace 731/731. Fresh-Opus
  verify: **PASS** — full deliberate-mutation matrix run in an isolated worktree, confirming
  Test A/C catch the issue's exact both-sides-flipped repro (see plan's Phase 2 status note
  for the table). One wording correction applied to the plan and the test file's module doc
  comment (AC2's "Test A is the only thing that fails" overstated it — a pre-existing,
  incidental `round_trip.rs` test also fails under the same mutations; doesn't weaken the
  phase's actual claim). Committed as its own commit.
- Phase 3 implemented 2026-09-25 (same branch): `signing_bytes_match_the_pinned_kat_vector`
  added to `builder.rs`'s existing `#[cfg(test)] mod tests`, driving the spec's
  `kat-manifest-001` vector through the shared `ManifestSigningView::from` +
  `manifest_signing_bytes`, asserting byte length/hex/digest match the pinned vector, plus two
  load-bearing mutation checks (`required_peer_capabilities` → `None`, `extensions` →
  `Some(empty)`) confirmed to break the byte match. `CHANGELOG.md` entry added under
  `[Unreleased]` → `### Added`. Local: `aitp-manifest` crate total now 50, full workspace
  suite and clippy `-D warnings` both clean. This closes all 3 phases of issue #147's plan.
- Ship-gate: fresh-Opus full-diff verify **GAPS** (3 doc-only items), all fixed in `83acdc9`;
  re-verify closure pass found one item (a 1-line truncation from the #148-section removal)
  needing a follow-up fix, applied in `5814c36`. Rebased onto `origin/main` after #148's PR
  #180 merged (2 conflicts, both in files both plans append to — `PROGRESS.md`,
  `CHANGELOG.md` — resolved by keeping both sections/entries in sequence). Full workspace
  suite + clippy re-confirmed clean post-rebase.
  pushed chore/manifest-signing-regression-coverage 5814c3639b48ab7c0b4e31688d4afdc5d6db8e09
