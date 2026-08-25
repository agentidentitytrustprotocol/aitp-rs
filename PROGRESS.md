# PROGRESS — jcs-inner-body-signing-input

Plan: `plans/jcs-inner-body-signing-input.md` · Issue: #82 · Branch: `deps/spec-5f8e588e128d` (PR #81)

## Repo map

### The four wrapped-signing sites (Phase 3 targets)
- `crates/aitp-tct/src/revocation.rs` — `RevocationList` :20-34 (no `signature` member; `entries` :33 has NO skip_serializing_if — correct), `RevocationListEnvelope` :55-63, `RevocationListSigningView` :68-71, `sign_revocation_list` :78-93, `verify_revocation_list` :103-130, `VerifyRevocationListContext` :133-138 (pub fields, no builder), `RevocationEntry.reason` :45-46 (skip_serializing_if — benign, fail-closed). Tests: `empty_entries_round_trips` :203, `rfc_kat_canonical_bytes_match` :216-247 (old hex :236, old digest :245), `spec_signed_example_snapshot_verifies` :249-276 (old sig :268).
- `crates/aitp-session-bundle/src/builder.rs` — sign call site :102-115, doc comment to replace :129-131, `BundleSigningView` :132-135, `BundleSigningBody` :139-147 (correct projection, keep).
- `crates/aitp-session-bundle/src/verifier.rs` — `verify_session_bundle` :63, wrapped reconstruction :107-119.
- `crates/aitp-session-bundle/src/types.rs` — `SessionTrustBundle.signature` doc ALREADY states the inner convention.
- `tools/mint-conformance-fixtures/src/main.rs:1298-1320` — `mint_rev_snapshot` hand-rolls `json!({"revocation_list": …})`, bypassing the library.
- `crates/aitp-conformance/src/fixture/placeholder.rs` — `substitute_signatures` :332, convention selection :433-457, key resolution w/ explicit wrapped branches :444-452, `sign_generic_body` :655-671 (signs whole map minus `signature`).

### Control case — DO NOT TOUCH
- `crates/aitp-manifest/src/builder.rs:309` — `ManifestSigningView`, already inner.
- `crates/aitp-cli/tests/cli.rs:210-237` — verifies the byte-unchanged committed manifest example.

### The four blind spots (Phase 2 + 4 targets)
- `crates/aitp-core/tests/kat.rs` — adaptive `signing_input` helper :14-30, call site :74, FALSE comment :62-73.
- `crates/aitp-tct/src/revocation.rs:216-247, :249-276` — self-referential; never read the vendored tree.
- Conformance suite — `__VALID_A_SIG__` placeholders re-minted by `placeholder.rs`; each impl signs+verifies its own output.
- `.github/workflows/bindings.yml:114` `interop (python ↔ node)` — both bindings wrap the same Rust core. `bindings/interop/test_interop.py:433` only PARSES, never verifies.
- The one honest signal: `tools/mint-signed-examples/tests/verify.rs:117` (`minted_revocation_snapshot_verifies`) reads the live spec sibling :20 — RED locally now, self-skips in CI :28-40.

### Vendoring
- `scripts/sync-schemas.sh` — `AITP_SPEC` :19 (default `../agentidentitytrustprotocol`), schemas :31, known-answer :38, signed-examples :43, writes SPEC_VERSION :50-53. No delete step.
- `tests/schemas/SPEC_VERSION` — currently `52582bb…` on main; target `5f8e588e128d232d9512cc5937caef1246955382`.
- `.github/workflows/ci.yml:295-322` `vendored schemas in sync` — checks out spec at the pin as `../spec`, re-runs the script, fails on diff. (Phase 4 adds `verify-known-answer.mjs` here.)
- `.github/workflows/ci.yml:325-359` `conformance fixtures` — runs the adapter against the LIVE spec at the pin, expects 51/0/2.

### Rename surface (Phase 6) — 70 occurrences
- `crates/aitp-delegation/src/verifier.rs` — doc already spec-named :17, `DEFAULT_MAX_HOPS = 3` :19, `pub max_hops` :41, `new()` sets 0 :60, `with_max_hops` :69-72, usage :103, :255.
- `crates/aitp-delegation/src/lib.rs:23` re-export · `src/error.rs:48,51` docs · `tests/multihop.rs:13,74,108,109,190,191,373` (struct literal at :373) · `tests/round_trip.rs:375`
- `crates/aitp-rs-adapter/src/lib.rs:60,1543,1544,1545,1552` · `fuzz/fuzz_targets/delegation_verify.rs:6,7,22,29`
- `crates/aitp-core/src/error.rs:149` — doc already spec-named.
- BREAKING: `bindings/aitp-node/src/delegation.rs:85` → generated `index.d.ts:142`; `bindings/aitp-py/src/delegation.rs:101` (PyO3 kwarg); `bindings/aitp-py/aitp.pyi:198` (hand-maintained).
- NOT breaking: `bindings/interop/node_worker.mjs:206` (own harness key, passed positionally).
- Docs: `docs/multihop-delegation.md:5,52,53,83,94`, `README.md:78,115,122`, `SECURITY.md:45`. Do NOT edit `CHANGELOG.md:271,506,521`.

### Release (Phase 7)
- Versions at `0.4.1`: root `Cargo.toml:36`, `bindings/aitp-node/{package.json:3,Cargo.toml:6}`, `bindings/aitp-py/{pyproject.toml:11,Cargo.toml:6}`, `=0.4.1` inter-crate pins.
- `scripts/check-versions.sh` → job `lockstep versions` (REQUIRED). `release-plz.toml` `version_group = "aitp"`, `semver_check = true` (blocking).
- `release-plz.yml` → `aitp-v<X.Y.Z>` tag → `release-bindings.yml` → `bindings-release.yml` (npm, `NPM_TOKEN`) + `aitp-py-release.yml` (PyPI OIDC).
- Required checks on main: lockstep versions, rustfmt, clippy, bindings fmt + clippy, docs, cargo-deny, 4× test. NOT required: vendored schemas in sync, conformance fixtures, cargo-semver-checks, cargo-audit, coverage, wasm, msrv.

### Siblings (read-only)
- `../agentidentitytrustprotocol` — spec, HEAD = `5f8e588`. `scripts/verify-known-answer.mjs` (Node-stdlib-only, 50+ checks, hardcoded relative paths).
- `../aitp-verifier-py` — independent verifier, no shared code. `run_conformance.py --spec-dir ../agentidentitytrustprotocol` → 51/0/2 at 5f8e588. `aitp_verifier/{revocation,sessionbundle}.py` already inner.
- `../aitp-control-plane` (`src/lib/revocation/producer.ts:11-35`, 60s cache), `../aitp-playground`, `../aitp-cp`, `../aitp-ui-console`, `../aitp-website`.
- No `seam/` repo. No `CLAUDE.md` in aitp-rs (gitignored).

### Docs status
- ALREADY CORRECT (verify, don't rewrite): `docs/architecture.md:50`, `docs/session-bundle.md:26,43,56`.
- STALE: `docs/jcs.md:96-101` (omits session bundle from the JCS-profile list).
- Phase 4 additions: `docs/testing.md`, `docs/conformance.md`.

## Baseline (pre-Phase-1, recorded 2026-08-24)
- `cargo test -p mint-signed-examples --test verify` → 4 pass, 1 FAIL (`minted_revocation_snapshot_verifies`: SignatureInvalid). This is the defect, live.
- `aitp-verifier-py` conformance vs spec@5f8e588 → 51 passed, 0 failed, 2 skipped.
- PR #81 CI: `vendored schemas in sync` FAIL, `cargo-audit` FAIL (pre-existing, unrelated), all else green.

## Checkpoints

| Phase | Status | Rounds | Verifier tier | Notes |
|---|---|---|---|---|
| 1 Re-vendor | DONE PASS | 1 | Sonnet | found 5th blind spot -> Phase 4 |
| 2 Make tests honest (RED) | DONE PASS | 2 | Opus | GAP1 vacuous-pass hole closed |
| 3 Move 4 signing sites | DONE PASS | 1 | Fable | 45/6 -> 51/0/2 measured; spec issue #23 filed |
| 4 Close coverage gaps | DONE PASS | 1 | Fable | falsification battery all RED |
| 5 Cross-impl acceptance | DONE PASS | 1 | Fable | CI green 1st run; now REQUIRED |
| 6 Rename max_delegation_hops | DONE PASS | 1 | Fable | 4 public surfaces; .d.ts regenerated |
| 7 #[non_exhaustive] + ctors (D2) | DONE PASS | 1 | Fable | semver-checks: 5 major breaks |
| 8 Release 0.5.0 | DONE | — | — | CHANGELOG + 2 downstream issues |

---

### Phase 1 — Re-vendor at 5f8e588 · PASS · 2026-08-24
- Commit `4c1b5bf`. Verifier: **Sonnet** (mechanical vendored-data change, well-defined right answer). **1 round**, no gaps.
- Files: `tests/schemas/{aitp-revocation-list.schema.json, known-answer/jcs-sha256.json, known-answer/signed-examples/README.md, known-answer/signed-examples/revocation/kat-keypair-001-snapshot.json}`. Nothing outside `tests/schemas/`.
- Outcome: **71 suites pass / 1 fails, identical before and after** (verifier re-ran at both f5ecfae and 4c1b5bf). Three vectors + one signed example changed and NO test noticed — the phase's finding, confirmed.
- Verifier found a **5th blind spot**, proven empirically: `sync-schemas.sh` copies but never mirrors, so an upstream deletion leaves a stale vendored file AND a clean `git diff` — the drift check reports green over it. Latent (no stale file today). Folded into **Phase 4 item 4**, along with the never-vendored `known-answer/README.md`.
- Assumption logged: Phase 1 AC6 reworded "green" -> "no change in outcome" (see ASSUMPTIONS.md).
- Next: Phase 2 — make the blind tests see.

### Phase 2 — Make the blind tests see · PASS · 2026-08-24
- Commits `d0288be` (initial) + `779a44d` (gap fixes). Verifier: **Opus** ×2 (test-only diff, but the phase's whole value is whether the harness can now fail). **2 rounds**.
- Round 1: PASS-with-GAPS. GAP 1 (significant) — deleting a vector's `object` left the suite fully GREEN; presence assertion checked only the id, and `Value::Null.get()` returns `None` so the wrapper check passed vacuously. GAP 2 (minor) — `expected_issuer` taken from the envelope under test, making issuer-binding tautological. Plus 2 nits.
- Round 2: **PASS**, all closed, measured via a 13-mutation battery (+3 adversarial extras: `object: null`, `hex: null`, missing `id` — all red). Fix for GAP 1 was an explicit `NON_CANONICAL_VECTORS` allowlist + `REQUIRED_PAYLOAD` check, which also catches a *fabricated new* vector — skip-on-absence let the file decide its own coverage.
- Files: `crates/aitp-core/tests/kat.rs`, `crates/aitp-tct/src/revocation.rs` (tests only — signing views byte-identical to 4c1b5bf, verified by hashing lines 1-211).
- State: **83 suites pass / 2 fail**, exactly 3 failing tests, all one defect: `rfc_kat_canonical_bytes_match` (241 wrapped vs 221 spec), `spec_signed_example_snapshot_verifies` (SignatureInvalid), `minted_revocation_snapshot_verifies` (pre-existing). This is the intended RED.
- New for Phase 4: `sha256_b64url` pinned in every vector, asserted by **no test** (added as Phase 4 item 5). Phase 3 gains a design note: route sign/verify/test through ONE shared signing-bytes helper so the test can't go green while the public API still signs wrapped.
- Next: Phase 3 — move all four signing sites.

### Phase 3 — Move all four signing sites · PASS · 2026-08-24
- Commits `6615a39` + `23b4f39`. Verifier: **Fable** (wire contract, one-way door, three registries). **1 round**, PASS with 3 minor observations (2 fixed in 23b4f39, 1 filed upstream).
- **The before/after measurement the plan required (AC5) — hypothesis SETTLED:**
  - After sites 1-3, before site 4: **45 passed / 6 FAILED** — `bundle-001` (BUNDLE_INVALID_SIGNATURE), `rev-001/002/003` (TCT_SIGNATURE_INVALID), `del-mh-004` + `tct-004` ("expected failure, got success" — a snapshot that fails to verify means revocation is never consulted).
  - After site 4: **51 passed / 0 failed / 2 skipped**.
  - The competing claim that conformance "stays green either way" was WRONG. `placeholder.rs` mints the fixtures' `__VALID_*_SIG__` placeholders itself, so harness and implementation must agree on the convention. This is why aitp-rs and aitp-verifier-py both reported 51/51 while disagreeing on the wire.
- Files: `crates/aitp-tct/src/revocation.rs`, `crates/aitp-session-bundle/src/{builder,verifier}.rs`, `tools/mint-conformance-fixtures/src/main.rs`, `crates/aitp-conformance/src/fixture/placeholder.rs`, `docs/jcs.md`.
- Design: one shared signing-input helper per artifact — `revocation_signing_bytes()`, `bundle_signing_bytes()` — with signer, verifier AND the KAT test routed through each, so they cannot drift.
- Independent confirmation by the verifier: wrote its own RFC-8785 JCS + Ed25519 (zero aitp-rs code), matched all pins incl. `sha256_b64url`; forged wrapped-signed artifacts in a scratch crate and confirmed BOTH are rejected (`SignatureInvalid`, `InvalidSignature`) — D1 holds, no dual-accept. `aitp-verifier-py` 51/0/2 against the same spec.
- Manifest control byte-unchanged (`git diff -- crates/aitp-manifest/` empty).
- State: **85 suites, 532 tests, 0 failures.** `minted_revocation_snapshot_verifies` now green (was red since the spec was corrected).
- Upstream: filed spec issue #23 — RFC-AITP-0010 §3 and the session-bundle JSON schema disagree on `signature` placement (no byte impact; aitp-rs emits the §3 shape and would fail the schema). Documented in `docs/jcs.md`.
- Next: Phase 4 — close the coverage gaps.

### Phase 4 — Close the coverage gaps · PASS · 2026-08-24
- Commits `43f77b7` + `d0f1a4e`(docs/bundle-helper follow-up). Verifier: **Fable**. **1 round**, PASS with 2 minor gaps + 1 flagged risk — all three closed in the follow-up.
- **AC2 falsification test — the only criterion that means anything:** re-wrapping a vector self-consistently (object + hex + len + BOTH digests, `signing_input` left "body") goes RED for all three artifacts. Strongest case verified by the Fable verifier: `kat-session-bundle-001` re-wrapped AND its `coordinator_signature_b64url` re-signed with the zero-seed key, so the vector was fully coherent in the wrapped convention — still RED (3 failures). Reverted; tree clean.
- Implementation-regression measurement: `revocation_signing_bytes` -> wrapped trips 5 tests + conformance 46/5/2. `bundle_signing_bytes` -> wrapped originally tripped only **1** test; after the follow-up, 2 (added an in-crate test driving the production helper — the helper is `pub(crate)`, so an integration test would have to re-implement canonicalization, which is the defect again).
- Coverage matrix now full for all three artifacts (bytes / committed-sig / **negative**). The negative column was empty everywhere before.
- `sync-schemas.sh` now MIRRORS: verifier deleted 4 files (one per vendored level) from a spec copy and confirmed all 4 surface as drift. Idempotent; vendored file list == spec's. Picks up `known-answer/README.md`, never vendored before.
- CI: `verify-known-answer.mjs` runs in `spec-schemas` (**50 checks**, meets the >=50 floor; fails loudly if the script is missing). YAML parses.
- Files: `crates/aitp-session-bundle/{tests/kat.rs,src/builder.rs,tests/round_trip.rs}`, `crates/aitp-manifest/tests/signing_input_kat.rs`, `crates/aitp-tct/src/revocation.rs`, `crates/aitp-core/tests/kat.rs`, `scripts/sync-schemas.sh`, `.github/workflows/ci.yml`, `docs/testing.md`, `docs/conformance.md`.
- Next: aitp-verifier-py P1-P2 (separate repo/PR, per D4) — must merge before Phase 5 pins its SHA.

### aitp-verifier-py P1-P2 (cross-repo, per D4) · MERGED · 2026-08-24
- PR agentidentitytrustprotocol/aitp-verifier-py#11, squash-merged as **`fc89b5d`**. CI green on py3.11/3.12/3.13; mypy --strict clean (27 files); conformance still 51/0/2.
- No wire-format change — that repo already signed/verified inner. Test coverage only, as planned.
- Gap 1: `signed-examples/` was half covered (3 compact-JWS artifacts; neither JCS-profile example). **Acceptance proven:** pointed at the pre-5f8e588 snapshot (`2OYmur9N…`), the new tests FAIL with `TCT_REVOKED` — the exact fail-closed symptom.
- Gap 2: KAT harness only canonicalized. Now asserts `signing_input == "body"` hard-coded per artifact, treats absent as failure, allowlists non-canonical vectors, asserts vector presence, asserts `jcs_canonical_len_bytes` + `sha256_b64url`, and asserts pinned bytes != wrapped form. Also verifies `kat-session-bundle-001`'s coordinator signature, which no test in EITHER implementation checked.
- Needed a rebase mid-flight (dependabot landed on main).

### Phase 5 — Cross-implementation acceptance · 2026-08-24
- Commit `13a8bf2`. New: `tools/mint-signed-examples/src/bin/xcheck_mint.rs`, `scripts/xcheck-verify.py`, `tests/AITP_VERIFIER_PY_VERSION` (= fc89b5d), CI job `cross-impl acceptance (aitp-verifier-py)`, note on `bindings/interop/test_interop.py`.
- **Direction (b) stronger than planned:** the Rust-minted snapshot is BYTE-IDENTICAL to the spec's committed Python-reference-minted example (`DTmCoELd…`), so "Rust mints -> Python verifies" and "Rust reproduces the reference bytes" collapse into one assertion.
- **AC1 measured:** reverting both signing helpers to the wrapped form fails all three checks — `TCT_REVOKED`, `BUNDLE_INVALID_SIGNATURE`, and byte-identity, with the minted signature reverting to exactly `2OYmur9N…`, the value the spec published before 5f8e588. Reverted.
- Envelope note: `aitp-verifier-py` expects the schema framing (`signature` sibling of the wrapper); aitp-rs's type emits RFC-0010 §3's (signature inside). The minter emits the schema framing. Signed bytes identical either way — envelope reframing, not a re-mint. Spec issue #23.
- D3: job must be added to branch protection AFTER its first green run on this PR.
- Next: Phase 6 — rename max_hops.

### Phases 6 + 7 — rename & non_exhaustive · PASS · 2026-08-24
- Commits `5bfa919` (rename), `f9c23ce` (non_exhaustive), `9515b92` (bindings rustfmt). Verifier: **Fable**, both phases together. **1 round**, PASS + 3 minor non-blocking notes.
- Verifier measured beyond the checklist: built the Python wheel with maturin (**41/41 pytest**, not just cargo check), ran `cargo +nightly fuzz build`, regenerated `index.d.ts` with napi and confirmed the committed file is **byte-identical**, and ran the conformance corpus (51/0/2) to prove the adapter's builder migration did not drop `hop_revocation_check` (`del-mh-004` would catch it).
- `cargo-semver-checks --baseline-rev e5aa555`: **5 major breaking changes** — aitp-delegation ×4 (`with_max_hops` removed, `DEFAULT_MAX_HOPS` removed, struct non_exhaustive, `max_hops` field removed) + aitp-tct ×1 (struct non_exhaustive). Confirms 0.5.0 is required.
- `aitp.pyi` verified to match the pyo3 signature exactly (name, order, default); old `max_hops=` kwarg now raises TypeError at runtime.
- Open minor notes (not blocking): adapter's single-hop `revocation_check` wiring is compile-gated only (no fixture drives it); no Node-side test pins the TS param name (JS has no kwargs — the committed `.d.ts` is the gate, but nothing enforces its freshness on future PRs).

### CI + release state · 2026-08-24
- PR #81, branch `deps/spec-5f8e588e128d`: **32 checks passing**, 2 failing, both expected and NOT required:
  - `cargo-audit` — fails to INSTALL (`kstring@2.0.4 requires rustc 1.96`, toolchain pinned 1.89). Pre-existing, unrelated.
  - `cargo-semver-checks` — advisory/PR-only; red because the breaking changes are real. Correct signal for a breaking release; deliberately not suppressed.
- Newly green that were red at the start: `vendored schemas in sync` (the original failure), plus `conformance fixtures`, `interop`, and the new `cross-impl acceptance (aitp-verifier-py)` (passed first run).
- **D3 applied:** `cross-impl acceptance (aitp-verifier-py)` added to `main` branch protection (now 11 required checks).
- Version NOT bumped by hand: release-plz runs default `release-pr + release` and computes 0.5.0 from the `!`/`BREAKING CHANGE` footers; `release-bindings.yml` stamps binding versions off the `aitp-v*` tag.
- Downstream issues filed: aitp-control-plane#45, aitp-playground#44. Spec issue filed: agentidentitytrustprotocol#23.
