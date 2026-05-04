# Phase 7 — RFC alignment and v0.1.0-alpha.2

You are working on the `aitp-rs` Rust reference implementation. Phases
0–6 shipped `v0.1.0-alpha.1`. This phase closes the gaps surfaced by the
post-alpha.1 audit and lands `v0.1.0-alpha.2`.

**Your goal:** the implementation matches the published RFCs exactly,
the conformance runner exercises Tiers A through D, the spec-side
blockers have been filed as issues against
`agentidentitytrustprotocol/`, and the workspace is in a state worthy of
cutting `v0.1.0-alpha.2`.

You will NOT publish to crates.io in this phase. Publishing is a human
decision.

---

## Required reading

1. `phase-6-report.md`
2. `phase-audit-report.md` — the cross-phase self-audit
3. `docs/design/PENDING.md` — every `BLOCKED-*` listed there is in scope
4. The current state of every crate you will touch
5. The current state of the spec at
   `../agentidentitytrustprotocol/rfcs/RFC-AITP-0001..0012`
6. The JSON schemas at
   `../agentidentitytrustprotocol/schemas/json/aitp-*.schema.json`

---

## Global rules

[All 12 from `_global-rules.md` apply. The "stop at the phase boundary"
rule means: do not publish to crates.io, do not push the
`v0.1.0-alpha.2` tag, do not announce.]

---

## Audit findings this phase resolves

From the audit run on 2026-05-02:

- **D-1** — `Manifest.description: Option<String>` exists in
  `crates/aitp-manifest/src/types.rs:23` but is NOT in
  `schemas/json/aitp-manifest.schema.json` and NOT in RFC-AITP-0003
  §3.1/§3.2. The schema sets `additionalProperties: false`, so a
  manifest with `description` set will fail spec validation. It is
  dormant today (defaults to `None`, `skip_serializing_if` keeps it off
  the wire), but the field's mere existence is spec drift.
- **No other code-level drift detected.** The OIDC `nonce` claim is
  validated correctly at `crates/aitp-handshake/src/identity_oidc.rs:139`
  (the audit's first agent reported this as missing — it was wrong;
  verify yourself before re-opening).

Everything else in scope here was already tracked in `PENDING.md`.

---

## Tasks

### 7.1 — Fix D-1: drop `Manifest.description`

File: `crates/aitp-manifest/src/types.rs`

Remove the `description: Option<String>` field from `Manifest`. Remove
any references in `ManifestBuilder`, in tests, and in
`crates/aitp/src/lib.rs` re-exports. Update the round-trip and
deny-unknown-fields tests to confirm a Manifest with an extra
`description` key now fails to deserialize.

If you discover a real consumer needs the field, STOP and write a
`BLOCKED-SPEC-MANIFEST-DESCRIPTION` entry in `PENDING.md` proposing it
as an addition to RFC-AITP-0003 §3.2 instead of silently keeping the
field.

### 7.2 — Schema-validation tests (drift firewall)

To catch this class of drift in future phases: add a new integration
test in `crates/aitp-manifest/tests/schema.rs` that:

1. Constructs a fully-populated valid Manifest via `ManifestBuilder`.
2. JCS-canonicalizes it.
3. Validates the canonicalized JSON against
   `../agentidentitytrustprotocol/schemas/json/aitp-manifest.schema.json`.
4. Asserts validation passes.

Do the same for `crates/aitp-tct/tests/schema.rs`,
`crates/aitp-delegation/tests/schema.rs`, and the four handshake
payloads in `crates/aitp-handshake/tests/schema.rs`. Use the schemas in
`schemas/json/aitp-*.schema.json` as ground truth.

**Schema validator:** use `boon` (pure Rust, lean, supports JSON
Schema draft 2020-12 which is what the spec uses). Add it as a
**`[dev-dependencies]` entry only** — schema validation is a
test/CI concern, not a runtime concern. Production code already
canonicalizes via JCS and signs; validating against the schema at
runtime would be a redundant trust check that bloats the runtime
closure for no security gain.

Add to `[workspace.dependencies]`:

```toml
boon = "0.6"  # or latest 0.x at time of phase
```

…and reference it as `boon = { workspace = true }` under
`[dev-dependencies]` in each crate that needs it. This is the only
new dep this phase introduces; do not add others without asking.

**Spec repo availability in CI.** Vendor the schemas into
`tests/schemas/` via a check-in script (`scripts/sync-schemas.sh`
that does `cp ../agentidentitytrustprotocol/schemas/json/*.json
tests/schemas/`) rather than a git submodule. Reasons:
- Submodules surprise contributors who don't recurse-clone and break
  CI in confusing ways.
- A vendored copy + sync script makes spec-version pinning explicit
  (commit hash recorded in `tests/schemas/SPEC_VERSION`), so a spec
  bump becomes a visible PR with a diff, not a silent submodule pointer
  bump.
- The script runs in a CI step that also verifies the vendored
  schemas match the pinned spec hash, so drift between the spec and
  the vendored copy is caught at PR review time.

### 7.3 — Implement BLOCKED-SERVER-SESSION-GC

File: `crates/aitp-transport-http/src/server.rs`

The handshake `HandshakeServer` keeps an in-memory `HashMap<SessionId,
SessionState>` with no expiry. Add:

- A configurable `session_ttl: Duration` on the server (default 60 s —
  a handshake should complete in under a second on healthy networks).
- A background sweep that drops sessions older than `session_ttl` on
  each new request (no separate task; piggyback on the request path to
  keep the dependency surface small).
- A test that pins the clock, opens a session, advances time past the
  TTL, and confirms the session is rejected with
  `ErrorCode::SessionExpired` (or the closest existing variant — if
  none fits cleanly, leave a `NOTE-SESSION-ERROR-CODE` entry).

### 7.4 — Tier B/C/D conformance ops (BLOCKED-CONF-TIERBCD)

Files: `crates/aitp-rs-adapter/src/main.rs`, `crates/aitp-conformance/`

Wire the missing operations into the subprocess adapter. Reference
RFC-AITP-0001 and `docs/design/02-conformance-adapter.md` for the op
catalog.

- **Tier B (issuance):** `manifest.issue`, `tct.issue`,
  `delegation.issue`, `handshake.initiate`. These mint signed objects
  from inputs the harness provides.
- **Tier C (stateful flows):** `handshake.step` (advance the state
  machine one message at a time, producing the next outbound payload
  given the inbound payload and prior state). The adapter holds session
  state across multiple NDJSON requests on the same `session_id`.
- **Tier D (test-only):** `clock.set`, `clock.advance`, `keys.import`,
  `nonce.set`. These let the harness drive deterministic flows.

Each op gets at least one round-trip integration test in
`crates/aitp-conformance/tests/runner_integration.rs`.

The in-process `Adapter` impl (today still has `todo!()` — intentional
per phase-5 report) can stay `todo!()` for this phase if it would
double the work; if so, leave a `NOTE-INPROCESS-ADAPTER-DEFERRED` entry
and call it out in the report.

### 7.5 — Resolve BLOCKED-SPEC-FIXTURE-MIGRATION

File: `agentidentitytrustprotocol/schemas/conformance/*.json` (in the
sibling repo).

The fixtures pre-date the runner's wire protocol — they have no
`input.operation` key and contain placeholder strings
(`__NOW_MINUS_3600__`, `__VALID_ENVELOPE_SIG__`, placeholder AIDs). The
runner correctly fails all 21.

**Migrate the fixtures in the spec repo, no compatibility shim.**
Specifically:

1. Write `scripts/mint-conformance-fixtures.rs` (a small bin in this
   repo) that takes the legacy fixture shape and the deterministic
   keypairs/clock the harness already uses, and produces the new
   shape with real signatures, real AIDs, and real timestamps.
2. Run it against every fixture in
   `agentidentitytrustprotocol/schemas/conformance/*.json`.
3. Open a PR against `agentidentitytrustprotocol/` titled
   `chore(conformance): migrate fixtures to runner v0.1 wire shape`.
   Body must reference the AITP-rs commit that introduced the runner
   wire format and explain why placeholders cannot work.
4. Land that PR before this one. The aitp-rs alpha.2 release notes
   reference the spec PR by URL.

**Do NOT add a `--fixture-format=legacy` flag to the runner.** A
translator inside the runner means the runner is testing a translated
dialect, not the wire format an actual implementation would consume.
A Python adapter wouldn't have the same translator and would fail the
same fixtures the Rust adapter "passes" — the runner becomes a lie.
Pay the coordination cost once.

If the spec maintainers reject the PR (unlikely — this is the same
maintainer team), STOP and surface the rejection rather than falling
back to a runner-side shim.

### 7.6 — Resolve BLOCKED-JCS-SURROGATE

`serde_jcs` 0.1 sorts object keys by UTF-8 byte order rather than
UTF-16 code-unit order (RFC 8785 §3.2.3). The astral-vs-BMP test vector
is `#[ignore]`'d in
`crates/aitp-core/tests/jcs_standard_vectors.rs::jcs_surrogate_pair_ordering`.

**Approach — upstream first, fork only as a fallback.** Forking is
fast and feels good ("now it's *our* code") but creates permanent
maintenance debt: every transitive dep that uses upstream `serde_jcs`
becomes a coordination problem. Patch upstream so every Rust user
benefits and we don't carry the burden forever.

Steps in order:

1. Check whether `serde_jcs` ≥ 0.2 has been published. If yes, bump
   and un-ignore the test. Done.
2. Otherwise, file an upstream PR with the fix (sort by UTF-16 code
   units per RFC 8785 §3.2.3) and a regression test using our pinned
   astral-vs-BMP vector. Link the PR from `PENDING.md` as
   `BLOCKED-JCS-UPSTREAM-PR` and leave the test `#[ignore]`'d.
3. Set a 4-week deadline on the upstream PR. If the maintainer is
   unresponsive after 4 weeks (no review, no merge, no rejection),
   fork into a new workspace crate. Name it **`aitp-jcs`** — NOT
   something generic like `serde_jcs2`. The name signals "this is
   AITP's opinionated JCS, not a drop-in replacement," which prevents
   the ecosystem from fragmenting into competing forks.
4. If forked, the fork's README MUST link the upstream PR and state
   the fork's lifecycle: "merge upstream when feasible, deprecate this
   crate at that point."

Whichever path resolves it, the ignored test MUST pass by the end of
the phase, OR `BLOCKED-JCS-UPSTREAM-PR` MUST exist in `PENDING.md`
with the upstream PR URL and a target date.

### 7.7 — File spec-side issues

For each item that requires the spec to change, file an issue against
`https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol`.
Use the GitHub CLI:

```sh
gh issue create -R agentidentitytrustprotocol/agentidentitytrustprotocol \
  --title "..." --body "..."
```

Issues to file:

- **SPEC-005** — Publish JCS known-answer hashes for TCT, Manifest,
  delegation token, revocation snapshot in
  `schemas/conformance/known-answer/`.
- **SPEC-006** — Add JWK thumbprint known-answer test to RFC-AITP-0002.
- **SPEC-007** — Add Ed25519 keypair test vectors (seed → pubkey → AID).
- **BLOCKED-SPEC-DELEGATION-ISSUEDAT** — `grant_proof` does not carry
  the source TCT's `issued_at`; reconstruction as `expires_at - 3600`
  fails for non-default TTLs. Spec should either add the field or pin
  a reconstruction recipe.
- **BLOCKED-SPEC-EXAMPLE** —
  `examples/manifest/agent-b-manifest.json` uses placeholder signatures
  and cannot pass verification.
- **PoP signing input ambiguity** — RFC-AITP-0005 §6.2 step 3 doesn't
  pin whether `sha256(nonce)` hashes the base64url ASCII bytes or the
  decoded raw bytes. We chose ASCII bytes; pin the choice in the spec.

Each issue should reference the relevant RFC section and quote the
specific text that's missing or ambiguous. Update `PENDING.md` with
the issue URLs.

**`gh` authentication is a one-time setup, not a per-phase blocker.**
Before this task runs, the human authenticates `gh` once at the org
level with a scoped token:

```sh
gh auth login -s repo,write:org
```

For projects with multiple agents and humans contributing in parallel,
prefer a dedicated bot account (e.g. `aitp-bot`) so issues filed by
automation are clearly attributable. Bots filing **issues** is fine and
encouraged; bots filing **PRs** without a human in the loop is a
separate decision and out of scope for this phase.

If `gh` is genuinely not authenticated when the task runs (auth
expired, token revoked, etc.), STOP and surface that — do NOT fall
back to writing the issue bodies as `.md` files on disk. Silent
dropped work is the worst outcome; a month from now nobody will
remember the six findings existed.

### 7.8 — PENDING.md sweep

Read `docs/design/PENDING.md` start to finish. For each task:

- ✅ check off completed tasks (everything in 7.1, 7.3, 7.4, 7.6 should
  be checked here)
- 🔗 add issue-URL annotations for spec-side blockers filed in 7.7
- 📝 move resolved `BLOCKED-*` entries into a "Resolved" section at
  the bottom (don't delete — preserve the audit trail)

If new findings surfaced during the phase, add them as `NOTE-*`
entries.

### 7.9 — CHANGELOG.md update

Append a new section to `CHANGELOG.md`:

```markdown
## v0.1.0-alpha.2 — UNRELEASED

Spec-alignment release. Tracks AITP spec v0.1.0-rc.1 with
post-alpha.1 corrections.

### Added
- Conformance runner: Tier B (issuance), Tier C (stateful), Tier D
  (test-only) operations on `aitp-rs-adapter`
- Schema-validation integration tests for Manifest, TCT, Delegation,
  and the four handshake payloads (firewalls future spec drift)
- `HandshakeServer` session expiry (`session_ttl`, default 60s)

### Changed
- ...

### Removed
- `Manifest.description` field (was not in RFC-AITP-0003 or the JSON
  schema; would fail `additionalProperties: false` validation if set).
  This is a breaking change for any caller that set it; none expected
  in alpha.1.

### Fixed
- BLOCKED-JCS-SURROGATE: ... (depending on which path 7.6 took)

### Known limitations
- (carry forward from alpha.1, minus anything resolved here)
```

### 7.10 — Version bumps

Bump every publishable crate to `0.1.0-alpha.2` in:

- `crates/aitp/Cargo.toml`
- `crates/aitp-core/Cargo.toml`
- `crates/aitp-crypto/Cargo.toml`
- `crates/aitp-manifest/Cargo.toml`
- `crates/aitp-tct/Cargo.toml`
- `crates/aitp-delegation/Cargo.toml`
- `crates/aitp-handshake/Cargo.toml`
- `crates/aitp-transport-http/Cargo.toml`
- `crates/aitp-conformance/Cargo.toml`

The non-publishable `crates/aitp-rs-adapter` and `examples/two-agents`
should also bump to keep diagnostics consistent.

Update inter-crate path/version dependencies to match.

Run `cargo build --workspace --all-features` to confirm the bumps are
internally consistent.

### 7.11 — Draft release notes

Create `RELEASE_NOTES_v0.1.0-alpha.2.md` in the repo root, following
the shape of `RELEASE_NOTES_v0.1.0-alpha.1.md`. Lead with what changed
since alpha.1, then carry forward "Try it" and "Feedback" sections.

This is for the human to use when actually publishing. Don't push it.

### 7.12 — Archive executed plans and phase reports

Context: `.gitignore` has `/plans/` — phase prompts were intentionally
treated as working scratch and never tracked in VCS. The phase reports
at the repo root are untracked too (only `LICENSE` is in the initial
commit; everything else has been sitting on disk uncommitted across all
six phases).

The cleanup elevates the historical material from "untracked scratch"
to "tracked history" by moving it to `docs/history/` (which is NOT in
`.gitignore`). Once moved, `plans/` becomes vestigial and is removed.

Layout:

```
docs/history/
├── README.md                       # what this directory is, how to read it
├── _global-rules.md                # ← from plans/_global-rules.md
├── phase-audit-report.md           # ← from repo-root phase-audit-report.md
├── phases/
│   ├── phase-0-plan.md             # ← from plans/phase-0.md
│   ├── phase-0-report.md           # ← from repo-root phase-0-report.md
│   ├── phase-1-plan.md
│   ├── phase-1-report.md
│   ├── ... (one pair per phase)
│   ├── phase-6-plan.md
│   ├── phase-6-report.md
│   ├── phase-7-plan.md             # ← from plans/phase-7-alpha-2.md (this file)
│   └── phase-7-report.md
└── releases/
    └── RELEASE_NOTES_v0.1.0-alpha.1.md   # ← from repo root (alpha.2 stays at root until shipped)
```

Mechanics:

- Use `git mv` where possible. For files that were never tracked (most
  of `plans/` and the phase reports), this is a plain `mv` followed by
  `git add` of the new path.
- After moving, `rm -rf plans/` and remove the `/plans/` line from
  `.gitignore`.
- **Write `docs/history/README.md`** with: a one-paragraph explanation
  of what the directory holds, an executed-phases table (Phase → Plan
  → Report → Date → Outcome), and a note that the canonical live state
  is `docs/design/PENDING.md` and `CHANGELOG.md`.
- **Update cross-references.** Grep the repo for `plans/phase-` and
  `phase-N-report.md` patterns and rewrite the paths. At minimum check
  `README.md`, `CONTRIBUTING.md`, and any in-source doc comments.

Verify nothing breaks:

```sh
git grep -nE 'plans/phase-[0-9]|phase-[0-9a-z]+-report\.md' \
  -- ':!docs/history/**'   # should return nothing meaningful
cargo doc --workspace --no-deps  # no broken intra-doc links
```

If a phase report contains information that's still load-bearing (a
deviation from a design doc, an open question that didn't make it into
`PENDING.md`), promote that information into the relevant
`docs/design/` doc or `PENDING.md` *before* archiving — the move is
not a delete, but contributors will stop reading these files after
this.

### 7.13 — Repo-root housekeeping

Resolve cruft that has accumulated outside the phase artifacts:

- **De-duplicate license files.** Today the repo has three:
  - `LICENSE` (the only file actually tracked in git; identical to
    `LICENSE-APACHE`)
  - `LICENSE-APACHE` (untracked)
  - `LICENSE-MIT` (untracked)

  Convention for dual MIT/Apache Rust crates is `LICENSE-MIT` +
  `LICENSE-APACHE` only. Action: `git rm LICENSE`, `git add
  LICENSE-MIT LICENSE-APACHE`, and confirm every `Cargo.toml` already
  has `license = "MIT OR Apache-2.0"` (it should — verify).

- **Delete the on-disk `.DS_Store`** at the repo root. It's gitignored
  (won't be committed), but it's still cruft on disk; remove it.

- **Move `RELEASE_NOTES_v0.1.0-alpha.1.md`** to
  `docs/history/releases/` (handled in 7.12). The fresh
  `RELEASE_NOTES_v0.1.0-alpha.2.md` from 7.11 stays at the repo root
  until alpha.2 is published; after the next release cycle it follows
  the same path.

- **Initial-commit hygiene.** The repo's `git log` is one
  "Initial commit" containing only `LICENSE`. Phases 0–6 of work are
  sitting entirely untracked. A naïve `git add . && git commit -m
  "everything"` would erase the per-phase blame/history forever.

  **Reconstruct the history as a small number of meaningful commits
  before alpha.2 work lands on top.** Do NOT attempt one-commit-per-
  micro-task; the goal is `git blame` legibility three months from
  now, not maximal granularity.

  Phase 0–6 reconstruction (run these BEFORE the alpha.2 commits):

  1. `chore: scaffold workspace, CI, licenses` — phase 0 deliverables:
     workspace `Cargo.toml`, `.github/`, `Makefile`, `clippy.toml`,
     `rustfmt.toml`, `rust-toolchain.toml`, `deny.toml`,
     `LICENSE-MIT`, `LICENSE-APACHE`, `.editorconfig`, `.gitignore`,
     `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`,
     `docs/design/*` design docs.
  2. `feat(core,crypto): primitives — Aid, JCS, base64url, Ed25519` —
     phases 1 + 2 folded together (small, tightly coupled).
  3. `feat(manifest,tct,delegation): protocol crates` — phases 3a +
     3b + 3c folded (each is small, all are sibling protocol types).
  4. `feat(handshake): mutual handshake state machines` — phase 3d
     alone (largest single phase, deserves its own commit).
  5. `feat(transport-http): HTTP servers, fetchers, two-agent demo` —
     phases 4a + 4b folded.
  6. `feat(conformance): runner + rs-adapter (Tier A)` — phase 5.
  7. `chore(release): polish for v0.1.0-alpha.1` — phase 6 (README,
     CHANGELOG, RELEASE_NOTES_v0.1.0-alpha.1.md, doctest, metadata).

  That's 7 reconstruction commits. Then alpha.2 commits land on top:

  8. `feat(manifest): drop description field (D-1, RFC alignment)`
  9. `test: schema-validation firewall for signed wire types` (incl.
     `boon` dep, `tests/schemas/`, `scripts/sync-schemas.sh`)
  10. `feat(transport-http): expire idle handshake sessions`
  11. `feat(conformance): wire Tier B/C/D ops on rs-adapter`
  12. `chore(jcs): … (whichever path 7.6 took)`
  13. `docs: archive phase plans and reports to docs/history/` (incl.
      removing `/plans/` from `.gitignore`)
  14. `chore: housekeeping — drop bare LICENSE, .DS_Store cleanup`
  15. `chore(release): bump to v0.1.0-alpha.2`

  Total: 15 commits. Each one buildable, each one passes tests. If a
  reconstruction commit (1–7) cannot be made buildable on its own
  because of cross-phase coupling that was glossed over at the time,
  fold it into the next commit — DO NOT push a broken intermediate
  commit just to preserve granularity.

  **Going forward, this can never happen again.** Add rule #13 to
  `_global-rules.md` (handled by adjacent change in this same phase):
  "Commit at the end of each phase, before writing the phase report."
  That makes phase boundaries also commit boundaries by construction.

- **Verify nothing else slips in.** Run:

  ```sh
  git status              # nothing untracked except known artifacts
  git ls-files | wc -l    # should be a sane file count, not 1
  ```

---

## Format, lint, doc, build

Final sweep before writing the phase report:

```sh
cargo fmt --all
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --no-default-features
cargo doc --workspace --no-deps --all-features 2>&1 | grep -i warning
cargo build --workspace --release
```

All clean.

---

## Phase report

Write `phase-7-report.md` with:

- Tasks completed (by section ID: 7.1 … 7.13)
- Tasks blocked (with reason and the `BLOCKED-*` entry it became)
- Final test counts (compare to alpha.1's 133)
- New schema-validation tests added (count per crate)
- Spec-side issues filed (URLs)
- Tier B/C/D op coverage matrix (op × tested?)
- Anything the human reviewer should look at carefully
- A note on the JCS surrogate situation (resolved in 7.6, or still
  blocked, with link)

---

## Success gate

- D-1 fixed: `Manifest.description` removed; round-trip + schema test
  green
- Schema-validation tests run in CI for every signed wire-format type
- `HandshakeServer` rejects expired sessions
- Conformance runner exercises Tier A, B, C, and D ops against
  `aitp-rs-adapter` end-to-end
- Spec-side issues filed and linked from `PENDING.md`
- `v0.1.0-alpha.2` is internally consistent: builds, tests, docs all
  green; CHANGELOG and release notes ready
- Phase plans and reports archived under `docs/history/`; `plans/`
  removed; `/plans/` line removed from `.gitignore`
- Repo root contains only `LICENSE-MIT` and `LICENSE-APACHE` (no
  bare `LICENSE`); `.DS_Store` cleaned; commit history is themed and
  legible (no monolithic squashes)

## Stop here

Do not push tags. Do not publish to crates.io. Do not announce. The
human reviews, decides whether to ship, and runs the publish steps if
yes.
