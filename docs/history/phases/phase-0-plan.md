# Phase 0 — Pre-flight Verification

You are working on the `aitp-rs` Rust reference implementation of the
Agent Identity & Trust Protocol. This is Phase 0 of a 6-phase build plan.

**Your goal in this phase:** verify that the current scaffold compiles
to the extent it can (most function bodies are `todo!()`, which is
expected), and document any issues for follow-up.

You will NOT implement any logic in this phase. This is a verification
pass only.

---

## Required reading (in order, before touching anything)

1. `README.md` — repo overview
2. `docs/design/00-architecture.md` — workspace structure
3. `docs/design/PENDING.md` — task list

---

## Global rules (apply to every phase)

1. **Read first, write second.** Read the design docs and the current
   scaffold before any change.

2. **Architectural decisions are settled.** Don't change workspace
   structure, sync-vs-async split, JSON-only stance, audience model,
   crate boundaries, or any other decision in the design docs. If
   something feels wrong, write a `BLOCKED-*` entry in PENDING.md and
   stop.

3. **No new dependencies.** Don't add anything to
   `[workspace.dependencies]` in this phase.

4. **Format and lint at the end.** Run `cargo fmt --all` and
   `cargo clippy --workspace -- -D warnings` before completing.

5. **Stop at the phase boundary.** Do not begin Phase 1.

---

## Tasks

### 0.1 — Initial build

Run `cargo build --workspace 2>&1 | tee phase-0-build.log`.

Expected: many compile errors from `todo!()` returning `!` at sites where
a concrete type is required (e.g. inside expressions used as struct field
values). This is normal; the scaffold uses `todo!()` extensively.

What to capture:
- Errors that look like Cargo configuration problems (missing deps,
  unresolved workspace members, wrong crate paths) — these are real bugs
  and need fixing
- Errors that are just `todo!()` returning `!` in contexts where Rust
  can't infer the type — these are expected and will resolve in later
  phases when bodies are filled in
- Anything else weird

### 0.2 — Format and lint

Run:
```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tee phase-0-clippy.log
```

The scaffold should be format-clean. Clippy may emit warnings on `todo!()`
heavy code; categorize what you see.

### 0.3 — Workspace sanity

Verify that:
- `cargo metadata --format-version 1 | jq -r '.workspace_members[]'`
  returns all 11 members listed in workspace `Cargo.toml`
- Each crate's `Cargo.toml` references workspace deps via
  `{ workspace = true }`, not pinned versions inline
- No crate has a path dependency that points outside the workspace
- No `Cargo.lock` exists yet (the workspace hasn't been resolved); if
  one was created during these checks, that's fine, leave it

### 0.4 — Document issues

Write `phase-0-report.md` in the repo root with:

```markdown
# Phase 0 Report

## Build status
<one of: "scaffold compiles cleanly except for expected todo!() type errors",
        "scaffold has Cargo configuration issues that need fixing", etc.>

## Real issues found (need fixing before Phase 1)
- <list, with file:line references>

## Expected todo!()-related errors (to be resolved in later phases)
- <count of distinct error sites; spot-check 2-3 with file:line>

## Format and lint
- cargo fmt --check: <pass/fail>
- cargo clippy: <warnings/clean>

## Workspace structure
- All 11 crates resolve: <yes/no>
- Workspace deps used consistently: <yes/no>

## Recommendations
- <anything the human reviewer should know before starting Phase 1>
```

### 0.5 — Fix only Cargo-configuration bugs (if any)

If you find real bugs (not `todo!()`-related):
- Fix them in the smallest possible diff
- Document each fix in `phase-0-report.md`
- Do NOT fix anything that requires implementing logic — that's later phases

If there are no Cargo-configuration bugs, leave the workspace untouched.

---

## Success gate

This phase is done when:
- `phase-0-report.md` is written in the repo root
- Any Cargo-configuration bugs (NOT `todo!()` issues) are fixed
- `cargo fmt --check` passes
- The report clearly distinguishes "real bugs needing follow-up" from
  "expected `todo!()` errors"

## Stop here

Do not begin Phase 1. Wait for human review of the report and any fixes
you made. The human will explicitly start the next phase.

---

## What NOT to do in Phase 0

- Do not implement any `todo!()` body
- Do not add new tests
- Do not change any design decision
- Do not add or remove crates
- Do not add dependencies
- Do not begin Phase 1 work even if Phase 0 finishes early
