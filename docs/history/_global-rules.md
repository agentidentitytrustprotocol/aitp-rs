# Global Rules — Apply to Every Phase

These rules apply to every phase of the `aitp-rs` work. They are repeated
in each phase prompt for clarity.

1. **Read first, write second.** Before touching any code, read:
   - `docs/design/00-architecture.md`
   - `docs/design/01-jcs.md` (if working on JCS or signing)
   - `docs/design/02-conformance-adapter.md` (if working on conformance)
   - `docs/design/PENDING.md`
   - The current state of any crate you will modify

2. **Architectural decisions are settled.** Decisions in the design docs
   were made deliberately in prior sessions. If you find yourself wanting
   to change one (workspace structure, sync-vs-async, JSON-only, audience
   model, etc.), STOP and write a `BLOCKED-*` entry into PENDING.md with
   your concern. Do not silently revise the design.

3. **Wire-format invariants are non-negotiable.**
   - Every wire-format struct MUST have `#[serde(deny_unknown_fields)]`.
   - Every `extensions: ExtensionsMap` field MUST have
     `#[serde(default, skip_serializing_if = "ExtensionsMap::is_empty")]`.
   - These are protocol requirements, not stylistic preferences.

4. **Public API gets rustdoc.** Every public function, type, trait, and
   module gets a doc comment explaining what it does, what it returns,
   and what each error variant means. Internal helpers do not need this.

5. **Tests come with the code.** Every function with non-trivial logic
   gets a unit test in the same file's `#[cfg(test)] mod tests`. Every
   wire-format struct gets a JSON round-trip test. Tests are part of
   "done," not a follow-up.

6. **Format and lint must pass.** Before declaring a phase complete:
   - `cargo fmt --all` (apply, don't just check)
   - `cargo clippy --workspace --all-targets -- -D warnings` (no warnings)

7. **Do not delete `todo!()` bodies you don't intend to finish.** A
   `todo!()` is better than a wrong implementation. Leave them for later
   phases. If the current phase legitimately implements one, replace it.
   Otherwise leave it.

8. **Tests that need future phases get marked `#[ignore]` with a comment
   explaining the dependency.** Do not silently skip; do not break the
   build; do not create a forgotten gap.

9. **No new dependencies without permission.** Never add a crate that
   isn't already in the workspace `[workspace.dependencies]` table without
   asking. If you need one, write a `BLOCKED-*` entry in PENDING.md
   explaining what and why.

10. **Update PENDING.md at end of phase.** Check off completed task IDs.
    Add any new findings as `NOTE-*` entries. Move blockers into
    `BLOCKED-*` entries.

11. **Write a `phase-N-report.md` at end of phase** in the repo root with:
    - Tasks completed (by ID)
    - Tasks blocked (by ID, with reason)
    - Deviations from design docs (if any, with rationale)
    - Tests added (count, brief description)
    - Remaining `todo!()` count by crate
    - Anything the human reviewer should look at carefully

12. **Stop at the phase boundary.** Do NOT begin the next phase. Phase
    boundaries are human review checkpoints. The human will explicitly
    start the next phase.

13. **Commit at the end of every phase, before writing the phase
    report.** A phase ends with a small number of themed commits that
    are buildable on their own (passes `cargo build && cargo test`).
    The phase report is written into the working tree and committed
    last, so `git log` shows what was done plus where the report
    landed. This rule exists because phases 0–6 of `aitp-rs` were
    executed without committing; the entire history sat untracked
    until phase 7 had to reconstruct it. Never again.

## When to STOP and ask

- A test from `docs/design/01-jcs.md` fails against `serde_jcs`. Do not
  modify the vector to match the implementation.
- A design decision feels wrong in implementation. Ask before changing.
- A new dependency would help. Ask first.
- A spec ambiguity blocks progress. Document it as `BLOCKED-*` and ask.
- A test would require something only humans can produce (real OIDC
  provider response, etc.). Mark `#[ignore]` and continue.
