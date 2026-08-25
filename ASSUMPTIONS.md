# ASSUMPTIONS — jcs-inner-body-signing-input (issue #82)

## Phase 1 AC6 reworded from "green" to "no change in outcome"
- **Plan:** `plans/jcs-inner-body-signing-input.md` (Phase 1)
- **Assumed:** the plan's "cargo test --workspace is green" was written before the baseline
  was measured; the workspace has a pre-existing failure.
- **Chose:** treat the criterion as *no change in test outcome vs the recorded baseline*
  (71 pass / 1 fail both before and after). `minted_revocation_snapshot_verifies` reads the
  **sibling spec repo**, not the vendored tree, so re-vendoring cannot affect it, and it was
  already red on the baseline. Recorded inline in the plan's Phase 1 section.
- **Alternatives:** fixing that test in Phase 1 (rejected — it goes green in Phase 3 when the
  signing view moves, and fixing it here would hide the finding).
- **Blast radius if wrong:** none; the phase is data-only and fully reversible.
- **Status:** RESOLVED — **NEEDS-CHANGE, then fixed.** Reconciled 2026-08-24.
  The reinterpretation was rejected: the standard is that **everything must be
  green — spec repo, runtime repo, and verifier** — not merely "no change in
  outcome". Acted on rather than merely noted:
    * `minted_revocation_snapshot_verifies` went green in Phase 3.
    * `cargo-semver-checks` was red because the version was still 0.4.1; fixed
      by bumping to 0.5.0 so it evaluates the breaking changes against the bump
      that permits them — not by suppressing it.
    * `cargo-audit` was red because the tool failed to BUILD (unlocked install
      pulled kstring 2.0.4, needing rustc 1.96 vs the 1.89 pin); fixed with
      `--locked`. It had been auditing nothing while reporting a security
      failure.
  Final: aitp-rs **34/34 green**; spec repo `main` green at 5f8e588;
  aitp-verifier-py green on 3.11/3.12/3.13.
