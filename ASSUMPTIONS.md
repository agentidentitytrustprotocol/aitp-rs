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
- **Status:** UNCONFIRMED
