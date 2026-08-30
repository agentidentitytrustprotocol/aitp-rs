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

## Phase 0 shipped as accumulate, not ship-now
- **Plan:** `plans/unknown-field-error-code.md` (Phase 0)
- **Assumed:** the Phase 0 verifier's "ship now" call (independently shippable,
  flips `vendored schemas in sync` green) is technically correct but not the
  better call for this run.
- **Chose:** accumulate all 11 phases locally and run one closing `/ship` pass
  against PR #141's branch, rather than pushing after every phase.
- **Alternatives:** push+watch-CI after each phase per the verifier's literal
  call — rejected because 9 of the remaining 10 phases will still leave
  `conformance fixtures` red by design (the corpus only reaches 0 failures once
  Phase 6b lands), so an early push buys no additional signal beyond what local
  `cargo test`/diff review already gives, at the cost of a full CI matrix watch
  (`/ship` §5, blocking) repeated up to 10 extra times.
- **Blast radius if wrong:** none structurally — every phase is still a
  separate, revertable commit; the only cost of this choice being wrong is a
  later, larger CI watch instead of several smaller ones. Reversible at any
  point by pushing the accumulated branch early.
- **Status:** UNCONFIRMED

## Manifest `Some(empty extensions)` has no cross-impl witness
- **Plan:** `plans/unknown-field-error-code.md` (Phase 3)
- **Assumed:** running `aitp-verifier-py`'s xcheck locally (it passed) is
  sufficient cross-implementation assurance for Phase 3's manifest
  signing-input change.
- **Chose:** accept it as sufficient for the *absent-extensions* case
  (covered by `crates/aitp-cli/tests/cli.rs`'s spec-minted manifest
  round-trip and fixtures man-001/man-005 going through the full
  `ManifestSigningView` path), but flag that xcheck's own vectors
  (`scripts/xcheck-verify.py`) cover only the revocation snapshot and
  session bundle — zero manifest coverage — so the *`Some(empty)`
  extensions* case this phase's OQ1 fix specifically introduces has no
  independent cross-implementation witness, only this repo's own KATs.
- **Alternatives:** hand-authoring a new xcheck vector for
  `Some(ExtensionsMap::new())` manifests — rejected for this pass because
  it requires either a cross-repo edit to `aitp-verifier-py` (gated) or a
  local-only script that CI can't enforce going forward, so it wouldn't
  reduce ongoing risk, only one-time risk.
- **Blast radius if wrong:** low — the KAT vectors are the load-bearing
  gate here and are untouched; if `aitp-verifier-py` ever disagreed about
  this case, the first real cross-impl manifest carrying
  `"extensions":{}` would surface it as a signature mismatch, not a
  silent divergence.
- **Status:** UNCONFIRMED
