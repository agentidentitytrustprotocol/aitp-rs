# Phase History

This directory preserves the phase-by-phase development trail of
`aitp-rs`. Each phase is a single piece of work driven by a Claude
Code prompt under `phases/phase-N-plan.md`, executed against the
workspace, and reported in `phases/phase-N-report.md`.

The canonical *live* state is elsewhere:

- **What works today, what doesn't:** [`../design/PENDING.md`](../design/PENDING.md)
- **What changed between releases:** [`../../CHANGELOG.md`](../../CHANGELOG.md)
- **What this release is:** [`../../README.md`](../../README.md)

This directory is the *source-archeology* answer: what was the prompt,
what landed, what got punted, and why.

## Executed phases

| Phase | Goal | Plan | Report | Outcome |
|---|---|---|---|---|
| 0 | Pre-flight: scaffold compiles | [plan](phases/phase-0-plan.md) | [report](phases/phase-0-report.md) | ✓ |
| 1 | `aitp-core` foundations | [plan](phases/phase-1-plan.md) | [report](phases/phase-1-report.md) | ✓ |
| 2 | `aitp-crypto` (Ed25519, JWK thumbprint) | [plan](phases/phase-2-plan.md) | [report](phases/phase-2-report.md) | ✓ |
| 3a | `aitp-manifest` | [plan](phases/phase-3a-plan.md) | [report](phases/phase-3a-report.md) | ✓ |
| 3b | `aitp-tct` | [plan](phases/phase-3b-plan.md) | [report](phases/phase-3b-report.md) | ✓ |
| 3c | `aitp-delegation` | [plan](phases/phase-3c-plan.md) | [report](phases/phase-3c-report.md) | ✓ |
| 3d | `aitp-handshake` (state machines) | [plan](phases/phase-3d-plan.md) | [report](phases/phase-3d-report.md) | ✓ |
| 4a | `aitp-transport-http` | [plan](phases/phase-4a-plan.md) | [report](phases/phase-4a-report.md) | ✓ |
| 4b | Two-agent demo | [plan](phases/phase-4b-plan.md) | [report](phases/phase-4b-report.md) | ✓ |
| 5 | Conformance runner + Tier-A adapter | [plan](phases/phase-5-plan.md) | [report](phases/phase-5-report.md) | ✓ |
| 6 | Polish + alpha.1 release prep | [plan](phases/phase-6-plan.md) | [report](phases/phase-6-report.md) | ✓ |
| audit | Cross-phase self-audit | — | [report](phase-audit-report.md) | ✓ |
| 7 | RFC alignment + alpha.2 | [plan](phases/phase-7-plan.md) | [report](phases/phase-7-report.md) | ✓ partial — 7.5 deferred |
| 8 | RFC v0.1.0-rc.2 alignment + alpha.3 | — (immediate-execution) | [report](phases/phase-8-report.md) | ✓ |
| 9 | Pending-item cleanup + responder + in-process adapter | — (immediate-execution) | [report](phases/phase-9-report.md) | ✓ |
| 10 | Spec rc.3 + paired aitp-rs follow-up + alpha.4 | [plan](../../plans/phase-10-spec-rc.3.md) | [report](phases/phase-10-report.md) | ✓ partial — 10.7 deferred |
| 11 | Conformance fixture migration + rc.4 sync | [plan](../../plans/phase-11-fixture-migration.md) | [report](phases/phase-11-report.md) | ✓ |

## Conventions

Phase plans are LLM execution prompts: complete, self-contained
instructions that an executing agent can follow without ambient
context. Phase reports describe what landed, what was deferred, and
what the human reviewer should look at carefully.

The cross-phase rules every phase obeys are in
[`_global-rules.md`](_global-rules.md). Rule #13 ("commit at the end
of each phase, before writing the report") was added in phase 7 after
the discovery that phases 0–6 had landed without commits — a mistake
the new rule prevents from recurring.

## Past releases

| Release | Notes |
|---|---|
| v0.1.0-alpha.1 | [release notes](releases/RELEASE_NOTES_v0.1.0-alpha.1.md) |
| v0.1.0-alpha.2 | (release notes at repo root until shipped) |
| v0.1.0-alpha.3 | (release notes at repo root until shipped) |
