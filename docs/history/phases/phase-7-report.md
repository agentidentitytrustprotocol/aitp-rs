# Phase 7 — RFC alignment + v0.1.0-alpha.2 — Report

Executed 2026-05-02. Scope: post-alpha.1 RFC alignment, drift firewall,
Tier B/C/D conformance, alpha.2 release prep, plus archive of the
phase prompts and reports into `docs/history/`.

## Tasks completed

- **7.1** — Removed `Manifest.description` field. Spec drift (D-1):
  field existed in Rust types but not in `aitp-manifest.schema.json`
  (which is `additionalProperties: false`). Added
  `rejects_legacy_description_field` round-trip test as the regression
  guard.
- **7.2** — Schema-validation drift firewall. Vendored AITP JSON
  schemas under `tests/schemas/` with pin file `SPEC_VERSION`
  (`367567fd234e6369cf63751db1790e9656bbdd38`). New
  `scripts/sync-schemas.sh`. New CI job `spec-schemas` that fails if
  the vendored copies drift from the pinned spec commit. Per-crate
  `tests/schema.rs` for Manifest, TCT, Delegation, and the four
  Mutual Handshake payloads (validated via `$defs/<Name>` $refs).
  Dev-only `boon = "0.6"` workspace dep.
- **7.3** — Handshake session expiry. `HandshakeServer` now accepts a
  `session_ttl: Duration` (default 60s via `DEFAULT_SESSION_TTL`).
  Inline sweep on each request drops expired entries; expired sessions
  on commit return 400 `session expired`. Two integration tests
  (`commit_after_session_ttl_is_rejected`, `fresh_session_within_ttl_is_accepted`).
- **7.4** — Tier B/C/D conformance ops on `aitp-rs-adapter`. New ops
  (13 total): `verify_envelope`, `verify_delegation_token`,
  `generate_keypair`, `issue_manifest`, `issue_tct`,
  `issue_delegation_token`, `sign_envelope`, `start_handshake`
  (initiator role only — see deferred items), `process_handshake_message`,
  `revoke_tct`, `set_clock`, `inject_revocation`, `dump_session`. Eight
  new runner integration tests, each exercising the full subprocess
  protocol. Adapter holds keypairs as 32-byte seeds (re-derive
  `AitpSigningKey` on demand) since the type is intentionally not
  `Clone`.
- **7.5** — Spec-fixture migration. **Deferred** to a follow-up session;
  see PHASE-B-FIXTURE-PR in PENDING.md. Reasoning: should land after
  SPEC-005 (#1) is resolved so fixtures use spec-pinned KAT seeds.
- **7.6** — `BLOCKED-JCS-SURROGATE` resolved. Bumped `serde_jcs` 0.1 →
  0.2.0 (released 2026-03-25 with the RFC 8785 §3.2.3 UTF-16 ordering
  fix). Surrogate test un-ignored and now passes.
- **7.7** — Filed 6 spec-side GitHub issues against
  `agentidentitytrustprotocol/agentidentitytrustprotocol`:
  - #1 SPEC-005 (KAT hashes)
  - #2 SPEC-006 (JWK thumbprint KAT)
  - #3 SPEC-007 (Ed25519 keypair vectors)
  - #4 BLOCKED-SPEC-DELEGATION-ISSUEDAT
  - #5 BLOCKED-SPEC-EXAMPLE
  - #6 SPEC-POP-INPUT-AMBIGUITY
- **7.8** — PENDING.md sweep. Marked resolved entries; added
  `NOTE-RESPONDER-CONFORMANCE`, `NOTE-VERIFY-REVOCATION-SNAPSHOT`,
  `NOTE-INPROCESS-ADAPTER-DEFERRED` for explicit alpha.2 deferrals.
  Added issue URLs from 7.7 next to each spec-side blocker.
- **7.9** — CHANGELOG.md updated with full alpha.2 section (Added,
  Changed, Removed, Known limitations).
- **7.10** — Bumped every `Cargo.toml` from `0.1.0-alpha.0` to
  `0.1.0-alpha.2`. Workspace builds cleanly after.
- **7.11** — Drafted `RELEASE_NOTES_v0.1.0-alpha.2.md`.
- **7.12** — Archived phase prompts and reports into `docs/history/`.
  Removed `/plans/` from `.gitignore` (it was scratch; now elevated
  to tracked history). Wrote `docs/history/README.md`.
- **7.13** — Pragmatic commit history: see "Commit history" below.

## Tasks deferred (with reasons)

- **PHASE-B-FIXTURE-PR (7.5)** — Spec-fixture migration PR. Better to
  land after spec issue #1 (SPEC-005). Tracked in PENDING.md.
- **NOTE-RESPONDER-CONFORMANCE** — Server-side handshake conformance
  ops (`start_handshake role=responder`). Initiator-side covers most
  high-value scenarios; responder-side adds substantial complexity
  (multi-step session state across NDJSON requests) that doesn't pay
  off until cross-language adapters need it. Adapter returns
  `OP_NOT_SUPPORTED` for the role today.
- **NOTE-INPROCESS-ADAPTER-DEFERRED** — In-process adapter still
  `todo!()`. Subprocess adapter is the conformance path; in-process
  is fast-local-development only.

## Final test counts

| Metric | alpha.1 | alpha.2 |
|---|---|---|
| Tests passing | 133 | **152** |
| Tests failed | 0 | 0 |
| Tests ignored | 3 | 2 |

Net +19 tests, −1 ignored (surrogate-pair vector promoted from ignored
to passing after the `serde_jcs` bump).

New tests by area:
- 11 conformance runner integration tests (Tier A/B/C/D)
- 7 schema-validation tests (4 protocol crates)
- 2 session-expiry tests (`HandshakeServer`)
- 1 manifest legacy-`description` regression guard

## Final lint/doc/build status

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | ✓ clean |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✓ clean |
| `cargo doc --workspace --no-deps --all-features` | ✓ no warnings |
| `cargo build --workspace --release` | ✓ clean |

## Reviewer should check carefully

- The schema-validation tests validate against vendored copies pinned
  to spec commit `367567fd…`. CI's `spec-schemas` job catches drift,
  but if the spec moves, the tests will catch up only when someone
  runs `scripts/sync-schemas.sh` and reviews the diff.
- The handshake conformance ops (start_handshake / process_handshake_message)
  are initiator-side only. Responder-side is a real gap if cross-language
  adapters want to be tested as responders.
- `Manifest.description` removal is technically a breaking change (any
  caller who wrote `.description("...")` now fails to compile). No
  alpha.1 caller is known to set it, but worth a CHANGELOG read.

## Commit history

The existing repo had only `Initial commit` with `LICENSE` tracked.
Phases 0–6 of the implementation sat untracked. Per phase 7.13's
pragmatic-split decision, history landed as themed commits rather
than a strict 15-commit per-task reconstruction:

- One commit absorbing alpha.1 (phases 0–6) as the implementation
  baseline
- Themed alpha.2 commits matching the phase-7 task list

The new global rule #13 (`docs/history/_global-rules.md`) requires
future phases to commit at the end of each phase before writing the
report — this situation cannot recur.
