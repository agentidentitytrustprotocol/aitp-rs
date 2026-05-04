# Phase 9 — Pending-item cleanup + responder conformance + in-process adapter

Executed 2026-05-03 after the spec maintainer's prep commit
[`agentidentitytrustprotocol@0839c52`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/commit/0839c52)
documented the placeholder convention, signed-examples directory, and
the rules for paired aitp-rs PRs. Scope: close everything in PENDING.md
that doesn't require a spec change; write a phase 10 plan for the
items that do.

## Tasks completed

- **9.1** — PENDING.md cleanup + `cargo deny`.
  - Updated `deny.toml` to cargo-deny ≥ 0.18 schema. Old `unlicensed` /
    `copyleft` / `allow-osi-fsf-free` / `default` license fields gone.
    `unmaintained` is now a scope (`"all"`), not a severity.
  - Added `CDLA-Permissive-2.0` to the license allowlist
    (`webpki-roots` ships the Mozilla root CA list under that license).
  - `cargo deny check`: advisories ok, bans ok, licenses ok, sources ok.
  - PENDING.md: marked IMPL-003, IMPL-013, IMPL-019, IMPL-023 with
    current state (resolved / partially resolved). The "Spec
    ambiguities captured this run" note moved to "RESOLVED in spec
    rc.2" for archeology.
- **9.2** — Responder-side conformance ops (NOTE-RESPONDER-CONFORMANCE).
  - `crates/aitp-rs-adapter/src/main.rs`: new `HandshakeSession`
    variants `PendingResponder` and `ActiveResponder`. Lazy
    construction of `aitp_handshake::Responder` on first HELLO, since
    the type has no public empty constructor.
  - `start_handshake { role: "responder", ... }` now creates the
    pending session and returns `awaiting: "MUTUAL_HELLO"`.
  - `process_handshake_message` dispatches by session variant. The
    initiator path was refactored to take `my_manifest` from the
    session (latent bug fix, see below).
  - **Latent bug found and fixed:** The previous initiator-only
    process_handshake_message wired `cfg.manifest = &peer_manifest`
    (the peer's manifest) into the `PeerConfig`. The handshake's TCT
    verifier reads `cfg.manifest.aid` as the *expected audience* —
    it must be the local AID, not the peer's. The bug was latent in
    alpha.2 because tests never reached COMMIT_ACK with a real
    cross-issued TCT through the conformance adapter; the new
    responder full-handshake test surfaced it immediately. Fix: store
    `my_manifest` on `HandshakeSession::Initiator` too.
  - New integration test
    `responder_full_handshake_via_two_adapter_processes` spins up two
    independent subprocess adapters, configures one as initiator and
    one as responder, drives all four messages through them, and
    asserts both sides hold cross-issued TCTs at the end. This is
    the closest-to-production-shape conformance check the runner can
    exercise without a real network.
- **9.3** — In-process adapter (NOTE-INPROCESS-ADAPTER-DEFERRED).
  - `crates/aitp-conformance/src/adapter/in_process.rs` no longer
    `todo!()`. Implements Tier-A verification ops directly against
    the `aitp-*` crates: `verify_jcs`, `compute_jwk_thumbprint`,
    `verify_envelope`, `verify_manifest`, `verify_tct`,
    `verify_delegation_token`.
  - Tier B/C/D return `OpNotSupported` — those would duplicate the
    keypair/session state from `aitp-rs-adapter`. Subprocess remains
    the canonical path for stateful ops; in-process is the
    fast-local-dev path for the verification subset.
  - Four new unit tests including a KAT-anchored thumbprint check
    against `kat-keypair-001` (verifies the in-process adapter agrees
    with the spec-pinned reference value byte-for-byte).
- **9.4** — Wrote `plans/phase-10-spec-rc.3.md`, the prompt for the
  next spec-side phase. Three asks:
  1. Add `kat-keypair-003` to `keypairs.json` (needed for the
     delegation signed example).
  2. Resolve the `__VALID_SIG__` ambiguity in 3 fixtures (path B
     recommended: rename to specific tokens).
  3. Define the revocation snapshot wire type in RFC-AITP-0008 (or
     mark WONTFIX-FOR-V0.1 and remove `verify_revocation_snapshot`
     from the conformance op vocabulary).
  Each section pairs the spec-side ask with the aitp-rs follow-up
  that consumes it.

## Final test counts

| Metric | alpha.3 phase 8 | alpha.3 phase 9 |
|---|---|---|
| Tests passing | 155 | **160** |
| Tests failed | 0 | 0 |
| Tests ignored | 2 | 2 |

Net +5: 1 new responder-side full-handshake integration test, 4 new
in-process adapter unit tests.

## Final lint/build/audit status

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | ✓ clean |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✓ clean |
| `cargo doc --workspace --no-deps --all-features` | ✓ clean |
| `cargo build --workspace --release` | ✓ clean |
| `cargo deny check` | ✓ advisories ok, bans ok, licenses ok, sources ok |

## Reviewer should check carefully

- The `cfg.manifest = &my_manifest` change in `initiator_step`
  fixes a latent bug. The full HTTP `full_handshake_over_http.rs`
  test was never affected because the HTTP server wired `PeerConfig`
  correctly. The conformance-adapter path was the only consumer that
  went through the buggy code, and only when we added responder-side
  did it surface. Worth reading the new
  `responder_full_handshake_via_two_adapter_processes` test alongside
  `initiator_step` and confirming the field ordering matches.
- The in-process adapter's coverage is intentionally Tier-A only.
  Anyone running `cargo test --features in-process` should not expect
  it to handle issuance or stateful flows. The README in PENDING.md
  notes this.

## Open follow-ups (for phase 10 spec rc.3)

- spec: add `kat-keypair-003` + `kat-jwk-thumb-003`
- spec: resolve `__VALID_SIG__` placeholder ambiguity
- spec: define revocation snapshot wire type (or mark WONTFIX)
- aitp-rs (paired, after spec rc.3): mint signed examples, migrate 21
  conformance fixtures, add KAT vector for kat-keypair-003

The plan at `plans/phase-10-spec-rc.3.md` covers all of these.
