# Phase 8 — RFC v0.1.0-rc.2 alignment + alpha.3 — Report

Executed 2026-05-02 immediately after the spec landed
[`agentidentitytrustprotocol@c0e4565`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/commit/c0e4565)
("Spec: close 5 cross-impl ambiguities flagged by aitp-rs"). Scope:
update aitp-rs to the new wire formats, anchor the implementation to
the spec's freshly pinned KAT vectors, and ship as v0.1.0-alpha.3.

## How this phase was scoped

The spec rc.2 commit closed 5 of the 6 issues `aitp-rs` filed in
phase 7 (`agentidentitytrustprotocol#1`–`#6`). Two of the closes
required code changes in `aitp-rs`:

- `#6` (PoP signing input) — pinned to **decoded raw bytes**, opposite
  of what alpha.1/alpha.2 did. Breaking change.
- `#4` (delegation `grant_proof.issued_at`) — added as REQUIRED. New
  required wire field. Breaking change.

The other three (`#1`/SPEC-005, `#2`/SPEC-006, `#3`/SPEC-007) added
KAT vectors that aitp-rs could now anchor to.

`#5` (placeholder example manifest) is left open — it's a tooling
task on the spec side, but is now actionable since `kat-keypair-001`
is a pinned seed.

## Tasks completed

- **8.1** — Re-ran `scripts/sync-schemas.sh`. `tests/schemas/SPEC_VERSION`
  advanced from `367567f…` to `c0e45653…`. Only delta in the schemas
  was `aitp-delegation.schema.json` adding `grant_proof.issued_at`
  as REQUIRED — exactly as expected. The drift firewall (phase 7's
  `tests/schema.rs`) immediately failed with
  `'/delegation/grant_proof': missing properties 'issued_at'` —
  exactly as designed.
- **8.2** — Fixed `crates/aitp-tct/src/pop.rs` PoP signing input.
  `Sha256::digest(challenge.nonce.as_bytes())` →
  `Sha256::digest(&base64url::decode_strict(&challenge.nonce)?)`.
  Both `sign_pop_response` and `verify_pop_response`. Doc comments
  updated to reflect the rc.2 rule.
- **8.3** — Added `issued_at: Timestamp` field to
  `aitp-delegation::GrantProof`. Builder copies it verbatim from the
  source TCT. Verifier uses the carried value (gone is the
  `expires_at - DEFAULT_TCT_TTL_SECS` workaround). Round-trip and
  schema tests both pass.
- **8.4** — Added KAT tests anchored to spec rc.2's pinned vectors:
  - `crates/aitp-crypto/tests/kat.rs` — keypair derivation
    (seed → pubkey → AID) and JWK thumbprint, against
    `keypairs.json` and `jwk-thumbprints.json`. Both vectors pass.
  - `crates/aitp-core/tests/kat.rs` — JCS canonicalization + SHA-256
    against `jcs-sha256.json`. All vectors pass byte-for-byte.
  - Extended `scripts/sync-schemas.sh` to vendor
    `schemas/conformance/known-answer/*.json` alongside the schemas.
- **8.5** — Bumped every workspace `Cargo.toml` from `0.1.0-alpha.2`
  to `0.1.0-alpha.3`. Wrote alpha.3 CHANGELOG section with explicit
  breaking-change callouts. Drafted `RELEASE_NOTES_v0.1.0-alpha.3.md`.
- **8.6** — This report. PENDING.md sweep marked the 5 resolved
  spec issues (`#1`–`#4`, `#6`).

## Final test counts

| Metric | alpha.2 | alpha.3 |
|---|---|---|
| Tests passing | 152 | **155** |
| Tests failed | 0 | 0 |
| Tests ignored | 2 | 2 |

Net +3: keypair KAT, JWK thumbprint KAT, JCS+SHA-256 KAT.

All gates clean: `cargo fmt --check`, `cargo clippy --all-features
--all-targets -- -D warnings`, `cargo doc --no-deps --all-features`,
`cargo build --workspace --release`.

## Breaking changes vs alpha.1/alpha.2

Two:

1. TCT PoP signatures — must re-issue. Affects anyone who issued
   challenges or stored PoP responses.
2. Delegation tokens — must re-issue. Affects anyone holding alpha.2
   delegation tokens; deserialization fails on missing `issued_at`.

Live handshakes don't need any action — handshake completes in ~1s
and produces fresh artifacts.

## Reviewer should check carefully

- The KAT tests proved aitp-rs already produced the right answers for
  Ed25519 derivation, JWK thumbprints, and JCS+SHA-256 — no surprises.
  Worth keeping these tests green before any change to those modules.
- The `grant_proof.issued_at` addition is a structural change to a
  signed wire type. The signing input the verifier reconstructs now
  uses the carried value. Worth a careful read of
  `verifier.rs:80–92` to confirm field order matches what the signer
  produced.
- Workspace test count is now 155 — every test should pass in CI on
  every supported platform.

## Open follow-ups

- `BLOCKED-SPEC-EXAMPLE` (#5) — still open. Could be closed by a
  small Rust binary that mints `examples/manifest/agent-b-manifest.json`
  using `kat-keypair-001` and the `issue_manifest` op. Estimate: ~30
  minutes. Not in alpha.3 scope.
- `PHASE-B-FIXTURE-PR` — spec conformance fixtures still use
  placeholder shapes. Now that KAT vectors exist, this is the next
  concrete spec-side task.
- `NOTE-RESPONDER-CONFORMANCE` — responder-side handshake conformance
  ops still deferred (alpha.4+).
