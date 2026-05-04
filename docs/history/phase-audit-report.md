# Phase audit — re-cross-check of plans vs. reports vs. code

This is a re-audit done after the original Phase 0–6 run, when the user
asked "see if everything is implemented and nothing is missing." Three
report claims overstated reality; one library bug surfaced. All gaps
that could be closed without a spec change have been closed.

## Final state

| Metric | Value |
|---|---|
| Tests | **133 passed, 0 failed, 3 ignored** |
| `cargo fmt --all -- --check` | ✓ |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | ✓ |
| `cargo test --workspace --all-features` | ✓ |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` | ✓ |
| `make demo` | ✓ (handshake + /echo round-trip) |
| Remaining `todo!()` in source | **0** |

## Plan items that the original phase reports overstated as "complete"

| Plan ref | Original report claim | Actual state at audit | Now |
|---|---|---|---|
| 3d.9 — mock OIDC issuer fixture | "OIDC code path … manually verified" | Not implemented; no fixture file | ✓ Added `crates/aitp-handshake/tests/fixtures/mock_oidc.rs`. |
| 3d.10 — OIDC integration test | Implicitly under "full handshake test" | Only pinned-key path was tested | ✓ Added `crates/aitp-handshake/tests/oidc_handshake.rs`. |
| 3d.11 — wire transcript design doc | Not mentioned | Not written | ✓ Added `docs/design/03-handshake-transcripts.md`. |
| 4a.5 — `client_manifest.rs` failure-path tests | "covered by manifest_server.rs" | Only happy path was covered | ✓ Added `crates/aitp-transport-http/tests/client_manifest.rs` (4 failure-path tests). |
| 4a.5 — `full_handshake_over_http.rs` | "demo binaries cover this" | Lib's `HandshakeServer` was never exercised by a Rust test | ✓ Added `crates/aitp-transport-http/tests/full_handshake_over_http.rs`. |
| 6.6 — Cargo.toml metadata | "covered" | Only `description` was set; no `keywords`/`categories`/`homepage` | ✓ Added workspace-level `keywords`, `categories`, `homepage`; inherited in every publishable crate. `aitp-rs-adapter` now `publish = false`. |

## Bugs surfaced during the re-audit

| Bug | Location | Fix |
|---|---|---|
| `HandshakeServer` ack envelope used a fresh `(message_id, timestamp)` while the identity proof inside was bound to the earlier `(ack_mid, ack_ts)`. Identical bug to the one we already fixed in the demo. | `crates/aitp-transport-http/src/server.rs::handle_hello` | Switched the helper to a new `sign_envelope_with(mid, ts)` that takes caller-provided values; updated the server to pass `(ack_mid, ack_ts)`. |
| `HandshakeServer::on_hello` hardcoded the responder's `requested_grants` to `Vec::new()`, which makes any symmetric handshake fail with `POLICY_VIOLATION`. | Same file | Added `requested_grants` to the constructor. |
| `JwksFetcher::parse_jwks` wrapped raw Ed25519 pubkeys in SPKI DER before calling `DecodingKey::from_ed_der`, but `jsonwebtoken`'s `from_ed_der` actually expects the raw 32 bytes (the function name is misleading). All OIDC verifications would have failed against a real JWKS endpoint. | `crates/aitp-transport-http/src/client.rs::parse_jwks` | Removed the SPKI wrapping; `from_ed_der(raw)` now matches what `verify_oidc` expects. Same fix in the mock OIDC issuer fixture. |
| OIDC `exp` validation used `jsonwebtoken`'s built-in check, which uses the **system clock** unconditionally. Tests pinning `cfg.now` therefore couldn't validate JWTs whose `exp` is in the past relative to wall-clock time. | `crates/aitp-handshake/src/identity_oidc.rs::verify_oidc` | Disabled `validation.validate_exp`; check `claims.exp <= ctx.now_unix_secs` manually. |

## Plan items legitimately deferred (not bugs)

| Plan ref | Status | Why |
|---|---|---|
| Tier B/C/D conformance ops | `BLOCKED-CONF-TIERBCD` (in PENDING.md) | Issuance + stateful flows need an issuer-side state map and a clock-override hook in the adapter binary. Deferred to v0.1.0-alpha.2. |
| Per-crate `README.md` files | Plan §6.7 marks optional | `cargo doc` is enough for a pre-alpha. |
| Spec example tests (manifest, TCT) | `BLOCKED-SPEC-EXAMPLE` | The spec ships fixture JSON with placeholder strings (`__VALID_ENVELOPE_SIG__` etc.) — they cannot pass verification until the spec ships real signed examples. |
| Spec KAT against pinned hashes | `BLOCKED-SPEC-005` / `BLOCKED-SPEC-006` | Spec hasn't published reference hashes for TCT/Manifest/JWK thumbprint. |

## Test inventory after the audit

| Crate | File | Active tests |
|---|---|---|
| `aitp-core` | `src/**` | 33 |
| `aitp-core` | `tests/jcs_standard_vectors.rs` | 24 vectors + 1 KAT (1 ignored — surrogate) |
| `aitp-core` | `tests/jcs_properties.rs` | 3 properties × 64 cases |
| `aitp-crypto` | `src/**` | 7 |
| `aitp-crypto` | `tests/integration.rs` | 11 |
| `aitp-manifest` | `src/**` | 6 |
| `aitp-manifest` | `tests/round_trip.rs` | 11 |
| `aitp-tct` | `src/**` | 5 |
| `aitp-tct` | `tests/round_trip.rs` | 13 |
| `aitp-delegation` | `src/**` | 5 |
| `aitp-delegation` | `tests/round_trip.rs` | 11 |
| `aitp-handshake` | `src/**` | 10 |
| `aitp-handshake` | `tests/full_handshake.rs` | 4 (pinned-key) |
| `aitp-handshake` | `tests/oidc_handshake.rs` | 1 (OIDC) **NEW** |
| `aitp-transport-http` | `tests/manifest_server.rs` | 1 |
| `aitp-transport-http` | `tests/client_manifest.rs` | 4 **NEW** |
| `aitp-transport-http` | `tests/full_handshake_over_http.rs` | 1 **NEW** |
| `aitp-conformance` | `tests/runner_integration.rs` | 3 |
| `examples/two-agents` | `tests/demo.rs` | 1 |
| `aitp` | doctest | 1 |

Plus `cargo test --workspace` runs every empty `mod tests {}` file as a
0-count test (those are reported as "ok" with 0 tests).

## What still depends on the spec repo (and only on the spec repo)

These are not Rust gaps — they are spec deliverables this implementation
is consuming once they land:

- `BLOCKED-SPEC-005` — pinned JCS signing-input hashes for TCT, Manifest,
  delegation token, revocation snapshot.
- `BLOCKED-SPEC-006` — pinned JWK thumbprint for a known-good Ed25519 key.
- `BLOCKED-SPEC-DELEGATION-ISSUEDAT` — `grant_proof` block in
  RFC-AITP-0006 §3 needs to either carry the source TCT's `issued_at`
  or pin a reconstruction recipe. We currently assume
  `expires_at - DEFAULT_TCT_TTL_SECS`.
- `BLOCKED-SPEC-FIXTURE-MIGRATION` — the spec's
  `schemas/conformance/*.json` fixtures predate the conformance
  runner's `input.operation` shape. The Rust runner correctly identifies
  this and emits `FAIL: input.operation missing` for each.
- `BLOCKED-JCS-SURROGATE` — `serde_jcs` 0.1 sorts object keys by UTF-8
  byte order, not UTF-16 code-unit order (RFC 8785 §3.2.3 violation).
  One test vector is `#[ignore]`'d; resolution paths in PENDING.md.

## Summary

The original Phase 0–6 run shipped a working AITP implementation that
passes 127 tests, runs the demo end-to-end, and exercises every protocol
crate. The audit found **5 plan items the reports claimed without
delivering**, **3 latent bugs the missing tests would have caught** (the
HandshakeServer mid/ts mismatch, the hardcoded empty `requested_grants`,
the SPKI vs. raw `from_ed_der` confusion, and the system-clock `exp`
validation). All have been fixed. Test count rose from 127 → 133, and
clippy/format/doc remain clean.
