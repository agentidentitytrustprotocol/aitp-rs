# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repo at a glance

`aitp-rs` is the Rust reference implementation of the **Agent Identity & Trust Protocol (AITP)**: a transport- and identity-agnostic, JCS-canonicalized, Ed25519-signed protocol where two agents establish bilateral trust by exchanging peer-issued **Trust Context Tokens** (TCTs). The wire spec lives in the sibling [`agentidentitytrustprotocol`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol) repo; this implementation tracks **AITP v0.1.0** (spec commit pinned in `tests/schemas/SPEC_VERSION`).

It is a Cargo workspace; the protocol crates carry no JS tooling. The `bindings/` tree holds language SDKs (PyO3 Python, NAPI-rs Node) that are **excluded** from the workspace and built separately by maturin / napi-cli. MSRV is **1.88** and the toolchain is pinned to `1.89.0` via `rust-toolchain.toml`. Every workspace crate sets `#![forbid(unsafe_code)]` — the binding crates omit it, since the PyO3 / NAPI-rs export macros expand to `unsafe` glue.

## Common commands

```bash
# Local CI gauntlet (same checks as `make test` and `scripts/test.sh`)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps --all-features      # RUSTDOCFLAGS="-D warnings" in CI

# Run the end-to-end two-agent demo (real four-message handshake + /echo)
make demo

# Cross-language interop: a real Python <-> Node handshake through the bindings
# (builds aitp-py + aitp-node, then runs the pytest suite in bindings/interop/)
make interop

# Single test by name (substring match against test path)
cargo test -p aitp-tct verifier::tests::rejects_expired
# Single integration-test file
cargo test -p aitp-delegation --test round_trip
# Single fixture through the conformance runner
cargo run -p aitp-conformance -- run --target ./target/debug/aitp-rs-adapter --filter <fixture-id>

# Fuzzing (nightly only; targets live in fuzz/fuzz_targets/)
cd fuzz && cargo +nightly fuzz run envelope_parse -- -max_total_time=60

# Miri (manual, not a PR gate; aitp-core is the primary target)
cargo +nightly miri test -p aitp-core --lib

# Re-vendor JSON Schemas from the spec repo (run when the pinned spec commit changes)
scripts/sync-schemas.sh        # or AITP_SPEC=/path/to/spec scripts/sync-schemas.sh
```

CI also runs `cargo deny check`, `cargo audit`, `cargo semver-checks` (PRs only), `cargo msrv verify`, and `cargo tarpaulin` with a **50% workspace-coverage floor** (ratchet upward, never down). The `spec-schemas` job re-runs `sync-schemas.sh` against the pinned commit in `tests/schemas/SPEC_VERSION` and fails on drift.

## Architecture: the layered crate graph

The workspace split is **load-bearing** — it exists so a TCT-only consumer (e.g. MACP) can verify tokens without inheriting an HTTP client, axum, or a handshake state machine. Read `docs/design/00-architecture.md` before changing crate boundaries.

```
aitp-core             pure: wire types, JCS, base64url, AID, error codes (no crypto, no I/O)
  └─ aitp-crypto      Ed25519 (verify_strict), JWK thumbprint — no protocol awareness
       ├─ aitp-envelope        Envelope sign/verify — sync, no I/O (reused by the bindings)
       ├─ aitp-manifest        Manifest issuance + verification
       ├─ aitp-tct             TCT issuance/verification + downstream PoP + renewal
       │    ├─ aitp-handshake  Mutual handshake state machine (depends on tct + manifest)
       │    └─ aitp-delegation Single-hop delegation (chain length =1; >1 → MULTIHOP_NOT_SUPPORTED)
       └─ aitp-transport-http  HTTP client/server — feature-gated, the ONLY async crate
  └─ aitp                      Facade re-exporting the above + run_initiator_handshake / renew_tct / TctStore
  └─ aitp-conformance          Language-agnostic runner with Adapter trait (subprocess + in-process)
  └─ aitp-rs-adapter           Canonical Rust adapter exercised by the runner
  └─ aitp-session-bundle       Session Trust Bundle (RFC-0010 draft) — re-exported as aitp::session_bundle under the experimental-session-bundle feature

bindings/aitp-py             PyO3 Python SDK — cdylib, excluded from the workspace
bindings/aitp-node           NAPI-rs Node SDK — cdylib, excluded from the workspace
bindings/interop             Cross-language interop integration tests — `make interop`
```

### Hard rules these crate boundaries enforce

- **Protocol crates are sync.** `aitp-transport-http` is the only async crate (`reqwest`, `axum`, `tokio`). Do not pull async into `aitp-core`/`aitp-tct`/`aitp-handshake`.
- **`aitp-core` has no crypto** — it must remain importable by tools that only parse/canonicalize wire data.
- **`aitp-envelope` is the sync envelope codec.** `sign_envelope` / `sign_envelope_with` / `verify_envelope_signature` live here, depending only on `aitp-core` + `aitp-crypto` — no HTTP, no async. `aitp-transport-http::common` keeps thin wrappers over them so existing `aitp_transport_http::common::*` imports keep compiling; the language bindings depend on `aitp-envelope` directly.
- **`bindings/*` are excluded from the workspace.** `aitp-py` (PyO3) and `aitp-node` (NAPI-rs) are `cdylib`s built against an external Python / Node toolchain — never pulled into `cargo test --workspace`. They carry their own `Cargo.lock`. Their per-language tests run via `pytest` / `node --test`; the cross-language interop suite runs via `make interop`.
- **`aitp-tct` does NOT depend on `aitp-handshake`.** TCT verification is the per-request hot path; reversing this dependency would force every verifier to compile the state machine.
- **`aitp-transport-http` features are split**: `client` (reqwest), `server` (axum), `client-spki-pinning` (rustls + x509-parser, off by default to avoid pulling in a CryptoProvider unnecessarily). The `aitp` facade exposes them as `http-client` / `http-server` / `all`.
- **Workspace deps only.** New third-party crates go in root `[workspace.dependencies]` and are referenced via `{ workspace = true }` so the lock has exactly one version of each.
- **Public items require docs** (`#![warn(missing_docs)]`). Errors use `thiserror` with specific variants — no string-only catch-alls.

### Wire-format invariants

- Canonicalization is **RFC 8785 JCS** via `serde_jcs`. Anything that gets signed is JCS-encoded first; tests in `crates/aitp-core/tests/kat.rs` and `tests/schemas/known-answer/jcs-sha256.json` pin byte-exact output. See `docs/design/01-jcs.md`.
- The wire schemas in `tests/schemas/` are **vendored copies** of the spec's `schemas/json/`, pinned by commit SHA in `tests/schemas/SPEC_VERSION`. The `spec-schemas` CI job blocks merges on drift — always re-run `scripts/sync-schemas.sh` after bumping the SHA.
- `aitp-rs-adapter` implements every conformance op — `verify_handshake_payload` (`id-*` / `mh-*`), `verify_session_bundle` / `issue_session_bundle` (`bundle-*`), and the `tct-007` PoP-enforcement ops (`authorize_capability_invocation`, `expect_pop_challenge_issued`, `withhold_pop_response`). All 37 `core` fixtures pass; the 7 `draft` fixtures pass under their opt-in features. The conformance runner enforces a **v0.1 gate**: a `required_for_v0_1` fixture that fails or is SKIPped for an adapter-capability reason makes `aitp-conformance run` exit non-zero. See `docs/conformance-matrix.md` for the per-fixture breakdown.

### Where async lives in `aitp-transport-http`

`KeyResolutionPolicy` (RFC-0007) bridges sync verification into async JWKS fetches via a tokio runtime; **a multi-thread tokio context is required** in the calling thread. Pure-sync deployments must use the pinned-issuer store instead. Other notable subsystems: `client_config.rs`, `dpop.rs`, `retry.rs`, `revocation.rs`, `server_limits.rs`, `tls_pinning.rs`, `token_exchange.rs` — each one corresponds to a hardening item in `plans/aitp-rs-unified-claude-code-plan.md`.

### Language bindings (`bindings/`)

`aitp-py` (PyO3) and `aitp-node` (NAPI-rs) are thin SDKs over the
protocol crates. Each exposes an `AitpAgent` plus initiator/responder
session types whose methods consume and produce **JSON strings** — the
HTTP request/response bodies — so agent code never sees a Rust type
across the FFI boundary. The two SDKs are intentionally symmetric
(`build_manifest` ↔ `buildManifest`, etc.).

- Per-language tests: `bindings/aitp-py/tests/` (`pytest`) and
  `bindings/aitp-node/tests/` (`node --test`) — in-process handshakes.
- `bindings/interop/` holds the **cross-language** integration tests:
  a real four-message handshake driven between the Python and Node
  SDKs in both directions, proving the two emit wire-compatible
  envelopes. The Python side runs in-process under `pytest`; the Node
  side runs as a JSON-RPC subprocess worker (`node_worker.mjs`). Run
  the whole thing with `make interop`.

If you change a binding's public API, update **both** SDKs to keep them
symmetric, and update `bindings/interop/test_interop.py` plus each
SDK's own test file.

## When changes touch the wire format or signing inputs

If you modify wire types, signing inputs, or canonicalization:

1. Update the corresponding crate(s).
2. Re-run `scripts/sync-schemas.sh` if the spec changed; otherwise the spec-schemas CI job will fail.
3. Update the relevant fixture(s) in `tests/schemas/` and the kat tests.
4. Link the matching spec-repo PR in your commit/PR description (per `CONTRIBUTING.md`).

Wire-affecting changes are **`semver-major`** for the published crates — `cargo-semver-checks` runs on every PR and gates the merge.

## Design docs to read first

- `docs/design/00-architecture.md` — workspace split rationale (this is the canonical version of the rules above)
- `docs/design/01-jcs.md` — JSON canonicalization strategy and test vectors
- `docs/design/02-conformance-adapter.md` — runner design and adapter contract
- `docs/design/03-handshake-transcripts.md` — the four-message exchange in detail
- `docs/conformance-matrix.md` — per-fixture conformance status (44/44 pass)
- `plans/defered/deferred.md` — declined / out-of-scope items (won't-fix register)
