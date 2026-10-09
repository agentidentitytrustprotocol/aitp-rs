# Progress — docs refresh (post-0.13)

Plan: `plans/docs-refresh.md` (local, gitignored). Branch `docs/refresh-post-0.13` off `origin/main` @ `35531c9` (0.13.2; delta vs 0.13.1 is version bumps + transport-http crate CHANGELOG only). Spec pin stays `ea22c710f50bc74c6331dcc1983a0ec6fa82a0de`.
PR strategy: one PR (docs + executable-sample tests + docs checker) — docs-only, tightly cross-linked, so splitting would leave dangling links. Closes #192.

Measured at the pin (existing `target/debug` binaries, 3 independent audits agree): strict 59 pass / 0 fail / 10 skip of 69; with both draft features 67 / 0 / 2 (`del-004`, `del-007`); at spec HEAD 70/0/2 of 72. Local rebuild blocked by macOS linker error ("tapi: unknown architecture") — CI is the oracle.

Issue map (this repo): G1 gate flag #194 · G2 bundle bare body #195 · G3 renewal #196 · G4 bundle check order #197 · G5 server defaults #198 · G6/G7 binding kwarg + return asymmetry #199 · G8 UNKNOWN_FIELD→malformed #152 · G9 stale rustdoc #200 · CHANGELOG rotation #201.

Risk tiers: P0 simple · P1 simple · P2 simple · P3 complex · P4 complex · P5 simple · P6 complex.

## Checkpoint trail
- Phase 0 — in progress.

## Repo map

Docs under change: `README.md`, `docs/{README,architecture,conformance,deployment,handshake-transcripts,jcs,key-management,multihop-delegation,sdk-node,sdk-python,session-bundle,tct-renewal,testing,transport-hardening}.md`, `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, `adapters/README.md`, `examples/README.md`, `crates/aitp-cli/README.md` (only crate README), `bindings/{aitp-py,aitp-node,interop}/README.md`.

Code truth:
- `crates/aitp-core` — error codes (`src/error.rs`), JCS (`src/jcs.rs`), `unknown_field.rs` (member-set + duplicate keys)
- `crates/aitp-crypto` — Ed25519/P-256, compact JWS (`src/jws.rs:85-90`)
- `crates/aitp-envelope` — envelope sign/verify (not a facade dep)
- `crates/aitp-manifest` — manifest build/verify (`verifier.rs:105`, `builder.rs:396`)
- `crates/aitp-tct` — TCT verify (`verifier.rs:254-275` §7.2 order), `renewal.rs`, `revocation.rs`
- `crates/aitp-delegation` — `verifier.rs:77,116` multihop opt-in; depends on aitp-tct
- `crates/aitp-handshake` — M1–M4, `identity_pinned.rs`, `jwk.rs:288` RSA floor
- `crates/aitp-session-bundle` — `verifier.rs`, `wire.rs`
- `crates/aitp-transport-http` — `client.rs`, `server.rs` (renew route ~587), `session_bundle_server.rs:141`, `key_resolution.rs`, `net_guard.rs`, `dpop.rs`, `token_exchange.rs`, `revocation.rs`
- `crates/aitp` — facade (`src/facade.rs:494,791`), features
- `crates/aitp-conformance` — runner (`src/main.rs:182-214` gate, `runner/{executor,output}.rs`)
- `crates/aitp-rs-adapter` — NDJSON adapter (`src/lib.rs`)
- `crates/aitp-cli` — `aitp keygen/tct/manifest/aid`
- `bindings/aitp-py` (`aitp.pyi`, `src/*.rs`, `tests/`), `bindings/aitp-node` (`index.d.ts`, `src/*.rs`, `tests/`), `bindings/interop` (`test_interop.py`, stock JOSE scripts)
- `tools/mint-conformance-fixtures`, `tools/mint-signed-examples` (xcheck), `tests/schemas/` (vendored; `SPEC_VERSION`), `tests/xcheck-fixtures`, `tests/AITP_VERIFIER_PY_VERSION`
- `Makefile` (`ci`, `check-versions`, `schemas-check`), `scripts/`, `.github/workflows/ci.yml` (conformance expectations ~420, xcheck 430, e2e 509), `.gitignore:69` (`plans/` ignored)

Siblings (link targets, read-only): `../agentidentitytrustprotocol/{rfcs,docs,registries,schemas/conformance}`, `../aitp-verifier-py`, `../aitp-playground/docs/aitp-integration.md` (inbound anchors), `../aitp-website/scripts/sync-content.sh` (republishes SDK pages), `../aitp-docs/kb`.
