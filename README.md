# aitp-rs

Rust reference implementation of the **Agent Identity & Trust Protocol (AITP)**.

> **Status: v0.1.0-alpha.1 (unreleased).** All seven core crates are
> implemented and tested. The two-agent demo runs end-to-end with a real
> four-message handshake. The conformance runner ships with subprocess
> adapter support for Tier-A verification ops. See
> [`docs/design/PENDING.md`](docs/design/PENDING.md) for what's still
> open and the per-phase reports (`phase-N-report.md`) for what landed
> in each milestone.

## What is AITP?

AITP is a transport-agnostic, identity-agnostic trust protocol for agent-to-agent
communication. Two agents establish bilateral trust without requiring a shared
verifier, exchanging signed peer-issued **Trust Context Tokens** (TCTs) that name
each peer as the audience and bind capabilities to the holder's key.

The protocol specification lives in the
[`agentidentitytrustprotocol`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol)
repository. This implementation tracks v0.1.0-rc.1.

## Workspace layout

```
aitp-rs/
├── crates/
│   ├── aitp-core/          types, JCS, base64url, AID — pure, no I/O
│   ├── aitp-crypto/        Ed25519, JWK thumbprint, signature ops
│   ├── aitp-manifest/      Manifest issuance and verification
│   ├── aitp-handshake/     Mutual handshake state machine
│   ├── aitp-tct/           TCT issuance and verification, PoP exchange
│   ├── aitp-delegation/    Single-hop delegation tokens
│   ├── aitp-transport-http/ HTTP client/server bindings (feature-gated)
│   ├── aitp/               facade re-exporting the protocol crates
│   ├── aitp-conformance/   conformance test runner with adapter trait
│   └── aitp-rs-adapter/    canonical Rust adapter for conformance testing
├── examples/
│   └── two-agents/         standalone demo: two agents establishing trust
├── adapters/               example adapters in other languages (Python, etc.)
├── docs/design/            architectural decisions and design notes
└── scripts/                build and release helpers
```

## Status by crate

| Crate                 | Status        | Notes                                                  |
|-----------------------|---------------|--------------------------------------------------------|
| `aitp-core`           | ✅ complete   | AID, JCS, base64url, timestamps, envelope, error codes. |
| `aitp-crypto`         | ✅ complete   | Ed25519 (`verify_strict`), JWK thumbprint.              |
| `aitp-manifest`       | ✅ complete   | Builder + verifier + HTTP wrapper.                      |
| `aitp-tct`            | ✅ complete   | Builder + verifier + downstream PoP.                    |
| `aitp-delegation`     | ✅ complete   | Builder + 11-check verifier (single-hop).               |
| `aitp-handshake`      | ✅ complete   | Initiator + Responder + OIDC + pinned-key.              |
| `aitp-transport-http` | ✅ complete   | Manifest server/fetcher, JWKS resolver, handshake server. |
| `aitp` (facade)       | ✅ complete   | Re-exports + working doctest.                           |
| `aitp-conformance`    | ✅ Tier A     | Subprocess adapter, fixture loader, runner. Tier B/C/D deferred. |
| `aitp-rs-adapter`     | ✅ Tier A     | `verify_jcs`, `compute_jwk_thumbprint`, `verify_manifest`, `verify_tct`. |

## Quick start

Run the two-agent demo (no external dependencies):

```bash
make demo
```

You should see the four-message handshake complete and an `/echo`
capability invocation succeed. See
[`examples/two-agents/README.md`](examples/two-agents/README.md) for the
walkthrough.

## Building

```bash
cargo build --workspace --all-targets --all-features
cargo test --workspace --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps --all-features
```

`scripts/test.sh` and `make test` both run the local CI gauntlet. CI runs
the same checks plus `cargo deny` and `cargo audit` on Linux + macOS +
Windows.

## Design documents

Read these before contributing:

- [`docs/design/00-architecture.md`](docs/design/00-architecture.md) — workspace structure rationale
- [`docs/design/01-jcs.md`](docs/design/01-jcs.md) — JSON canonicalization strategy and test vectors
- [`docs/design/02-conformance-adapter.md`](docs/design/02-conformance-adapter.md) — conformance runner design
- [`docs/design/PENDING.md`](docs/design/PENDING.md) — pending tasks and open questions

## Development plan

A 5-sprint plan to reach `v0.1.0-alpha.1`:

1. **Sprint 1** — Workspace bootstrap, CI, dependency policy, `aitp-core` types.
2. **Sprint 2** — `aitp-core` complete (JCS, envelope, AID), `aitp-crypto` complete.
3. **Sprint 3** — `aitp-manifest`, `aitp-handshake`, `aitp-tct`, `aitp-delegation`.
4. **Sprint 4** — `aitp-transport-http` and the two-agent demo.
5. **Sprint 5** — Conformance runner and `aitp-rs-adapter`.

## License

Dual-licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option. See [`LICENSE-APACHE`](LICENSE-APACHE) and [`LICENSE-MIT`](LICENSE-MIT).
