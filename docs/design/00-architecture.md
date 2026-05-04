# 00 — Workspace Architecture

This document captures the rationale for the `aitp-rs` workspace structure.
Read this before changing crate boundaries.

## Goals

The Rust reference implementation needs to satisfy three audiences with
different needs:

1. **MACP and similar runtimes** want to verify TCTs and nothing else.
   They do not want to inherit an HTTP client, a handshake state machine,
   or an OIDC JWT library.
2. **Standalone agent implementations** want the full handshake, TCT
   exchange, manifest fetch, and HTTP serving — a one-line dependency
   that gives them everything.
3. **The conformance runner** needs an in-process adapter that can call
   into every layer of the protocol.

Satisfying all three with a monolithic crate is impossible. The workspace
layout below is the minimum split that satisfies them all.

## The crates

```
aitp-core             types, JCS, base64url, AID — pure, no I/O
  └─ aitp-crypto      Ed25519, JWK thumbprint
       ├─ aitp-manifest    Manifest issuance + verification
       ├─ aitp-tct         TCT issuance + verification, PoP exchange
       │    └─ aitp-handshake   Mutual handshake state machine
       │    └─ aitp-delegation  Single-hop delegation
       └─ aitp-transport-http   HTTP client/server (feature-gated)
  └─ aitp                facade re-exporting the above
  └─ aitp-conformance    runner with Adapter trait
  └─ aitp-rs-adapter     subprocess adapter for the runner
```

## Why this split

**`aitp-core` has no crypto.** It defines wire types, JCS canonicalization,
base64url, AID parsing. Anyone working with AITP data structures (e.g. for
storage, logging, analysis) can depend on this crate without an Ed25519
dependency.

**`aitp-crypto` has no protocol.** It wraps `ed25519-dalek` with AITP-specific
key handling and the JWK thumbprint computation, but nothing else. It does
not know what a Manifest or TCT is.

**`aitp-tct` does not depend on `aitp-handshake`.** TCT verification is the
hottest path in the protocol — every consumer of AITP capabilities runs
`verify_tct` per request. It must be possible to import it without the
handshake state machine.

**`aitp-handshake` depends on `aitp-tct` and `aitp-manifest`.** The handshake
issues TCTs and verifies Manifests; that's its job.

**`aitp-transport-http` is feature-gated.** Its `client` feature pulls
`reqwest`; its `server` feature pulls `axum`. No protocol crate depends on
it. A consumer that uses a different transport (gRPC, MessagePack) can
implement the wire layer themselves while reusing all the protocol crates.

**`aitp` is the facade.** It re-exports the protocol crates and provides
a `prelude`. This is what most users depend on.

**`aitp-conformance` and `aitp-rs-adapter` are separate.** The runner is
language-agnostic; the adapter is `aitp-rs`-specific. Keeping them apart
lets future-language adapters (Python, Go) live alongside the Rust adapter
without forcing dependencies.

## Async story

The protocol crates are sync. `aitp-transport-http` is async because
`reqwest` and `axum` are async. This split has two benefits:

- TCT verification can run from sync codebases.
- Implementations that prefer `async-std` over `tokio`, or that wrap AITP
  in a non-Rust runtime via FFI, are not blocked.

If we ever need an async-by-default API, we add async wrappers in the
facade crate without changing the protocol crates.

## Workspace dependencies

All third-party deps are pinned in the root `Cargo.toml` under
`[workspace.dependencies]`. Every crate references them via
`{ workspace = true }`. This guarantees one version of every dependency
across the workspace and makes upgrades a one-line change.

## Why MSRV 1.75

Old enough to be in Linux distros and CI runners. New enough for
`async fn in trait`, modern lifetime improvements, and `let-else`.
We will not bump MSRV without a strong reason.

## Why dual MIT OR Apache-2.0

Standard Rust convention. Friendlier to enterprise adoption than either
license alone. Same as `tokio`, `serde`, `tower`, etc.
