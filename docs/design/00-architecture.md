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
       ├─ aitp-envelope    Envelope sign/verify — sync, no I/O
       ├─ aitp-manifest    Manifest issuance + verification
       ├─ aitp-tct         TCT issuance + verification, PoP exchange
       │    ├─ aitp-handshake       Mutual handshake state machine
       │    ├─ aitp-delegation      Single-hop delegation
       │    └─ aitp-session-bundle  Session Trust Bundle (RFC-0010, opt-in)
       └─ aitp-transport-http   HTTP client/server (feature-gated)
  └─ aitp                facade re-exporting the above
  └─ aitp-conformance    runner with Adapter trait
  └─ aitp-rs-adapter     subprocess adapter for the runner

bindings/aitp-py       Python SDK (PyO3)    — excluded from the workspace
bindings/aitp-node     Node.js SDK (NAPI-rs) — excluded from the workspace
```

## Why this split

**`aitp-core` has no crypto.** It defines wire types, JCS canonicalization,
base64url, AID parsing. Anyone working with AITP data structures (e.g. for
storage, logging, analysis) can depend on this crate without an Ed25519
dependency.

**`aitp-crypto` has no protocol.** It wraps `ed25519-dalek` with AITP-specific
key handling and the JWK thumbprint computation, but nothing else. It does
not know what a Manifest or TCT is.

**`aitp-envelope` is the sync envelope codec.** Wrapping a payload in a
signed `AitpEnvelope` and verifying an envelope's outer signature depends
only on `aitp-core` and `aitp-crypto` — no HTTP, no async, no I/O. It lives
in its own crate so language bindings and other sync consumers can reuse the
signing helpers without inheriting a transport stack.
`aitp-transport-http::common` keeps thin wrappers over `sign_envelope` /
`sign_envelope_with` / `verify_envelope_signature`, so callers that imported
them from the transport crate keep compiling unchanged.

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

## Language bindings

`bindings/aitp-py` (PyO3) and `bindings/aitp-node` (NAPI-rs) are thin SDKs
over the protocol crates. They are **excluded from the Cargo workspace**:
both are `cdylib` crates built by maturin / napi-cli against an external
Python / Node toolchain, so pulling them into `cargo test --workspace`
would couple the workspace build to those toolchains. Each carries its own
`Cargo.lock`.

Both SDKs depend on `aitp-envelope` directly — the reason that crate was
split out of `aitp-transport-http`. They expose JSON-string-in /
JSON-string-out methods so agent code never sees a Rust type across the FFI
boundary, and they are kept API-symmetric (`build_manifest` ↔
`buildManifest`). `bindings/interop/` holds cross-language integration
tests that run a real handshake between the two SDKs in both directions;
`make interop` builds both and runs them.

## Workspace dependencies

All third-party deps are pinned in the root `Cargo.toml` under
`[workspace.dependencies]`. Every crate references them via
`{ workspace = true }`. This guarantees one version of every dependency
across the workspace and makes upgrades a one-line change.

## Why MSRV 1.88

The workspace declares `rust-version = "1.88"`; the toolchain is pinned to
`1.89.0` in `rust-toolchain.toml`. MSRV moved up from 1.75 once transitive
dependencies (`time`, `icu_*`, `idna_adapter`, `clap_lex`) began requiring
edition 2024. `cargo msrv verify` runs in CI. We will not bump MSRV without
a strong reason.

## Why dual MIT OR Apache-2.0

Standard Rust convention. Friendlier to enterprise adoption than either
license alone. Same as `tokio`, `serde`, `tower`, etc.
