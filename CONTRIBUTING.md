# Contributing to aitp-rs

Thanks for your interest. This document covers the local workflow and the
quality bar that CI enforces.

## Prerequisites

- Rust toolchain (the repo pins one via `rust-toolchain.toml`; rustup will
  install it on first `cargo` invocation).
- `cargo deny` (optional, for license/advisory checks): `cargo install cargo-deny`.

## Local CI gauntlet

The same checks CI runs:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps --all-features
```

`scripts/test.sh` runs the first three.

## Workspace layout

See [`docs/architecture.md`](docs/architecture.md).
The short version: protocol crates are pure and synchronous;
`aitp-transport-http` is the only crate that speaks HTTP and is
feature-gated.

## Coding standards

- `#![forbid(unsafe_code)]` on every crate (CI does not gate this, but the
  project does).
- `#![warn(missing_docs)]` on every public crate. Public items must have
  doc comments.
- Errors implement `thiserror::Error` and use specific variants — no
  catch-all string-only errors in new code.
- New dependencies: declare in `[workspace.dependencies]` of the root
  `Cargo.toml` and reference via `{ workspace = true }` in member crates.
- MSRV is **1.89**, kept in lockstep with the `rust-toolchain.toml`
  pin (originally targeted 1.75; forced up by transitive deps —
  `time`, `time-macros`, `icu_*`, `idna_adapter`, `clap_lex`). Do not
  use newer language features without a follow-up bump in
  `rust-toolchain.toml`, `Cargo.toml` (`rust-version`), `clippy.toml`
  (`msrv`), and the CI MSRV matrix entry.

## Documentation

- [`docs/README.md`](docs/README.md) is the index. Implementation guides
  and design notes live under `docs/`; the protocol itself is defined
  **normatively** by the [AITP RFCs](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/tree/main/rfcs).
- **Point to the RFC; don't restate it.** When a doc needs a wire detail
  (a signing-input recipe, a field invariant), cite the RFC section
  rather than copying the bytes — duplicated normative text silently
  drifts from the spec. If both must show it, make the doc defer to the
  RFC as the source of truth.
- If you change a binding's public API, update **both** SDK guides
  (`docs/sdk-python.md`, `docs/sdk-node.md`) so they stay symmetric.

## Commit messages

- One logical change per commit.
- Subject line in the imperative ("add X", "fix Y"), under 72 chars.
- Body explains the *why*; the diff covers the *what*.

## Pull requests

- Rebase on `main` before opening.
- Fill out the PR template; tick the checklist.
- If your change touches the wire format or signing inputs, link the
  matching change in the [spec repo](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol).

## Security

Never open a public issue for a vulnerability. See
[`SECURITY.md`](SECURITY.md) for the disclosure channel.

## License

By submitting a contribution you agree that it is licensed under both the
MIT and Apache-2.0 licenses, matching the repository's dual-license.
