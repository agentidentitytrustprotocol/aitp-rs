# Contributing to aitp-rs

Thanks for your interest. This document covers the local workflow and the
quality bar that CI enforces.

## Prerequisites

- Rust toolchain (the repo pins one via `rust-toolchain.toml`; rustup will
  install it on first `cargo` invocation).
- `cargo deny` (optional, for license/advisory checks): `cargo install cargo-deny`.

## Local CI gauntlet

`make ci` runs everything a PR gates on that works without extra repos:
`check-versions`, then `test` (fmt check, clippy with `-D warnings`, the
full test suite), `doc` (rustdoc with `-D warnings`), `deny` and `audit`.
The individual steps are:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
cargo deny check --all-features
cargo audit
```

`make deny` and `make audit` need `cargo-deny` and `cargo-audit`
installed. `scripts/test.sh` runs the first three commands. CI also runs
jobs `make ci` does not cover, among others (MSRV, `cargo-semver-checks`, coverage, the
conformance runner, the vendored-schema check); `make msrv`, `make semver`,
`make coverage` and `make schemas-check` run them locally when you have the
tools and a spec-repo clone.

- `make docs-check` (`scripts/check-docs.py`, the non-required CI
  `docs-check` job) checks doc links and anchors, `RFC-AITP-NNNN §x.y`
  citations against the pinned spec, protected inbound anchors and banned
  stale strings. Run it when you touch any `.md`; it is not part of `make ci`.

## Versions

All published crates share one version, set once in `[workspace.package]`
in the root `Cargo.toml` and inherited with `version.workspace = true`;
inter-crate dependencies pin it exactly (`=x.y.z`). The SDK bindings under
`bindings/` sit outside the Cargo workspace but must carry the same version.

- `make check-versions` (`scripts/check-versions.sh`, the CI `versions`
  job) fails if any crate, inter-crate pin or binding manifest is out of
  step.
- `make sync-versions` (`scripts/sync-binding-versions.sh`) rewrites the
  binding manifests to the workspace version. release-plz runs it on its
  own release PRs; run it locally only after a manual version bump or when
  `check-versions` reports binding drift.

Don't bump versions by hand in a normal PR — release-plz does it (see
[Commit messages](#commit-messages)).

## Spec pin and vendored schemas

`tests/schemas/SPEC_VERSION` pins the commit of the
[spec repo](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol)
that the vendored JSON Schemas and known-answer vectors under
`tests/schemas/` come from, and that the CI conformance job runs fixtures
against.

- `scripts/sync-schemas.sh` mirrors the schemas and known-answer vectors
  from a spec checkout (a sibling `../agentidentitytrustprotocol` clone by
  default, or `AITP_SPEC=/path/to/spec`) and rewrites `SPEC_VERSION` to
  that checkout's commit.
- `make schemas-check` re-runs the sync and fails if `git diff` shows
  changes under `tests/schemas/` (CI also rejects untracked files). Check out the spec at the pinned commit first, or the check
  reports drift against whatever commit you have.
- The `bump-spec` workflow (`.github/workflows/bump-spec.yml`) adopts a new
  spec revision: the spec repo dispatches it, or you run it manually with a
  SHA. It updates `SPEC_VERSION` and opens a PR that is held for review,
  never auto-merged. If the schemas changed, check out the spec at that
  SHA, run `scripts/sync-schemas.sh` on the PR branch and commit the
  result so the `vendored schemas in sync` job passes.

## Workspace layout

See [`docs/architecture.md`](docs/architecture.md).
The short version: the protocol crates are pure and synchronous.
HTTP lives in `aitp-transport-http` (client and server behind its `client`
and `server` features) and in the `aitp` facade, whose async
`run_initiator_handshake` helper drives a handshake over it.

## Coding standards

- `#![forbid(unsafe_code)]` on every library root under `crates/`
  (`src/lib.rs`). CI does not gate this, but the project does. It is not
  set on the binary roots (`crates/aitp-cli/src/main.rs`,
  `crates/aitp-conformance/src/main.rs`, `crates/aitp-rs-adapter/src/main.rs`),
  `examples/two-agents` or the `tools/*` binaries, and the binding crates
  omit it because the PyO3 / NAPI-rs export macros expand to `unsafe` code.
  See [`docs/architecture.md`](docs/architecture.md).
- `#![warn(missing_docs)]` on every public crate. Public items must have
  doc comments.
- Errors implement `thiserror::Error` and use specific variants — no
  catch-all string-only errors in new code.
- New dependencies: declare in `[workspace.dependencies]` of the root
  `Cargo.toml` and reference via `{ workspace = true }` in member crates.
- MSRV is **1.90**, kept in lockstep with the `rust-toolchain.toml`
  pin (originally targeted 1.75; forced up by transitive deps —
  `time`, `time-macros`, `icu_*`, `idna_adapter`, `clap_lex` — to
  1.89, then to 1.90 by `ordered-float` 5.5.0 via `metrics-util`
  0.20). Do not
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

Use [Conventional Commits](https://www.conventionalcommits.org/). release-plz
computes the next version and writes the per-crate `crates/*/CHANGELOG.md`
entries from them, so the commit type matters:

- `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:` and so on, with
  an optional scope: `fix(transport-http): …`.
- Mark a breaking change with `!` after the type or scope
  (`fix!: …`, `refactor(aitp-handshake)!: …`) or a `BREAKING CHANGE:`
  footer. While the crates are pre-1.0, a breaking change bumps the minor
  digit (0.12.x → 0.13.0), not the major.
- release-plz also runs `cargo-semver-checks` (`semver_check = true` in
  `release-plz.toml`), and CI runs it on PRs. If it reports a break your
  commit doesn't mark, mark the commit — don't rely on the tool's result
  alone.
- A squash merge uses the PR title as the commit subject, so make the PR
  title a valid Conventional Commit too, including any `!`.

Also:

- One logical change per commit.
- Subject line in the imperative ("add X", "fix Y"), under 72 chars.
- Body explains the *why*; the diff covers the *what*.
- The root `CHANGELOG.md` is maintained by hand (release-plz only writes
  the per-crate changelogs). For a user-visible change, add an entry under
  `[Unreleased]`, per the PR template's CHANGELOG checkbox.

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
