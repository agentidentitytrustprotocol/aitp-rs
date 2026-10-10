# aitp-rs

[![CI](https://github.com/agentidentitytrustprotocol/aitp-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/agentidentitytrustprotocol/aitp-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/aitp.svg)](https://crates.io/crates/aitp)
[![docs.rs](https://img.shields.io/docsrs/aitp)](https://docs.rs/aitp)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Rust reference implementation of the **Agent Identity & Trust Protocol (AITP)**.

> **Status:** tracks the AITP **v0.2** wire protocol (`aitp/0.2`) at the
> spec commit pinned in [`tests/schemas/SPEC_VERSION`](tests/schemas/SPEC_VERSION).
> The current crate version is in [`Cargo.toml`](Cargo.toml) and the
> [release notes](https://github.com/agentidentitytrustprotocol/aitp-rs/releases);
> history is in [`CHANGELOG.md`](CHANGELOG.md). Conformance results at the
> pin, and what they do and do not prove, are in
> [`docs/conformance.md`](docs/conformance.md#v02-conformance-matrix).

## What is AITP?

AITP (Agent Identity & Trust Protocol) lets two agents establish mutual
trust without a shared verifier. The protocol is defined normatively by the
RFCs in the
[spec repository](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/README.md);
for how this implementation maps onto it, read
[`docs/architecture.md`](docs/architecture.md). The
[ecosystem map](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/docs/ecosystem.md)
lists the sibling repositories (independent verifier, control plane,
playground, website) and what each one owns.

## Workspace layout

```
aitp-rs/
├── crates/
│   ├── aitp-core/           types, JCS, base64url, AID — pure, no I/O
│   ├── aitp-crypto/         Ed25519 + P-256 keys, compact JWS, JWK thumbprint
│   ├── aitp-envelope/       envelope signing and verification — sync, no I/O
│   ├── aitp-manifest/       Manifest issuance and verification
│   ├── aitp-handshake/      Mutual handshake state machine
│   ├── aitp-tct/            TCT issuance and verification, PoP exchange
│   ├── aitp-delegation/     Delegation tokens (single-hop; multi-hop opt-in)
│   ├── aitp-session-bundle/ Session Trust Bundle (RFC-0010, opt-in)
│   ├── aitp-transport-http/ HTTP client/server (feature-gated, async)
│   ├── aitp/                facade: re-exports + async handshake/renewal helpers
│   ├── aitp-cli/            `aitp` command-line tool (keygen, tct/manifest verify)
│   ├── aitp-conformance/    conformance test runner with adapter trait
│   └── aitp-rs-adapter/     canonical Rust adapter for conformance testing
├── bindings/                language SDKs — excluded from the Cargo workspace
│   ├── aitp-py/             Python SDK (PyO3)
│   ├── aitp-node/           Node.js SDK (NAPI-rs)
│   └── interop/             cross-language interop tests — `make interop`
├── examples/                runnable demos — see examples/README.md
│   ├── two-agents/          handshake demo + OIDC / revocation / renewal / delegation bins
│   └── observability/       tracing / metrics integration example
├── tools/                   fixture- and example-minting binaries
├── adapters/                example conformance adapters in other languages
├── docs/                    implementation guides + design/ decision notes
└── scripts/                 build and release helpers
```

## Status by crate

| Crate                 | Status        | Notes                                                  |
|-----------------------|---------------|--------------------------------------------------------|
| `aitp-core`           | ✅ complete   | AID, JCS, base64url, timestamps, envelope, error codes. |
| `aitp-crypto`         | ✅ complete   | Ed25519 (`verify_strict`) + P-256/ES256 (canonical **low-S**, high-S rejected), compact-JWS profile (`jws.rs`), JWK thumbprint. No RSA code: the RSA-2048 floor lives in `aitp-handshake` (OIDC JWK, `jwk.rs`) and `aitp-transport-http` (DPoP, `dpop.rs`). |
| `aitp-envelope`       | ✅ complete   | `sign_envelope` / `verify_envelope_signature` — sync, no I/O; wrapped by `aitp-transport-http`. |
| `aitp-manifest`       | ✅ complete   | Builder + verifier + HTTP wrapper.                      |
| `aitp-tct`            | ✅ complete   | Builder + verifier + downstream PoP + renewal; strict `TctVerifyContext::builder()` forces explicit revocation / manifest-expiry-cap decisions (`*_dangerous` waivers). |
| `aitp-delegation`     | ✅ complete   | Builder + verifier: single-hop by default, multi-hop chains (RFC-0011) via the runtime opt-in `VerifyDelegationContext::with_max_delegation_hops`. |
| `aitp-handshake`      | ✅ complete   | Initiator + Responder + OIDC + pinned-key (with trust store + grant policy); RSA-2048 floor on OIDC RSA keys. |
| `aitp-session-bundle` | ✅ opt-in | Session Trust Bundle (RFC-0010): builder + verifier; gated behind `experimental-session-bundle`. |
| `aitp-transport-http` | ✅ complete   | Manifest fetcher (cache-correct, oversize-capped), JWKS resolver (RFC-0007 §2.3 branch), handshake server (AITP error envelopes), revocation endpoint. SSRF `HostGuard` on peer fetches, pluggable `ReplayGuard`, optional `metrics` feature. |
| `aitp` (facade)       | ✅ complete   | Re-exports + async `run_initiator_handshake` + `TctStore` (+ `renew_tct` behind `experimental-renewal`); `InitiatorConfig` with `with_http_timeout` / `with_host_guard`. |
| `aitp-cli`            | ✅ complete   | Offline `aitp` binary: `keygen`, `aid`, `tct inspect`/`verify`, `manifest verify`. Stdin-friendly, non-zero exit on failure. See [`crates/aitp-cli/README.md`](crates/aitp-cli/README.md). |
| `aitp-conformance`    | ✅ Tier A     | Subprocess adapter, fixture loader, runner. |
| `aitp-rs-adapter`     | ✅ Tier A–D   | All conformance ops, including `verify_handshake_payload` (`id-*` / `mh-*`), `verify_session_bundle` / `issue_session_bundle`, and the `tct-007` PoP-enforcement ops (`authorize_capability_invocation`, `expect_pop_challenge_issued`, `withhold_pop_response`). Results: [`docs/conformance.md`](docs/conformance.md#v02-conformance-matrix). |

### Language SDKs (`bindings/`)

| SDK         | Path                 | Built with | Tests                                  |
|-------------|----------------------|------------|----------------------------------------|
| `aitp-py`   | `bindings/aitp-py`   | PyO3 / maturin | `pytest` (in-process handshake)     |
| `aitp-node` | `bindings/aitp-node` | NAPI-rs    | `node --test` (in-process handshake)   |

Thin SDKs over the protocol crates: an `AitpAgent` plus initiator/responder
session types whose methods exchange JSON strings (HTTP request/response
bodies), so agent code never touches a Rust type. They are **excluded** from
the Cargo workspace — `cargo test --workspace` does not build them.
`bindings/interop/` cross-checks the two SDKs against each other; see
[Cross-language interop](#cross-language-interop) below.

## RFC compliance matrix

The Status column is the state of **this implementation**. The RFCs' own
status is in the
[RFC index](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/README.md):
RFC-0001 to RFC-0011 are Community Standards Track (Draft), with 0010 and
0011 opt-in; RFC-0012 is Reserved and RFC-0013 is Planned.

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| [0001](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md) | Core wire format | ✅ implemented | JCS canonicalization, envelope, error codes, replay deny list. |
| [0002](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0002-identity.md) | Identity binding | ✅ implemented | Pinned-key v1 (5-field domain-prefixed proof) + OIDC with `cnf.jkt`. Trust store enforced. |
| [0003](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0003-manifest.md) | Manifest | ✅ implemented | Builder + verifier + HTTP server + cache-correct fetcher. |
| [0004](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0004-mutual-handshake.md) | Mutual handshake | ✅ implemented | Four-message exchange + identity-aware grant policy + Manifest-bound TCT expiry + replay protection. |
| [0005](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0005-tct.md) | TCT | ✅ implemented | Issuance, verification, downstream PoP, renewal flow. |
| [0006](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0006-delegation.md) | Single-hop delegation | ✅ implemented | `verify_delegation` runs §4 steps 1–8; the step-9 downstream PoP exchange is run by the caller (`aitp_tct::sign_pop_response` / `verify_pop_response`). Tokens carrying a `chain` claim are rejected unless the caller opts into RFC-0011 (row below). |
| [0007](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0007-key-resolution.md) | Key resolution | ✅ implemented | `KeyResolutionPolicy`: cache, then the pinned issuer store, then the network. The network step is the §2.3 branch: OIDC discovery first; `/.well-known/aitp-keys` only when discovery is not validly exposed (`JwksFetcher::resolve` in `client.rs`). Three fail modes. |
| [0008](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0008-revocation.md) | Revocation | ✅ implemented | Snapshot signing/verification + per-issuer cache + HTTP endpoint + Manifest extension. |
| [0009](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0009-security.md) | Security considerations | ✅ honored | Replay window, timestamp tolerance, HTTPS-only fetches, fail-closed defaults; SSRF `HostGuard` (redirect-block + address classification + DNS-rebind-safe pinning), canonical low-S P-256, RSA-2048 floor. See [`docs/transport-hardening.md`](docs/transport-hardening.md). |
| [0010](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0010-session-trust-bundle.md) | Session Trust Bundle | ✅ Draft, opt-in | Gated behind `experimental-session-bundle`. Builder + verifier in `aitp-session-bundle`; conformance fixtures `bundle-*` exercise issuance + verify when the feature is enabled, SKIP otherwise. |
| [0011](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0011-multihop-delegation.md) | Multi-hop delegation | ✅ Draft, opt-in | Always compiled; gated at runtime. `VerifyDelegationContext::new` sets `max_delegation_hops = 0`, which rejects chains with `DELEGATION_MULTIHOP_NOT_SUPPORTED`. `with_max_delegation_hops(n)` with `n > 0` (typically `DEFAULT_MAX_DELEGATION_HOPS = 3`) enables chain verification; the conformance runner's `--feature experimental-multihop-delegation` flag exercises the `del-mh-*` fixtures. |
| [0012](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0012-extensions.md) | Extensions | ◐ container only | The §1 container is carried: `ExtensionsMap` on JCS payloads, the `ext` claim on JWS artifacts, unknown keys ignored; revocation URL extension wired. No ZK/TEE extension family is implemented. |
| [0013](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0013-tct-renewal-extension.md) | TCT renewal | ✅ opt-in; implementation ahead of spec status (Planned) | Shortened in-band renewal (RFC-0004 §8.1, non-normative) behind the `experimental-renewal` Cargo feature: `renew_tct` facade + holder-PoP renewal exchange. Known gaps: [#196](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/196); see [`docs/tct-renewal.md`](docs/tct-renewal.md). |

## Known limitations (v0.2)

- **Single-hop delegation only by default.** Multi-hop chains (RFC-0011)
  are rejected unless the caller opts in at runtime with
  `VerifyDelegationContext::with_max_delegation_hops(n)`, `n > 0`. See
  [`docs/multihop-delegation.md`](docs/multihop-delegation.md) and, for
  why the default must stay strict,
  [`docs/architecture.md`](docs/architecture.md#why-multi-hop-delegation-is-unreachable-by-default).
- **Session Trust Bundle and renewal are opt-in.** N-party trust
  artifacts (RFC-0010, Draft, opt-in) are gated behind the
  `experimental-session-bundle` Cargo feature, and in-band TCT renewal
  (RFC-0013, Planned) behind `experimental-renewal`, both on the `aitp`
  facade. The language SDKs ship these features **on by default**.
- **Revocation checking is the verifier's obligation.** `verify_tct`
  consults revocation only when a revocation source is configured; the
  SDKs accept a caller-supplied revoked-`jti` set. A revoked but
  unexpired TCT is accepted if no source is wired. The
  strict `TctVerifyContext::builder()` makes the revocation and
  manifest-expiry-cap decisions **explicit** (opting out requires a named
  `*_dangerous` waiver); the permissive `permissive_at()` constructor
  preserves the older accept-if-unwired behavior.
- **JWKS resolution from a current-thread runtime.** The synchronous
  `JwksResolver::resolve` sync→async bridge uses `block_in_place`,
  which requires a multi-thread tokio runtime; on a current-thread
  runtime `resolve` now fails closed with a descriptive error rather
  than panicking. Async callers should use
  `AsyncJwksResolver::resolve_async` (e.g. to pre-warm the resolver
  cache); pure-sync deployments rely on the pinned-issuer store.

## Conformance matrix

`aitp-conformance` runs the spec's fixture suite against
`aitp-rs-adapter`. The results at the pinned spec commit, the strict and
opt-in run modes, and the commands to reproduce them are in
[`docs/conformance.md`](docs/conformance.md#v02-conformance-matrix). That
page is the only place these docs give fixture counts.

The runner's exit-code gate has a known blind spot: it keys on
`required_for_v0_1`, not `required_for_v0_2`, so a required v0.2 fixture
skipped for a missing op does not fail the run
([#194](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/194);
details under
[v0.2 conformance gate](docs/conformance.md#v02-conformance-gate)).

## Install

```bash
cargo add aitp                                   # Rust library (crates.io)
npm install @agentidentitytrustprotocol/aitp     # Node SDK (npm)
pip install aitp-sdk                              # Python SDK (PyPI)
```

The `aitp` crate is the facade re-exporting the protocol surface. The
HTTP **client** ships by default; add the server when you need it
(`cargo add aitp --features http-server`, or `--features all`).
The offline `aitp` CLI ships in-repo and is not yet published to
crates.io — build it with `cargo build -p aitp-cli` (see
[`crates/aitp-cli/README.md`](crates/aitp-cli/README.md)).

## Quick start

Run the two-agent demo (no external dependencies):

```bash
make demo
```

You should see the four-message handshake complete and an `/echo`
capability invocation succeed. See
[`examples/two-agents/README.md`](examples/two-agents/README.md) for the
walkthrough.

## Cross-language interop

```bash
make interop
```

Builds the Python and Node SDKs, then runs a real four-message AITP
handshake *between the two runtimes* — in both directions — proving the
two implementations emit wire-compatible envelopes. The Python side runs
in-process under `pytest`; the Node side runs as a subprocess worker.
See [`bindings/interop/README.md`](bindings/interop/README.md) for the
design.

## Building

```bash
cargo build --workspace --all-targets --all-features
cargo test --workspace --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps --all-features
```

`make test` and `scripts/test.sh` run fmt, clippy and the workspace
tests. `make ci` is the full local gauntlet: version-lockstep check
(`check-versions`), `test`, `doc`, `cargo deny` and `cargo audit`. In the
[`ci.yml`](.github/workflows/ci.yml) workflow only the `test` job runs on
Linux, macOS and Windows (plus an MSRV leg on Linux); `cargo deny`,
`cargo audit` and the other jobs run on Linux only.
See [`docs/testing.md`](docs/testing.md).

## Documentation

[`docs/README.md`](docs/README.md) is the index and the entry point.
Highlights:

- [`docs/architecture.md`](docs/architecture.md) — topology, crate map, and the workspace-split rationale
- [`docs/jcs.md`](docs/jcs.md) — JSON canonicalization strategy and test vectors
- [`docs/conformance.md`](docs/conformance.md) — NDJSON adapter protocol, conformance results and the gate caveat
- [`docs/handshake-transcripts.md`](docs/handshake-transcripts.md) — four-message exchange, byte by byte
- [`docs/session-bundle.md`](docs/session-bundle.md) · [`docs/multihop-delegation.md`](docs/multihop-delegation.md) · [`docs/tct-renewal.md`](docs/tct-renewal.md) — opt-in extensions (RFC-0010/0011 Draft, RFC-0013 Planned)
- [`docs/sdk-python.md`](docs/sdk-python.md) · [`docs/sdk-node.md`](docs/sdk-node.md) — SDK feature guides
- [`docs/transport-hardening.md`](docs/transport-hardening.md) — HTTP-transport hardening register
- [`docs/deployment.md`](docs/deployment.md) · [`docs/key-management.md`](docs/key-management.md) — running in production: where state lives, clustering, and signing-key handling
- [`crates/aitp-cli/README.md`](crates/aitp-cli/README.md) — the offline `aitp` CLI

The protocol itself is defined **normatively** by the
[AITP RFCs](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/tree/main/rfcs);
docs here point to the relevant RFC section rather than restating it.

## Roadmap

The v0.1 bootstrap, the v0.2 compact-JWS migration (portable trust
artifacts re-serialized as compact JWS) and the security-hardening work are
complete. See [`CHANGELOG.md`](CHANGELOG.md) for the history and
[`docs/transport-hardening.md`](docs/transport-hardening.md) for the
transport-layer status register.

The runtime covers the common case: two agents, pinned-key or OIDC
identity, single-hop delegation, the `aitp/0.2` wire. The crates are
pre-1.0, so a breaking API change bumps the minor version. The remaining
work is the opt-in extensions (Session Trust Bundle, multi-hop delegation,
TCT renewal), which follow their RFCs through the spec lifecycle.

## License

Dual-licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option. See [`LICENSE-APACHE`](LICENSE-APACHE) and [`LICENSE-MIT`](LICENSE-MIT).
