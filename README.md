# aitp-rs

Rust reference implementation of the **Agent Identity & Trust Protocol (AITP)**.

> **Status: 0.4.0** — Tracks AITP specification **v0.2** (wire protocol
> `aitp/0.2`; spec RFCs at `0.2.0-draft`). All 45 required v0.2 `core`
> conformance fixtures pass; the 7 `draft` fixtures pass under their
> opt-in features (53 fixtures total, 1 v0.1-frozen SKIP).
> 0.4.0 is a security-hardening + tooling release — SSRF-guarded peer
> fetches, canonical low-S P-256 signatures, an RSA-2048 floor on the
> OIDC/DPoP paths, a strict `TctVerifyContext` builder, an offline
> [`aitp` CLI](crates/aitp-cli/README.md) (in-repo tool, not yet
> published to crates.io), an optional `metrics`
> feature, and operator docs — with the on-the-wire protocol unchanged.
> See [`docs/conformance.md`](docs/conformance.md) for the per-fixture
> breakdown and [`CHANGELOG.md`](CHANGELOG.md) for the full history.

## What is AITP?

AITP is a transport-agnostic, identity-agnostic trust protocol for agent-to-agent
communication. Two agents establish bilateral trust without requiring a shared
verifier, exchanging signed peer-issued **Trust Context Tokens** (TCTs) that name
each peer as the audience and bind capabilities to the holder's key.

The protocol specification lives in the
[`agentidentitytrustprotocol`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol)
repository. This implementation tracks AITP v0.2: portable trust
artifacts (TCT, grant voucher, delegation token) are compact JWS
(RFC 7515) verified over the exact transmitted bytes; protocol-internal
artifacts use JCS (RFC 8785) embedded signatures. Ed25519 and P-256
(ES256) are both supported end-to-end.

## Workspace layout

```
aitp-rs/
├── crates/
│   ├── aitp-core/           types, JCS, base64url, AID — pure, no I/O
│   ├── aitp-crypto/         Ed25519, JWK thumbprint, signature ops
│   ├── aitp-envelope/       envelope signing and verification — sync, no I/O
│   ├── aitp-manifest/       Manifest issuance and verification
│   ├── aitp-handshake/      Mutual handshake state machine
│   ├── aitp-tct/            TCT issuance and verification, PoP exchange
│   ├── aitp-delegation/     Single-hop delegation tokens
│   ├── aitp-session-bundle/ Session Trust Bundle (RFC-0010, opt-in draft)
│   ├── aitp-transport-http/ HTTP client/server (feature-gated, async)
│   ├── aitp/                facade re-exporting the protocol crates
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
| `aitp-crypto`         | ✅ complete   | Ed25519 (`verify_strict`) + P-256/ES256 (canonical **low-S**, high-S rejected), compact-JWS profile, JWK thumbprint, RSA-2048 floor on OIDC/DPoP. |
| `aitp-envelope`       | ✅ complete   | `sign_envelope` / `verify_envelope_signature` — sync, no I/O; wrapped by `aitp-transport-http`. |
| `aitp-manifest`       | ✅ complete   | Builder + verifier + HTTP wrapper.                      |
| `aitp-tct`            | ✅ complete   | Builder + verifier + downstream PoP + renewal; strict `TctVerifyContext::builder()` forces explicit revocation / manifest-expiry-cap decisions (`*_dangerous` waivers). |
| `aitp-delegation`     | ✅ complete   | Builder + verifier: single-hop by default, multi-hop chains (RFC-0011) via `max_hops` opt-in. |
| `aitp-handshake`      | ✅ complete   | Initiator + Responder + OIDC + pinned-key (with trust store + grant policy). |
| `aitp-session-bundle` | ✅ Draft (opt-in) | Session Trust Bundle (RFC-0010): builder + verifier; gated behind `experimental-session-bundle`. |
| `aitp-transport-http` | ✅ complete   | Manifest fetcher (cache-correct, oversize-capped), JWKS resolver (RFC-0007 ordering), handshake server (AITP error envelopes), revocation endpoint. SSRF `HostGuard` on peer fetches, pluggable `ReplayGuard`, optional `metrics` feature. |
| `aitp` (facade)       | ✅ complete   | Re-exports + `run_initiator_handshake` + `renew_tct` + `TctStore`; `InitiatorConfig` with `with_http_timeout` / `with_host_guard`. |
| `aitp-cli`            | ✅ complete   | Offline `aitp` binary: `keygen`, `aid`, `tct inspect`/`verify`, `manifest verify`. Stdin-friendly, non-zero exit on failure. See [`crates/aitp-cli/README.md`](crates/aitp-cli/README.md). |
| `aitp-conformance`    | ✅ Tier A     | Subprocess adapter, fixture loader, runner. |
| `aitp-rs-adapter`     | ✅ Tier A–D   | All conformance ops, including `verify_handshake_payload` (`id-*` / `mh-*`), `verify_session_bundle` / `issue_session_bundle`, and the `tct-007` PoP-enforcement ops (`authorize_capability_invocation`, `expect_pop_challenge_issued`, `withhold_pop_response`). All 45 required v0.2 `core` fixtures pass; the 7 `draft` fixtures pass under their opt-in features. |

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

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| [0001](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md) | Core wire format | ✅ implemented | JCS canonicalization, envelope, error codes, replay deny list. |
| [0002](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0002-identity.md) | Identity binding | ✅ implemented | Pinned-key v1 (5-field domain-prefixed proof) + OIDC with `cnf.jkt`. Trust store enforced. |
| [0003](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0003-manifest.md) | Manifest | ✅ implemented | Builder + verifier + HTTP server + cache-correct fetcher. |
| [0004](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0004-mutual-handshake.md) | Mutual handshake | ✅ implemented | Four-message exchange + identity-aware grant policy + Manifest-bound TCT expiry + replay protection. |
| [0005](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0005-tct.md) | TCT | ✅ implemented | Issuance, verification, downstream PoP, renewal flow. |
| [0006](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0006-delegation.md) | Single-hop delegation | ✅ implemented | 11-check verifier; chain length enforced =1 (multihop reserved for RFC-0011). |
| [0007](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0007-key-resolution.md) | Key resolution | ✅ implemented | `KeyResolutionPolicy` with cache → pinned → aitp-keys → OIDC ordering and three fail modes. |
| [0008](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0008-revocation.md) | Revocation | ✅ implemented | Snapshot signing/verification + per-issuer cache + HTTP endpoint + Manifest extension. |
| [0009](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0009-security.md) | Security considerations | ✅ honored | Replay window, timestamp tolerance, HTTPS-only fetches, fail-closed defaults; SSRF `HostGuard` (redirect-block + address classification + DNS-rebind-safe pinning), canonical low-S P-256, RSA-2048 floor. See [`docs/transport-hardening.md`](docs/transport-hardening.md). |
| [0010](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0010-session-trust-bundle.md) | Session Trust Bundle | ✅ Draft (opt-in) | Gated behind `experimental-session-bundle`. Builder + verifier in `aitp-session-bundle`; conformance fixtures `bundle-*` exercise issuance + verify when the feature is enabled, SKIP otherwise. |
| [0011](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0011-multihop-delegation.md) | Multi-hop delegation | ✅ Draft (opt-in) | Default verifier config (`max_hops=0`) rejects chains with `DELEGATION_MULTIHOP_NOT_SUPPORTED`. Setting `max_hops > 0` (typically `DEFAULT_MAX_HOPS=3`) enables chain verification; the conformance runner's `--feature experimental-multihop-delegation` flag exercises the `del-mh-*` fixtures. |
| [0012](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0012-extensions.md) | Extensions | ✅ implemented | `ExtensionsMap` with namespace conventions; `ext` claim on JWS artifacts; revocation URL extension wired. |
| [0013](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0013-tct-renewal-extension.md) | TCT renewal | ✅ Draft (opt-in) | Shortened in-band renewal (RFC-0004 §8.1) behind the `experimental-renewal` Cargo feature: `renew_tct` facade + holder-PoP renewal exchange. |

## Known limitations (v0.2)

- **Single-hop delegation only by default.** Multi-hop chains (RFC-0011)
  are rejected unless the verifier opts in with `max_hops > 0`. See
  [conformance-matrix](#conformance-matrix) for fixture coverage.
- **Session Trust Bundle and renewal are opt-in.** N-party trust
  artifacts (RFC-0010, Draft) are gated behind the
  `experimental-session-bundle` Cargo feature, and in-band TCT renewal
  (RFC-0013, Draft) behind `experimental-renewal`, both on the `aitp`
  facade. Note the language SDKs (0.4.0+) ship these features **on by
  default**.
- **Revocation checking is the verifier's obligation.** `verify_tct`
  consults revocation only when a revocation source is configured; the
  SDKs accept a caller-supplied revoked-`jti` set. A revoked but
  unexpired TCT is accepted if no source is wired. As of 0.4.0 the
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

The conformance runner reads fixture metadata (`status`, `feature`,
`required_for_v0_2`) to decide which fixtures run in strict v0.2 vs.
opt-in modes. The spec ships 53 fixtures.

| Mode | Command | Result |
|------|---------|--------|
| v0.2 strict (default) | `aitp-conformance run --target <adapter> --fixtures-dir <spec>/schemas/conformance` | 45 PASS / 8 SKIP / 0 FAIL |
| Opt-in (Draft RFCs) | `… --feature experimental-multihop-delegation --feature experimental-session-bundle` | 52 PASS / 1 SKIP / 0 FAIL |

The 8 SKIPs in strict mode are the 7 `draft`-tier fixtures (3 session
bundle + 4 multi-hop delegation, all `required_for_v0_2: false`) plus
`del-004`, which is frozen in the v0.1 wire shape and applies to v0.1
runners only. In opt-in mode the draft fixtures run and `del-004`
remains the single SKIP. See
`crates/aitp-conformance/src/runner/executor.rs:negated_by_feature`.

The runner enforces a **v0.2 conformance gate**: a fixture marked
`required_for_v0_2` that fails — or is SKIPped because the adapter
lacks the op — makes `aitp-conformance run` exit non-zero, so CI
cannot regress required coverage to a silent SKIP. A full per-fixture
breakdown is in [`docs/conformance.md`](docs/conformance.md).

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

`scripts/test.sh` and `make test` both run the local CI gauntlet. CI runs
the same checks plus `cargo deny` and `cargo audit` on Linux + macOS +
Windows.

## Documentation

[`docs/README.md`](docs/README.md) is the index and the entry point.
Highlights:

- [`docs/architecture.md`](docs/architecture.md) — topology, crate map, and the workspace-split rationale
- [`docs/jcs.md`](docs/jcs.md) — JSON canonicalization strategy and test vectors
- [`docs/conformance.md`](docs/conformance.md) — NDJSON adapter protocol + the per-fixture matrix
- [`docs/handshake-transcripts.md`](docs/handshake-transcripts.md) — four-message exchange, byte by byte
- [`docs/session-bundle.md`](docs/session-bundle.md) · [`docs/multihop-delegation.md`](docs/multihop-delegation.md) · [`docs/tct-renewal.md`](docs/tct-renewal.md) — draft, opt-in extensions
- [`docs/sdk-python.md`](docs/sdk-python.md) · [`docs/sdk-node.md`](docs/sdk-node.md) — SDK feature guides
- [`docs/transport-hardening.md`](docs/transport-hardening.md) — HTTP-transport hardening register
- [`docs/deployment.md`](docs/deployment.md) · [`docs/key-management.md`](docs/key-management.md) — running in production: where state lives, clustering, and signing-key handling
- [`crates/aitp-cli/README.md`](crates/aitp-cli/README.md) — the offline `aitp` CLI

The protocol itself is defined **normatively** by the
[AITP RFCs](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/tree/main/rfcs);
docs here point to the relevant RFC section rather than restating it.

## Roadmap

The v0.1 bootstrap and hardening phases, the v0.2 compact-JWS migration
(portable trust artifacts re-serialized as compact JWS), and the 0.4.0
security-hardening + tooling release are complete — see
[`CHANGELOG.md`](CHANGELOG.md) for the history and
[`docs/transport-hardening.md`](docs/transport-hardening.md) for the
transport-layer status register.

The runtime is feature-complete and conformant for the common case (two
agents; pinned-key or OIDC identity; single-hop delegation; the
`aitp/0.2` wire). 0.4.0 closed the security-review action items and
stabilized the crates' public API — any further breaking API change now
targets 0.5.0. The remaining directions are the opt-in Draft RFCs
(Session Trust Bundle, multi-hop delegation, TCT renewal) and their
eventual graduation to Final.

## License

Dual-licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option. See [`LICENSE-APACHE`](LICENSE-APACHE) and [`LICENSE-MIT`](LICENSE-MIT).
