# aitp-rs

Rust reference implementation of the **Agent Identity & Trust Protocol (AITP)**.

> **Status: v0.1.0-beta.1 (unreleased).** All ten protocol crates plus
> the high-level `aitp` facade, HTTP transport, and conformance runner
> are implemented and tested. The two-agent demo runs end-to-end with a
> real four-message handshake. P0–P3 of the unified hardening plan are
> complete: pinned-key proof format, key-resolution policy, manifest
> cache correctness, revocation end-to-end, HTTP transport hardening,
> TCT renewal, and high-level facade. See
> [`docs/design/PENDING.md`](docs/design/PENDING.md) for what's still
> open and `CHANGELOG.md` / `RELEASE_NOTES_v0.1.0-beta.1.md` for what
> landed.

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
| `aitp-tct`            | ✅ complete   | Builder + verifier + downstream PoP + renewal.          |
| `aitp-delegation`     | ✅ complete   | Builder + 11-check verifier (single-hop).               |
| `aitp-handshake`      | ✅ complete   | Initiator + Responder + OIDC + pinned-key (with trust store + grant policy). |
| `aitp-transport-http` | ✅ complete   | Manifest fetcher (cache-correct, oversize-capped), JWKS resolver (RFC-0007 ordering), handshake server (AITP error envelopes), revocation endpoint. |
| `aitp` (facade)       | ✅ complete   | Re-exports + `run_initiator_handshake` + `renew_tct` + `TctStore`. |
| `aitp-conformance`    | ✅ Tier A     | Subprocess adapter, fixture loader, runner. |
| `aitp-rs-adapter`     | ✅ Tier A–C   | `verify_envelope` (with tolerance), `verify_manifest`, `verify_tct` (with revocation list), `verify_delegation_token`, `verify_revocation_snapshot` (with policy), `set_clock`, `inject_revocation`. 12/15 spec fixtures pass; 3 (`env-002`, `env-003`, `mh-001`) use scenario shapes the adapter wire format does not yet express. 16 (`id-*`, `mh-*`) skip until `verify_handshake_payload` is implemented. The same RFC behaviors are covered by in-process integration tests. |

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
| [0009](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0009-security.md) | Security considerations | ✅ honored | Replay window, timestamp tolerance, HTTPS-only fetches, fail-closed defaults. |
| [0010](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0010-session-trust-bundle.md) | Session Trust Bundle | ⏸ reserved | Deferred until v0.1 has soaked. |
| [0011](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0011-multihop-delegation.md) | Multi-hop delegation | ⏸ reserved | Single-hop only in v0.1; chain length >1 rejected with `MULTIHOP_NOT_SUPPORTED`. |
| [0012](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0012-extensions.md) | Extensions | ✅ implemented | `ExtensionsMap` with namespace conventions; revocation URL extension wired. |

## Known limitations (v0.1)

- **Single-hop delegation only.** Multi-hop chains (RFC-0011) are
  rejected. Implementing them requires resolving mid-chain revocation
  semantics; tracked for post-beta.
- **No Session Trust Bundle.** N-party trust artifacts (RFC-0010) are
  reserved; bilateral handshakes only.
- **`verify_handshake_payload` adapter op** not implemented in
  `aitp-rs-adapter`, so the spec's `id-*` / `mh-*` (single-step)
  fixtures SKIP through the conformance runner. The underlying
  verification logic is in `crates/aitp-handshake/src/identity_*.rs`
  and exhaustively unit-tested.
- **Three scenario-shaped spec fixtures fail through the conformance
  runner** — `env-002` (POLICY_VIOLATION over an envelope+TCT pair),
  `env-003` (KEY_RESOLUTION_FAILED across multiple discovery sources),
  and `mh-001` (sequence-form replay). The corresponding RFC behaviors
  are covered in-process by `crates/aitp-transport-http/tests/` and
  `crates/aitp-transport-http/src/key_resolution.rs::tests`.
- **No multi-runtime support in the JWKS resolver.** The
  `KeyResolutionPolicy` sync→async bridge requires a multi-thread tokio
  runtime in the calling thread context; pure sync deployments must
  rely on the pinned-issuer store.

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

## Roadmap

The original five-sprint bootstrap (alpha.1 through alpha.4) is
complete. Subsequent work followed the unified hardening plan in
[`plans/aitp-rs-unified-claude-code-plan.md`](plans/aitp-rs-unified-claude-code-plan.md):

- **alpha.5** — Phases 1–9: pinned-key proof v1, identity type
  enforcement, `PinnedKeyStore`, grant policy hook, replay deny list,
  JwksFetcher hardening.
- **beta.1** *(this release)* — Phases 10–16: key resolution policy,
  manifest cache correctness, revocation end-to-end, HTTP transport
  hardening, conformance fixture expansion, TCT renewal + facade.
- **post-beta** — RFC-0010 (Session Trust Bundle) and RFC-0011
  (Multi-hop Delegation) once v0.1 soaks. Both have design
  prerequisites in the unified plan.

## License

Dual-licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option. See [`LICENSE-APACHE`](LICENSE-APACHE) and [`LICENSE-MIT`](LICENSE-MIT).
