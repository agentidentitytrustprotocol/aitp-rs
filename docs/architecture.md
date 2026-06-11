# Architecture

A reading guide for someone picking up `aitp-rs` for the first time.

`aitp-rs` is the Rust reference implementation of the
[Agent Identity & Trust Protocol](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol)
(AITP). AITP is a JSON-only, A2A (agent-to-agent) trust protocol:
two agents perform a Mutual Handshake, exchange signed Trust
Context Tokens (TCTs), and then invoke each other's capabilities
under those TCTs.

This document covers the topology — what the pieces are and how they
fit — and then the rationale for why the workspace is split the way it
is. For the deeper, topic-specific dives, see the sibling docs:
[`jcs.md`](jcs.md), [`handshake-transcripts.md`](handshake-transcripts.md),
and [`conformance.md`](conformance.md).

## The four signed wire types

Every AITP interaction reduces to producing and verifying one of
four signed JSON objects. Each has its own RFC, JSON Schema, and a
crate.

| Type | RFC | Crate | Purpose |
|---|---|---|---|
| **Manifest** | [RFC-AITP-0003](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0003-manifest.md) | [`aitp-manifest`](../crates/aitp-manifest) | Self-description an agent publishes at `/.well-known/aitp-manifest`: which handshake endpoint to hit, which identity provider it uses, which capabilities it offers/requires |
| **TCT (Trust Context Token)** | [RFC-AITP-0005](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0005-tct.md) | [`aitp-tct`](../crates/aitp-tct) | A signed, audience-bound, capability-scoped grant. Each peer holds the TCT issued to it by its counterpart |
| **Delegation token** | [RFC-AITP-0006](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0006-delegation.md) | [`aitp-delegation`](../crates/aitp-delegation) | Single-hop subdelegation: B holds A's TCT, issues a derived token to C with a subset of grants |
| **Revocation snapshot** | [RFC-AITP-0008](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0008-revocation.md) | [`aitp-tct::revocation`](../crates/aitp-tct/src/revocation.rs) | Periodically-refreshed signed list of revoked TCT JTIs. An empty list is also signed — defends against suppression of fresher snapshots |

All four use [JCS](https://datatracker.ietf.org/doc/html/rfc8785)
canonicalization for the signing input and Ed25519 for the
signature.

## The four-message handshake

Defined in [RFC-AITP-0004](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0004-mutual-handshake.md).
Implemented in [`aitp-handshake`](../crates/aitp-handshake) as two
state machines, `Initiator` and `Responder`:

```
A (Initiator)                                       B (Responder)
  │                                                       │
  │ ── MUTUAL_HELLO        (identity_A, manifest_A) ────► │
  │ ◄─ MUTUAL_HELLO_ACK    (identity_B, manifest_B) ──── │
  │ ── MUTUAL_COMMIT       (TCT_A_for_B)            ────► │
  │ ◄─ MUTUAL_COMMIT_ACK   (TCT_B_for_A)            ──── │
  ▼                                                       ▼
holds TCT_B                                       holds TCT_A
```

After the handshake, capability invocation is just a normal
HTTP/JSON request signed with the holder's key, where the receiver
verifies the request's TCT against the issuer's revocation list
before honoring it.

## Crate map

```
aitp                       facade — re-exports the protocol surface
├── aitp-core              primitives: Aid, JCS, base64url, Timestamp,
│                          ExtensionsMap, AitpEnvelope, ErrorCode
├── aitp-crypto            Ed25519 (verify_strict) + JWK thumbprint
├── aitp-envelope          sign_envelope + verify_envelope_signature —
│                          sync, no I/O; reused by the language bindings
├── aitp-manifest          ManifestBuilder + verify_manifest
├── aitp-tct               TctBuilder + verify_tct + PoP exchange +
│                          revocation snapshots
├── aitp-delegation        DelegationBuilder + verify_delegation
├── aitp-handshake         Initiator/Responder state machines, OIDC
│                          and pinned-key identity proofs
├── aitp-session-bundle    SessionBundleBuilder + verify_session_bundle
│                          (RFC-0010 draft, opt-in feature)
└── aitp-transport-http    ManifestServer + HandshakeServer (axum) +
                           ManifestFetcher + JwksFetcher (reqwest)

aitp-conformance           runner + Adapter trait + SubprocessAdapter
                           + InProcessRustAdapter
aitp-rs-adapter            subprocess conformance adapter, Tier A/B/C/D

bindings/aitp-py           Python SDK (PyO3)     — excluded from the workspace
bindings/aitp-node         Node.js SDK (NAPI-rs) — excluded from the workspace
bindings/interop           cross-language interop tests — `make interop`

examples/two-agents        end-to-end demo — `make demo`
tools/mint-signed-examples       mint signed artifacts from spec KAT seeds
tools/mint-conformance-fixtures  walk spec fixtures, substitute placeholders
```

The dependency direction is strict: `aitp-core` has no AITP
dependencies; every other crate depends on it. Protocol crates
(`manifest`, `tct`, `delegation`, `handshake`) depend on `core` and
`crypto` only. `aitp-transport-http` is the only crate with
async/HTTP/network surface; everything below it is sync.

## Why the workspace is split this way

The split is load-bearing — it exists to serve three audiences with
different needs from one codebase:

1. **TCT-only consumers** (e.g. the MACP runtime) want to verify TCTs and
   nothing else — no HTTP client, no handshake state machine, no OIDC JWT
   library.
2. **Standalone agents** want the full handshake, TCT exchange, manifest
   fetch, and HTTP serving behind a one-line dependency.
3. **The conformance runner** needs an in-process adapter that can call
   into every layer.

A monolithic crate can't serve all three. The boundaries that follow are
the minimum split that does:

- **`aitp-core` has no crypto.** Wire types, JCS, base64url, AID parsing —
  importable by anything that handles AITP data (storage, logging,
  analysis) without inheriting an Ed25519 dependency.
- **`aitp-crypto` has no protocol.** It wraps `ed25519-dalek` with AITP
  key handling and the JWK thumbprint; it does not know what a Manifest or
  TCT is.
- **`aitp-envelope` is the sync envelope codec.** `sign_envelope` /
  `verify_envelope_signature` depend only on `core` + `crypto` — no HTTP,
  no async. It was split out of `aitp-transport-http` precisely so the
  language bindings (and other sync consumers) can sign/verify without a
  transport stack; `aitp-transport-http::common` keeps thin wrappers so
  older `aitp_transport_http::common::*` imports still compile.
- **`aitp-tct` does not depend on `aitp-handshake`.** TCT verification is
  the per-request hot path; reversing this would force every verifier to
  compile the state machine. `aitp-handshake` depends on `tct` +
  `manifest` — it issues TCTs and verifies Manifests, so that direction is
  correct.
- **`aitp-transport-http` is feature-gated and the only async crate.** Its
  `client` feature pulls `reqwest`, `server` pulls `axum`. No protocol
  crate depends on it, so a consumer on a different transport (gRPC,
  MessagePack) can implement just the wire layer and reuse every protocol
  crate.
- **`aitp` (the facade) re-exports the protocol crates** plus a `prelude` —
  this is what most users depend on.
- **`aitp-conformance` and `aitp-rs-adapter` stay separate.** The runner is
  language-agnostic; the adapter is `aitp-rs`-specific. Keeping them apart
  lets future-language adapters live alongside the Rust one.

### Async story

The protocol crates are sync; only `aitp-transport-http` is async (because
`reqwest` / `axum` are). This keeps TCT verification callable from sync
codebases and from non-Rust runtimes via FFI, and leaves room to add async
wrappers in the facade later without changing the protocol crates.

## Workspace conventions

- **Workspace deps only.** Every third-party crate is pinned once in the
  root `[workspace.dependencies]` and referenced via `{ workspace = true }`,
  so the lock holds exactly one version of each — upgrades are one-line.
- **MSRV 1.88**, toolchain pinned to `1.89.0` in `rust-toolchain.toml`.
  MSRV rose from 1.75 once transitive deps (`time`, `icu_*`,
  `idna_adapter`, `clap_lex`) began requiring edition 2024; `cargo msrv
  verify` gates it in CI.
- **Dual MIT OR Apache-2.0** — standard Rust convention (same as `tokio`,
  `serde`, `tower`), friendlier to enterprise adoption than either alone.
- **`#![forbid(unsafe_code)]`** on every workspace crate (the binding
  crates omit it — the PyO3 / NAPI-rs export macros expand to `unsafe`
  glue) and **`#![warn(missing_docs)]`** on public crates.

## What's anchored to the spec, not just self-consistent

A common failure mode for early protocol implementations is
"works against itself, fails against any other implementation."
Four test families pin `aitp-rs` against spec-published reference
values rather than its own output:

- **Keypair derivation** (`crates/aitp-crypto/tests/kat.rs`) —
  seed → pubkey → AID for three pinned keypairs
- **JWK thumbprints** (same file) — RFC 7638 thumbprints for the
  three pinned keypairs
- **JCS + SHA-256** (`crates/aitp-core/tests/kat.rs`) — canonical
  bytes and SHA-256 digest of the four signed AITP artifact types
- **Revocation snapshot** (`crates/aitp-tct/src/revocation.rs::rfc_kat_canonical_bytes_match`)
  — canonical bytes byte-for-byte against `kat-revocation-001`

If any of these break, the implementation has drifted from the
spec — investigate before touching the test.

## How the schemas stay honest

[`tests/schemas/`](../tests/schemas) is a vendored copy of the spec
repo's JSON schemas, pinned to a specific spec commit by the
[`SPEC_VERSION`](../tests/schemas/SPEC_VERSION) file. A CI job
(`spec-schemas` in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml))
re-runs [`scripts/sync-schemas.sh`](../scripts/sync-schemas.sh)
against the pinned commit and fails if the vendored copies have
drifted. Per-crate `tests/schema.rs` files validate fully-populated
wire types against those schemas. Together the firewall catches
the class of drift where Rust types and spec schemas accidentally
diverge.

When the spec moves, the workflow is:

1. Re-run `scripts/sync-schemas.sh` (pulls new schemas and KAT
   vectors into `tests/schemas/`)
2. Schema tests fail with a precise diagnostic about the new field
3. Fix the Rust types
4. Update `SPEC_VERSION`
5. Commit

## Conformance

[`aitp-conformance`](../crates/aitp-conformance) defines the runner and the
`Adapter` trait. Two adapters ship: `SubprocessAdapter` (speaks NDJSON over
stdin/stdout to any binary that implements the protocol — the
[`aitp-rs-adapter`](../crates/aitp-rs-adapter) is the Rust one) and
`InProcessRustAdapter` (calls the crates directly, for fast local dev). The
op vocabulary spans four tiers — verification, issuance, stateful flows,
and test-only.

A cross-language adapter need only implement that NDJSON protocol; the
runner, fixtures, and assertion machinery are shared. The full wire
protocol, the per-tier op table, and the live 44-fixture matrix all live in
[`conformance.md`](conformance.md).

## Language bindings

[`bindings/aitp-py`](../bindings/aitp-py) (PyO3) and
[`bindings/aitp-node`](../bindings/aitp-node) (NAPI-rs) are thin SDKs
over the protocol crates — an `AitpAgent` plus initiator/responder
session types whose methods take and return JSON strings (the HTTP
request/response bodies), so agent code never handles a Rust type.
Both depend on `aitp-envelope` directly; that crate was split out of
`aitp-transport-http` precisely so a binding can sign and verify
envelopes without an HTTP stack.

The bindings are **excluded from the Cargo workspace** — they are
`cdylib`s built by maturin / napi-cli against an external toolchain.
Each SDK has its own in-process handshake tests
([`aitp-py/tests`](../bindings/aitp-py/tests),
[`aitp-node/tests`](../bindings/aitp-node/tests)).
[`bindings/interop`](../bindings/interop) goes further: it runs a real
four-message handshake *between* the two SDKs, in both directions, to
prove they emit wire-compatible envelopes. `make interop` builds both
bindings and runs that suite.

## Where to read further

- [`jcs.md`](jcs.md) — JSON canonicalization strategy, test vectors, the
  surrogate-pair history
- [`conformance.md`](conformance.md) — the full NDJSON adapter protocol
  and the per-fixture matrix
- [`handshake-transcripts.md`](handshake-transcripts.md) — the four-message
  exchange, byte by byte
- [`session-bundle.md`](session-bundle.md),
  [`multihop-delegation.md`](multihop-delegation.md),
  [`tct-renewal.md`](tct-renewal.md) — the draft, opt-in extensions
- [`sdk-python.md`](sdk-python.md) / [`sdk-node.md`](sdk-node.md) and
  [`transport-hardening.md`](transport-hardening.md) — SDK guides and the
  HTTP-transport hardening register
- [`../plans/defered/deferred.md`](../plans/defered/deferred.md) — live
  tracker for open items, deferred work, and spec-side dependencies
- The [AITP RFCs](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/tree/main/rfcs)
  themselves — the protocol is normatively defined there; this
  implementation tracks them

## Where to start reading the code

- New to AITP and want to understand what a handshake produces?
  Read [`crates/aitp-handshake/src/state_machine.rs`](../crates/aitp-handshake/src/state_machine.rs)
- Want to see end-to-end usage in ~250 lines?
  Read [`examples/two-agents/`](../examples/two-agents) or run
  `make demo`
- Writing an adapter in another language? Read
  [`conformance.md`](conformance.md) and look at
  [`crates/aitp-rs-adapter/src/main.rs`](../crates/aitp-rs-adapter/src/main.rs)
  for a working reference
- Curious about a specific signed wire type? Each
  `crates/aitp-<type>/src/types.rs` has rustdoc plus
  `tests/round_trip.rs` showing the full lifecycle
