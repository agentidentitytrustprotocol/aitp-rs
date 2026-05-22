# Architecture

A reading guide for someone picking up `aitp-rs` for the first time.

`aitp-rs` is the Rust reference implementation of the
[Agent Identity & Trust Protocol](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol)
(AITP). AITP is a JSON-only, A2A (agent-to-agent) trust protocol:
two agents perform a Mutual Handshake, exchange signed Trust
Context Tokens (TCTs), and then invoke each other's capabilities
under those TCTs.

This document is the topology — what the pieces are and how they
fit. For the *why* behind specific design decisions, read
[`design/00-architecture.md`](design/00-architecture.md) and the
sibling design notes.

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

## What's anchored to the spec, not just self-consistent

A common failure mode for early protocol implementations is
"works against itself, fails against any other implementation."
Three test families pin `aitp-rs` against spec-published reference
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

[`aitp-conformance`](../crates/aitp-conformance) defines the runner
and the `Adapter` trait. Two adapters today:

- `SubprocessAdapter` — speaks NDJSON over stdin/stdout to any
  binary that implements the protocol. The
  [`aitp-rs-adapter`](../crates/aitp-rs-adapter) binary is the
  Rust implementation
- `InProcessRustAdapter` — calls into the `aitp-*` crates directly
  for fast local development. Tier A only

The conformance op vocabulary covers four tiers:

- **Tier A** (verification): `verify_envelope`, `verify_manifest`,
  `verify_tct`, `verify_delegation_token`,
  `verify_revocation_snapshot`, `verify_jcs`,
  `compute_jwk_thumbprint`
- **Tier B** (issuance): `generate_keypair`, `issue_manifest`,
  `issue_tct`, `issue_delegation_token`, `sign_envelope`
- **Tier C** (stateful flows): `start_handshake` (initiator and
  responder roles), `process_handshake_message`, `revoke_tct`
- **Tier D** (test-only): `set_clock`, `inject_revocation`,
  `dump_session`

Cross-language adapters in any language need only implement the
NDJSON protocol from
[`design/02-conformance-adapter.md`](design/02-conformance-adapter.md);
the runner, fixtures, and assertion machinery are shared.

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

- [`design/00-architecture.md`](design/00-architecture.md) —
  workspace structure rationale (sync core, async at HTTP edges,
  why `aitp-jcs` doesn't exist as its own crate, etc.)
- [`design/01-jcs.md`](design/01-jcs.md) — JSON canonicalization
  strategy, test vectors, the surrogate-pair history
- [`design/02-conformance-adapter.md`](design/02-conformance-adapter.md)
  — full NDJSON protocol the subprocess adapter speaks
- [`design/03-handshake-transcripts.md`](design/03-handshake-transcripts.md)
  — handshake transcript format
- [`design/PENDING.md`](design/PENDING.md) — live tracker for
  open items, deferred work, spec-side dependencies
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
  [`design/02-conformance-adapter.md`](design/02-conformance-adapter.md)
  and look at [`crates/aitp-rs-adapter/src/main.rs`](../crates/aitp-rs-adapter/src/main.rs)
  for a working reference
- Curious about a specific signed wire type? Each
  `crates/aitp-<type>/src/types.rs` has rustdoc plus
  `tests/round_trip.rs` showing the full lifecycle
