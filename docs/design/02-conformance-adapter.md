# 02 — Conformance Adapter Design

The conformance runner exists so that AITP implementations in any language
can be validated against the same fixtures. This document captures the
adapter protocol and runner architecture.

## Scope

A conformance fixture is a JSON file describing a scenario and expected
outcome. The runner's job is to feed each fixture's input into an
implementation, observe what comes out, and assert it matches the
expected outcome. There are roughly 13 fixtures today and the count will
grow.

The architectural question: how does the runner talk to an implementation?

## Decision: subprocess over FFI

Implementations under test are spawned as child processes. They speak
NDJSON over stdin/stdout. The runner is a Rust binary; the adapters can
be written in any language.

Rationale:

- **Language-agnostic.** A Python implementation needs only a 100-line
  Python script that reads stdin, dispatches, writes stdout.
- **Process isolation.** Adapter bugs can't corrupt the runner; a crash
  is observable, not catastrophic.
- **Implementation-private state.** Each adapter holds its own keypairs
  and session state.
- **Trivial debugging.** Pipe a fixture's NDJSON into an adapter and
  watch what comes out.
- **Performance is irrelevant.** Conformance runs are sequential; a
  few-millisecond subprocess cost per fixture doesn't matter.

The cost — slightly slower than FFI, no in-process race-condition tests —
is not a v0.1 concern.

## Wire protocol

NDJSON: one JSON object per line on stdin (request) and stdout (response).

### Lifecycle

1. Runner spawns adapter process.
2. Runner sends `init`. Adapter declares capabilities.
3. Runner sends operations one at a time.
4. Runner sends `shutdown` when done.
5. Adapter exits cleanly.

### Request

```json
{"id": "req-001", "op": "verify_tct", "params": {...}}
```

| Field | Description |
|---|---|
| `id` | Opaque correlation ID, echoed in response. |
| `op` | Operation name from the fixed vocabulary. |
| `params` | Operation-specific input as JSON. |

### Response — success

```json
{"id": "req-001", "ok": true, "result": {...}}
```

### Response — failure

```json
{"id": "req-001", "ok": false, "error_code": "AUDIENCE_MISMATCH", "message": "..."}
```

`error_code` matches the AITP error registry exactly. `message` is
human-readable; the runner ignores it for pass/fail logic.

### Init handshake

```json
// runner sends:
{"id": "init", "op": "init", "params": {"version": "1"}}

// adapter responds:
{
  "id": "init",
  "ok": true,
  "result": {
    "implementation": "aitp-rs",
    "version": "0.1.0-alpha.1",
    "supported_ops": ["verify_tct", "verify_manifest", ...],
    "supported_features": ["pinned_key_identity", "oidc_identity"]
  }
}
```

The runner uses `supported_ops` and `supported_features` to skip fixtures
the adapter cannot handle. A partial implementation declares only what it
supports; fixtures requiring missing operations are reported as `SKIP`,
not `FAIL`.

## Operation vocabulary

Operations are organized by tier. Adapters can support any subset.

### Tier A — pure verification

Stateless operations on fully-formed AITP objects.

| Op | Purpose |
|---|---|
| `verify_envelope` | Verify envelope signature and structure. |
| `verify_manifest` | Verify a Manifest. |
| `verify_tct` | Verify a TCT against a known issuer pubkey. |
| `verify_delegation_token` | Verify a delegation token. |
| `verify_jcs` | Compute JCS canonical form (return hex). |
| `compute_jwk_thumbprint` | Compute thumbprint of a 32-byte pubkey. |

Tier A handles ~60% of fixture types.

### Tier B — issuance

Stateful: adapter needs access to managed keypairs.

| Op | Purpose |
|---|---|
| `generate_keypair` | Generate or import a keypair; return handle. |
| `issue_manifest` | Sign a Manifest with a keypair handle. |
| `issue_tct` | Sign a TCT. |
| `issue_delegation_token` | Sign a delegation token. |
| `sign_envelope` | Sign an envelope. |

Keypairs are referenced by opaque adapter-assigned handles
(e.g. `"kp-1"`). Private keys never leave the adapter.

### Tier C — stateful flows

| Op | Purpose |
|---|---|
| `start_handshake` | Begin a handshake; return session_id and first envelope. |
| `process_handshake_message` | Feed an envelope into a session. |
| `revoke_tct` | Revoke a TCT by JTI. |
| `verify_revocation_snapshot` | Verify a signed revocation snapshot. |

Sessions are referenced by adapter-assigned IDs.

### Tier D — test-only

| Op | Purpose |
|---|---|
| `set_clock` | Override "now" for time-dependent tests. |
| `inject_revocation` | Force a JTI into the deny list. |
| `dump_session` | Dump session state for debugging. |

Adapters that don't support clock override just refuse the op; fixtures
that need it are skipped.

## Adapter trait

Inside the runner, an adapter is represented by `Adapter`. The default
backing implementation is `SubprocessAdapter`. An optional in-process
implementation (`InProcessRustAdapter`) calls the `aitp-rs` crates
directly for fast local development; CI uses the subprocess path so the
protocol itself is exercised.

```rust
pub trait Adapter {
    fn init(&mut self) -> Result<AdapterInfo, AdapterError>;
    fn execute(&mut self, op: &str, params: serde_json::Value)
        -> Result<OpResult, AdapterError>;
    fn shutdown(&mut self) -> Result<(), AdapterError>;
}
```

Three methods, the trait is intentionally simple.

## Subprocess implementation notes

- **Stderr inherits.** Adapter logs go to the runner's stderr. No
  structured log protocol; just print.
- **Synchronous.** One outstanding request at a time.
- **Timeout.** Default 30 seconds per request. Hung adapters are killed.
- **Process supervision.** On shutdown, the runner gives the adapter a
  brief grace period then kills it.

## Fixture format extensions

The current fixture schema needs small additions. The `input` block gains
an `operation` field naming which adapter op to invoke. A new
`preconditions` field lets fixtures set up adapter state before running
the input:

```json
{
  "id": "tct-002-expired",
  "preconditions": {
    "set_clock": 1700000000
  },
  "input": {
    "operation": "verify_tct",
    "tct": { ... },
    "expected_audience": "aid:pubkey:..."
  },
  "expected": {
    "outcome": "failure",
    "error_code": "TCT_EXPIRED"
  }
}
```

Multi-step fixtures like `mh-001` use `input.sequence` (already in the
spec). The runner detects the variant and dispatches accordingly.

## CLI surface

```
aitp-conformance run --target <CMD> [--filter <PAT>] [--tag <TAG>] \
                     [--output text|json|tap] [--fail-fast]
aitp-conformance list [--tag <TAG>]
aitp-conformance describe <FIXTURE_ID>
```

Text output:

```
Loaded 13 fixtures
Adapter: aitp-rs 0.1.0-alpha.1 (subprocess)
  ✓ id-001-oidc-missing-aud           [12ms]
  ✓ id-002-oidc-wrong-aud             [11ms]
  ⊘ mh-009-tee-required               [skipped: feature 'tee' not supported]
  ✗ tct-002-expired                   [18ms]
      expected outcome=failure error_code=TCT_EXPIRED
      got      outcome=success
Summary: 11 passed, 1 failed, 1 skipped of 13 fixtures
```

CI-friendly TAP and machine-readable JSON formats are also provided.

## Why not gRPC for the adapter protocol

We considered using gRPC instead of NDJSON. Reasons we picked NDJSON:

- **Zero codegen.** Adapters in any language need only `json` and
  `stdin`/`stdout`. No `.proto` files.
- **Trivially debuggable.** A human can read and write requests by hand.
- **Aligned with the protocol's JSON-only stance.** AITP itself is
  JSON-only; the conformance runner being JSON-only is consistent.

We may revisit this in v0.2 if performance ever becomes a concern.

## Why fixtures live in the spec repo, not here

Conformance fixtures are part of the protocol definition. They belong in
`agentidentitytrustprotocol/schemas/conformance/`. This crate consumes
them via a configured path or git submodule. Other-language
implementations consume the same fixtures.

The runner does not bundle fixtures.
