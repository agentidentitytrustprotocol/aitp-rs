# Conformance

The conformance runner exists so that AITP implementations in any language
can be validated against the same fixtures. This page covers two things:
the **adapter protocol and runner architecture** (how any implementation
is driven), and the **v0.1 conformance matrix** (where `aitp-rs` stands
today — jump to [the matrix](#v01-conformance-matrix)).

## Scope

A conformance fixture is a JSON file describing a scenario and expected
outcome. The runner's job is to feed each fixture's input into an
implementation, observe what comes out, and assert it matches the
expected outcome. The spec ships 44 fixtures today (37 `core` +
7 `draft`); the count grows with the spec.

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

Operations are organized by tier. Adapters can support any subset. The
**authoritative live list** is whatever an adapter returns in its `init`
response (`supported_ops`); the tables below are the taxonomy, kept in
sync with `crates/aitp-rs-adapter/src/`. Draft ops (session bundle,
multi-hop) are only exercised under their opt-in features.

### Tier A — pure verification

Stateless operations on fully-formed AITP objects.

| Op | Purpose |
|---|---|
| `verify_envelope` | Verify envelope signature and structure. |
| `verify_manifest` | Verify a Manifest. |
| `verify_tct` | Verify a TCT against a known issuer pubkey. |
| `verify_delegation_token` | Verify a delegation token. |
| `verify_revocation_snapshot` | Verify a signed revocation snapshot. |
| `verify_handshake_payload` | Verify a single handshake message payload (`id-*` / `mh-*` fixtures). |
| `verify_jcs` | Compute JCS canonical form (return hex). |
| `compute_jwk_thumbprint` | Compute thumbprint of a pubkey. |
| `verify_session_bundle` | Verify a Session Trust Bundle (draft, `experimental-session-bundle`). |

Tier A handles the majority of fixture types.

### Tier B — issuance

Stateful: adapter needs access to managed keypairs.

| Op | Purpose |
|---|---|
| `generate_keypair` | Generate or import a keypair; return handle. |
| `issue_manifest` | Sign a Manifest with a keypair handle. |
| `issue_tct` | Sign a TCT. |
| `issue_delegation_token` | Sign a delegation token. |
| `sign_envelope` | Sign an envelope. |
| `issue_pop_challenge` | Mint a PoP challenge for a grant marked PoP-required. |
| `issue_session_bundle` | Build a Session Trust Bundle (draft, `experimental-session-bundle`). |

Keypairs are referenced by opaque adapter-assigned handles
(e.g. `"kp-1"`). Private keys never leave the adapter.

### Tier C — stateful flows

| Op | Purpose |
|---|---|
| `start_handshake` | Begin a handshake; return session_id and first envelope. |
| `process_handshake_message` | Feed an envelope into a session. |
| `revoke_tct` | Revoke a TCT by JTI. |
| `authorize_capability_invocation` | Authorize a capability call, enforcing PoP when the grant requires it (`tct-007`). |
| `produce_pop_response` / `verify_pop_response` | Answer / check a downstream PoP challenge. |
| `expect_pop_challenge_issued` / `withhold_pop_response` | Assertion helpers for the `tct-007` PoP-enforcement sequence. |

Sessions are referenced by adapter-assigned IDs.

### Tier D — test-only

| Op | Purpose |
|---|---|
| `set_clock` | Override "now" for time-dependent tests. |
| `inject_revocation` | Force a JTI into the deny list. |
| `set_features` | Toggle opt-in draft features for the run. |
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

## Fixture format

The fixture schema carries a few adapter-runner conventions. The `input`
block has an `operation` field naming which adapter op to invoke, and a
`preconditions` field lets a fixture set up adapter state before running
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
Loaded 44 fixtures
Adapter: aitp-rs 0.1.0 (subprocess)
  ✓ id-001-oidc-missing-aud           [12ms]
  ✓ id-002-oidc-wrong-aud             [11ms]
  ⊘ bundle-001                        [skipped: feature 'experimental-session-bundle' off]
  ✗ tct-002-expired                   [18ms]
      expected outcome=failure error_code=TCT_EXPIRED
      got      outcome=success
Summary: ... passed, ... failed, ... skipped of 44 fixtures
```

(Illustrative — the line shapes, not a real run; `aitp-rs` passes all 44.)

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

## v0.1 conformance matrix

Per-fixture status of the `aitp-rs` reference implementation against the
spec's conformance suite (`schemas/conformance/`).

### Summary

| Tier | Fixtures | `aitp-rs` |
|---|---|---|
| `core` (required for v0.1) | 37 | **37 PASS** |
| `draft` — session bundle (`experimental-session-bundle`) | 3 | **3 PASS** (feature opt-in) |
| `draft` — multi-hop delegation (`experimental-multihop-delegation`) | 4 | **4 PASS** (feature opt-in) |
| **Total** | **44** | **44 PASS, 0 FAIL** |

Reproduce:

```bash
cargo build -p aitp-rs-adapter --all-features
# v0.1-strict: 37 PASS / 7 SKIP (draft fixtures) / 0 FAIL
cargo run -p aitp-conformance --all-features -- run \
  --target ./target/debug/aitp-rs-adapter \
  --fixtures-dir ../agentidentitytrustprotocol/schemas/conformance
# opt-in (Draft RFCs): 43 PASS / 1 SKIP (del-004, negated) / 0 FAIL
cargo run -p aitp-conformance --all-features -- run \
  --target ./target/debug/aitp-rs-adapter \
  --fixtures-dir ../agentidentitytrustprotocol/schemas/conformance \
  --feature experimental-multihop-delegation \
  --feature experimental-session-bundle
```

### v0.1 conformance gate

`aitp-conformance run` exits non-zero if any fixture marked
`required_for_v0_1: true` either fails or is SKIPped because the adapter
lacks the operation. A skip whose v0.1 assertion was negated by an
opted-in experimental feature (e.g. `del-004` under
`experimental-multihop-delegation`) is exempt. This stops CI from
silently regressing required coverage into a SKIP.

### Core fixtures (required for v0.1) — 37/37 PASS

| RFC | Fixtures | Notes |
|---|---|---|
| 0001 / 0007 — envelope & key resolution | `env-001`–`env-004` | Signature, replay, timestamp, key-resolution discovery order. |
| 0003 — manifest | `man-001`–`man-003` | Issuance + verification + expiry. |
| 0002 / 0004 — identity & handshake | `id-001`–`id-007`, `mh-001`–`mh-009`, `mh-success-001` | `verify_handshake_payload` op; pinned-key + OIDC identity proofs; four-message exchange; replay. |
| 0005 — TCT | `tct-002`–`tct-006` | Issuance, audience/expiry checks, revocation, downstream PoP round-trip. |
| 0005 §6.2 — PoP enforcement | `tct-007` | A grant the issuer marked PoP-required cannot be invoked without a valid `pop_response`. Exercised via the `authorize_capability_invocation` → `expect_pop_challenge_issued` → `withhold_pop_response` sequence. |
| 0008 — revocation | `rev-001`–`rev-003` | Stale snapshot (`fail_closed` / `soft_fail`), fresh snapshot. |
| 0008 §3.3 — revocation ordering | `rev-004` | An invalid TCT signature is rejected with `TCT_SIGNATURE_INVALID` before any revocation lookup. `verify_tct` verifies the signature ahead of the revocation hook. |
| 0006 — delegation | `del-001`, `del-003`, `del-004` | Single-hop verify; `del-004` pins the v0.1 multi-hop refusal (`DELEGATION_MULTIHOP_NOT_SUPPORTED`). |

### Draft fixtures (post-v0.1, opt-in) — 7/7 PASS under feature flags

| RFC | Fixtures | Feature |
|---|---|---|
| 0010 — Session Trust Bundle | `bundle-001`–`bundle-003` | `experimental-session-bundle` |
| 0011 — multi-hop delegation | `del-mh-001`–`del-mh-004` | `experimental-multihop-delegation` |

In v0.1-strict mode these 7 SKIP (`required_for_v0_1: false`). Opting
into the matching feature runs them; `del-004` then auto-skips because
its v0.1-strict assertion no longer applies.

### Notes

- Side-effect assertions (`side_effects` block on a fixture's
  `expected`, e.g. `rev-004`'s `revocation_lookup_called` and
  `tct-007`'s `pop_challenge_issued` / `capability_authorized`) are
  honored by the runner: any side effect the adapter reports in its
  result's `side_effects` object is asserted against the fixture, and a
  *reported* mismatch is a hard failure. Side effects the adapter does
  not instrument are skipped (treated as un-instrumented, never a
  silent pass). `tct-007` step 2's `pop_challenge_issued` is asserted
  this way; its step 3 outcome (`POP_RESPONSE_INVALID`) independently
  catches a PoP-skipping adapter.
- Fixture metadata (`status`, `feature`, `required_for_v0_1`) and the
  vendored schemas track the spec commit pinned in
  `tests/schemas/SPEC_VERSION`; re-run `scripts/sync-schemas.sh` after
  the spec commit advances.
- **P-256 (RFC-AITP-0001 §5.4.3) has no dedicated *conformance fixture*
  yet** — the `env-001`–`env-004` envelope fixtures are Ed25519. P-256 is
  instead covered locally by: the `kat-keypair-005-p256` vector
  (`tests/schemas/known-answer/keypairs.json`) exercised by
  `aitp-crypto`'s `p256_keypair_kat_scalar_pubkey_aid_and_signature`
  (scalar → pubkey → AID + tagged sign/verify); `aitp-tct`'s
  `p256_subject_round_trip_and_pop`; the pure-Rust OIDC handshakes
  `oidc_minter_handshake_p256_initiator` / `_p256_responder`
  (`aitp-handshake`); and the cross-language
  `test_p256_handshake_via_oidc_python_to_node` interop test.
  - **Adapter readiness:** `aitp-rs-adapter`'s `p256_readiness_tests`
    drive a P-256-signed envelope through the very `verify_envelope` op
    the `env-*` fixtures use (accept + tamper-reject), so this adapter
    will pass a P-256 envelope fixture the moment the spec defines one.
  - A future spec-repo `env-005` P-256 envelope fixture would fold this
    into the conformance gate; until then the drift check rides on
    `keypairs.json` and the adapter-readiness tests above.
