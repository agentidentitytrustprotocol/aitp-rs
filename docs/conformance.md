# Conformance

The conformance runner exists so that AITP implementations in any language
can be validated against the same fixtures. This page covers two things:
the **adapter protocol and runner architecture** (how any implementation
is driven), and the **v0.2 conformance matrix** (where `aitp-rs` stands
today — jump to [the matrix](#v02-conformance-matrix)).

## Scope

A conformance fixture is a JSON file describing a scenario and expected
outcome. The runner's job is to feed each fixture's input into an
implementation, observe what comes out, and assert it matches the
expected outcome. The spec ships 53 fixtures today (45 v0.2 `core`, 1
frozen in the v0.1 shape for v0.1 runners, and 7 `draft`); the count
grows with the spec.

Many fixtures now carry the **v0.2 compact-JWS token family** (TCT, grant
voucher, delegation token) as opaque strings; the placeholder and
claims-sibling conventions for minting them are described under
[Fixture format](#fixture-format).

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
is acceptable for a conformance harness.

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
    "version": "0.4.0",
    "supported_ops": ["verify_tct", "verify_grant_voucher", "verify_manifest", ...],
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
| `verify_tct` | Verify a TCT compact JWS against a known issuer pubkey (optionally a set of revoked `jti`s). |
| `verify_grant_voucher` | Verify a grant voucher compact JWS under the issuer's own key. |
| `verify_delegation_token` | Verify a delegation token (compact JWS, embedded voucher). |
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
the input. In v0.2 the TCT is an opaque compact JWS, so a fixture cannot
embed a final token statically — instead it carries a **`__JWS_*__`
placeholder** with a **claims-sibling** companion that names the decoded
claims to mint:

```json
{
  "id": "tct-002-expired",
  "preconditions": {
    "set_clock": 1700000000
  },
  "input": {
    "operation": "verify_tct",
    "tct_token": "__JWS_TCT__",
    "tct_claims": { "ver": "aitp/0.2", "jti": "...", "iss": "...", "exp": ... },
    "expected_audience": "aid:pubkey:..."
  },
  "expected": {
    "outcome": "failure",
    "error_code": "TCT_EXPIRED"
  }
}
```

### Compact-JWS placeholders and the claims-sibling convention

The v0.2 token-family fixtures carry the artifact field as a
`__JWS_TCT__` / `__JWS_GRANT_VOUCHER__` / `__JWS_DELEGATION__` placeholder
with an **`X_claims` sibling** (e.g. a `tct_token` field has a `tct_claims`
sibling; a `voucher` field has a `voucher_claims` sibling) in the **same
object**, carrying the decoded payload the runner must mint with the
pinned KAT keypairs. The runner mints each token from its `*_claims`
companion, strips every `*_claims` field, then runs the op. For the
multi-hop `chain` array the rule extends as a **parallel array**: `chain`
holds the `__JWS_DELEGATION__` placeholders and a `chain_claims` sibling
array holds the per-entry claims (each entry may carry its own nested
`voucher`/`voucher_claims`, resolved innermost-first); `chain_hash` uses
`__COMPUTED_CHAIN_HASH__`, recomputed from the minted chain strings.

The runner **pins a reference clock** (`__NOW__` = `1711900000`) so that
re-minted time-sensitive tokens are reproducible. Tampered-signature
variants use dedicated placeholders such as `__JWS_TCT_TAMPERED_SIG__`.

Multi-step fixtures like `mh-001` use `input.sequence` (already in the
spec). The runner detects the variant and dispatches accordingly. Some
fixtures (`tct-006`, `tct-007`) are marked `dynamic` because they drive a
live PoP exchange whose nonces and signatures must be freshly minted per
run; the runner MUST regenerate the listed `dynamic_fields` and never feed
the placeholders through verbatim.

## CLI surface

```
aitp-conformance run --target <CMD> [--filter <PAT>] [--tag <TAG>] \
                     [--output text|json|tap] [--fail-fast]
aitp-conformance list [--tag <TAG>]
aitp-conformance describe <FIXTURE_ID>
```

Text output:

```
Loaded 53 fixtures
Adapter: aitp-rs 0.4.0 (subprocess)
  ✓ id-001-oidc-missing-aud           [12ms]
  ✓ tct-008-alg-none-rejected         [10ms]
  ✓ vch-001                           [11ms]
  ⊘ bundle-001                        [skipped: feature 'experimental-session-bundle' off]
  ✗ tct-002-expired                   [18ms]
      expected outcome=failure error_code=TCT_EXPIRED
      got      outcome=success
Summary: ... passed, ... failed, ... skipped of 53 fixtures
```

(Illustrative — the line shapes, not a real run.)

CI-friendly TAP and machine-readable JSON formats are also provided.

## Why not gRPC for the adapter protocol

We considered using gRPC instead of NDJSON. Reasons we picked NDJSON:

- **Zero codegen.** Adapters in any language need only `json` and
  `stdin`/`stdout`. No `.proto` files.
- **Trivially debuggable.** A human can read and write requests by hand.
- **Aligned with the protocol's JSON-only stance.** AITP itself is
  JSON-only; the conformance runner being JSON-only is consistent.

We may revisit this in a future revision if performance ever becomes a concern.

## Why fixtures live in the spec repo, not here

Conformance fixtures are part of the protocol definition. They belong in
`agentidentitytrustprotocol/schemas/conformance/`. This crate consumes
them via a configured path or git submodule. Other-language
implementations consume the same fixtures.

The runner does not bundle fixtures.

## v0.2 conformance matrix

Per-fixture status of the `aitp-rs` reference implementation against the
spec's conformance suite (`schemas/conformance/`).

### Summary

| Tier | Fixtures | `aitp-rs` |
|---|---|---|
| `core` (required for v0.2) | 45 | **PASS** |
| `core` frozen in the v0.1 shape (`del-004`, v0.1 runners only) | 1 | **SKIP** (not required for v0.2) |
| `draft` — session bundle (`experimental-session-bundle`) | 3 | **PASS** (feature opt-in) |
| `draft` — multi-hop delegation (`experimental-multihop-delegation`) | 4 | **PASS** (feature opt-in) |
| **Total** | **53** | |

Reproduce:

```bash
cargo build -p aitp-rs-adapter --all-features
# v0.2-strict: every required_for_v0_2 core fixture PASS; draft fixtures SKIP;
# del-004 (v0.1-frozen) SKIP.
cargo run -p aitp-conformance --all-features -- run \
  --target ./target/debug/aitp-rs-adapter \
  --fixtures-dir ../agentidentitytrustprotocol/schemas/conformance
# opt-in (Draft RFCs): the 7 draft fixtures additionally run.
cargo run -p aitp-conformance --all-features -- run \
  --target ./target/debug/aitp-rs-adapter \
  --fixtures-dir ../agentidentitytrustprotocol/schemas/conformance \
  --feature experimental-multihop-delegation \
  --feature experimental-session-bundle
```

### v0.2 conformance gate

`aitp-conformance run` exits non-zero if any fixture marked
`required_for_v0_2: true` either fails or is SKIPped because the adapter
lacks the operation. Fixtures frozen in the v0.1 wire shape (`del-004`)
and all `draft` fixtures are `required_for_v0_2: false`, so a v0.2 runner
SKIPs them without failing the gate. This stops CI from silently
regressing required coverage into a SKIP.

### Core fixtures (required for v0.2)

| RFC | Fixtures | Notes |
|---|---|---|
| 0001 / 0007 — envelope & key resolution | `env-001`–`env-005` | Timestamp window, policy violation, key-resolution failure, replay; `env-005` is a P-256 sender (`aid:pubkey:p256:`) with the algorithm-tagged signature wire form. |
| 0003 — manifest | `man-001`–`man-003` | Verification + expiry (cached + at-fetch). |
| 0002 / 0004 — identity & handshake | `id-001`–`id-007`, `mh-001`–`mh-009`, `mh-success-001` | `verify_handshake_payload` op; pinned-key + OIDC identity proofs; four-message exchange (commit carries the TCT **and** grant voucher as compact JWS); replay. |
| 0005 — TCT (compact JWS) | `tct-002`–`tct-007` | Expiry, JWS signature invalid, revocation, manifest-expiry bound, downstream PoP round-trip, and PoP-enforcement. The TCT is an opaque compact JWS; `verify_tct` enforces strict parsing. |
| 0005 §5.4.5 — JWS algorithm/type pinning | `tct-008`, `tct-009`, `tct-010` | `alg: none` and ES256-for-Ed25519-AID rejected with `TOKEN_ALG_MISMATCH` before any signature work; a grant voucher presented as a TCT rejected with `TOKEN_TYP_MISMATCH`. |
| 0005 §8 — grant voucher | `vch-001`, `vch-002` | Valid voucher verifies under the issuer's own key; expired voucher surfaces (in delegation context) as `DELEGATION_EXPIRED`. |
| 0008 — revocation | `rev-001`–`rev-003` | Stale snapshot (`fail_closed` / `soft_fail`), fresh snapshot. |
| 0008 §3.3 — revocation ordering | `rev-004` | An invalid TCT signature is rejected with `TCT_SIGNATURE_INVALID` before any revocation lookup. |
| 0006 — delegation (voucher-based) | `del-001`, `del-003`, `del-005`, `del-006`, `del-007` | Single-hop happy path (scope ⊆ `voucher.grants`); scope-exceeded; third-party voucher (`voucher.iss` ≠ verifier) and wrong-subject voucher (`voucher.sub` ≠ outer `iss`) both `DELEGATION_INVALID_VOUCHER`; `del-007` is the v0.2 structural multi-hop refusal (`DELEGATION_MULTIHOP_NOT_SUPPORTED`). |

`del-004` is **frozen in the v0.1 wire shape** for v0.1 runners only; a
v0.2 runner SKIPs it (`del-007` is its v0.2 claim-shaped sibling).

### Draft fixtures (post-v0.2, opt-in) under feature flags

| RFC | Fixtures | Feature |
|---|---|---|
| 0010 — Session Trust Bundle | `bundle-001`–`bundle-003` | `experimental-session-bundle` |
| 0011 — multi-hop delegation | `del-mh-001`–`del-mh-004` | `experimental-multihop-delegation` |

In v0.2-strict mode these 7 SKIP (`required_for_v0_2: false`). Opting into
the matching feature runs them.

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
- **Structural-rejection fixtures** reject before reaching the crypto
  layer, so their placeholder signatures are never resolved: `del-004` /
  `del-007` (a `chain`-bearing token rejected with
  `DELEGATION_MULTIHOP_NOT_SUPPORTED`), and `tct-008` / `tct-009` (the
  AID-derived `alg` pin fails first). `tct-010` is the exception in spirit
  — it carries a *cryptographically valid* voucher, and the explicit-typing
  check is what rejects it.
- Fixture metadata (`status`, `feature`, `required_for_v0_2`) and the
  vendored schemas track the spec commit pinned in
  `tests/schemas/SPEC_VERSION`; re-run `scripts/sync-schemas.sh` after
  the spec commit advances.
- **P-256 (RFC-AITP-0001 §5.4.3)** now has a dedicated envelope fixture
  (`env-005`) in addition to the local coverage: the `kat-keypair-005-p256`
  vector (`tests/schemas/known-answer/keypairs.json`) exercised by
  `aitp-crypto`'s `p256_keypair_kat_scalar_pubkey_aid_and_signature`;
  `aitp-tct`'s `p256_subject_round_trip_and_pop`; the pure-Rust OIDC
  handshakes `oidc_minter_handshake_p256_initiator` / `_p256_responder`;
  and the cross-language `test_p256_handshake_via_oidc_python_to_node`
  interop test. On the JWS side, a P-256 issuer AID pins `alg: ES256`
  (RFC-AITP-0001 §5.4.5) with raw `R || S` signature encoding.
