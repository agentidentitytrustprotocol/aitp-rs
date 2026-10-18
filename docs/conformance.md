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
expected outcome. The corpus grows with the spec; the fixture counts at
the spec commit this repo pins are in the
[matrix summary](#v02-conformance-matrix).

Many fixtures now carry the **v0.2 compact-JWS token family** (TCT, grant
voucher, delegation token) as opaque strings; the placeholder and
claims-sibling conventions for minting them are linked under
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

A refusal made below the protocol layer carries no AITP code. It
reports the HTTP status the transport would answer with instead of an
`error_code`. The presentation rate limit of RFC-AITP-0002 §3.4 is one
(RFC-AITP-0009 §3.1, `id-022`):

```json
{"id": "req-002", "ok": false, "http_status": 429, "message": "..."}
```

A fixture that expects this sets `expected.http_status`. It must then
also expect no `error_code`, and the runner fails the step if the
adapter returns one.

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
    "version": "<the adapter crate's version>",
    "supported_ops": ["verify_tct", "verify_grant_voucher", "verify_manifest", ...],
    "supported_features": ["pinned_key_identity", "oidc_identity"]
  }
}
```

`aitp-rs-adapter` reports its own crate version
(`env!("CARGO_PKG_VERSION")` in `crates/aitp-rs-adapter/src/lib.rs`), so
the value tracks the workspace release.

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
| `verify_attestation` | Verify a self-attestation outside a grant context (RFC-AITP-0005 §5.3, extension `aitp-self-attestation`). The issuer must be in the step's `trust_store`. |

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
| `issue_presentation_challenge` | Issue a one-way admission challenge to the step's `source` (RFC-AITP-0002 §3.4, extension `aitp-pinned-admission`). The runner captures `result.pop_nonce` as `__ISSUED_NONCE_<n>__`, numbered from 1 within the sequence. |
| `verify_identity_presentation` | Admit one `identity_presentation` envelope in the §3.4 check order: `message_id` deny list, presentation rate limit, timestamp, structure, nonce, key, signature, proof, nonce consume. |

The admission verifier lives for one fixture, so a nonce consumed in one
sequence step stays consumed in the next. It is built from the first
step's `self_aid`, `trust_store`, `max_outstanding_nonces`,
`presentation_rate_limit` and `outstanding_challenges`.

Sessions are referenced by adapter-assigned IDs.

### Tier D — test-only

| Op | Purpose |
|---|---|
| `set_clock` | Override "now" for time-dependent tests. |
| `inject_revocation` | Force a JTI into the deny list. |
| `set_features` | Toggle opt-in draft features for the run. |
| `dump_session` | Dump session state for debugging. |
| `begin_fixture` | Drop per-fixture adapter state. The runner sends it before each fixture and ignores an error, so adapters without the op still run. This is how the runner meets the spec's rule that each fixture runs against fresh verifier state (fixture README, "Multi-step sequence form"). |

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

The fixture format belongs to the spec, not to this repo. Read it there:

- [Fixture Format](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/conformance/README.md#fixture-format):
  the metadata fields (`status`, `feature`, `required_for_v0_2`), the
  multi-step `sequence` form, side-effect assertions, dynamic fixtures and
  structural-rejection fixtures.
- [Compact-JWS token placeholders](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/conformance/PLACEHOLDERS.md#compact-jws-token-placeholders-v02-portable-trust-artifacts):
  the `__JWS_*__` placeholders and their claims-sibling companions.
- [Reference clock for byte-stable minting](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/conformance/PLACEHOLDERS.md#reference-clock-for-byte-stable-minting):
  the pinned `__NOW__` value.

How `aitp-conformance` implements those rules:

- `crates/aitp-conformance/src/fixture/placeholder.rs` does the
  substitution. For every field `X` that holds a `__JWS_*__` placeholder
  and has an `X_claims` sibling in the same object, it mints `X` from
  those claims with the pinned KAT keypairs. Examples are
  `tct_token` / `tct_token_claims` (`tct-002`) and `voucher` /
  `voucher_claims`. It then strips every `*_claims` companion before the
  op runs. The reference clock is the constant `REFERENCE_NOW` in that
  file.
- `crates/aitp-conformance/src/fixture/types.rs` deserializes the
  fixture. Its `required_for_v0_2` field (or `required_for_v0_1` under
  `--profile v0.1`) drives the exit-code gate; see
  [v0.2 conformance gate](#v02-conformance-gate).

## CLI surface

```
aitp-conformance run --target <CMD> [--fixtures-dir <DIR>] [--filter <PAT>] \
                     [--tag <TAG>] [--feature <NAME>]... \
                     [--output text|json|tap] [--fail-fast] \
                     [--profile v0.2|v0.1]
aitp-conformance list [--fixtures-dir <DIR>] [--tag <TAG>]
aitp-conformance describe [--fixtures-dir <DIR>] <FIXTURE_ID>
```

`--fixtures-dir` defaults to `./schemas/conformance`. `--feature` can be
repeated. Each one opts into a draft feature (for example
`experimental-session-bundle`), so fixtures tagged with it run instead of
being skipped. `--profile` picks the protocol version the exit-code gate
checks (default `v0.2`; see [v0.2 conformance gate](#v02-conformance-gate)).
The flags are defined in `crates/aitp-conformance/src/main.rs`.

Text output has this shape (from `crates/aitp-conformance/src/runner/output.rs`):

```
Loaded <N> fixtures
Adapter: aitp-rs <adapter version>
  PASS env-001 [3ms]
  SKIP bundle-001 (non-core fixture (status=Draft); requires feature `experimental-session-bundle`)
  FAIL tct-002 [4ms]
        reason: <expected vs. actual>
Summary: <p> passed, <f> failed, <s> skipped of <N> fixtures
```

`--output tap` prints TAP 13. `--output json` prints a JSON array with one
object per fixture.

## Why not gRPC for the adapter protocol

We considered using gRPC instead of NDJSON. Reasons we picked NDJSON:

- **Zero codegen.** Adapters in any language need only `json` and
  `stdin`/`stdout`. No `.proto` files.
- **Trivially debuggable.** A human can read and write requests by hand.
- **Aligned with the protocol's JSON-only stance.** AITP itself is
  JSON-only; the conformance runner being JSON-only is consistent.

We may revisit this in a future revision if performance ever becomes a concern.

### Unminted placeholders

A placeholder the harness does not know is replaced with a
`RUNNER_UNKNOWN_PLACEHOLDER_*` sentinel. A negative fixture could then
pass for the wrong reason: the adapter rejects garbage, not the defect the
fixture names. Before 652cdb9 was vendored, `id-006` passed this way on
`__PINNED_PROOF_OVER_WRONG_NONCE__`. The runner therefore **FAILs** a
fixture that used a placeholder it could not mint, whatever the adapter
answered, and names the placeholders in the reason (spec
[#77](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/issues/77)).
A fixture skipped before it ran stays a SKIP. At the pin, no fixture uses
an unminted placeholder. Each negative is a real, correctly formed
artifact that differs from its valid form in exactly one property. Unit
tests in `placeholder.rs` check this, and
`unminted_placeholder_fails_the_fixture` in
`tests/runner_integration.rs` checks the FAIL.

## What the fixture corpus cannot detect

The fixtures are not signed artifacts. Signature fields carry placeholders
(`__VALID_A_SIG__`, `__SIG_PENDING__`) that
`crates/aitp-conformance/src/fixture/placeholder.rs` materializes with the
harness's own KAT keys immediately before the fixture is handed to the
adapter. That is what makes one corpus reusable across implementations and
keeps the fixtures readable — but it has a consequence worth stating
plainly:

> **A conformance pass proves an implementation is self-consistent. It does
> not prove two implementations interoperate.**

Because the harness both mints and checks, each implementation is measured
against its *own* signing convention. If two implementations disagree about
what bytes a signature covers, both still pass — every fixture, every run.

That is not hypothetical. Before spec commit `5f8e588`, `aitp-rs` signed the
transport-wrapped `{"revocation_list": …}` form and `aitp-verifier-py` signed
the inner body. Both reported **51 passed, 0 failed**. A revocation snapshot
minted by either would have failed verification against the other on first
contact — surfacing, under `fail_closed`, as a spurious `TCT_REVOKED`.

Two things close that gap, and conformance is neither:

1. **Committed signed examples**, verified byte-for-byte with no
   re-minting — `known-answer/signed-examples/`. These are real signatures
   over real bytes, produced once by a reference implementation.
2. **Cross-implementation acceptance** — artifacts minted by one stack and
   verified by another that shares no code with it. Note the
   `interop (python ↔ node)` job does *not* qualify: both bindings wrap the
   same Rust core, so it is Rust-to-Rust across runtimes and is blind to a
   wire divergence for the same reason re-minting is. In this repo the
   `xcheck` job in `.github/workflows/ci.yml` does qualify. `aitp-rs` mints
   with `cargo run -p mint-signed-examples --bin xcheck-mint`, and
   [`aitp-verifier-py`](https://github.com/agentidentitytrustprotocol/aitp-verifier-py),
   pinned by `tests/AITP_VERIFIER_PY_VERSION` (kept current by the weekly
   `bump-verifier-py` workflow, which opens a bump PR when the verifier's
   `main` moves), verifies those exact bytes
   through `scripts/xcheck-verify.py`. The reverse direction is covered by
   the committed bytes in `tests/xcheck-fixtures/`. See
   [testing.md](testing.md#cross-implementation-acceptance-xcheck).

When a conformance number and an interop failure disagree, the interop
failure is the one telling the truth.

## Why fixtures live in the spec repo, not here

Conformance fixtures are part of the protocol definition. They belong in
`agentidentitytrustprotocol/schemas/conformance/`. The runner reads them
from the directory passed in `--fixtures-dir`. There is no git submodule.
The `conformance` job in `.github/workflows/ci.yml` checks out the spec
repo at the commit pinned in `tests/schemas/SPEC_VERSION` and points the
runner at that checkout. Implementations in other languages use the same
fixtures.

The runner does not bundle fixtures.

## v0.2 conformance matrix

This is where the `aitp-rs` reference implementation stands against the
spec's conformance suite (`schemas/conformance/`). The spec's
[Fixture Index](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/conformance/README.md#fixture-index)
says what each fixture tests. This page only records how `aitp-rs` does on
them.

### Summary

These counts are **at pin `cfd2f16`**, the spec commit in
[`tests/schemas/SPEC_VERSION`](../tests/schemas/SPEC_VERSION). They are
the only place in these docs where fixture counts appear. Other pages link
here.

| Tier | Fixtures | Strict run (no `--feature`) | With all four features |
|---|---|---|---|
| `core`, `required_for_v0_2: true` | 74 | 74 PASS | 73 PASS, 1 SKIP (`del-007`) |
| `core`, frozen in the v0.1 shape (`del-004`; `required_for_v0_1: true`, `required_for_v0_2: false`) | 1 | PASS | SKIP |
| `draft`: session bundle (`experimental-session-bundle`) | 6 | SKIP | PASS |
| `draft`: multi-hop delegation (`experimental-multihop-delegation`) | 4 | SKIP | PASS |
| `extension`: pinned-key admission (`aitp-pinned-admission`) | 8 | SKIP | PASS |
| `extension`: self-attestation (`aitp-self-attestation`) | 3 | SKIP | PASS |
| **Total** | **96** | **75 pass / 0 fail / 21 skip** | **94 pass / 0 fail / 2 skip** |

Why the skips look the way they do:

- **Strict run.** `del-004` runs and passes. It expects
  `DELEGATION_MULTIHOP_NOT_SUPPORTED`, and that is what a runtime without
  multi-hop returns. The 21 skips are the 6 session-bundle, 4 multi-hop,
  8 pinned-admission and 3 self-attestation fixtures. A `draft` or
  `extension` fixture is skipped unless its `feature` has been enabled.
- **With `--feature experimental-multihop-delegation`.** `del-004` and
  `del-007` both expect `DELEGATION_MULTIHOP_NOT_SUPPORTED`. Turning the
  feature on makes that assertion meaningless, so the runner skips them.
  The skip reason reads "assertion … no longer applies". The mapping from
  error code to feature is `negated_by_feature` in
  `crates/aitp-conformance/src/runner/executor.rs`. This is intended
  behaviour, not a gap.

Reproduce. The fixture path assumes a sibling checkout of the spec repo at
the pinned commit:

```bash
cargo build -p aitp-rs-adapter -p aitp-conformance
# Strict: 75 pass / 0 fail / 21 skip at the pin. The `--profile v0.1`
# counts are the same; only the gate's required flag differs.
./target/debug/aitp-conformance run \
  --target ./target/debug/aitp-rs-adapter \
  --fixtures-dir ../agentidentitytrustprotocol/schemas/conformance
# Opt-in (draft RFCs and extensions): 94 pass / 0 fail / 2 skip at the pin.
# The `conformance` CI job runs both of these.
./target/debug/aitp-conformance run \
  --target ./target/debug/aitp-rs-adapter \
  --fixtures-dir ../agentidentitytrustprotocol/schemas/conformance \
  --feature experimental-multihop-delegation \
  --feature experimental-session-bundle \
  --feature aitp-pinned-admission \
  --feature aitp-self-attestation
```

### v0.2 conformance gate

`aitp-conformance run` exits non-zero in two cases:

1. Any fixture fails.
2. A fixture required by the selected profile fails or is skipped, for
   example because the adapter answers `OP_NOT_SUPPORTED`. The default
   profile is `v0.2`, which checks **`required_for_v0_2: true`**.
   `--profile v0.1` checks `required_for_v0_1: true` instead (at the pin,
   only `del-004`). This follows the spec's
   [Conformance runner enforcement rules](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/conformance/README.md#conformance-runner-enforcement-rules)
   and RFC-AITP-0001 §10 item 9.

A feature-negation skip does not count, because the run opted into a
feature that contradicts the fixture's assertion (see the multi-hop note
above). The runner lists each such exemption on stderr, so it is never
silent. With all four features at the pin that is `del-007` under the
default profile, and `del-004` under `--profile v0.1`. There is no other
allowlist: every other required fixture must pass.

The gate is `check_gate` in `crates/aitp-conformance/src/runner/gate.rs`,
called from `run()` in `crates/aitp-conformance/src/main.rs`. The
`conformance` CI job runs the corpus twice under the default profile:
strict, and with all four features.

### Fixtures by area

Each row gives the governing RFC sections and the fixture IDs. Every
fixture in the rows below passes in both runs. The one exception is
`del-007`: it is skipped when `--feature experimental-multihop-delegation`
is set, as explained above.

| Area | Fixtures |
|---|---|
| Envelope and key resolution: RFC-AITP-0001, RFC-AITP-0007 | `env-001`–`env-007` |
| Manifest: RFC-AITP-0003 | `man-001`–`man-007` |
| Identity and Mutual Handshake: RFC-AITP-0002, RFC-AITP-0004 | `id-001`–`id-009`, `mh-001`–`mh-009`, `mh-success-001` |
| Pinned-key P-256, tagged AIDs and descriptor shape: RFC-AITP-0002 §1, §3.1–§3.3 | `id-010`, `id-011`, `id-011b`, `id-012`, `id-017`, `id-018` |
| OIDC `cnf.jkt` follows the AID's algorithm (P-256): RFC-AITP-0002 §2.2.1 | `id-023` |
| One-way pinned-key admission (extension `aitp-pinned-admission`): RFC-AITP-0002 §3.4 | `id-013`–`id-016`, `id-019`–`id-022` |
| TCT: RFC-AITP-0005 | `tct-002`–`tct-007` |
| TCT `jti` UUID v4 layout: RFC-AITP-0005 §2.2 | `tct-013`, `tct-014` |
| Self-issued and attestation TCTs in a grant context: RFC-AITP-0005 §5.3 | `tct-015`, `tct-016`, `tct-018` |
| ES256 low-S: RFC-AITP-0001 §5.4.7 | `tct-017` |
| Self-attestation verification (extension `aitp-self-attestation`): RFC-AITP-0005 §5.3 | `tct-019`–`tct-021` |
| JWS `alg`/`typ` pinning: RFC-AITP-0001 §5.4.5, RFC-AITP-0005 §7.2 steps 2–3 | `tct-008`, `tct-009`, `tct-010` |
| TCT unknown claims: RFC-AITP-0005 §7.2 step 1 | `tct-011`, `tct-012` |
| Grant voucher: RFC-AITP-0005 §8 | `vch-001`, `vch-002` |
| Revocation: RFC-AITP-0008 | `rev-001`–`rev-003`, `rev-009` |
| Revocation lookup ordering: RFC-AITP-0008 §3.3 | `rev-004` |
| Revocation snapshot unknown members: RFC-AITP-0008 §1.5, RFC-AITP-0001 §7 | `rev-005`, `rev-006` |
| Revocation snapshot structural validation: RFC-AITP-0008 §1.5 | `rev-007`, `rev-008` |
| Delegation (voucher-based): RFC-AITP-0006 | `del-001`, `del-003`, `del-005`, `del-006`, `del-007`; `del-004` (v0.1 shape) |
| Session Trust Bundle (draft, `experimental-session-bundle`): RFC-AITP-0010 | `bundle-001`–`bundle-006` |
| Multi-hop delegation (draft, `experimental-multihop-delegation`): RFC-AITP-0011 | `del-mh-001`–`del-mh-004` |

The RFCs are indexed in the spec repo's [`rfcs/README.md`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/README.md).

### Notes

- **Side-effect assertions.** A fixture's `expected.side_effects` block is
  checked against the `side_effects` object the adapter reports in its
  result. A reported value that does not match is a hard failure. A side
  effect the adapter does not report is skipped as un-instrumented, never
  counted as a pass. See `assert_side_effects` in
  `crates/aitp-conformance/src/runner/executor.rs`. The spec's rule is
  under
  [Side-effect assertions](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/conformance/README.md#side-effect-assertions).
- **Fixture metadata and vendored schemas follow the pin.** That covers
  `status`, `feature`, `required_for_v0_1` and `required_for_v0_2`, and
  the schemas under `tests/schemas/`. All of them track the spec commit in
  `tests/schemas/SPEC_VERSION`. Re-run `scripts/sync-schemas.sh` (or
  `make schemas-check`) after the pin moves.
- **P-256 coverage beyond `env-005`:**
  - `aitp-crypto`'s `p256_keypair_kat_scalar_pubkey_aid_and_signature`
    tests the `kat-keypair-005-p256` vector in
    `tests/schemas/known-answer/keypairs.json`.
  - `aitp-tct`'s `p256_issuer_and_subject_round_trip_and_pop`.
  - The pure-Rust OIDC handshakes `oidc_minter_handshake_p256_initiator`
    and `oidc_minter_handshake_p256_responder`.
  - The cross-language interop test
    `test_p256_handshake_via_oidc_python_to_node`.

  The JWS rules for a P-256 issuer (`alg: ES256`, raw `R || S` signatures)
  are in RFC-AITP-0001 §5.4.5.
