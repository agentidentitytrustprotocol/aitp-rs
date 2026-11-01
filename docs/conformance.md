# Conformance

The conformance runner exists so that AITP implementations in any language
can be validated against the same fixtures. This page covers two things:
how this repo's **runner drives an implementation** (the protocol itself
is the spec's), and the **conformance matrix** (where `aitp-rs` stands
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

## Adapter protocol

The spec defines the adapter protocol, in
[`schemas/conformance/ADAPTER.md`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/conformance/ADAPTER.md)
(`adapter-protocol: 1`). It covers the transport, the request and
response shapes, `init` and `shutdown`, the operations fixtures use, the
housekeeping ops, SKIP and the claim gates. This page does not repeat it.
ADAPTER.md was checked against this runner, and its notes marked
**aitp-rs** describe the choices `aitp-conformance` makes where the
protocol leaves one. The ones an adapter author meets first:

- **Request ids** are `req-1`, `req-2`, … numbered over the whole run,
  `init` included.
- **SKIPs come from `supported_ops` only.** The runner never reads
  `supported_features`, which is informational. Which draft and extension
  fixtures run is chosen by `--feature`.
- **`OP_NOT_SUPPORTED` is a SKIP.** A declared op may refuse one input it
  does not implement with `"error_code": "OP_NOT_SUPPORTED"`; the step is
  a SKIP, not a FAIL. Like every SKIP of a `required_for_core` fixture, it
  still blocks the `AITP v0.3` claim.
- **A timeout fails the step; it does not kill the adapter.** A request
  with no response line within 30 seconds
  (`SubprocessAdapter::with_timeout` overrides it) fails the fixture step
  that sent it. The adapter keeps running, so a late response is read as
  the answer to the next request and fails that one on the `id` check. The
  runner kills the process only at shutdown, about 500 ms after sending
  `shutdown`.
- **Stderr** passes through to the runner's stderr; stdout carries only
  the protocol.

To write an adapter, start from the
[Python template](../adapters/README.md).

### `aitp-rs-adapter`

The adapter for this implementation (`crates/aitp-conformance/src/rs_adapter/`,
binary `aitp-rs-adapter`) reports the `aitp-conformance` package version
(`env!("CARGO_PKG_VERSION")`) in `init`, so the value tracks the workspace
release. Its live operation list is `supported_ops` in `init()` in
`rs_adapter/mod.rs`.

- It answers every fixture operation ADAPTER.md lists. It advertises
  `verify_a2a_agent_card_binding` and the feature `aitp-a2a-agent-card`
  only when built with the crate's `a2a-agent-card` feature, on by default.
- It also answers ops no fixture uses: issuance (`generate_keypair`,
  `issue_manifest`, `issue_tct`, `issue_delegation_token`,
  `issue_session_bundle`, `sign_envelope`), `start_handshake`,
  `revoke_tct`, and the helpers `verify_jcs`, `compute_jwk_thumbprint`,
  `inject_revocation` and `dump_session`. They are outside the protocol.
- `verify_session_bundle` requires `coordinator_manifest`; a missing
  Manifest or one for another AID is `KEY_RESOLUTION_FAILED`
  (RFC-AITP-0010 §5 step 5).
- The admission verifier behind `verify_identity_presentation` and
  `issue_presentation_challenge` lives for one fixture, so a nonce
  consumed in one sequence step stays consumed in the next. It is built
  from the first step's `self_aid`, `trust_store`,
  `max_outstanding_nonces`, `presentation_rate_limit` and
  `outstanding_challenges`. `begin_fixture` drops it.
- `renew_tct` acts as the issuer `self_aid` (a KAT keypair) and returns
  the signed response envelope as `result.response_envelope`; the runner
  checks `expected.renewed_tct_claims`, `renewed_jti_differs` and
  `response` against it. Its replay guard lives for one fixture;
  `begin_fixture` drops it.

### Inside the runner

An adapter is represented by `Adapter`. The default backing
implementation is `SubprocessAdapter`. An optional in-process
implementation (`InProcessRustAdapter`) calls `aitp` directly for fast
local development; CI uses the subprocess path so the protocol itself is
exercised.

```rust
pub trait Adapter {
    fn init(&mut self) -> Result<AdapterInfo, AdapterError>;
    fn execute(&mut self, op: &str, params: serde_json::Value)
        -> Result<OpResult, AdapterError>;
    fn shutdown(&mut self) -> Result<(), AdapterError>;
}
```

## Fixture format

The fixture format belongs to the spec, not to this repo. Read it there:

- [Fixture Format](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/conformance/README.md#fixture-format):
  the metadata fields (`status`, `feature`, `required_for_core`), the
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
  fixture. Its `required_for_core` field (or `required_for_v0_1` under
  `--profile v0.1`) drives the exit-code gate; see
  [core conformance gate](#core-conformance-gate).

## CLI surface

```
aitp-conformance run --target <CMD> [--fixtures-dir <DIR>] [--filter <PAT>] \
                     [--tag <TAG>] [--feature <NAME>]... \
                     [--output text|json|tap] [--fail-fast] \
                     [--profile core|v0.1] \
                     [--report <PATH> [--spec-commit <SHA>] [--spec-version <TAG>] \
                      [--implementation-repository <URL>] [--implementation-commit <SHA>]]
aitp-conformance list [--fixtures-dir <DIR>] [--tag <TAG>]
aitp-conformance describe [--fixtures-dir <DIR>] <FIXTURE_ID>
```

`--fixtures-dir` defaults to `./schemas/conformance`. `--feature` can be
repeated. Each one opts into a draft feature (for example
`experimental-session-bundle`), so fixtures tagged with it run instead of
being skipped. `--profile` picks the protocol version the exit-code gate
checks (default `core`; see [core conformance gate](#core-conformance-gate)).
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
object per fixture. `--report` additionally writes the spec's report
document; see [Conformance report](#conformance-report).

### Conformance report

`--report <PATH>` writes a report valid against the spec's
`aitp-conformance-report.schema.json` (`report_version` `"1"`, vendored at
`tests/schemas/aitp-conformance-report.schema.json`). The spec's
`docs/conformance-badge.md` defines it. It holds:

- `implementation` and `runner`;
- `spec` (`commit`, `version` and `protocol` `aitp/0.3`);
- `fixtures_dir_digest` and the sorted `features_enabled`;
- one `results` entry per non-reserved fixture, with `status`, `feature`
  and `required_for_core` copied from the fixture;
- `totals` by status;
- `gates`.

The code is in `crates/aitp-conformance/src/runner/report.rs`.

`gates` evaluates `"AITP v0.3"`, plus each extension claim whose feature
is enabled (`AITP v0.3 pinned-admission`, `AITP v0.3 self-attestation`):

- **`AITP v0.3`** passes only when every core fixture with
  `required_for_core: true` passes.
- **An extension claim** passes only when every fixture with its feature
  passes.

Unlike the exit-code gate below, a core fixture skipped because an enabled
draft feature negates it still blocks `AITP v0.3`. Make the core claim
from a run without draft features. Draft fixtures gate no claim.

The report's sources:

- **`spec.commit`** is never guessed. It is `--spec-commit`, else the first
  `SPEC_VERSION` file in or above `--fixtures-dir`, else `HEAD` of a clean
  checkout of the spec repository whose `schemas/conformance` is
  `--fixtures-dir`. Otherwise the run fails before it starts.
- **`spec.version`** is `--spec-version`, else
  `git describe --tags --match 'v[0-9]*'` of that commit in a spec
  checkout.
- **`fixtures_dir_digest`** is `sha256:` plus the SHA-256 of the
  `sha256sum`-format listing of the top-level `*.json` files, sorted by
  name in byte order. It equals
  `cd <dir> && LC_ALL=C sha256sum -- *.json | sha256sum`.

A report covers the whole corpus, so `--report` refuses `--filter`, `--tag`
and `--fail-fast`. The exit code is unaffected: it reports run health (the
gate below), and the claims live only in `gates`.

The `conformance` CI job writes a report from a run with the two extension
features and no draft features. It checks the report three ways:

1. against the schema;
2. that every gate passed;
3. with the spec's
   `scripts/check-conformance-report.py --fixtures-dir`, which recomputes
   the totals, the gates and the digest.

The job uploads the report as the `conformance-report` artifact, and a second
report from a run with `--feature aitp-a2a-agent-card` as
`a2a-conformance-report`. To reproduce the first locally:

```bash
./target/debug/aitp-conformance run \
  --target ./target/debug/aitp-rs-adapter \
  --fixtures-dir ../agentidentitytrustprotocol/schemas/conformance \
  --feature aitp-pinned-admission --feature aitp-self-attestation \
  --report conformance-report.json
python3 ../agentidentitytrustprotocol/scripts/check-conformance-report.py \
  conformance-report.json --fixtures-dir ../agentidentitytrustprotocol/schemas/conformance
```

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
   through `scripts/xcheck-verify.py`. The `xcheck-ts` job does the same
   with [`aitp-verifier-ts`](https://github.com/agentidentitytrustprotocol/aitp-verifier-ts),
   whose `xcheck-verify.mjs` is pinned by `tests/AITP_VERIFIER_TS_VERSION` and
   whose conformance adapter comes from npm at the version locked in
   `tests/xcheck-verifier-ts/`, and the `xcheck-go` job with
   [`aitp-verifier-go`](https://github.com/agentidentitytrustprotocol/aitp-verifier-go),
   pinned by `tests/AITP_VERIFIER_GO_VERSION`. The reverse direction is covered by
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

The table holds at the spec commit in
[`tests/schemas/SPEC_VERSION`](../tests/schemas/SPEC_VERSION). It
records outcomes per tier, not fixture counts, so it does not go stale
when the spec adds a fixture. For the counts, see the `conformance` CI
job, which derives them from the runner on every run. The job's step
summary shows the report's `totals` and `gates`, and the
`conformance-report` artifact is the full
[report](#conformance-report). Other pages link here instead of quoting
numbers.

| Tier | Strict run (no `--feature`) | With all seven features |
|---|---|---|
| `core`, `required_for_core: true` (the `aitp/0.3` core tier) | all PASS | all PASS except `del-007` (SKIP) |
| `core`, frozen in the v0.1 shape (`del-004`; `required_for_v0_1: true`, `required_for_core: false`) | PASS | SKIP |
| `draft`: session bundle (`experimental-session-bundle`) | SKIP | PASS |
| `draft`: multi-hop delegation (`experimental-multihop-delegation`) | SKIP | PASS |
| `draft`: SPIFFE identity (`experimental-spiffe-identity`) | SKIP | PASS |
| `draft`: TCT renewal (`experimental-renewal`) | SKIP | PASS |
| `draft`: A2A Agent Card binding (`aitp-a2a-agent-card`) | SKIP | PASS |
| `extension`: pinned-key admission (`aitp-pinned-admission`) | SKIP | PASS |
| `extension`: self-attestation (`aitp-self-attestation`) | SKIP | PASS |

No fixture fails in either run. The report run (both extensions, no draft
features) passes all three claims: `AITP v0.3`, `AITP v0.3 pinned-admission`
and `AITP v0.3 self-attestation`.

This section keeps its `v0.2` heading because other repositories link to
its anchor. The fixture key is `required_for_core` (renamed from
`required_for_v0_2` at spec `0ad4bf2`), and the runner's default
`--profile core` gates on it.

Why the skips look the way they do:

- **Strict run.** `del-004` runs and passes. It expects
  `DELEGATION_MULTIHOP_NOT_SUPPORTED`, and that is what a runtime without
  multi-hop returns. The skips are the session-bundle, multi-hop,
  SPIFFE, renewal, pinned-admission and self-attestation fixtures: a `draft` or
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
cargo build -p aitp-conformance   # builds aitp-conformance and aitp-rs-adapter
# Strict: no failures; the draft and extension fixtures skip. The
# `--profile v0.1` outcomes are the same; only the gate's required flag
# differs.
./target/debug/aitp-conformance run \
  --target ./target/debug/aitp-rs-adapter \
  --fixtures-dir ../agentidentitytrustprotocol/schemas/conformance
# Opt-in (draft RFCs and extensions): no failures; del-004 and del-007
# skip. The `conformance` CI job runs both of these.
./target/debug/aitp-conformance run \
  --target ./target/debug/aitp-rs-adapter \
  --fixtures-dir ../agentidentitytrustprotocol/schemas/conformance \
  --feature experimental-multihop-delegation \
  --feature experimental-session-bundle \
  --feature experimental-spiffe-identity \
  --feature aitp-pinned-admission \
  --feature aitp-self-attestation \
  --feature experimental-renewal \
  --feature aitp-a2a-agent-card
```

### Core conformance gate

`aitp-conformance run` exits non-zero in two cases:

1. Any fixture fails.
2. A fixture required by the selected profile fails or is skipped, for
   example because the adapter answers `OP_NOT_SUPPORTED`. The default
   profile is `core`, which checks **`required_for_core: true`**.
   `--profile v0.1` checks `required_for_v0_1: true` instead (at the pin,
   only `del-004`). This follows the spec's
   [Conformance runner enforcement rules](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/conformance/README.md#conformance-runner-enforcement-rules)
   and RFC-AITP-0001 §10 item 9.

A feature-negation skip does not count, because the run opted into a
feature that contradicts the fixture's assertion (see the multi-hop note
above). The runner lists each such exemption on stderr, so it is never
silent. With all five features at the pin that is `del-007` under the
default profile, and `del-004` under `--profile v0.1`. There is no other
allowlist: every other required fixture must pass.

The gate is `check_gate` in `crates/aitp-conformance/src/runner/gate.rs`,
called from `run()` in `crates/aitp-conformance/src/main.rs`. The
`conformance` CI job runs the corpus under the default profile strict and
with all five features, then writes the [report](#conformance-report) from
a run with the two extensions.

### Fixtures by area

Each row gives the governing RFC sections and the fixture IDs. Every
fixture in the rows below passes in both runs. The one exception is
`del-007`: it is skipped when `--feature experimental-multihop-delegation`
is set, as explained above.

| Area | Fixtures |
|---|---|
| Envelope and key resolution: RFC-AITP-0001, RFC-AITP-0007 | `env-001`–`env-011` (`env-007`–`env-011`: the `aitp-envelope-v2` signing input and the §5.4 check order, `aitp/0.2` strict cutover included) |
| Manifest: RFC-AITP-0003 | `man-001`–`man-007` |
| Identity and Mutual Handshake: RFC-AITP-0002, RFC-AITP-0004 | `id-001`–`id-009`, `mh-001`–`mh-015`, `mh-success-001` |
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
| Revocation: RFC-AITP-0008 | `rev-001`–`rev-003`, `rev-009`, `rev-010` |
| A snapshot signed by a third party is discarded: RFC-AITP-0008 §1.5, §3.1 | `rev-011` |
| Revocation lookup ordering: RFC-AITP-0008 §3.3 | `rev-004` |
| Revocation snapshot unknown members: RFC-AITP-0008 §1.5, RFC-AITP-0001 §7 | `rev-005`, `rev-006` |
| Revocation snapshot structural validation: RFC-AITP-0008 §1.5 | `rev-007`, `rev-008` |
| A discarded snapshot is absent and `revocation_policy.mode` decides: RFC-AITP-0008 §1.5, §3.1 | `tct-022` (`fail_closed`), `tct-023` (`fail_open`) |
| No revocation source: the default is `fail_closed`, `fail_open` is explicit: RFC-AITP-0008 §3.1 | `tct-024` (default `fail_closed`), `tct-025` (`fail_open`) |
| Delegation (voucher-based): RFC-AITP-0006 | `del-001`, `del-003`, `del-005`, `del-006`, `del-007`; `del-004` (v0.1 shape) |
| The verifier's own deny list fails verification: RFC-AITP-0006 §4 step 7 | `del-008` |
| Session Trust Bundle (draft, `experimental-session-bundle`): RFC-AITP-0010 | `bundle-001`–`bundle-008` |
| Multi-hop delegation (draft, `experimental-multihop-delegation`): RFC-AITP-0011 | `del-mh-001`–`del-mh-006` (`del-mh-006`: a discarded hop snapshot under `fail_closed`, §6) |
| SPIFFE identity (draft, `experimental-spiffe-identity`): RFC-AITP-0002 §6 | `id-024` (JWT-SVID), `id-025` (X509-SVID); rejected: `id-026` (no bundle for the subject's trust domain), `id-027` (nonce), `id-028` (expired), `id-029` (`aud`), `id-030` (two URI SANs) |
| A2A Agent Card binding (draft, `aitp-a2a-agent-card`): RFC-AITP-0014 | `a2a-001`–`a2a-006` |

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
  `status`, `feature`, `required_for_v0_1` and `required_for_core`, and
  the schemas under `tests/schemas/`. All of them track the spec commit in
  `tests/schemas/SPEC_VERSION`. Re-run `scripts/sync-schemas.sh` (or
  `make schemas-check`) after the pin moves.
- **P-256 coverage beyond `env-005`:**
  - `p256_keypair_kat_scalar_pubkey_aid_and_signature`
    (`crates/aitp/tests/crypto_kat.rs`) tests the `kat-keypair-005-p256` vector in
    `tests/schemas/known-answer/keypairs.json`.
  - `p256_issuer_and_subject_round_trip_and_pop`
    (`crates/aitp/tests/tct_round_trip.rs`).
  - The pure-Rust OIDC handshakes `oidc_minter_handshake_p256_initiator`
    and `oidc_minter_handshake_p256_responder`.
  - The cross-language interop test
    `test_p256_handshake_via_oidc_python_to_node`.

  The JWS rules for a P-256 issuer (`alg: ES256`, raw `R || S` signatures)
  are in RFC-AITP-0001 §5.4.5.
