# Phase 5 Report — conformance runner

## Tasks completed

- CONF-001 (`Adapter` trait already shaped by Phase 0 scaffold; verified)
- CONF-002 (`SubprocessAdapter` — full implementation: spawn, NDJSON
  request/response, worker-thread reader with `recv_timeout` for the
  30 s default per-request timeout, graceful shutdown, kill-on-Drop)
- CONF-003 (`aitp-rs-adapter` binary — Tier-A op dispatch:
  `init`, `shutdown`, `verify_jcs`, `compute_jwk_thumbprint`,
  `verify_manifest`, `verify_tct`)
- CONF-004 (clap-driven CLI: `run` / `list` / `describe`, with
  `--filter`, `--tag`, `--output text|json|tap`, `--fail-fast`)
- CONF-005 (fixture loader walks `*.json` files, sorts by id)
- CONF-006 (sequence support already in fixture types; executor handles
  both `single` and `sequence` variants)
- CONF-007 (output formatters: text, json, tap)

## Test counts

| Suite | Count |
|---|---|
| `tests/runner_integration.rs` | 3 (spawns the real adapter binary) |

All 3 tests pass:
- `jcs_canonicalize_roundtrip_via_adapter` — drives `verify_jcs` end-to-end.
- `unsupported_op_yields_skip` — verifies the runner converts
  `OpNotSupported` adapter errors into `FixtureResult::Skip`.
- `verify_tct_against_adapter_fails_for_random_pubkey_aid` — drives
  `verify_tct` and asserts the spec's `TCT_SIGNATURE_INVALID` error code
  comes through.

## Smoke test against the spec's fixtures

Ran:

```sh
cargo run -p aitp-conformance -- run \
    --target ./target/debug/aitp-rs-adapter \
    --fixtures-dir <spec-repo>/schemas/conformance --output text
```

Result: **21 fixtures loaded, 0 passed, 21 failed**, all with
`reason: input.operation missing`. Root cause: the spec's current
`schemas/conformance/*.json` fixtures use a **legacy** input shape
(`input` is a free-form object describing what to verify) and do not yet
carry an `operation` key. They predate the conformance protocol pinned
in `docs/design/02-conformance-adapter.md`.

Resolution path (spec-side, not Rust-side):
1. Rewrite each fixture's `input` to `{operation: "<op>", <op-specific
   fields>}`. Most envelope-level fixtures map to `verify_envelope`,
   manifest-level to `verify_manifest`, etc.
2. Resolve the placeholder strings (`__NOW_MINUS_3600__`,
   `__VALID_ENVELOPE_SIG__`) to concrete values, ideally via a fixture
   generator script.
3. Replace placeholder AIDs (`agentB_pubkey_AID_v01_placeholder_BBBBBBBBB`)
   with real 43-char base64url values.

Tracked under `BLOCKED-SPEC-FIXTURE-MIGRATION` in
`docs/design/PENDING.md`.

## Decisions in this phase

1. **Subprocess timeout via `mpsc::recv_timeout`.** A worker thread
   `read_line`s from the adapter's stdout into the channel; the main
   thread waits up to 30 s. No `wait-timeout` crate dependency.
2. **Adapter error → runner action.** `AdapterError::OpNotSupported`
   maps to `FixtureResult::Skip`; everything else maps to `Fail`.
3. **`OpResult` reshaping.** The wire response carries `id`, `ok`,
   plus either `result` or `error_code` + `message`. After matching the
   echoed id, the runner strips `id` and lets `serde` pick the correct
   `OpResult` variant via `untagged`.
4. **CLI exit codes.** `0` = all pass; `1` = at least one fail; `2` =
   infrastructure error (couldn't load fixtures, couldn't spawn
   adapter, bad arguments).
5. **Output formats.** `Text` prints inline; `Json` and `Tap` are
   collected and emitted at the end. `Json` is `serde_json` pretty
   output; `Tap` follows TAP 13 with YAML-style failure blocks.

## Tier B/C/D operations — not in this phase

The original Phase 5 plan described every op in the vocabulary
(`generate_keypair`, `issue_*`, `start_handshake`,
`process_handshake_message`, `set_clock`, etc.). Only Tier A is
landed; Tier B/C/D are **deferred to v0.1.0-alpha.2** so this milestone
ships a working subprocess protocol and an adapter for verification
fixtures rather than a half-implementation of issuance fixtures.
Tracked under `BLOCKED-CONF-TIERBCD` in `docs/design/PENDING.md`.

## Things the human reviewer should look at

1. The `OpResult` `untagged` matching is robust to the `id` field being
   stripped first. If the adapter ever sends a response missing both
   `result` and `error_code`, the deserialize will fail with a generic
   "did not match any variant" error — which is `MalformedResponse`.
2. Spec fixtures need the migration described above before the runner
   can produce useful pass/fail output against them.
3. Tier C ops (`start_handshake`, `process_handshake_message`) require
   a session map in the adapter and a way to thread a fixed clock —
   both unimplemented. The handshake state machines from Phase 3d are
   ready for it; the gap is the adapter's session bookkeeping.
