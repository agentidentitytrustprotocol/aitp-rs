# Tier-3 e2e tests — real LLM agents over AITP

End-to-end tests that wire **real LLM agents** together over a full
AITP handshake. The planner handshakes with the worker, then delegates
a task to the worker over a signed envelope authenticated by a
peer-issued Trust Context Token (TCT). The worker's `/work` endpoint
verifies the TCT, prompts an LLM to produce an answer, and returns
it inside a signed envelope.

This package is **outside the Cargo workspace** so it never runs under
`cargo test --workspace` and never burns API credits in CI. It mirrors
the placement of `bindings/aitp-py` and `bindings/aitp-node` — an
opt-in sibling that depends on the workspace via path.

## Test tiers (cross-repo terminology)

| Tier | What it covers | Where it lives in `aitp-rs` |
|---|---|---|
| 1 | Wire format / JCS / envelope / TCT KATs | `crates/aitp-core/tests/kat.rs`, conformance fixtures |
| 2 | Real HTTP handshake + signed capability invocation, no LLM | `examples/two-agents` + `make demo` |
| 3 | **Two LLM-driven agents** delegating real work over a TCT | **this package** |

Tier 3 is for storytelling, regression-testing the binding ergonomics,
and proving the protocol survives being embedded in a realistic agent
flow. It will **not** catch protocol bugs that Tiers 1–2 don't already
catch.

## How to run

```sh
cd tests/e2e-llm
cp .env.example .env
$EDITOR .env                    # set AITP_RUN_LLM_TESTS=1 + one API key

# Run everything in this package.
AITP_RUN_LLM_TESTS=1 cargo test -- --nocapture

# Or run a single scenario.
AITP_RUN_LLM_TESTS=1 cargo test --test handshake_then_delegate -- --nocapture
```

Without `AITP_RUN_LLM_TESTS=1` (or with no API key set), each test
prints a `SKIPPED` line to stderr and exits successfully. This is the
default so running `cargo test` in the repo root never touches a
provider API.

## Provider selection

The harness picks a provider at runtime:

1. `ANTHROPIC_API_KEY` set → Anthropic Messages API, model
   `claude-haiku-4-5` (overridable via `AITP_LLM_MODEL`)
2. Otherwise `OPENAI_API_KEY` set → OpenAI Chat Completions, model
   `gpt-4o-mini` (overridable via `AITP_LLM_MODEL`)
3. Neither set → tests skip

No `rig-core` dependency: the LLM is just a text-in / text-out
function. If the tests grow into multi-turn tool-using agents later,
re-introduce `rig-core` then — not before.

## What gets tested

### `handshake_then_delegate.rs` — the canonical scenario

1. Spin up an LLM-backed **worker** agent on a random local port
   (`HandshakeServer` + a merged manifest route and `/work` endpoint).
2. **Planner** (plain code, no LLM) fetches the worker's manifest, pins
   its key, runs the four-message mutual handshake via
   `run_initiator_handshake`, and ends up holding a TCT the worker
   issued for it.
3. Planner posts the task to `/work`, presenting the TCT (an opaque
   compact JWS) in the `X-AITP-TCT` header.
4. Worker verifies the TCT — issuer pinning, audience, expiry,
   revocation, grants — then prompts the LLM and returns the answer.
5. Test asserts: handshake completed, TCT carries `task.delegate`,
   status is 200, answer is non-empty.

### `revocation_blocks_delegation.rs` — the 0.5.0 signing-input scenario

The revocation snapshot is one of the two artifacts whose JCS signing
input moved from the transport-wrapped form (`{"revocation_list": …}`)
to the inner artifact body in 0.5.0. Tier-1 KATs pin the bytes and the
`xcheck` CI job proves Rust and Python agree on them; what neither
covers is the full loop *in situ* — a server signing a snapshot on
demand, serving it over a socket, and a peer fetching, verifying, and
acting on it.

1. Handshake, as above.
2. Fetch + verify the worker's (empty) revocation snapshot.
3. Delegate a task — succeeds. *(This leg calls the LLM.)*
4. Worker revokes the planner's TCT `jti`.
5. Fetch + verify the snapshot again — it now lists that `jti`, over a
   freshly-signed set of bytes.
6. Delegate again — refused with 403, before the LLM is reached (so the
   negative leg costs no API credits).

A second test in the same file mints a structurally valid TCT under a
key the worker has never seen and asserts it is refused, covering the
issuer-pinning branch that the happy path never exercises.

## What is **not** tested here

- Protocol correctness (Tier 1 + conformance)
- Wire compatibility (Tier 2 + interop)
- Anything that can be expressed as a deterministic KAT

Tier 3 is the **integration story**, not the safety net.

## Why this package is built in CI even though it never runs there

It is excluded from the workspace, so `cargo fmt`, `cargo clippy` and
`cargo test --workspace` do **not** reach it. That exclusion is
correct — it must never burn API credits in CI — but for two releases
it also meant nothing compiled the package at all, and it silently
stopped building at the 0.4.0 breaking change. Nobody found out until
0.5.0. A test suite no job compiles is indistinguishable from one that
does not exist.

The `tier-3 e2e build (no API calls)` job in `.github/workflows/ci.yml`
closes that: it runs fmt + clippy + `cargo test` with the master gate
explicitly unset, so every test takes its skip branch. That costs
nothing, and still proves the harness links, boots, and that the skip
gate itself works.

The harness is also deliberately built on the **same** high-level APIs
as `examples/two-agents` (`HandshakeServer`, `run_initiator_handshake`)
rather than re-implementing the state machine by hand, as an earlier
revision did. A breaking change to those APIs now breaks the demo too —
and CI does build the demo.
