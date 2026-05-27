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

`handshake_then_delegate.rs` — the canonical scenario:

1. Spin up an LLM-backed **worker** agent on a random local port (axum
   server with manifest + handshake + `/work` endpoint).
2. **Planner** (plain code, no LLM) fetches the worker's manifest,
   runs the four-message mutual handshake, and ends up holding a TCT
   the worker issued for it.
3. Planner posts a signed envelope to `/work`, attaching the TCT in
   the `X-AITP-TCT` header.
4. Worker verifies the envelope signature + TCT (audience, expiry,
   grants), prompts the LLM with the task, returns a signed envelope.
5. Test asserts: handshake completed, TCT carries `task.delegate` in
   its grants, response status is 200, response body is non-empty.

## What is **not** tested here

- Protocol correctness (Tier 1 + conformance)
- Wire compatibility (Tier 2 + interop)
- Anything that can be expressed as a deterministic KAT

Tier 3 is the **integration story**, not the safety net.
