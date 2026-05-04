# Phase 4b — Two-Agent Demo

You are working on the `aitp-rs` Rust reference implementation. This is
Phase 4b of 6.

**Your goal:** a runnable end-to-end demo where two agents (`agent-a`
and `agent-b`) on different ports establish trust via AITP and exchange
a capability invocation.

This is the artifact that goes in a blog post. Make it readable.

---

## Required reading

1. `phase-4a-report.md`
2. `examples/two-agents/` — current scaffold (stubbed `main` functions)
3. The `clap` 4.x derive API for command-line args

---

## Demo design

Two binaries running locally:

```
agent-a (port 8001)                   agent-b (port 8002)
─────────────────                     ─────────────────
1. Generate fresh keypair             1. Generate fresh keypair
2. Build own Manifest                 2. Build own Manifest
3. Start ManifestServer + Handshake   3. Start ManifestServer +
                                         HandshakeServer
4. Wait briefly for B to be up
5. Fetch B's Manifest
6. Run Initiator against B's
   handshake endpoint
7. Hold a TCT issued by B
8. Invoke B's "echo" capability,
   passing the TCT
9. Print the result
```

Both agents use **pinned-key identity** (no OIDC dependency for the
demo). Pinned keys are derived from a fixed seed so the demo is
reproducible.

The "echo" capability is intentionally trivial — it's the simplest
thing that demonstrates A presenting a TCT to B and B verifying it.
B accepts a request like `POST /echo` with header `X-AITP-TCT: <tct>`,
verifies the TCT, and echoes the request body.

---

## Global rules

[All 12 apply.]

- **Stop at the phase boundary.** Do not begin Phase 5.

---

## Tasks

### 4b.1 — `agent-a` binary (EX-001)

File: `examples/two-agents/src/bin/agent-a.rs`

Replace the placeholder `main`. Use `tokio::main` and `clap`.

Args:
- `--port` (default 8001)
- `--peer` (default `https://localhost:8002`)
- `--seed` (default `aaaa...` — fixed for reproducibility)

Flow:
1. Print a clear banner: `"agent-a starting on port {port}"`
2. Generate a signing key from the seed
3. Build a Manifest:
   - `aid = key.aid()`
   - `display_name = "agent-a"`
   - `identity_hint = pinned_key { subject: "agent-a", public_key: <pk> }`
   - `handshake_endpoint = https://localhost:{port}/aitp/handshake/hello`
   - `accepted_identity_types = ["pinned_key"]`
   - `offered_capabilities = []` (a doesn't offer anything in this demo)
   - `required_peer_capabilities = ["demo.echo"]`
   - TTL: 1 hour
4. Print: `"agent-a AID: {key.aid()}"`
5. Start `ManifestServer` + `HandshakeServer` in a background task
6. Wait 500ms for B to be ready (or implement a tiny retry loop)
7. Fetch B's Manifest via `ManifestFetcher`. Print: `"fetched B's manifest, AID: {b_aid}"`
8. Run `Initiator::start` with `requested_grants = ["demo.echo"]`
9. POST the HELLO envelope to B's `handshake_endpoint`
10. Receive HELLO_ACK, run `Initiator::on_hello_ack`, POST COMMIT
11. Receive COMMIT_ACK, run `Initiator::on_commit_ack`, get the TCT
12. Print: `"got TCT from B, jti={jti}, grants={grants}"`
13. POST `https://localhost:8002/echo` with header
    `X-AITP-TCT: <tct serialized as JSON>` and body `"hello world"`
14. Print: `"echo response: {response_body}"`
15. Exit cleanly

Each major step should print a line so the demo is readable when run.

### 4b.2 — `agent-b` binary (EX-002)

File: `examples/two-agents/src/bin/agent-b.rs`

Args:
- `--port` (default 8002)
- `--seed` (default `bbbb...`)

Flow:
1. Banner: `"agent-b starting on port {port}"`
2. Generate signing key from seed
3. Build Manifest with `offered_capabilities = ["demo.echo"]`,
   `required_peer_capabilities = []` (b doesn't require anything from
   peers)
4. Print AID
5. Start `ManifestServer`, `HandshakeServer`, AND a custom router that
   exposes `POST /echo`
6. The `/echo` handler:
   - Reads `X-AITP-TCT` header, parses as JSON into `Tct`
   - Verifies via `aitp_tct::verify_tct` with `ctx.expected_audience =
     <a's AID — which we know because we issued the TCT>`
   - HOLD ON: B issued a TCT to A with `subject == audience == A`. So
     when A presents the TCT to B, B's verification needs
     `expected_audience = A.aid()`. B can extract A's AID from the TCT
     itself (`tct.subject`) — this is the holder-receipt model.
   - Verify the TCT (signature against B's own pubkey since B issued
     it; audience matches subject; not expired; etc.)
   - Verify `demo.echo` is in the TCT's grants
   - Echo back the request body
7. Server runs forever (or until SIGINT)

### 4b.3 — Makefile target (EX-003)

Create a top-level `Makefile` with:

```makefile
.PHONY: demo demo-build

demo-build:
	cargo build --release -p aitp-example-two-agents

demo: demo-build
	@echo "Starting two-agent demo..."
	@./target/release/agent-b &
	@sleep 0.5
	@./target/release/agent-a
	@kill %1 2>/dev/null || true
```

Test that `make demo` actually works on Linux. On macOS the syntax may
need slight adjustment.

### 4b.4 — Demo README (EX-004)

Create `examples/two-agents/README.md` that walks through:

1. What the demo does (one paragraph)
2. How to run it (`make demo`)
3. What to expect in stdout (annotated transcript)
4. Where to look in the code for each AITP concept:
   - Generating keys
   - Building Manifests
   - Running the Initiator
   - Running the Responder
   - Verifying a TCT at request time
5. How to tweak it (run with different seeds, add capabilities, etc.)

Keep it under 400 lines. The point is to be approachable to someone who
just cloned the repo.

### 4b.5 — End-to-end test

Create `examples/two-agents/tests/demo.rs`:

A test that:
1. Spawns `agent-b` on a random port
2. Spawns `agent-a` pointing at that port
3. Captures stdout from both
4. Asserts agent-a's stdout contains
   `"echo response: hello world"` (or whatever your echo path returns)
5. Cleans up both processes

This catches regressions where one of the agents stops working.

---

## Format, lint, tests

```sh
cargo fmt --all
cargo clippy -p aitp-example-two-agents --all-targets -- -D warnings
cargo test -p aitp-example-two-agents
make demo
```

All clean. `make demo` produces visible, sensible output.

---

## Update PENDING.md

Check off EX-001, 002, 003, 004.

---

## Phase report

`phase-4b-report.md`. Include:
- Sample output of `make demo` (paste the actual lines)
- Total lines of code in the two binaries
- Any UX papercuts (e.g., race conditions when starting both agents
  simultaneously)

---

## Success gate

- `make demo` runs cleanly and produces readable output
- The integration test passes
- README walks a reader through what's happening
- Clippy clean

## Stop here.
