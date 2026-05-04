# Phase 5 — Conformance Runner

You are working on the `aitp-rs` Rust reference implementation. This is
Phase 5 of 6.

**Your goal:** working `aitp-conformance` runner that loads fixtures
from the AITP spec repo and executes them against an `Adapter` over
NDJSON-stdin/stdout. Plus a complete `aitp-rs-adapter` binary that
implements every operation in the vocabulary.

When this phase is done, `aitp-conformance run --target
./aitp-rs-adapter` should run all fixtures and produce green or
explainable-red.

---

## Required reading

1. `phase-4b-report.md`
2. `docs/design/02-conformance-adapter.md` — the entire design doc.
   Read it twice.
3. `crates/aitp-conformance/src/*` — current scaffold
4. `crates/aitp-rs-adapter/src/main.rs` — current scaffold (handles
   only init/shutdown)

---

## Decisions baked in

- Subprocess over FFI (Q-016)
- NDJSON wire protocol (one JSON object per line, both directions)
- Three tiers of operations: A (verification), B (issuance), C
  (stateful). Tier D (test-only) is optional
- 30-second timeout per request
- Stderr inherits — adapters can print logs to stderr
- Fixtures live in the spec repo (`agentidentitytrustprotocol/schemas/
  conformance/`); the runner consumes them via a configured `--fixtures-
  dir` path

---

## Global rules

[All 12 apply.]

- **Stop at the phase boundary.** Do not begin Phase 6.

---

## Tasks

### 5.1 — `Adapter` trait (CONF-001)

`crates/aitp-conformance/src/adapter/mod.rs` already has the trait
sketched. Verify it compiles and matches the design doc. No changes
expected.

### 5.2 — `SubprocessAdapter` (CONF-002)

File: `crates/aitp-conformance/src/adapter/subprocess.rs`

Replace TODOs. Implementation:

```rust
pub struct SubprocessAdapter {
    process: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    info: Option<AdapterInfo>,
    next_id: u64,
    timeout: Duration,
}

impl SubprocessAdapter {
    pub fn spawn(executable: &str, args: &[&str]) -> Result<Self, AdapterError> {
        let mut process = Command::new(executable)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())  // adapter logs go to runner's stderr
            .spawn()?;
        let stdin = process.stdin.take().unwrap();
        let stdout = BufReader::new(process.stdout.take().unwrap());
        Ok(Self {
            process,
            stdin,
            stdout,
            info: None,
            next_id: 0,
            timeout: Duration::from_secs(30),
        })
    }
}

impl Adapter for SubprocessAdapter {
    fn init(&mut self) -> Result<AdapterInfo, AdapterError> {
        let response = self.send("init", json!({"version": "1"}))?;
        let info: AdapterInfo = serde_json::from_value(
            response.get("result").cloned()
                .ok_or_else(|| AdapterError::MalformedResponse("no result".into()))?
        ).map_err(|e| AdapterError::MalformedResponse(e.to_string()))?;
        self.info = Some(info.clone());
        Ok(info)
    }

    fn execute(&mut self, op: &str, params: serde_json::Value)
        -> Result<OpResult, AdapterError>
    {
        if let Some(info) = &self.info {
            if !info.supported_ops.contains(op) {
                return Err(AdapterError::OpNotSupported(op.into()));
            }
        }
        let response = self.send(op, params)?;
        serde_json::from_value(response)
            .map_err(|e| AdapterError::MalformedResponse(e.to_string()))
    }

    fn shutdown(&mut self) -> Result<(), AdapterError> {
        let _ = self.send("shutdown", json!({}));
        std::thread::sleep(Duration::from_millis(500));
        let _ = self.process.kill();
        Ok(())
    }
}

impl SubprocessAdapter {
    fn send(&mut self, op: &str, params: serde_json::Value)
        -> Result<serde_json::Value, AdapterError>
    {
        self.next_id += 1;
        let id = format!("req-{}", self.next_id);
        let request = json!({"id": id, "op": op, "params": params});
        writeln!(self.stdin, "{}", request)?;
        self.stdin.flush()?;

        // Read one line with timeout
        // Note: BufRead doesn't natively support timeouts. Use a thread
        // or the `wait-timeout` crate. If wait-timeout isn't in
        // workspace deps, write a BLOCKED-DEP entry and use a thread.
        let line = self.read_line_with_timeout(self.timeout)?;
        if line.is_empty() {
            return Err(AdapterError::ProcessDied("EOF on stdout".into()));
        }
        let response: serde_json::Value = serde_json::from_str(&line)
            .map_err(|e| AdapterError::MalformedResponse(e.to_string()))?;

        // Verify ID echoes match
        if response.get("id").and_then(|v| v.as_str()) != Some(&id) {
            return Err(AdapterError::MalformedResponse("id mismatch".into()));
        }
        Ok(response)
    }

    fn read_line_with_timeout(&mut self, timeout: Duration)
        -> Result<String, AdapterError>
    {
        // Implement using a worker thread + channel, or std::sync::mpsc
        // with recv_timeout. Either works.
        todo!()
    }
}
```

If `wait-timeout` isn't already in workspace deps and you'd prefer it,
flag with `BLOCKED-DEP-WAITTIMEOUT`.

Tests:
- Spawn an adapter that just echoes `init` correctly, verify capability
  declaration parses
- Spawn an adapter that exits immediately, verify `ProcessDied`
- Spawn an adapter that hangs on stdin, verify `Timeout`

### 5.3 — `aitp-rs-adapter` binary (CONF-003)

File: `crates/aitp-rs-adapter/src/main.rs`

The scaffold handles `init` and `shutdown`. Add dispatch for every
operation in `crates/aitp-conformance/src/ops/mod.rs`.

This is a long but mechanical function. The structure:

```rust
fn handle_request(state: &mut AdapterState, req: serde_json::Value) -> serde_json::Value {
    let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
    let op = req.get("op").and_then(|v| v.as_str()).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or_default();

    let result = match op {
        "init" => return ok_response(id, init_response()),
        "shutdown" => return ok_response(id, json!({})),

        OP_VERIFY_ENVELOPE => verify_envelope_op(state, params),
        OP_VERIFY_MANIFEST => verify_manifest_op(state, params),
        OP_VERIFY_TCT => verify_tct_op(state, params),
        OP_VERIFY_DELEGATION_TOKEN => verify_delegation_op(state, params),
        OP_VERIFY_JCS => verify_jcs_op(params),
        OP_COMPUTE_JWK_THUMBPRINT => compute_thumbprint_op(params),

        OP_GENERATE_KEYPAIR => generate_keypair_op(state, params),
        OP_ISSUE_MANIFEST => issue_manifest_op(state, params),
        OP_ISSUE_TCT => issue_tct_op(state, params),
        OP_ISSUE_DELEGATION_TOKEN => issue_delegation_op(state, params),
        OP_SIGN_ENVELOPE => sign_envelope_op(state, params),

        OP_START_HANDSHAKE => start_handshake_op(state, params),
        OP_PROCESS_HANDSHAKE_MESSAGE => process_handshake_op(state, params),
        OP_REVOKE_TCT => revoke_tct_op(state, params),
        OP_VERIFY_REVOCATION_SNAPSHOT => verify_revocation_op(state, params),

        OP_SET_CLOCK => set_clock_op(state, params),
        OP_INJECT_REVOCATION => inject_revocation_op(state, params),
        OP_DUMP_SESSION => dump_session_op(state, params),

        unknown => Err(format!("unknown op: {}", unknown)),
    };

    match result {
        Ok(value) => ok_response(id, value),
        Err(msg) => err_response(id, "INTERNAL_ERROR", &msg),
    }
}

struct AdapterState {
    keypairs: HashMap<String, AitpSigningKey>,
    sessions: HashMap<String, /* responder/initiator session */>,
    revocation_set: HashSet<Uuid>,
    clock_override: Option<Timestamp>,
    next_handle: u64,
}
```

Each `*_op` function takes the state and params, returns a JSON result
or an error string.

For Tier C (stateful) operations: `start_handshake` returns a session
ID; `process_handshake_message` looks up the session and feeds it the
next message. The session map has to be per-handle.

For test-only ops: `set_clock` overrides `Timestamp::now()` for time-
dependent verification. This requires either:
- Threading a clock parameter through the verifier APIs (cleaner but
  more refactoring)
- Using a thread-local override in `aitp-core::time` for adapter use only
- Or a global `AtomicI64` clock override behind a feature flag

Pick the cleanest option that doesn't pollute the production API.
Document the choice.

Update `init_response()` to declare every operation in
`supported_ops` and the features the adapter supports.

### 5.4 — CLI (CONF-004)

`crates/aitp-conformance/src/main.rs` already has the clap structure.
Wire up the actual commands:

- `Run`: load fixtures, spawn adapter, run each, format output
- `List`: load fixtures, print IDs (filtered by `--tag`)
- `Describe`: load one fixture, pretty-print its JSON

### 5.5 — Fixture loader (CONF-005, CONF-006)

`crates/aitp-conformance/src/fixture/loader.rs`:

```rust
pub fn load_dir(dir: &Path) -> Result<Vec<Fixture>, std::io::Error> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        if path.file_name().and_then(|s| s.to_str()) == Some("README.md") {
            continue;  // shouldn't be a json file but be safe
        }
        let bytes = std::fs::read(&path)?;
        let fixture: Fixture = serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData,
                format!("{}: {}", path.display(), e)))?;
        out.push(fixture);
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}
```

Multi-step `sequence` form is already in the type definitions (Phase 0
scaffold). Verify it parses.

### 5.6 — Output formatters (CONF-007)

`crates/aitp-conformance/src/runner/output.rs`:

Three formats:

- **`OutputFormat::Text`** — colored: `✓` (green), `✗` (red), `⊘`
  (yellow). Print one line per fixture: `{symbol} {id} [{duration_ms}ms]`.
  On failure, print indented `expected: ...` and `got: ...`. Use
  `colored` crate? — only if already in workspace. Otherwise use raw
  ANSI escape codes (10 lines of helpers).
- **`OutputFormat::Json`** — one JSON object per fixture result, all
  collected at the end into an array. Useful for piping to `jq`.
- **`OutputFormat::Tap`** — TAP 13 format. Each fixture is one
  `ok N - id` or `not ok N - id` line. Final line `1..N`. CI integrates
  directly.

### 5.7 — Runner executor (extends scaffold)

Replace the TODO in `crates/aitp-conformance/src/runner/executor.rs`.

The executor:

```rust
impl<A: Adapter> Runner<A> {
    pub fn run(&mut self, fixture: &Fixture) -> FixtureResult {
        let started = Instant::now();

        // Apply preconditions if any
        if let Err(e) = self.apply_preconditions(&fixture.preconditions) {
            return FixtureResult::Fail {
                id: fixture.id.clone(),
                reason: format!("precondition failed: {}", e),
                duration_ms: started.elapsed().as_millis() as u64,
            };
        }

        // Dispatch single vs sequence
        let outcome = match &fixture.input.variant {
            FixtureInputVariant::Single(params) => {
                self.run_single(params, fixture.expected.as_ref())
            }
            FixtureInputVariant::Sequence { sequence } => {
                self.run_sequence(sequence)
            }
        };

        let duration_ms = started.elapsed().as_millis() as u64;
        match outcome {
            Ok(()) => FixtureResult::Pass { id: fixture.id.clone(), duration_ms },
            Err(reason) => FixtureResult::Fail {
                id: fixture.id.clone(),
                reason,
                duration_ms,
            },
        }
    }
}
```

`run_single` extracts the `operation` field from params, calls
`adapter.execute`, compares against `expected.outcome` and
`expected.error_code`.

`run_sequence` runs each step in order against the same adapter
instance. If any step's expected outcome is "failure", that step's
error must match the per-step `expected.error_code`. Don't abort the
sequence on first failure — run all steps so the report is complete.

### 5.8 — Integration test

Create `crates/aitp-conformance/tests/runner_integration.rs`:

A test that:
1. Builds the `aitp-rs-adapter` binary (use `cargo` or assume already
   built; `escargot` crate would help but probably not in deps; use
   `Command::new("cargo").args(["build", "-p", "aitp-rs-adapter"])`
   in the test setup, or document the binary must be pre-built)
2. Spawns it as a `SubprocessAdapter`
3. Runs a small set of hand-crafted in-test fixtures (don't depend on
   the spec repo for this test — keep it self-contained)
4. Asserts pass/fail expectations match

This test exercises the full conformance machinery end-to-end.

---

## Format, lint, tests

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p aitp-conformance
cargo test -p aitp-conformance --test runner_integration
```

Then a manual smoke test:

```sh
cargo build --release -p aitp-rs-adapter
cargo run -p aitp-conformance -- run \
  --target ./target/release/aitp-rs-adapter \
  --fixtures-dir <path to spec repo's schemas/conformance>
```

Should run without crashing. Whether all fixtures pass depends on the
spec fixtures' AID format (Phase 0 of the spec work was to fix
placeholder AIDs to be 43 chars). If many fixtures fail because they
have malformed AIDs, that's a spec-side issue (SPEC-001) not an
implementation issue. Document what fails and why in the report.

---

## Update PENDING.md

Check off CONF-001 through CONF-007.

---

## Phase report

`phase-5-report.md`. Include:
- Output of running the conformance suite against the Rust adapter
  (paste a representative slice)
- Pass/fail/skip breakdown
- Any operations that turned out to be hard to map to the existing
  protocol crates
- Whether `wait-timeout`-style logic worked or required a thread
- Decisions about clock override mechanism
- Any fixtures that failed for spec-side reasons (e.g. malformed AIDs)

---

## Success gate

- All conformance crate tests pass
- `aitp-rs-adapter` runs and responds to all op types
- The runner can execute the full fixture set and produce a coherent
  report (even if some fixtures fail for spec-side reasons)
- Clippy clean across the workspace

## Stop here.
