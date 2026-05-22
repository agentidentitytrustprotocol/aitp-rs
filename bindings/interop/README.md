# AITP cross-language interop tests

Integration tests that prove the **Python** (`aitp-py`) and **Node**
(`aitp-node`) bindings emit wire-compatible AITP envelopes — by running
a real four-message handshake *between the two language runtimes*.

## What it does

`test_interop.py` drives a complete AITP mutual handshake where the two
ends run in different runtimes:

- the **Python** end runs in-process via the `aitp` extension;
- the **Node** end runs in a `node` subprocess (`node_worker.mjs`),
  driven over line-delimited JSON-RPC on stdin/stdout.

Each wire message one binding produces is fed straight into the other.
Both directions are covered:

```
test_python_initiator_node_responder   Python HELLO → Node → mutual TCTs
test_node_initiator_python_responder   Node   HELLO → Python → mutual TCTs
test_node_rejects_python_issued_tct…   cross-language TCT scope rejection
test_python_rejects_node_issued_tct…   cross-language TCT scope rejection
```

A green run means both SDKs canonicalize, sign, and verify identically.

## Running

```bash
make interop          # from the repo root — builds both bindings, then runs
# or
scripts/interop.sh
```

`scripts/interop.sh` creates `.venv/`, `maturin develop`s `aitp-py` into
it, `napi build`s `aitp-node`, then runs `pytest`.

### Running pytest directly

If both bindings are already built into the active environment:

```bash
maturin develop -m ../aitp-py/Cargo.toml
(cd ../aitp-node && npm install && npm run build:debug)
pytest -v
```

The Node tests `skip` if `node` is not on `PATH`.

## Files

| File              | Role                                                    |
|-------------------|---------------------------------------------------------|
| `test_interop.py` | pytest suite — the Python end, plus the test harness    |
| `node_worker.mjs` | the Node end — a JSON-RPC worker over stdio             |
