# aitp — Python SDK

Python bindings for the **Agent Identity & Trust Protocol (AITP)**, built on
the pure-Rust `aitp-rs` protocol crates via [PyO3](https://pyo3.rs).

A thin SDK: an `AitpAgent` plus initiator/responder session objects whose
methods take and return JSON strings — the HTTP request/response bodies — so
agent code never handles a Rust type across the FFI boundary.

## Build

This crate is **not** part of the `aitp-rs` Cargo workspace. Build it with
[maturin](https://github.com/PyO3/maturin):

```bash
pip install maturin
maturin develop          # builds the extension into the active venv
```

## Usage

```python
import aitp

initiator = aitp.AitpAgent.generate()
responder = aitp.AitpAgent.generate()

initiator.build_manifest(
    display_name="initiator",
    handshake_endpoint="http://localhost:8100/aitp/handshake/",
    offered_caps=["demo.echo"],
)
resp_manifest = responder.build_manifest(
    display_name="responder",
    handshake_endpoint="http://localhost:8200/aitp/handshake/",
    offered_caps=["demo.write"],
)

# Four-message mutual handshake — each call's output is the next peer's input.
sess  = initiator.new_session()
rsess = responder.new_responder()

hello                 = sess.build_hello(resp_manifest, ["demo.write"])
hello_ack, session_id = rsess.process_hello(hello)
commit                = sess.process_hello_ack(hello_ack, session_id)
commit_ack, held_tct  = rsess.process_commit(commit)
initiator_held_tct    = sess.complete(commit_ack)

# Each peer now holds a TCT the other issued it.
ident = initiator.verify_tct(initiator_held_tct, "demo.write")
print(ident.peer_aid, ident.grants)
```

In a real deployment each message moves over HTTP: `build_hello` returns the
`POST /aitp/handshake/hello` body, `process_hello` returns the response body
plus the value for the `X-Aitp-Session-Id` header, and so on.

## API

| Type               | Members                                                                                       |
|--------------------|-----------------------------------------------------------------------------------------------|
| `AitpAgent`        | `generate()`, `from_seed(bytes)`, `aid`, `build_manifest(...)`, `new_session()`, `new_responder()`, `verify_tct(tct_json, required_grant)` |
| `InitiatorSession` | `build_hello(peer_manifest, grants)`, `process_hello_ack(ack, session_id)`, `complete(commit_ack)` |
| `ResponderSession` | `process_hello(hello)`, `process_commit(commit)`                                              |
| `TctIdentity`      | `peer_aid`, `grants`, `expires_at`, `jti`                                                     |

## Tests

```bash
maturin develop
pip install pytest
pytest
```

The cross-language interop suite (Python ↔ Node) lives in
[`../interop`](../interop) — run it with `make interop` from the repo root.
