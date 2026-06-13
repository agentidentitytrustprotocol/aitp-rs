# AITP examples

Runnable examples and integration references for `aitp-rs`. Everything
here runs offline — no external IdP, no network beyond `localhost`.

| Directory | What it is |
|---|---|
| [`two-agents/`](two-agents/) | The main demo crate: a full Mutual Handshake + `demo.echo` exchange between two agents, plus standalone binaries for OIDC, revocation, TCT renewal, and delegation. Start here. |
| [`observability/`](observability/) | An operator reference — the `tracing` spans/events `aitp-rs` emits and a companion Grafana dashboard (`grafana-dashboard.json`) for wiring them into a metrics/log pipeline. |

## Quick start

```sh
# The two-agent handshake (built on the high-level facade/server API):
make demo

# A standalone demo, e.g. single-hop delegation:
cargo run -p aitp-example-two-agents --bin delegation-demo
```

See [`two-agents/README.md`](two-agents/README.md) for the full list of
binaries, what each demonstrates, and where to look in the code.

## Which API level should I copy?

- **Most integrations** — use the high-level API the `agent-a`/`agent-b`
  demo is built on: `aitp::facade::run_initiator_handshake` (client) and
  `aitp::transport::HandshakeServer` (server).
- **Fine-grained control** — drive `aitp::handshake::{Initiator,
  Responder}` directly, as `oidc-demo` does.
- **Verify-only** (you already hold a TCT) — depend on `aitp-tct` +
  `aitp-crypto` alone and call `aitp::tct::verify_tct`.
