# AITP Observability — Tracing fields and dashboard example

Reference for operators wiring `aitp-rs`'s `tracing` output into a
metrics/log pipeline. Pair with the JSON dashboard in this directory
(`grafana-dashboard.json`).

## How `aitp-rs` emits

Library crates use `tracing::debug!` / `warn!` only — no subscriber is
installed. Your binary picks one. The minimal install:

```rust
fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,aitp=debug".into()),
        )
        .json() // structured output for Loki/Splunk/etc.
        .init();

    // ... rest of your service
}
```

For metric scraping (Prometheus via OTLP exporter), prefer
`tracing-opentelemetry` plus `opentelemetry-otlp` to convert spans
into traces/metrics.

## First-class metrics (`metrics` feature)

Beyond the tracing events above, `aitp-transport-http` emits counters at
the operational trust-decision points when built with the `metrics`
feature. They route through the [`metrics`](https://docs.rs/metrics)
facade — zero-cost until you install a recorder in your binary:

```toml
aitp-transport-http = { version = "0.4", features = ["server", "metrics"] }
metrics-exporter-prometheus = "0.16"
```

```rust
let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
    .install_recorder()?;
// expose `handle.render()` on your /metrics endpoint
```

| Metric | Type | Labels | Fires when |
|---|---|---|---|
| `aitp_replay_rejected_total` | counter | — | an envelope `message_id` is rejected as a replay (RFC-AITP-0001 §5.5) |
| `aitp_handshake_total` | counter | `stage`=hello\|commit, `result`=ok\|rejected | a handshake message reaches a terminal outcome |
| `aitp_sessions_evicted_total` | counter | — | in-flight sessions are evicted to hold the max-sessions cap (HELLO-flood pressure) |
| `aitp_revocation_cache_total` | counter | `outcome`=hit\|miss\|stale\|refresh | a revocation-snapshot cache lookup resolves |
| `aitp_jwks_cache_total` | counter | `outcome`=hit\|miss\|negative_hit | a JWKS/key-resolution cache lookup resolves |

Label values are bounded, low-cardinality enums by design — no AIDs,
session ids, or message ids appear as labels (those stay in trace
fields; see the cardinality note at the end of this doc).

Useful derived signals: handshake reject rate
(`aitp_handshake_total{result="rejected"}` / total), replay-attack
pressure (`rate(aitp_replay_rejected_total)`), cache effectiveness
(`hit / (hit+miss)` for either cache), and revocation staleness
(`rate(aitp_revocation_cache_total{outcome="stale"})` — a nonzero rate
means consumers are seeing snapshots past `max_staleness_secs`).

## Spans (one per request)

| Span name | Crate | Fields |
|---|---|---|
| `fetch` | `aitp-transport-http::client` (`ManifestFetcher::fetch`) | `origin` |
| `resolve` | `aitp-transport-http::client` (`JwksFetcher::resolve`) | `issuer` |
| `handle_renew` | `aitp-transport-http::server` | (request-scoped) |

Add `aid`, `session_id`, `message_id` as span fields on outer
caller spans for end-to-end traceability.

## Events (structured logs)

Every event line below has a stable `target` or message, suitable
as a Grafana / Datadog log query.

### Manifest cache

| Message | Fields | Where |
|---|---|---|
| `manifest cache hit` | `aid` | `client.rs::cached` |
| `manifest cache miss` | `aid` | `client.rs::cached` |
| `manifest fetch transient error; retrying` | `attempt`, `error` | `client.rs::fetch` |
| `manifest fetch succeeded after retry` | `attempt` | `client.rs::fetch` |

### JWKS resolution

| Message | Fields | Where |
|---|---|---|
| `JWKS resolved` | `issuer`, `source = cache \| pinned_store \| network` | `key_resolution.rs` |
| `JWKS resolved (after lock)` | `issuer`, `source = cache` | `key_resolution.rs` |
| `JWKS kid miss; invalidating discovery cache and refetching` | `kid`, `issuer` | `client.rs::resolve_with_kid_hint` |
| `skipping malformed root CA PEM` | `error` | `client_config.rs` |

### Revocation

| Message | Fields | Where |
|---|---|---|
| `revocation check` | `jti`, `issuer`, `outcome = clear \| revoked \| soft_fail_safe_subset`, `safe_grant_count?` | `revocation.rs::check` |
| `revocation check failed closed` | `jti`, `issuer`, `error` | `revocation.rs::check` |

### Handshake state machine

| Message | Fields | Where |
|---|---|---|
| `handshake start (Initiator → AwaitingHelloAck)` | `initiator_aid`, `peer_aid`, `session_id` | `state_machine.rs::Initiator::start` |
| `Initiator: AwaitingHelloAck → AwaitingCommitAck` | `session_id`, `message_id` | `Initiator::on_hello_ack` |
| `Initiator: AwaitingCommitAck → Done` | `message_id` | `Initiator::on_commit_ack` |
| `Responder: Initial → AwaitingCommit` | `responder_aid`, `initiator_aid`, `message_id` | `Responder::on_hello` |
| `Responder: AwaitingCommit → Done` | `message_id` | `Responder::on_commit` |

### Server hygiene

| Message | Target | Fields |
|---|---|---|
| `swept expired handshake sessions` | (default) | `evicted` |
| `AITP error envelope returned` | `aitp.error.envelope` | `code`, `status`, `message` |

### Outbound HTTP retry

| Message | Fields |
|---|---|
| `manifest fetch retry sleep` | `delay`, `attempt` |

## Suggested Grafana panels

The companion `grafana-dashboard.json` defines:

1. **Error envelope rate by code** — `count_over_time({target="aitp.error.envelope"}[5m])` grouped by `code`.
2. **Revocation outcome split** — log query on `outcome` field.
3. **JWKS resolution source** — split between `cache`, `pinned_store`, `network` reveals cache effectiveness.
4. **Manifest cache hit ratio** — `count(message="manifest cache hit") / (hit + miss)`.
5. **Handshake state-transition latency** — derive from span durations on `fetch` + `resolve`.
6. **Retry pressure** — count of `manifest fetch transient error; retrying`.

## Cardinality guidance

`session_id` and `message_id` are UUIDv4s — never use them as label
keys in Prometheus/metrics. They're fine in log/trace fields. Use
`code` (32 fixed strings), `outcome` (3 values), and `source` (3
values) for label-cardinality-bounded metrics.

## Server request limits

Two caps to apply when running an AITP HTTP server: request body
size and HTTP header size. Recommended defaults are exported from
`aitp_transport_http::server_limits`:

| Knob | Default | Constant |
|---|---|---|
| Request body | 64 KiB | `DEFAULT_REQUEST_BODY_LIMIT` |
| HTTP header buffer | 16 KiB | `RECOMMENDED_MAX_HEADER_BYTES` |

### Body limit (router-level, axum-native)

Wrap the router with `with_request_body_limit_default`:

```rust
use aitp_transport_http::{
    HandshakeServer,
    with_request_body_limit_default,
};

let router = with_request_body_limit_default(server.router());
axum::serve(listener, router).await?;
```

Tune up for revocation-list uploads (which scale with the number of
revoked JTIs); 256 KiB is a reasonable ceiling.

### Header limit (hyper-builder level)

axum 0.7 does not expose a knob for the header buffer; it inherits
hyper's defaults. To cap headers, drop down to `hyper-util` and
launch each connection through a configured
`hyper::server::conn::http1::Builder`:

```rust
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tower::Service;
use aitp_transport_http::RECOMMENDED_MAX_HEADER_BYTES;

let listener = TcpListener::bind("0.0.0.0:8080").await?;
let app = my_router();

loop {
    let (stream, _) = listener.accept().await?;
    let io = TokioIo::new(stream);
    let mut app = app.clone();
    tokio::spawn(async move {
        let svc = hyper::service::service_fn(move |req| {
            let mut app = app.clone();
            async move { app.call(req).await }
        });
        http1::Builder::new()
            .max_buf_size(RECOMMENDED_MAX_HEADER_BYTES)
            .serve_connection(io, svc)
            .await
            .ok();
    });
}
```

Headers larger than `max_buf_size` cause hyper to terminate the
connection before the request reaches the application — no
attacker-controlled bytes touch axum's parser.
