# Deployment & clustering

**Audience:** operators and framework authors embedding `aitp-rs`.
**Scope:** where AITP state lives, what is safe to run multi-node with no
coordination, and what needs a shared store or sticky routing.

`aitp-rs` is a **library**, not a runtime. It never persists anything to
disk on its own and holds no global state. Whether any state exists at
all depends on *which layer you use*.

## The one rule

> **The verification/signing core is stateless. Only the optional
> `aitp-transport-http` *server* keeps state — and of that, only the
> replay deny-list carries a correctness guarantee at scale.**

Everything below is a consequence of that rule.

## What holds state, and what to do about it

| Layer / state | Stateful? | Multi-node story |
|---|---|---|
| `aitp-core`, `aitp-crypto`, `aitp-tct`, `aitp-delegation`, `aitp-handshake`, `aitp-manifest`, `aitp-envelope` | **No** | Pure functions. Verify/sign take inputs and return outputs; revocation is a caller-supplied callback. Run as many instances as you like — nothing to share. |
| **Replay deny-list** (envelope `message_id`, DPoP `jti`) | Yes | **Supply a shared [`ReplayGuard`](../crates/aitp-transport-http/src/replay_store.rs) or use sticky routing.** This is the one place per-node in-memory state silently weakens a guarantee at scale — see below. |
| **In-flight handshake sessions** | Yes | **Use sticky routing.** A handshake is a ~tens-of-ms, 4-message conversation holding live state; it is not a shared-store problem. The built-in `max_sessions` + TTL + sweeper bound per-node memory. See below. |
| Manifest cache, OIDC discovery cache, JWKS (positive + negative) cache, revocation-snapshot cache | Yes (caches) | **Nothing to do.** All are re-fetchable and TTL-bounded. A cache miss just re-fetches; there is no correctness impact from not sharing them, so they are deliberately in-memory and not pluggable. |
| Facade `TctStore` (held TCTs) | Yes | Client-side convenience your code already owns — hold/replace it as you see fit. |

## Replay detection — the one that matters at scale

AITP rejects replays by remembering a one-time value for a freshness
window: envelope `message_id`s (RFC-AITP-0001 §5.5) and DPoP `jti`s
(RFC 9449). The default store is **per-process**:

```
                 ┌── node A ──┐        client replays the same
   client ──────▶│ sees mid X │        signed envelope, but the LB
                 │ records X  │        routes the retry to node B ──┐
                 └────────────┘                                     │
                 ┌── node B ──┐  ◀───────────────────────────────── ┘
                 │ mid X not  │        node B has never seen X →
                 │ in its map │        ACCEPTED  ✗  (replay bypass)
                 └────────────┘
```

Behind a load balancer with round-robin (or any non-sticky) routing, a
replay sent to a *different* node is accepted, because the first node
holds the record. Two fixes:

1. **Shared `ReplayGuard`** — implement the trait against a store all
   nodes see (Redis `SET key val NX EX <ttl>` is a direct match for the
   `check_and_record(key, ttl)` shape) and inject it:

   ```rust
   let guard: Arc<dyn ReplayGuard> = Arc::new(MyRedisReplayGuard::new(pool));
   let server = HandshakeServer::new(/* … */).with_replay_guard(guard.clone());
   // Share the SAME guard with DPoP so both replay checks hit one backend:
   let dpop_cache = DpopReplayCache::with_guard(guard, Duration::from_secs(300));
   ```

   `aitp-rs` ships only the trait and the in-memory default; the storage
   choice (Redis, a database, an in-cluster service) is yours.

2. **Sticky routing** — pin each client to one node for the replay
   window. Simpler, no shared store, but the deny-list is only as
   coherent as your session affinity.

The default `InMemoryReplayGuard` is correct and sufficient for a
**single-node** deployment.

## Handshake sessions — use sticky routing

The responder keeps in-flight handshake state (`HandshakeServer`
`sessions`) between `MUTUAL_HELLO` and `MUTUAL_COMMIT`, correlated by the
`X-Aitp-Session-Id` header. This is *live* state — nonces, the peer's
verified key and identity, captured manifest fields — not a serializable
token. The right multi-node answer is **sticky routing**: keep a client's
HELLO and COMMIT on the same node. A handshake completes in tens of
milliseconds, so affinity for that window is cheap.

Per-node memory is bounded out of the box:

- `with_max_sessions(n)` — oldest-first eviction once `n` in-flight
  sessions are held (defends against a HELLO flood); default 10 000.
- `with_session_ttl(d)` — half-finished sessions are swept after `d`;
  default 60 s.
- A background sweeper (default every 30 s) reclaims expired sessions
  even without traffic.

There is deliberately **no** shared session store: it would require
serializing the handshake state machine and buys nothing that sticky
routing does not, for a conversation this short-lived.

## Transport hardening you should turn on

Independent of clustering, production servers/clients should set:

- **SSRF guard** on peer-derived fetches — `ManifestFetcher` and
  `JwksFetcher` default to `HostGuard::WarnPrivate`; call
  `.with_host_guard(HostGuard::strict())` on internet-facing deployments
  where no legitimate peer/IdP host is on a private network, and
  `.with_insecure_localhost(false)` to drop the dev exception. (See
  [`transport-hardening.md`](transport-hardening.md).)
- **Strict TCT verification** — build `TctVerifyContext` via
  `::builder(...)` and supply a revocation source and the issuer-Manifest
  expiry cap, rather than the permissive `::now()` / `::permissive_at()`
  shortcuts. The builder refuses to construct until both decisions are
  made (RFC-AITP-0005 §10.4, RFC-AITP-0008).
- **Rate limiting** — `with_rate_limit(...)` (RFC-AITP-0009 §3.1). Note
  the rate-limit counters are also per-node; for hard global limits,
  enforce at the edge/LB.
- **HTTPS everywhere** — the fetchers reject non-HTTPS peers by default;
  keep it that way outside local dev.
- **Observability** — the optional `metrics` feature on
  `aitp-transport-http` emits low-cardinality counters via the
  [`metrics`](https://docs.rs/metrics) facade (`aitp_handshake_total`,
  `aitp_replay_rejected_total`, `aitp_sessions_evicted_total`,
  `aitp_revocation_cache_total`, `aitp_jwks_cache_total`); see
  [`examples/observability/`](../examples/observability/README.md) for
  tracing/dashboard wiring.
- **Key handling** — see [`key-management.md`](key-management.md) for seed
  storage, in-memory hygiene, KMS/HSM reality, and the rotation runbook.

## Summary

Run the pure core at any scale with nothing shared. If you deploy the
`aitp-transport-http` **server** across multiple nodes, either use sticky
routing or inject a shared `ReplayGuard`; sessions want sticky routing
regardless. The performance caches need no attention. `aitp-rs` supplies
the seams and sensible in-memory defaults — the storage and topology
decisions are the embedding framework's to make.
