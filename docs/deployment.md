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
| **In-flight handshake sessions** | Yes | **Use sticky routing.** A handshake is a ~tens-of-ms, 4-message conversation holding live state; it is not a shared-store problem. The built-in `max_sessions` cap and session TTL, plus an opt-in sweeper, bound per-node memory. See below. |
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

Per-node memory is bounded, partly out of the box and partly by you:

- `with_max_sessions(n)` — oldest-first eviction once `n` in-flight
  sessions are held (defends against a HELLO flood). Default
  `DEFAULT_MAX_SESSIONS` = 10 000; RFC-AITP-0009 §3.1 recommends at most
  1 000 concurrent in-flight sessions, so set it explicitly.
- Session TTL — half-finished sessions expire after `DEFAULT_SESSION_TTL`
  (60 s). To change it, construct the server with
  `HandshakeServer::with_session_ttl(...)`, a constructor that takes
  `new`'s arguments plus the TTL (it is not a builder method).
- Expired sessions are swept on the next HELLO or COMMIT. **No background
  sweeper runs unless you start one**: call
  `server.spawn_session_sweeper(interval)` from inside a Tokio runtime
  (`DEFAULT_SESSION_SWEEP_INTERVAL` is 30 s) so a burst that goes quiet
  doesn't hold memory until the next request
  ([#198](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/198)).

There is deliberately **no** shared session store: it would require
serializing the handshake state machine and buys nothing that sticky
routing does not, for a conversation this short-lived.

## Transport hardening you should turn on

Independent of clustering, production servers/clients should set:

- **SSRF guard** on peer-derived fetches — `ManifestFetcher` and
  `JwksFetcher` default to `HostGuard::default()`, i.e.
  `GuardMode::WarnPrivate` (link-local/metadata always denied, private
  ranges logged but allowed). Call `.with_host_guard(HostGuard::strict())`
  (`GuardMode::DenyPrivate`) on internet-facing deployments where no
  legitimate peer/IdP host is on a private network. (See
  [`transport-hardening.md`](transport-hardening.md).)
- **Strict TCT verification** — build `TctVerifyContext` via
  `::builder(...)` and supply a revocation source and the issuer-Manifest
  expiry cap, rather than the permissive `::now()` / `::permissive_at()`
  shortcuts. The builder refuses to construct until both decisions are
  made (RFC-AITP-0005 §10.4, RFC-AITP-0008).
- **Rate limiting** — on by default since 0.14, at the RFC-AITP-0009 §3.1
  recommended 30 requests per source and 10 per sender AID per 60 s
  (`RateLimitConfig::default()`). The source is the socket peer, so serve
  the router with `into_make_service_with_connect_info::<SocketAddr>()`;
  without connect info every request shares one bucket. Behind a reverse
  proxy, list it in `trusted_proxies` (addresses or CIDRs): only then are
  `X-Forwarded-For` (rightmost untrusted hop) and `X-Real-IP` read.
  IPv6 sources are keyed by /64. The per-AID key is the
  still-unauthenticated envelope `sender`, so it is only ever an extra
  limit on top of the transport key, as §3.1 requires. The hello/commit
  handlers apply the §3.1 check order: replay deny list, then rate limit,
  then timestamp. Counters are per node; for hard global limits, enforce
  at the edge and call `.without_rate_limit()` only if that edge keys on
  the transport source. The spec's defaults and check order are in
  [RFC-AITP-0009 §3.1](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0009-security.md#31-rate-limiting).
- **HTTPS everywhere** — the fetchers reject non-HTTPS URLs, except that
  `ManifestFetcher` accepts `http://localhost` / `http://127.0.0.1` by
  default. Call `.with_insecure_localhost(false)` in production.
- **Observability** — the optional `metrics` feature on
  `aitp-transport-http` emits low-cardinality counters via the
  [`metrics`](https://docs.rs/metrics) facade (`aitp_handshake_total`,
  `aitp_replay_rejected_total`, `aitp_sessions_evicted_total`,
  `aitp_revocation_cache_total`, `aitp_jwks_cache_total`), and with
  `pinned-admission` also `aitp_admission_challenge_total`,
  `aitp_admission_admit_total` and `aitp_admission_nonces_outstanding`; see
  [`examples/observability/`](../examples/observability/README.md) for
  tracing/dashboard wiring.
- **Key handling** — see [`key-management.md`](key-management.md) for seed
  storage, in-memory hygiene, KMS/HSM reality, and the rotation runbook.

## Known limitations

`HandshakeServer` and fetcher defaults that fall short of the RFCs, tracked
in [#198](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/198)
(file paths under `crates/aitp-transport-http/src/`):

- **Session and body limits are looser than RFC-AITP-0009 §3.1
  recommends.** `DEFAULT_MAX_SESSIONS` is 10 000
  (`server.rs:50`; RFC: 1 000). `DEFAULT_MAX_BODY_BYTES` is 256 KiB
  (`server.rs:266`; RFC: 64 KB for `MUTUAL_HELLO`). These are RECOMMENDED
  values, so this is a weaker default, not a violation.
- **No automatic session sweeper.** `spawn_session_sweeper` (`server.rs:389`)
  is never called by the library; without it, expired sessions are only
  swept when the next HELLO or COMMIT arrives.
- **The renewal replay guard is per process.** With
  `experimental-renewal`, the renewal route records each `pop_nonce` in an
  in-memory store; behind several replicas, pass a shared one with
  `with_renewal_nonce_store` — see [tct-renewal.md](tct-renewal.md#server-handshakeserver).
- **Dev conveniences are on by default.** `ManifestFetcher` sets
  `allow_insecure_localhost: true` (`client.rs:134`), and `HostGuard::default()`
  is `GuardMode::WarnPrivate` (`net_guard.rs:58-66`). Internet-facing
  deployments should call `.with_insecure_localhost(false)` and
  `.with_host_guard(HostGuard::strict())`.

## Summary

Run the pure core at any scale with nothing shared. If you deploy the
`aitp-transport-http` **server** across multiple nodes, either use sticky
routing or inject a shared `ReplayGuard`; sessions want sticky routing
regardless. The performance caches need no attention. `aitp-rs` supplies
the seams and sensible in-memory defaults — the storage and topology
decisions are the embedding framework's to make.
