# Deployment & clustering

**Audience:** operators and framework authors embedding `aitp-rs`.
**Scope:** where AITP state lives, what is safe to run multi-node with no
coordination, and what needs a shared store or sticky routing.

`aitp-rs` is a **library**, not a runtime. It never persists anything to
disk on its own and holds no global state. Whether any state exists at
all depends on *which layer you use*.

## The one rule

> **The verification/signing core is stateless. Only the optional
> `aitp::transport` *server* (`http-server`) keeps state — and of that, only the
> replay deny-list carries a correctness guarantee at scale.**

Everything below is a consequence of that rule.

## What holds state, and what to do about it

| Layer / state | Stateful? | Multi-node story |
|---|---|---|
| `aitp::core`, `aitp::crypto`, `aitp::tct`, `aitp::delegation`, `aitp::handshake`, `aitp::manifest`, `aitp::envelope` | **No** | Pure functions. Verify/sign take inputs and return outputs; revocation is a caller-supplied callback. Run as many instances as you like — nothing to share. |
| **Replay deny-list** (envelope `message_id`) | Yes | **Supply a shared [`ReplayGuard`](../crates/aitp/src/transport/replay_store.rs) or use sticky routing.** This is the one place per-node in-memory state silently weakens a guarantee at scale — see below. |
| **In-flight handshake sessions** | Yes | **Use sticky routing.** A handshake is a ~tens-of-ms, 4-message conversation holding live state; it is not a shared-store problem. The built-in `max_sessions` cap and session TTL, plus an opt-in sweeper, bound per-node memory. See below. |
| Manifest cache, OIDC discovery cache, JWKS (positive + negative) cache, revocation-snapshot cache | Yes (caches) | **Nothing to do.** All are re-fetchable and TTL-bounded. A cache miss just re-fetches; there is no correctness impact from not sharing them, so they are deliberately in-memory and not pluggable. |
| Facade `TctStore` (held TCTs) | Yes | Client-side convenience your code already owns — hold/replace it as you see fit. |

## Replay detection — the one that matters at scale

AITP rejects replays by remembering each envelope `message_id` for a
freshness window (RFC-AITP-0001 §5.5). The default store is **per-process**:

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
   let server = HandshakeServer::new(/* … */).with_replay_guard(guard);
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
  `DEFAULT_MAX_SESSIONS` = 1 000, the RFC-AITP-0009 §3.1 recommended
  maximum of concurrent in-flight sessions; raise it for high-volume
  responders.
- Session TTL — half-finished sessions expire after `DEFAULT_SESSION_TTL`
  (60 s). Change it with `HandshakeServer::with_session_ttl(Duration)`.
  The replay deny list remembers each `message_id` for
  `DEFAULT_REPLAY_WINDOW` (300 s); change it with
  `HandshakeServer::with_replay_window(Duration)`.
- Expired sessions are swept on every HELLO and COMMIT, and by a
  background sweeper that `serve()` starts every
  `DEFAULT_SESSION_SWEEP_INTERVAL` (30 s), so a burst that goes quiet
  doesn't hold memory until the next request. Change the period with
  `.with_session_sweep_interval(d)` or turn it off with
  `.without_session_sweeper()`. A router from `into_router()` (feature
  `experimental-axum`) starts it too; built outside a Tokio runtime, it
  starts the sweeper with the first HELLO. The task holds only a
  weak reference and exits once the server state is dropped.

There is deliberately **no** shared session store: it would require
serializing the handshake state machine and buys nothing that sticky
routing does not, for a conversation this short-lived.

## Transport hardening you should turn on

Independent of clustering, production servers/clients should set:

- **SSRF guard** on peer-derived fetches — `ManifestFetcher`,
  `JwksFetcher`, `RevocationFetcher` and `InitiatorConfig` default to
  `HostGuard::default()`, i.e. `GuardMode::DenyPrivate` (link-local/metadata
  and private ranges denied). An intranet deployment whose peers or IdP
  live on private addresses calls
  `.with_host_guard(HostGuard::new(GuardMode::WarnPrivate))` (allowed,
  logged). (See [`transport-hardening.md`](transport-hardening.md).)
- **Revocation list (`ListRevoked`)** — required of every TCT issuer
  (RFC-AITP-0005 §11, RFC-AITP-0008 §1.4). `HandshakeServer::router`
  always serves it at `REVOCATION_LIST_PATH`. Without a
  `RevocationListProducer` it serves an empty snapshot signed by the
  server key, re-signed every 60 s and valid for an hour. That snapshot
  says "nothing is revoked", so once you can revoke, attach a producer
  backed by your deny list. Advertise the absolute HTTPS URL in the signed
  Manifest with `ManifestBuilder::revocation_list_uri(origin.join(REVOCATION_LIST_PATH)?)`;
  the server logs a warning when the key is missing. On the consumer side,
  `RevocationFetcher::prepare` fetches the advertised URL (or reads a
  `RevocationProvider` set with `with_provider`) and caches the verified
  snapshot. A
  Manifest without the key is still accepted: revocation for that issuer
  is treated as unavailable and the configured `RevocationFailMode`
  applies (RFC-AITP-0008 §3). The default is `fail_closed`, so
  `HandshakeServer` and `run_initiator_handshake` refuse such a peer with
  `TCT_REVOKED`; set `RevocationFailMode::FailOpen` through
  `with_revocation_policy` only for a peer you accept without revocation.
  `RevocationFailMode::FailOpenIfUnadvertised` is narrower: it accepts
  only an issuer whose verified Manifest advertises no list, logging each
  acceptance at info, and still refuses one whose advertised list can't
  be fetched or verified. It suits a responder that authorises nothing
  with the TCTs it receives, like the interop peer
  ([interop-peer.md](interop-peer.md)).
- **Strict TCT verification** — `TctVerifyContext::builder()` refuses
  to construct until the revocation and issuer-Manifest expiry-cap
  decisions are made (RFC-AITP-0005 §10.4, RFC-AITP-0008). Supply a
  revocation hook and the cap; a hook that cannot answer returns
  `TctError::RevocationUnavailable` (wire code `TCT_REVOKED`).
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
  at the edge and call `.without_rate_limit_dangerous()` only if that edge keys on
  the transport source. The spec's defaults and check order are in
  [RFC-AITP-0009 §3.1](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0009-security.md#31-rate-limiting).
- **HTTPS everywhere** — the fetchers reject non-HTTPS URLs
  (RFC-AITP-0003 §4.1). `ManifestFetcher` and `RevocationFetcher` accept
  `http://localhost` / `http://127.0.0.1` only after
  `.with_insecure_localhost_dangerous()` (and the facade only after
  `InitiatorConfig::with_insecure_localhost_dangerous()`). The same call
  admits loopback addresses (`127.0.0.0/8`, `::1`), and only those,
  through the host guard (`HostGuard::allow_loopback_dangerous`). Never
  enable it in production.
- **Observability** — the optional `metrics` feature on
  `aitp` emits low-cardinality counters via the
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

`HandshakeServer` and fetcher defaults that fall short of the RFCs:

- **The body limit is looser than RFC-AITP-0009 §3.1 recommends.**
  `DEFAULT_MAX_BODY_BYTES` is 256 KiB (RFC: 64 KB for `MUTUAL_HELLO`).
  That is a RECOMMENDED value, so this is a weaker default, not a
  violation.

## Summary

Run the pure core at any scale with nothing shared. If you deploy the
`aitp::transport` **server** across multiple nodes, either use sticky
routing or inject a shared `ReplayGuard`; sessions want sticky routing
regardless. The performance caches need no attention. `aitp-rs` supplies
the seams and sensible in-memory defaults — the storage and topology
decisions are the embedding framework's to make.
