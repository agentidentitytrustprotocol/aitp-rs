# `aitp::transport` — hardening register

> Status tracker for the `aitp::transport` subsystems: what each module
> does, which RFC governs it, and what is still open. Operator-facing
> guidance (what to turn on in production) is in
> [`deployment.md`](deployment.md).
>
> `aitp::transport` is the **only async module** of `aitp`
> (`reqwest`/`axum`/`tokio`); the protocol modules stay sync. Its features,
> all on the `aitp` crate: `http-client` (default), `http-server` (implies
> `http-client` and `source-ip`), `source-ip`, `client-spki-pinning`
> (implies `http-client`; off by default), `metrics` and `all`.
> The Session Trust Bundle and TCT renewal endpoints live in
> `aitp-experimental`, behind that crate's `http-server` feature.
>
> Status legend: **scaffolded** (compiles, thin) · **tested** (unit/integration
> coverage) · **documented** (rustdoc + usage notes) · **done** (tested +
> documented).

## Subsystems

| Module | Purpose | RFC | Status | Remaining / notes |
|---|---|---|---|---|
| `client.rs` | `ManifestFetcher` (HTTPS-only Manifest fetch, expiry-bounded per-AID cache, optional retry) and `JwksFetcher` | 0003 / 0007 | done | Cache honors `published_at`/`expires_at`; no HTTP validators (`ETag`/`If-None-Match`). Retry defaults to `RetryPolicy::none()`. `http://localhost` / `127.0.0.1` accepted only after `with_insecure_localhost(true)`; the default is `false`. JWKS network resolution follows RFC-AITP-0007 §2.3: OIDC discovery first, `/.well-known/aitp-keys` only when discovery is not validly exposed. |
| `client_config.rs` | Connection-pool + TLS knobs per fetcher | — | done | Rustdoc example for pool sizing (`with_pool_max_idle_per_host`). |
| `net_guard.rs` | SSRF `HostGuard` on peer-derived fetches (Manifest, JWKS/discovery/`aitp-keys`, facade handshake/renew): redirect-block, resolved-address classification (link-local/metadata always denied; private ranges per mode), DNS-rebind-safe address pinning | 0009 | done | `HostGuard::default()` is `GuardMode::WarnPrivate`; internet-facing deployments call `.with_host_guard(HostGuard::strict())` (`GuardMode::DenyPrivate`). `HostGuard::permissive()` (`GuardMode::AllowAll`) for air-gapped/test networks. |
| `replay_store.rs` | Pluggable `ReplayGuard` (`InMemoryReplayGuard` default) for envelope `message_id` dedup | 0001 §5.5 | done | `check_and_record(key, ttl)` maps to Redis `SET NX EX`; supply a shared backend for clustered deployments (`HandshakeServer::with_replay_guard`). |
| `key_resolution.rs` | `KeyResolutionPolicy`: cache → pinned issuer store → network (`JwksFetcher::resolve`), with fail modes | 0007 | done | The sync `JwksResolver::resolve` bridges to the network only on a **multi-thread** Tokio runtime; on a current-thread runtime it returns `ResolveError::NetworkError` — use `AsyncJwksResolver::resolve_async` (e.g. to pre-warm the cache) or the pinned store. `SoftFail` fails closed on `resolve()`; degraded state only via `resolve_outcome()`. |
| `retry.rs` | Exponential backoff + jitter for idempotent outbound reads | — | done | Jitter strategy + max-attempts are configurable; keep retries to idempotent GETs only. |
| `revocation.rs` | `RevocationCache` + `RevocationProvider`, per-issuer cache, fail modes; `EmptyRevocationProvider` for tests/dev | 0008 | done | Snapshot member-set and shape failures surface as `RevocationError::UnknownField` / `Malformed` (the `REVOCATION_SNAPSHOT_INVALID` case, RFC-AITP-0008 §1.5; an unknown `version` is `Malformed` too, #265), distinct from `SignatureInvalid`. Keep `RevocationFailMode` default = fail-closed. |
| `server.rs` | `ManifestServer` + `HandshakeServer` (hello/commit), `RevocationListProducer` | 0003 / 0004 / 0009 | done | Hello/commit run replay → rate limit → timestamp (RFC-AITP-0009 §3.1). Manifest structural failures map to `MANIFEST_INVALID`; unknown members to `UNKNOWN_FIELD`. Rate limiting is on by default at the RFC-AITP-0009 §3.1 values; `DEFAULT_MAX_SESSIONS` is the §3.1 1 000; `serve()` starts a background session sweeper (`without_session_sweeper()` opts out). **Open:** the body cap is above the §3.1 recommendation (see [deployment](deployment.md#known-limitations)). Producer must never mint a fresh empty list on backing-store failure. |
| `server_limits.rs` | Request body-size cap (axum-level) + header recommendations | 0009 | done | Document how the cap composes with `axum::DefaultBodyLimit`. |
| `tls_pinning.rs` | SHA-256 SPKI pinning for outbound HTTPS | RFC 7469 | done | Behind `client-spki-pinning` (off by default — avoids pulling a rustls `CryptoProvider`). Rustdoc covers `compute_spki_hash` and a `reqwest` integration example. |
| `aitp_experimental::session_bundle::server` | Session Trust Bundle HTTP transport (§4.3.1) — in-memory store, no verification | 0010 (Draft, opt-in) | tested | In `crates/aitp-experimental/src/session_bundle/server.rs`, behind `aitp-experimental/http-server`. Unknown body member → `UNKNOWN_FIELD`; wrapper defect or bare (unwrapped) body → `SESSION_BUNDLE_INVALID`. Advertise the route with `aitp_experimental::session_bundle::advertise_bundle_uri` and `SessionBundleServer::bundle_uri` (see [session-bundle](session-bundle.md)). |
| `obs.rs` | Low-cardinality counters at trust-decision points | — | done | Behind `metrics`; metric names in [deployment](deployment.md#transport-hardening-you-should-turn-on). |

## Cross-cutting acceptance criteria

- **Async stays contained.** No async leaks into `aitp::core` / `aitp::tct` /
  `aitp::handshake`. New blocking-bridge points must document the Tokio-context
  requirement (as `key_resolution.rs` does).
- **Fail-closed defaults.** Revocation and key-resolution soft-fail modes must
  fail closed on the plain accessor; degraded state is opt-in via the
  `*_outcome()` variants.
- **Feature minimalism.** Pinning stays behind `client-spki-pinning` so a
  default `http-client` build doesn't pull in a rustls `CryptoProvider`.

## Open items (rolled up)

Nothing is open now.

