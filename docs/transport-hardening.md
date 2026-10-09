# aitp-transport-http — hardening register

> Status tracker for the `aitp-transport-http` subsystems: what each module
> does, which RFC governs it, and what is still open. Operator-facing
> guidance (what to turn on in production) is in
> [`deployment.md`](deployment.md).
>
> `aitp-transport-http` is the **only async crate** in the workspace
> (`reqwest`/`axum`/`tokio`); the protocol crates stay sync. Its features:
> `client`, `server`, `client-spki-pinning` (requires `client`; off by
> default), `experimental-renewal` (mounts `/aitp/handshake/renew`),
> `experimental-session-bundle` (mounts the bundle routes; implies `server`)
> and `metrics`. The `aitp` facade re-exposes a subset: `http-client`,
> `http-server`, `all`, `experimental-renewal` and
> `experimental-session-bundle`. `client-spki-pinning` and `metrics` are not
> re-exported; enable them on `aitp-transport-http` directly.
>
> Status legend: **scaffolded** (compiles, thin) · **tested** (unit/integration
> coverage) · **documented** (rustdoc + usage notes) · **done** (tested +
> documented).

## Subsystems

| Module | Purpose | RFC | Status | Remaining / notes |
|---|---|---|---|---|
| `client.rs` | `ManifestFetcher` (HTTPS-only Manifest fetch, expiry-bounded per-AID cache, optional retry) and `JwksFetcher` | 0003 / 0007 | done | Cache honors `published_at`/`expires_at`; no HTTP validators (`ETag`/`If-None-Match`). Retry defaults to `RetryPolicy::none()`. `http://localhost` / `127.0.0.1` accepted while `allow_insecure_localhost` is `true` (the default). JWKS network resolution follows RFC-AITP-0007 §2.3: OIDC discovery first, `/.well-known/aitp-keys` only when discovery is not validly exposed. |
| `client_config.rs` | Connection-pool + TLS knobs per fetcher | — | done | Rustdoc example for pool sizing (`with_pool_max_idle_per_host`). |
| `net_guard.rs` | SSRF `HostGuard` on peer-derived fetches (Manifest, JWKS/discovery/`aitp-keys`, facade handshake/renew): redirect-block, resolved-address classification (link-local/metadata always denied; private ranges per mode), DNS-rebind-safe address pinning | 0009 | done | `HostGuard::default()` is `GuardMode::WarnPrivate`; internet-facing deployments call `.with_host_guard(HostGuard::strict())` (`GuardMode::DenyPrivate`). `HostGuard::permissive()` (`GuardMode::AllowAll`) for air-gapped/test networks. |
| `replay_store.rs` | Pluggable `ReplayGuard` (`InMemoryReplayGuard` default) for envelope `message_id` / DPoP `jti` dedup | 0001 §5.5 / RFC 9449 | done | `check_and_record(key, ttl)` maps to Redis `SET NX EX`; supply a shared backend for clustered deployments (`HandshakeServer::with_replay_guard`, `DpopReplayCache::with_guard`). |
| `key_resolution.rs` | `KeyResolutionPolicy`: cache → pinned issuer store → network (`JwksFetcher::resolve`), with fail modes | 0007 | done | The sync `JwksResolver::resolve` bridges to the network only on a **multi-thread** Tokio runtime; on a current-thread runtime it returns `ResolveError::NetworkError` — use `AsyncJwksResolver::resolve_async` (e.g. to pre-warm the cache) or the pinned store. `SoftFail` fails closed on `resolve()`; degraded state only via `resolve_outcome()`. The module doc still lists `aitp-keys` before OIDC (stale, [#200](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/200)). |
| `dpop.rs` | DPoP (RFC 9449) proof generation + verification, replay cache | RFC 9449 (no AITP RFC) | done | Wired into token exchange via `TokenExchangeRequest::with_dpop_proof`. See *Support status* below. |
| `retry.rs` | Exponential backoff + jitter for idempotent outbound reads | — | done | Jitter strategy + max-attempts are configurable; keep retries to idempotent GETs only. |
| `revocation.rs` | `RevocationCache` + `RevocationProvider`, per-issuer cache, fail modes; `EmptyRevocationProvider` for tests/dev | 0008 | done | Snapshot member-set and shape failures surface as `RevocationError::UnknownField` / `Malformed` (the `REVOCATION_SNAPSHOT_INVALID` case, RFC-AITP-0008 §1.5), distinct from `SignatureInvalid`. Keep `RevocationFailMode` default = fail-closed. |
| `server.rs` | `ManifestServer` + `HandshakeServer` (hello/commit; `/aitp/handshake/renew` with `experimental-renewal`), `RevocationListProducer` | 0003 / 0004 / 0009 | done | Hello/commit run replay → rate limit → timestamp (RFC-AITP-0009 §3.1). Manifest structural failures map to `MANIFEST_INVALID`; unknown members to `UNKNOWN_FIELD`. **Open:** rate limiting off by default and defaults above RFC-AITP-0009 recommendations; no automatic session sweeper ([#198](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/198), see [deployment](deployment.md#known-limitations)). The renew route has no replay guard, rate limit or revocation re-check, and maps every `process_renewal_request` failure to `TCT_SIGNATURE_INVALID` (parse failures map to `UNKNOWN_FIELD`/`INVALID_ENVELOPE`) ([#196](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/196), see [tct-renewal](tct-renewal.md#known-limitations)). Producer must never mint a fresh empty list on backing-store failure. |
| `server_limits.rs` | Request body-size cap (axum-level) + header recommendations | 0009 | done | Document how the cap composes with `axum::DefaultBodyLimit`. |
| `tls_pinning.rs` | SHA-256 SPKI pinning for outbound HTTPS | RFC 7469 | done | Behind `client-spki-pinning` (off by default — avoids pulling a rustls `CryptoProvider`). Rustdoc covers `compute_spki_hash` and a `reqwest` integration example. |
| `token_exchange.rs` | OAuth 2.0 Token Exchange (RFC 8693): bootstrap OIDC identity from mTLS/SAML/JWT | RFC 8693 (no AITP RFC) | done | DPoP-bound exchange (`with_dpop_proof`) and the JWT → AID `cnf.jkt` binding test (`exchanged_token_binds_to_agent_aid_via_cnf_jkt`) landed in `da40242`. Composition with `KeyResolutionPolicy` for the resulting identity is not separately tested. See *Support status*. |
| `session_bundle_server.rs` | Session Trust Bundle HTTP transport (§4.3.1) — in-memory store, no verification | 0010 (Draft, opt-in) | tested | Behind `experimental-session-bundle`. Unknown body member → `UNKNOWN_FIELD`; wrapper defect → `SESSION_BUNDLE_INVALID`. **Open:** accepts a bare (unwrapped) body and does not advertise `rfc-aitp-0010.bundle_uri` ([#195](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/195), see [session-bundle](session-bundle.md#known-limitations)). |
| `obs.rs` | Low-cardinality counters at trust-decision points | — | done | Behind `metrics`; metric names in [deployment](deployment.md#transport-hardening-you-should-turn-on). |

## Support status of DPoP and token exchange

No AITP RFC specifies DPoP (RFC 9449) or OAuth 2.0 Token Exchange
(RFC 8693). `dpop.rs` and `token_exchange.rs` carry no conformance fixtures
and no RFC-AITP-0009 threat-model entry; treat them as an unsupported
convenience layer outside the protocol
([#151](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/151)).

## Cross-cutting acceptance criteria

- **Async stays contained.** No async leaks into `aitp-core` / `aitp-tct` /
  `aitp-handshake`. New blocking-bridge points must document the Tokio-context
  requirement (as `key_resolution.rs` does).
- **Fail-closed defaults.** Revocation and key-resolution soft-fail modes must
  fail closed on the plain accessor; degraded state is opt-in via the
  `*_outcome()` variants.
- **Feature minimalism.** Pinning stays behind `client-spki-pinning` so a
  default `client` build doesn't pull in a rustls `CryptoProvider`.

## Open items (rolled up)

The four items previously listed here (DPoP-bound token exchange, the
JWT → AID mapping test, a no-op revocation provider, rustdoc examples for
`tls_pinning` and `client_config`) were closed by `da40242`. Open now:

1. `server.rs` defaults and sweeper —
   [#198](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/198).
2. `/aitp/handshake/renew` replay, revocation and `renew_uri` gaps —
   [#196](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/196).
3. `session_bundle_server.rs` bare body and `bundle_uri` —
   [#195](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/195).
4. Stale rustdoc (key-resolution order, "flips in 0.4") —
   [#200](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/200).
5. Support statement for DPoP / token exchange —
   [#151](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/151).
