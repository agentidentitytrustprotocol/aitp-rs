# aitp-transport-http — hardening register

> Status tracker for the `aitp-transport-http` subsystems. CLAUDE.md's
> architecture notes point here ("each one corresponds to a hardening item in
> `docs/transport-hardening.md`").
>
> `aitp-transport-http` is the **only async crate** in the workspace
> (`reqwest`/`axum`/`tokio`); the protocol crates stay sync. Features split:
> `client`, `server`, `client-spki-pinning` (the facade re-exposes them as
> `http-client` / `http-server` / `all`).
>
> Status legend: **scaffolded** (compiles, thin) · **tested** (unit/integration
> coverage) · **documented** (rustdoc + usage notes) · **done** (tested +
> documented, shipping in 0.2.0).

## Subsystems

| Module | Purpose | RFC | Status | Remaining / acceptance |
|---|---|---|---|---|
| `client.rs` | Manifest fetch (HTTPS-only, cache validators, retry) | 0003 / 0007 | done | Honors `published_at`/`expires_at`; HTTPS enforced. |
| `client_config.rs` | Connection-pool + TLS knobs per fetcher | — | done | Document max-pool-size + any per-route override if one is added. |
| `key_resolution.rs` | `KeyResolutionPolicy`: cache → pinned store → `/.well-known/aitp-keys` → OIDC JWKS, with fail modes | 0007 | done | Requires a **multi-thread tokio context** in the calling thread; pure-sync deployments MUST use the pinned-issuer store. `SoftFail` fails closed on `resolve()`; degraded state only via `resolve_outcome()`. |
| `dpop.rs` | DPoP (RFC 9449) proof generation + verification, replay cache | RFC 9449 | tested | **Open:** wire `DpopProof` into the `token_exchange.rs` flow end-to-end; add a conformance-style test for the bound-token path. |
| `retry.rs` | Exponential backoff + jitter for idempotent outbound reads | — | done | Jitter strategy + max-attempts are configurable; keep retries to idempotent GETs only. |
| `revocation.rs` | `RevocationCache` + `RevocationProvider`, per-issuer cache, fail modes | 0008 | done | **Open (nice-to-have):** add a `no_op` provider type for tests; keep `RevocationFailMode` default = fail-closed. |
| `server.rs` | `ManifestServer` + `HandshakeServer` (hello/commit), `RevocationListProducer` | 0003 / 0004 | done | Producer trait lets a control plane supply signed lists; never mint a fresh empty list on backing-store failure. |
| `server_limits.rs` | Request body-size cap (axum-level) + header recommendations | 0009 | done | Document how the cap composes with `axum::DefaultBodyLimit`. |
| `tls_pinning.rs` | SHA-256 SPKI pinning for outbound HTTPS | RFC 7469 | done | Behind `client-spki-pinning` (off by default — avoids pulling a CryptoProvider). Document feature activation + a `reqwest` integration example. |
| `token_exchange.rs` | OAuth 2.0 Token Exchange (RFC 8693): bootstrap OIDC identity from mTLS/SAML/JWT | RFC 8693 | tested | **Open:** add a JWT → AID mapping test; confirm composition with `KeyResolutionPolicy` for the resulting identity. |
| `session_bundle_server.rs` | Session Trust Bundle HTTP transport | 0010 (draft) | tested | Gated by `experimental-session-bundle`; draft, no wire-stability promise. |

## Cross-cutting acceptance criteria

- **Async stays contained.** No async leaks into `aitp-core` / `aitp-tct` /
  `aitp-handshake`. New blocking-bridge points must document the tokio-context
  requirement (as `key_resolution.rs` does).
- **Fail-closed defaults.** Revocation and key-resolution soft-fail modes must
  fail closed on the plain accessor; degraded state is opt-in via the
  `*_outcome()` variants.
- **Feature minimalism.** Pinning stays behind `client-spki-pinning` so a
  default `http-client` build doesn't pull in a rustls CryptoProvider.

## Open items (rolled up)

1. `dpop.rs` ↔ `token_exchange.rs`: end-to-end DPoP-bound token-exchange flow + test.
2. `token_exchange.rs`: JWT → AID mapping test.
3. `revocation.rs`: `no_op` provider type for tests.
4. Usage examples in rustdoc for `tls_pinning` (reqwest) and `client_config`
   pool sizing.
