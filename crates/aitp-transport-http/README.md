# aitp-transport-http

HTTP client and server bindings for AITP, all behind Cargo features
(`default = []`):

- `client` — `ManifestFetcher` and `JwksFetcher` (RFC-AITP-0003 / 0007),
  `KeyResolutionPolicy`, the SSRF `HostGuard`, retry and pool/TLS knobs.
- `server` — `ManifestServer` and `HandshakeServer` on axum
  (RFC-AITP-0003 / 0004 / 0009). `HandshakeServer` always serves
  `ListRevoked` at `REVOCATION_LIST_PATH` (RFC-AITP-0005 §11): a
  `RevocationListProducer` if attached, otherwise an empty snapshot signed
  by the issuer key. Advertise the route's absolute URL in the Manifest
  with `ManifestBuilder::revocation_list_uri`.
- `source-ip`, `client-spki-pinning`, `metrics`, and the `experimental-*`
  features are described in `Cargo.toml`.

Per-module status, defaults and open items are in the
[hardening register](../../docs/transport-hardening.md); deployment
guidance is in [deployment.md](../../docs/deployment.md).

## DPoP and token exchange are unsupported

The `dpop` module (RFC 9449) and the `token_exchange` module (RFC 8693)
are compiled in with `client` / `server`, and some of their items are
re-exported at the crate root. **No AITP RFC specifies either, and both
are unsupported.** They sit outside the protocol and outside conformance.
See
[Support status of DPoP and token exchange](../../docs/transport-hardening.md#support-status-of-dpop-and-token-exchange).
