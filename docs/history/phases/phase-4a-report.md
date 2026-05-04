# Phase 4a Report — `aitp-transport-http`

## Tasks completed

- IMPL-039 (`ManifestFetcher` with HTTPS-only check, cache, verify)
- IMPL-040 (`JwksFetcher` with OIDC discovery + JWKS resolve, returning
  `aitp_handshake::JwkPublicKey` via the `JwksResolver` trait shape)
- IMPL-041 (`ManifestServer` axum router serving `/.well-known/aitp-manifest`)
- IMPL-042 (`HandshakeServer` axum router serving the two POST endpoints)

## Test counts

| Suite | Count |
|---|---|
| `aitp-transport-http` unit tests | 0 |
| `tests/manifest_server.rs` | 1 (full TCP round-trip) |

The test starts a `ManifestServer` on a real ephemeral port, fetches its
manifest via `ManifestFetcher`, and asserts the fetched manifest's AID and
signature match the original.

## Decisions in this phase

1. **`ManifestFetcher` allows HTTP for `localhost`/`127.0.0.1` only.** The
   spec says HTTPS-only on the wire, but the demo (Phase 4b) runs both
   peers on `localhost` — issuing a self-signed TLS certificate just for
   the demo would muddy the example. Production callers fetching from
   non-local hosts get `FetchError::InsecureUrl`.
2. **JWKS resolver returns sync `Vec<JwkPublicKey>`** to satisfy the
   `aitp_handshake::JwksResolver` trait. The `JwksFetcher` itself is
   async (network I/O); the bridge is `block_in_place` or — for the
   demo — pre-fetching keys at startup and serving them from a
   `HashMap`-backed sync resolver. Phase 5 will provide such a wrapper
   for conformance tests.
3. **Session correlation** uses `X-Aitp-Session-Id` request/response
   header. The HELLO_ACK response carries a fresh session id; the
   client must echo it on the COMMIT request. Spec doesn't pin a
   correlation mechanism (RFC-AITP-0011 §12 mentions a session header
   but is not normative); we picked one that works with stock HTTP
   clients.
4. **Sessions live in-memory** in a `Mutex<HashMap>`. No expiry GC yet —
   tracked under `BLOCKED-SERVER-SESSION-GC` (small, easily added).
5. **`HandshakeServer` is generic over `R: JwksResolver`** so both the
   pre-fetched cache resolver and a live `JwksFetcher`-backed resolver
   work without changes.
6. **OIDC support** in the server defaults to pinned-key only — calling
   it with `PresentedIdentity::Oidc` requires the caller to mint the
   JWT outside the server (the JWT-minting side is the IdP's job, not
   AITP's).

## Things the human reviewer should look at

1. The `ManifestFetcher` cache — currently never expires. The
   `expires_at` field on the cached manifest is read but the cache
   never evicts. Cheap to add but spec is vague on cache eviction
   behaviour.
2. `pk_to_spki_ed25519` in `client.rs` — manually wraps a 32-byte raw
   public key in the SPKI DER prefix `jsonwebtoken` requires for
   `from_ed_der`. The byte sequence is the canonical RFC 8410 §4
   Ed25519 SPKI prefix. Worth a code-review eye.
3. The decision to allow `http://localhost`. If undesirable, the demo
   should grow a self-signed TLS setup; otherwise this exception in
   `ManifestFetcher::fetch` documents the relaxation.
4. The full HTTP handshake test (HELLO+COMMIT round-trip across the
   wire) is **not** in this phase. It depends on the demo's server
   wiring and is part of Phase 4b's integration test.

## Recorded follow-ups

- `BLOCKED-SERVER-SESSION-GC` — add per-session timeout + background
  cleanup task. Trivial; deferred so Phase 4b can land.
- The `verify_received_tct` step in `Responder::on_commit` does not yet
  thread a revocation list. Phase 5 conformance fixtures need this hook.
