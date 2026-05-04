# Phase 4a — `aitp-transport-http`

You are working on the `aitp-rs` Rust reference implementation. This is
Phase 4a of 6.

**Your goal:** working HTTP client and server bindings for AITP.

The protocol crates are sync; this crate is async. The split was a
deliberate decision (see `docs/design/00-architecture.md`) so that
consumers can use the protocol crates from sync codebases.

---

## Required reading

1. `phase-3d-report.md`
2. `docs/design/00-architecture.md` — why this crate is feature-gated
3. `crates/aitp-transport-http/src/*.rs` — current scaffold (mostly TODO)
4. The `axum` 0.7 docs and the `reqwest` 0.12 docs

---

## Decisions baked in

- **HTTPS only.** Reject `http://` URLs at the type level. Use `url::Url`
  and check `url.scheme() == "https"` in every fetch path. Plain HTTP
  MUST be rejected.
- **Two HTTP endpoints for the handshake** (Q-009 in PENDING):
  - `POST /aitp/handshake/hello` — accepts a MUTUAL_HELLO envelope,
    returns MUTUAL_HELLO_ACK
  - `POST /aitp/handshake/commit` — accepts MUTUAL_COMMIT, returns
    MUTUAL_COMMIT_ACK
  - Sessions correlated by `message_id` and the responder's session_id
- **Manifest at `/.well-known/aitp-manifest`.**
- **OIDC discovery**: `<issuer>/.well-known/openid-configuration` →
  `jwks_uri` → JWK Set fetch.

---

## Global rules

[All 12 apply.]

- **Stop at the phase boundary.** Do not begin Phase 4b.

---

## Tasks

### 4a.1 — `ManifestFetcher` (client) — IMPL-039

File: `crates/aitp-transport-http/src/client.rs`

Replace the placeholder. Implement:

```rust
pub struct ManifestFetcher {
    client: reqwest::Client,
    cache: Mutex<HashMap<Aid, CachedManifest>>,
}

struct CachedManifest {
    manifest: Manifest,
    fetched_at: Instant,
    expires_at: Timestamp,
}

impl ManifestFetcher {
    pub fn new() -> Self;

    /// Fetch and verify a Manifest from a peer's well-known endpoint.
    ///
    /// `peer_origin` is something like `https://agent-b.example.com`.
    /// Returns the verified Manifest (fresh fetch or cache hit).
    pub async fn fetch(&self, peer_origin: &Url) -> Result<Manifest, FetchError>;
}
```

The fetch path:
1. Validate `peer_origin.scheme() == "https"`. Else
   `FetchError::InsecureUrl`.
2. Construct URL: `peer_origin.join("/.well-known/aitp-manifest")`.
3. GET the URL with a 10-second timeout.
4. Parse response as JSON. The wire form is `{"manifest": {...}}`
   (per RFC-AITP-0003 §6 — the wrapper is HTTP-only). Extract the inner
   Manifest object.
5. Verify it via `aitp_manifest::verify_manifest`.
6. Cache by AID.
7. Return.

`FetchError` is a new error type in this crate:
- `InsecureUrl` — non-HTTPS scheme
- `Network(reqwest::Error)`
- `MalformedJson(serde_json::Error)`
- `MalformedWrapper` — response wasn't `{"manifest": ...}`
- `VerificationFailed(ManifestError)`
- `Timeout`

Cache TTL: respect `manifest.expires_at`. Don't cache forever.

### 4a.2 — `JwksFetcher` (client) — IMPL-040

```rust
pub struct JwksFetcher {
    client: reqwest::Client,
    cache: Mutex<HashMap<Url, CachedJwks>>,
}

impl JwksFetcher {
    pub fn new() -> Self;

    /// Resolve an OIDC issuer's signing keys.
    ///
    /// 1. GET <issuer>/.well-known/openid-configuration
    /// 2. Parse jwks_uri from the response
    /// 3. GET jwks_uri
    /// 4. Parse and cache the JWK Set
    pub async fn resolve(&self, issuer: &Url) -> Result<Vec<JwkPublicKey>, JwksError>;
}
```

Same HTTPS-only check, same timeout discipline. Cache by issuer URL.

Implement the `aitp_handshake::JwksResolver` trait for this struct so
the handshake can use it. Note: the trait was defined as sync in the
handshake crate; you may need to make it async-capable here, or wrap
the async fetcher in a sync facade that blocks on the async runtime.

If sync-async bridging is messy, consider:
- Adding an `async fn resolve(...)` method to `JwksResolver` (as an
  async trait via `async-trait`), and updating the handshake crate to
  use it where appropriate
- Or providing a separate sync `JwksResolver` impl that does an upfront
  bulk-fetch and caches everything, and the handshake never needs to
  fetch async during verification

Pick whichever feels cleaner. Document the choice.

### 4a.3 — `ManifestServer` (server) — IMPL-041

```rust
pub struct ManifestServer {
    manifest: Arc<Manifest>,
}

impl ManifestServer {
    pub fn new(manifest: Manifest) -> Self;
    pub fn router(self) -> axum::Router;
}
```

The router exposes `GET /.well-known/aitp-manifest` returning
`{"manifest": <the manifest>}`. Set `Content-Type: application/json`.

### 4a.4 — `HandshakeServer` (server) — IMPL-042

```rust
pub struct HandshakeServer {
    my_signing_key: AitpSigningKey,
    my_manifest: Arc<Manifest>,
    sessions: Arc<Mutex<HashMap<Uuid, ResponderSession>>>,
    // jwks_resolver, trust_anchors, etc.
}

impl HandshakeServer {
    pub fn new(...) -> Self;
    pub fn router(self) -> axum::Router;
}
```

Two routes:

`POST /aitp/handshake/hello`:
1. Body is an `AitpEnvelope` with `message_type: mutual_hello`
2. Run `Responder::on_hello`
3. Stash the resulting state in `sessions` keyed by `session_id`
4. Sign and return the MUTUAL_HELLO_ACK envelope

`POST /aitp/handshake/commit`:
1. Body is an `AitpEnvelope` with `message_type: mutual_commit`
2. Look up the session from `sessions` (correlated by some header or
   field — the spec needs to be specific here; if it isn't, use a
   `session_id` field in the payload's extensions, or the `message_id`
   from the original HELLO_ACK)
3. Run `Responder::on_commit`
4. Sign and return the MUTUAL_COMMIT_ACK envelope
5. Clean up the session

Add session timeout (60 seconds) — sessions that don't progress get
garbage-collected.

### 4a.5 — Tests

Create `crates/aitp-transport-http/tests/`:

`client_manifest.rs` — uses `wiremock` (need to add to dev-deps; if not
available, write a `BLOCKED-DEP-WIREMOCK` and use a manual axum test
server instead). Tests:
- Successful fetch and verification
- HTTP (not HTTPS) URL → rejected
- Network timeout → `Timeout`
- Bad JSON → `MalformedJson`
- Wrong wrapper shape → `MalformedWrapper`

`server_manifest.rs`:
- Build a `ManifestServer`, hit it with axum's `oneshot`, parse response,
  verify it round-trips

`full_handshake_over_http.rs`:
- Run a `HandshakeServer` on a random port
- Use `ManifestFetcher` + `Initiator` to drive a handshake against it
- Assert both peers end up holding valid TCTs

---

## Format, lint, tests

Default features build:
```sh
cargo build -p aitp-transport-http
cargo test -p aitp-transport-http
```

Client feature:
```sh
cargo test -p aitp-transport-http --features client
```

Server feature:
```sh
cargo test -p aitp-transport-http --features server
```

All features:
```sh
cargo test -p aitp-transport-http --all-features
cargo clippy -p aitp-transport-http --all-features --all-targets -- -D warnings
```

Note: `wiremock` is NOT in workspace deps. If you need it for tests,
write a `BLOCKED-DEP-WIREMOCK` entry in PENDING.md and either get
permission or use axum's test client for HTTP mocking instead.

---

## Update PENDING.md

Check off IMPL-039, 040, 041, 042.

---

## Phase report

`phase-4a-report.md`. Note:
- Whether you needed to make `JwksResolver` async-capable
- The session correlation mechanism you chose for handshake commit
  (header? payload field? other?)
- Any test infrastructure decisions (wiremock vs. axum-test vs. manual)

---

## Success gate

- All transport-http tests pass
- Full HTTP handshake test passes end-to-end
- Clippy clean across all feature combinations

## Stop here.
