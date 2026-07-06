# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **`aitp` CLI** (`aitp-cli` crate): an offline command-line tool for the
  common build/debug tasks — `keygen`, `aid`, `tct inspect`, `tct verify`,
  and `manifest verify` (stdin-friendly, non-zero exit on failure). Ships
  in-repo (`cargo run -p aitp-cli`); not yet published to crates.io.

## [0.4.0] — Security hardening (2026-07)

Rust crates **0.3.0 → 0.4.0**. Implements the 2026-07 protocol + runtime
review (`plans/protocol-runtime-review-2026-07.md`). The on-the-wire
protocol is unchanged (`aitp/0.2`); this is an API + hardening release.
Details and per-item verification in `plans/build_status.md`.

### Added

- **SSRF guard** (`net_guard`): peer-derived fetches (Manifest,
  JWKS/discovery/`aitp-keys`, facade handshake+renew POST) reject
  redirects, classify resolved addresses (link-local/metadata always
  denied; private ranges warn), and pin vetted addresses to defeat DNS
  rebinding. Configurable via `with_host_guard(HostGuard::strict())`.
- **Pluggable replay store** (`ReplayGuard` trait + `InMemoryReplayGuard`
  default) for envelope `message_id` / DPoP `jti` dedup — supply a shared
  backend (e.g. Redis) for clustered deployments. `HandshakeServer::with_replay_guard`, `DpopReplayCache::with_guard`.
- **Strict TCT verification**: `TctVerifyContext::builder(..)` forces an
  explicit decision on revocation and the issuer-Manifest expiry cap
  (named `*_dangerous` waivers); `clock_skew_secs` knob.
- **Configurable facade transport**: `InitiatorConfig::new(..)` +
  `with_http_timeout` / `with_host_guard`.
- Five verify-path fuzz targets + a fuzz PR gate; `docs/deployment.md`.

### Changed — **BREAKING (Rust API)**

- `TctVerifyContext` and `InitiatorConfig` are now `#[non_exhaustive]`;
  construct via `TctVerifyContext::builder(..)`/`permissive_at(..)` and
  `InitiatorConfig::new(..)` respectively.
- `Aid::to_ed25519_bytes` / `to_p256_bytes` (panicking) **removed** — use
  the `try_*` variants.
- `DpopReplayCache` internals reworked to sit behind `ReplayGuard`
  (constructors `with_ttl` / `with_guard`).
- P-256 signatures are now emitted in canonical **low-S** form and the
  verifier rejects high-S (malleability fix); RSA keys below 2048 bits
  are rejected on the OIDC / DPoP paths.

## [Unreleased] — SDK bindings 0.4.0

> Bindings-only release. The Rust crates (0.3.0, published) and the
> on-the-wire protocol (`aitp/0.2`) are unchanged; the language SDKs
> (`aitp-sdk` on PyPI, `@agentidentitytrustprotocol/aitp` on npm) bump
> 0.3.0 → 0.4.0.

### Changed — **BREAKING (bindings): all capabilities ship by default**

The Python and Node SDKs no longer hide post-v0.1 capabilities behind an
opt-in `experimental` build. **TCT renewal, session bundles, SPKI
pinning, and multi-hop delegation are now compiled into the default
wheel / `.node`**, so the published PyPI wheel and the default Docker
build expose the full surface with no special build step. Each capability
remains a named Cargo feature (`renewal`, `session-bundle`,
`spki-pinning`, `multihop-delegation`), all on by default; a minimal
artifact can opt out with `--no-default-features`.

- The `experimental` umbrella feature and the `experimental-*` feature
  names are removed (renamed to the plain capability names above).
- `verify_delegation_experimental_multihop` →
  `verify_delegation_multihop` (Python) and
  `verifyDelegationExperimentalMultihop` → `verifyDelegationMultihop`
  (Node). The strict single-hop `verify_delegation` is unchanged and
  remains the safe default.

Migration: depend on `aitp-sdk>=0.4.0`; replace any call to the old
multi-hop function name; drop any `--features experimental` build flags
(the default build now includes everything).

## [0.3.0] (AITP protocol `aitp/0.2`)

> Crate version 0.3.0. The Rust API has breaking changes (the
> compact-JWS migration below), so the crates bump their 0.x major
> from 0.2 to 0.3; the **protocol** version is `aitp/0.2`. The two
> version namespaces are independent.

Tracked in `plans/v0.2-roadmap.md`. Forward-looking work that did not
land in 0.1.0.

### Changed — **BREAKING: compact-JWS portable trust artifacts (`aitp/0.2`)**

The JWS/TCT migration (`plans/jws-tct-migration.md`; spec commit
`52582bb`). The portable trust artifacts — the **TCT**, the new **grant
voucher**, and the **delegation token** — are re-serialized as RFC 7515
compact JWS strings with explicit typing (`aitp-tct+jwt`,
`aitp-grant+jwt`, `aitp-delegation+jwt`). Signatures cover the exact
transmitted bytes: verifiers never re-serialize, re-canonicalize, or
reconstruct anything, and any off-the-shelf JOSE library verifies the
tokens given only the issuer public key (proven in CI by a
`jsonwebtoken` differential oracle and byte-for-byte reproduction of
the spec's signed-example KAT vectors). Protocol-internal artifacts
(envelopes, manifests, revocation snapshots) stay on the JCS
embedded-signature profile; the protocol version literal is `aitp/0.2`
everywhere. There is no wire migration path: v0.1 verifiers reject
v0.2 artifacts on the version gate; re-handshake.

Old → new claim mapping for TCTs: `version→ver`, `jti`, `issuer→iss`,
`subject→sub`, `audience→aud`, `issued_at→iat`, `expires_at→exp`,
`grants`, `binding.cnf` (raw key) → `cnf.jkt` (RFC 7638 thumbprint).

- **`aitp-crypto`**: new `jws` module — `sign_compact` /
  `verify_compact` with AID-derived algorithm pinning (`EdDSA`/`ES256`;
  `alg: none` and confusion headers rejected with the new
  `TOKEN_ALG_MISMATCH` code), RFC 8725 explicit-typing enforcement
  (`TOKEN_TYP_MISMATCH`), and strict three-segment parsing.
- **`aitp-tct`**: `Tct`/`TctEnvelope`/`TctBinding` replaced by
  `TctClaims` / `IssuedTct { token, claims, voucher }` /
  `VerifiedTct { token, claims }`. `TctBuilder::build()` also mints the
  companion **grant voucher** (RFC-AITP-0005 §8) unless
  `.without_voucher()`. `verify_tct` takes the compact string and the
  expected issuer **AID** (which pins key and algorithm). New
  `verify_voucher`. Renewal carries compact strings. The revocation
  snapshot stays JCS but signs the wrapped `{"revocation_list": …}`
  view per the v0.2 KAT.
- **`aitp-delegation`**: `grant_proof` and its source-TCT byte
  reconstruction (`verify_source_tct_projection`) are **gone** — a
  delegation embeds the issuer's grant voucher verbatim and the
  verifier checks its own past signature directly
  (`DELEGATION_INVALID_VOUCHER` replaces
  `DELEGATION_INVALID_GRANT_PROOF`). Multi-hop (RFC-AITP-0011) chains
  carry verbatim delegation JWS strings with per-hop `jti`, voucher on
  `chain[0]` only, and a digest-array `chain_hash`.
- **`aitp-handshake`**: commit payloads carry `tct` + optional
  `grant_voucher` as opaque strings; completions return
  `CompletedHandshake { tct: VerifiedTct, grant_voucher }`. The
  received voucher is verified to mirror its companion TCT.
- **`aitp-session-bundle`**: participants embed TCT compact strings
  verbatim; the bundle signs the wrapped `{"session_bundle": …}` view.
- **`aitp` facade**: `SessionContext` exposes `held_tct: VerifiedTct` +
  `grant_voucher`; `TctStore` stores token + claims + voucher;
  `renew_tct` returns `RenewedTct { tct, grant_voucher }`.
- **Conformance**: the runner materializes the spec's v0.2 placeholder
  families (compact-JWS tokens with claims-sibling minting, computed
  chain hashes, manifest PoP, P-256 envelope signatures, pinned
  reference clock); the adapter was reworked op-by-op. Full spec
  matrix: **46/46 core fixtures pass** (51/51 with the multihop +
  session-bundle opt-ins; the remaining 2 are the v0.1-frozen
  structural rejections, correctly skipped under opt-in).
- **Adapter fixes**: the handshake round-2 PoP is verified under the
  **sender** (TCT issuer) key per RFC-AITP-0004 §3, and HELLO-family
  envelope signatures are checked after the Manifest/identity
  bootstrap (RFC-AITP-0004 §5.1 step 6).
- **Bindings (`bindings/aitp-py`, `bindings/aitp-node`)**: migrated to
  the compact-JWS API — TCT/voucher/delegation cross the FFI boundary
  as opaque strings; handshake completions expose `tct` (token) +
  `claims` + optional `grant_voucher`; delegation issuance roots in the
  grant voucher. **F-1 closed**: both `verify_tct` entry points now take
  an optional set/array of revoked `jti` strings, wired into the
  verifier's revocation check (previously hard-coded to `None`, silently
  honoring revoked-but-unexpired TCTs).
- **Interop**: the cross-runtime Python↔Node handshake harness migrated
  to the JWS contract, plus a new **stock-JOSE acceptance check** — the
  spec's signed-example TCT / voucher / delegation tokens are verified
  by third-party `pyjwt` (Python) and `jose` (Node) given only the
  issuer public key, and both corroborate the `alg: none` rejection.
  This is the migration's headline property (off-the-shelf
  verifiability), proven against independent JOSE stacks and runnable
  without the native bindings.
- **Docs**: `docs/` refreshed for v0.2 — signing-profile boundary
  table, grant-voucher model, multi-hop rewrite, renewal/session-bundle
  shapes, conformance placeholder conventions, and a "debugging a TCT
  with jwt.io / jose / pyjwt" note.

Full migration verified: workspace tests + clippy clean, both bindings
`cargo check` clean, conformance **46/46 core (51/51 with opt-ins)**,
stock-`jose`/`pyjwt` acceptance green. Not executed here: the native
binding builds (maturin/napi absent) — their Rust compiles cleanly and
the Python/JS test + interop migrations are faithful to the contract,
to be confirmed in CI where the bindings build.

### Added — `aitp-envelope` crate

- **New crate `aitp-envelope`.** `sign_envelope`, `sign_envelope_with`,
  and `verify_envelope_signature` moved out of
  `aitp-transport-http::common` into a standalone crate depending only
  on `aitp-core` + `aitp-crypto` — no HTTP, no async, no I/O. This lets
  the language bindings (below) sign and verify envelopes without
  inheriting a transport stack. `aitp-transport-http::common` keeps thin
  wrappers over the three functions, so existing
  `aitp_transport_http::common::*` imports keep compiling unchanged.

### Added — language SDKs (`bindings/`)

- **`bindings/aitp-py`** — Python SDK built with PyO3 / maturin. An
  `AitpAgent` plus `InitiatorSession` / `ResponderSession` /
  `TctIdentity` classes; every method takes and returns JSON strings
  (HTTP request/response bodies), so agent code never handles a Rust
  type. In-process handshake tests under `bindings/aitp-py/tests/`.
- **`bindings/aitp-node`** — Node.js SDK built with NAPI-rs, the
  API-symmetric counterpart of `aitp-py` (`buildManifest` ↔
  `build_manifest`, etc.). In-process handshake tests under
  `bindings/aitp-node/tests/`.
- Both binding crates are **excluded from the Cargo workspace**: they
  are `cdylib`s built against an external Python / Node toolchain and
  must not be pulled into `cargo test --workspace`. Each carries its
  own `Cargo.lock`.

### Changed — language SDKs `0.1.0` → `0.2.0` (BREAKING)

- **Strict-by-default delegation.** `verify_delegation` /
  `verifyDelegation` now verify under strict AITP v0.1 single-hop and
  **reject** any token carrying a non-empty `chain`
  (`DELEGATION_MULTIHOP_NOT_SUPPORTED`), matching the Rust core default.
  Previously both SDKs silently defaulted to draft RFC-AITP-0011
  multi-hop (`max_hops = 3`). The `max_hops` parameter was removed from
  these functions. **Migration:** to accept multi-hop, build with the
  new `experimental-multihop-delegation` feature and call
  `verify_delegation_experimental_multihop` /
  `verifyDelegationExperimentalMultihop`.
- **OIDC mint-callback** presentation path (`IdentityMode::OidcWithMintCallback`
  in the facade; bindings already wrapped host callables as the minter).
- **`TctStore` / `verify_tct_cached`** — a hot-path cache that skips the
  signature check for a byte-identical, still-valid TCT (keyed by the
  SHA-256 of the envelope; tampered bytes miss and are fully verified).
- **Node binding now compiles with all features off** — the default
  v0.1-core-only build previously failed to compile.
- Published SDK versions bumped `0.1.0` → `0.2.0` to signal the breaking
  delegation change (pre-1.0 minor bump).

### Added — cross-language interop tests

- **`bindings/interop/`** — integration tests that drive a real
  four-message AITP handshake between the Python and Node SDKs in both
  directions, proving the two emit wire-compatible envelopes. The
  Python end runs in-process under `pytest`; the Node end runs as a
  line-delimited JSON-RPC subprocess worker (`node_worker.mjs`). Four
  tests cover both handshake directions plus cross-language TCT
  scope-rejection.
- **`make interop`** / **`scripts/interop.sh`** build both bindings
  (maturin + napi), then run the interop suite. Exits non-zero on any
  failure, so it can gate CI.

### Added — DPoP scaffolding (Phase 6, RFC 9449)

- **`aitp-transport-http::dpop`** module with `DpopProof`,
  `DpopHeader::parse`, and a `verify_dpop_proof` stub returning
  `DpopError::NotImplemented`. 4 unit tests cover header parsing.
- Full DPoP verification (signature, htm/htu/iat binding,
  replay-cache, `cnf.jkt` thumbprint check) is **deferred** — see
  `plans/v0.2-closeout.md` Phase 6.

### Added — CI hardening (Phase 8)

- New CI jobs: `semver` (cargo-semver-checks vs PR base ref),
  `msrv` (cargo-msrv verify), `coverage` (cargo-tarpaulin → Cobertura
  artifact).
- Fuzz scaffolding under `fuzz/` (excluded from the main workspace
  for cargo-fuzz's nightly profile): targets for envelope parsing,
  manifest parsing, delegation parsing. Run via
  `cd fuzz && cargo +nightly fuzz run <target>`.

### Documented — design / follow-ups

- `plans/v0.2-roadmap.md` — full 9-phase plan with dependencies.
- `plans/v0.2-closeout.md` — what landed, what's deferred, exact
  pickup order for the next session.
- `plans/v0.2-crypto-agility-design.md` — Phase 7 implementation
  sketch. Implementation blocked on spec-side algorithm identifier.
- (Spec repo) `plans/v0.2-conformance-followups.md` — concrete
  list of KATs and conformance fixtures still to mint.

### Fixed — documentation

- **Corrected the handshake signing-input recipes in
  `docs/handshake-transcripts.md`.** The page (written for
  cross-language implementers) documented the PoP/nonce preimage as the
  ASCII bytes of the base64url nonce string and the pinned-key proof as
  `message_id|timestamp` — both wrong. Per the code and
  RFC-AITP-0001 §5.4.2 / RFC-AITP-0002 §3.1, PoP inputs hash the
  **base64url-decoded** nonce bytes (hashing the string form is explicitly
  non-conformant), and the pinned-key proof is the 5-field domain-prefixed
  structure. The tables now defer to the normative RFC sections.
- **Fixed the TCT-renewal RFC reference** (`docs/tct-renewal.md`,
  `docs/sdk-node.md`, `docs/sdk-python.md`): renewal is RFC-AITP-0013
  (+ RFC-AITP-0004 §8.1, non-normative), not "RFC-AITP-0005 §10" (which is
  the Verification API).
- **Repaired dangling links to `docs/design/PENDING.md`** (a file that
  never existed) in `architecture.md`, `jcs.md`, `handshake-transcripts.md`,
  and a `state_machine.rs` comment — now pointing at
  `plans/defered/deferred.md`.
- **Refreshed stale design docs:** `conformance.md` ("13 fixtures"
  → 44; op vocabulary reconciled with `aitp-rs-adapter`); `jcs.md` (spec
  KAT hashes now exist and are CI-pinned, no longer a de-facto local value).

### Added — documentation

- **`docs/README.md`** — a documentation index establishing the
  "implementation docs here / normative protocol in the spec RFCs" boundary
  and linking the spec-side guides, so the implementation docs point rather
  than duplicate.

### Changed — documentation structure

- **Flattened `docs/design/` into `docs/`** and dropped the numeric
  filename prefixes — every page now lives directly under `docs/` with a
  descriptive name (`jcs.md`, `handshake-transcripts.md`,
  `session-bundle.md`, `multihop-delegation.md`, `tct-renewal.md`).
- **Merged the topology guide and the workspace rationale** into a single
  `docs/architecture.md` (former `docs/architecture.md` +
  `docs/design/00-architecture.md`), de-duplicating the crate map and
  bindings sections.
- **Merged the conformance matrix into the adapter-design doc** as
  `docs/conformance.md` (former `docs/design/02-conformance-adapter.md` +
  `docs/conformance-matrix.md`); `architecture.md`'s conformance section now
  points there instead of restating the op tables.
- Updated all inbound references (README, CONTRIBUTING,
  `adapters/README.md`, and the `//!` doc-comments in `aitp-core`,
  `aitp-conformance`, and `aitp-rs-adapter`).

### Deferred — production posture (to Phase 9)

These items were in the original Phase 2 scope but moved to Phase 9
polish since they are deployment-tunable rather than library-level
concerns:

- TLS root-CA override / certificate pinning (currently uses
  `reqwest`'s system roots).
- HTTP header-size cap and per-chunk slow-loris read timeout
  (axum/hyper provides `http1_max_buf_size`; deployment tunable).
- OIDC discovery cache + `iss` URL normalization (will land with
  Phase 6 OIDC DPoP work).

## [0.1.0] — 2026-05-19

First stable release. Tracks AITP specification v0.1.0-rc.1.
Closes the rc.1 → rc.2 hardening cycle: revocation ordering,
fail-mode strictness, server rate-limiting, facade response handling,
RFC-AITP-0007/0010 surface, multi-hop delegation under feature flag,
and the v0.1 conformance gate. 44/44 fixtures pass (37 `core` + 7
`draft` under their opt-in features).

### Security — rc.1 → rc.2 hardening

- **Revocation ordering (RFC-AITP-0008 §3.3).** `verify_received_tct`
  in the handshake state machine now verifies the TCT signature
  *before* consulting the revocation hook. `tct.issuer` / `tct.jti`
  are attacker-controlled bytes until the signature checks out; the
  prior order let an unsigned TCT steer revocation network I/O
  (amplification DoS, cache pollution, telemetry skew).
- **`SoftFail` key resolution fails closed through `resolve()`.** The
  plain `JwksResolver::resolve` path now returns the new
  `ResolveError::SoftFailRequiresOutcome` under
  `KeyResolutionFailMode::SoftFail` instead of an empty key set
  (which was wire-indistinguishable from `FailOpen`). The degraded
  outcome is reachable only via `KeyResolutionPolicy::resolve_outcome`.

### Added — server & facade hardening

- **Rate limiting wired into the handshake handlers** (RFC-AITP-0009
  §3.1): the normative `replay → rate-limit → timestamp` check order
  is enforced in `enforce_envelope_boundary_checks`; over-quota
  requests get HTTP 429 with no AITP error envelope.
- **Distinct TCT error codes** during the handshake — `TCT_REVOKED` /
  `TCT_EXPIRED` / `TCT_EXPIRES_AFTER_MANIFEST` instead of collapsing
  every `TctError` to `TCT_SIGNATURE_INVALID`.
- **`HandshakeServer::with_pinned_key_store`** wires a `PinnedKeyStore`
  into the responder handlers (RFC-AITP-0002 §3.2 step 1); an
  untrusted pinned-key initiator gets `IDENTITY_FAILED`.
- **Facade response handling**: `run_initiator_handshake` / `renew_tct`
  validate HTTP status, Content-Type and body size, and surface a
  peer's AITP error envelope as the new `FacadeError::Protocol`. The
  body is read under a hard cap — a `Content-Length` over the limit is
  rejected before any read, and the streaming read aborts the moment
  the running total exceeds it — so a malicious peer cannot exhaust
  initiator memory with an unbounded response.
- **`IdentityMode`** on `InitiatorConfig` — the facade presents the
  configured identity type (pinned-key or OIDC) and pre-checks it
  against the peer Manifest's `accepted_identity_types` before the
  handshake (previously always presented pinned-key).

### Added — RFC-AITP-0007 / 0010 surface

- `PresentedIdentity::oidc_checked` — construction-time validation
  that an OIDC JWT's `nonce` claim matches the handshake `pop_nonce`.
- `AsyncJwksResolver` trait + impl for `KeyResolutionPolicy`; the sync
  `resolve()` bridge detects a current-thread runtime and fails closed
  with a descriptive error instead of panicking in `block_in_place`.
- Session-bundle HTTP transport (RFC-AITP-0010 §4.3.1) behind the
  `experimental-session-bundle` feature: `SessionBundleServer` with
  `POST /aitp/session/bundle` + `GET /aitp/session/bundle/:session_id`,
  and the `aitp_session_bundle::RFC_AITP_0010_BUNDLE_URI` Manifest
  extension key.

### Added — conformance

- Adapter ops `authorize_capability_invocation`,
  `expect_pop_challenge_issued`, `withhold_pop_response` — the new
  `tct-007` PoP-enforcement fixture (RFC-AITP-0005 §6.2) now passes.
- `aitp-conformance run` enforces a **v0.1 conformance gate**: a
  `required_for_v0_1` fixture that fails or is SKIPped for an
  adapter-capability reason makes the run exit non-zero.
- The runner now honors fixture `side_effects` assertions — any side
  effect the adapter reports in its result is asserted against the
  fixture, and a reported mismatch fails the fixture.
- `docs/conformance-matrix.md` — per-fixture status (44 fixtures:
  37 `core` PASS, 7 `draft` PASS under their opt-in features).
- Runner placeholder resolver wires the spec's `__TAMPERED_SIG__` /
  `__TAMPERED_SIGNATURE__` recipe (PLACEHOLDERS.md §129–130 — sign
  properly, then flip the least-significant bit of the last raw
  signature byte) so `rev-004` exercises `Ed25519::verify_strict()`
  failure rather than a base64url decode error.
- Vendored spec schemas advanced to spec commit
  `4bb933a4ade85eb36b12b64cc66c11b636722c19` (RFC normative-hardening
  pass + `expected.side_effects` block in
  `aitp-conformance-fixture.schema.json`).

### Added — Session Trust Bundle (Phase 5, RFC-AITP-0010)

- **New crate `aitp-session-bundle`.** Coordinator-attested membership
  artifact for multi-agent sessions. Redistributes N bilateral
  coordinator↔participant Mutual Handshakes to all participants
  without requiring an O(N²) full mesh.
- Types: `SessionTrustBundle`, `ParticipantEntry`,
  `SessionBundleEnvelope`. Schema-conformant with the new
  `schemas/json/aitp-session-bundle.schema.json` shipped in the
  spec repo's Phase 3 PR.
- `SessionBundleBuilder` — coordinator-side: collects N participant
  TCTs, validates `issuer == coordinator` and `audience == aid`
  invariants, computes `expires_at = min(participant TCT expiries)`
  per RFC-AITP-0010 §6, JCS-canonicalizes and signs.
- `verify_session_bundle` — checks version, expiry, expiry-window
  invariant, member presence, outer signature, per-participant TCT
  validity. Per-pair revocation degradation: revoked participants
  are dropped from the active set rather than invalidating the
  whole bundle (`BundleOutcome::DegradedSubset`).
- 8 new integration tests in `crates/aitp-session-bundle/tests/round_trip.rs`
  — happy path with 3 participants, non-member, expired, tampered
  signature, revoked-participant degraded subset, empty
  participants, audience mismatch at build, schema rejection of
  unknown fields.
- Re-exported via `aitp::session_bundle` facade.

### Added — multi-hop delegation (Phase 4, RFC-AITP-0011)

- **`DelegationToken` carries optional `chain` and `chain_hash`** for
  delegation chains longer than one hop. Single-hop tokens are
  byte-identical to pre-rc.1 (both fields skip-if-none in JCS view).
- **`DelegationStep`** type alias for `GrantProof`. Each `chain[i]` is
  a step; the most-recent step lives in the top-level `grant_proof`.
- **`VerifyDelegationContext::max_hops`** caps total chain length
  (default 3 from RFC-AITP-0011 §2). Setting `0` reverts to strict
  v0.1 posture (rejects any chain with `MultihopNotSupported`).
- **Verifier per-hop checks** (RFC-AITP-0011 §3-§6): hop-0 source-TCT
  projection signature; hops i>0 step-body JCS signature; audience
  continuity through chain; `chain[0].issuer == delegator`; per-hop
  expiry monotonically non-increasing; transitive scope subsetting
  end-to-end; per-hop revocation lookup; JTI uniqueness within chain;
  `chain_hash` recompute and outer-signature-binding check.
- **New error variants**: `HopLimitExceeded`, `ChainHashMismatch`. The
  conformance adapter maps these to `DELEGATION_HOP_LIMIT_EXCEEDED`
  and `DELEGATION_CHAIN_HASH_MISMATCH` per the new RFC-AITP-0011
  registry. `MultihopNotSupported` is now mapped to the spec's
  `DELEGATION_MULTIHOP_NOT_SUPPORTED` (was `MULTIHOP_NOT_SUPPORTED`).
- **9 new integration tests** in `crates/aitp-delegation/tests/multihop.rs`
  — 3-hop happy path, hop-limit exceeded, max_hops=0 (strict v0.1),
  chain_hash tampered, chain truncation, scope inflation, revoked
  hop, duplicate JTI, single-hop unchanged.

### Added — production posture (Phase 2)

- **`tracing` instrumentation.** `aitp-transport-http` now emits structured
  `tracing` spans on `ManifestFetcher::fetch` and `JwksFetcher::resolve`,
  with span fields for the target origin/issuer. Library code is
  zero-cost when consumers don't install a subscriber. Add
  `tracing-subscriber = "0.3"` and call e.g.
  `tracing_subscriber::fmt::init()` in your binary to enable.
- **Retry policy for transient fetches.** `RetryPolicy` (in
  `aitp-transport-http::retry`) carries an exponential-backoff
  configuration: `none()`, `conservative()` (3 attempts / 100 ms
  base / 1 s cap), `aggressive()` (5 attempts / 200 ms / 5 s cap),
  or `custom(...)`. Wired into `ManifestFetcher::with_retry_policy`.
  Only transient errors (`Timeout`, `Network(_)`, 5xx upstream) are
  retried; verification, oversize, and content-type errors are not.
  Default is no retry (rc.1 behavior preserved).

### Fixed — production safety (Phase 1)

- **HTTP server mutex poisoning DoS** (post-rc.1 audit P0). `HandshakeState`
  used `std::sync::Mutex` for its session map and message-id deny list,
  with `.lock().unwrap()` at every call site
  (`crates/aitp-transport-http/src/server.rs:351,399,619`). A panic in
  any locked section would have poisoned the mutex; subsequent requests
  would have unwrapped on `PoisonError` and crashed the request handler
  permanently. The `JwksFetcher` cache (`client.rs:170,186,205`) had
  the same shape, as did the demo agent's session map
  (`examples/two-agents/src/bin/agent-b.rs:129,162`).
  Swapped to `parking_lot::Mutex` (no poison state, drop-in API)
  workspace-wide; all `.lock().unwrap()` call sites are gone. No
  observable behavior change in the happy path.

### Fixed — production hygiene

- Replaced five infallible `.unwrap()` calls in `crates/aitp/src/facade.rs`
  (`run_initiator_handshake` and `renew_tct` payload-serialization +
  URL-join sites) with `?`-propagated `FacadeError::Http` results so
  `cargo clippy -- -D clippy::unwrap_used` stays clean in production
  paths.

[0.1.0]: https://github.com/agentidentitytrustprotocol/aitp-rs/compare/v0.1.0-rc.1...v0.1.0

## [v0.1.0-rc.1]

Release-candidate gate over beta.1. Six P0/P1 bugs from the
post-beta.1 audit are fixed; the TCT verifier now caps `expires_at`
by the issuer Manifest's expiry; revocation is wired into the Mutual
Handshake; SoftFail enforces a real safe-grant subset; the Manifest
PoP signing input matches the spec's unified
`sha256(base64url_decode(x))` convention; and the responder's
grant_policy receives the verified peer identity instead of a
placeholder.

Breaking changes are confined to internal struct literals
(`PeerConfig`, `TctVerifyContext`, `RevocationFailMode::SoftFail`)
that any caller will have to update — the wire format is unchanged.

### Changed — breaking

- **`RevocationFailMode::SoftFail` now carries `safe_grants`** (BUG-4,
  P1 spec non-conformance). Pre-rc.1, `SoftFail` was identical in
  every observable way to `FailOpen` — both returned `Ok(false)` for
  `is_revoked` when the snapshot source failed, so a revoked TCT's
  issuer would still hand out the full grant set under degraded
  policy. RFC-AITP-0008 says SoftFail must reduce the grant set to a
  configured safe subset; SoftFail without a non-empty safe-grant
  list MUST behave as `FailClosed`.
  - `SoftFail` is now `SoftFail { safe_grants: Vec<String> }`. `Copy`
    is gone from `RevocationFailMode` and `RevocationPolicy`.
  - New `RevocationCache::check` returns `RevocationOutcome::{Clear,
    Revoked, SoftFailSafeSubset { safe_grants }}` so callers can
    branch on the degraded-policy result. Existing `is_revoked` is
    kept for handshake hooks that only need the bool.
  - New `apply_safe_subset(requested, safe_grants)` helper for the
    issuance site. Empty intersection is the caller's signal to
    surface `POLICY_VIOLATION`.

### Added — conformance

- **`aitp-rs-adapter` is now a library + binary**. The dispatch
  logic moved from `main.rs` into `lib.rs` so callers can drive the
  same dispatch in-process. The binary is a thin shell over
  `lib::handle`; behavior is unchanged.
- **In-process adapter at parity with the subprocess binary**.
  `aitp_conformance::adapter::in_process::InProcessRustAdapter` now
  delegates to `aitp_rs_adapter::handle`, so every Tier A/B/C/D op
  the subprocess supports is also reachable in-process. Pre-rc.1 the
  in-process adapter only spoke Tier A.
- **PoP challenge/response ops** (Phase 7, RFC-AITP-0005 §6).
  Adapter exposes `issue_pop_challenge`, `produce_pop_response`,
  `verify_pop_response`. State stashes pending challenges by JTI so
  multi-step fixtures (e.g. `tct-006`) can drive the full exchange
  without supplying a challenge to every step.
- **`verify_handshake_payload` adapter op**. Wires the op the spec's
  `id-*` and single-message `mh-*` fixtures dispatch to. Defaults to
  kat-keypair-001 when `self_aid` is omitted (the spec's mh-*
  convention).
- **OIDC mock-issuer demo**: `examples/two-agents/src/bin/oidc-demo.rs`
  drives a complete OIDC handshake against an in-process IdP that
  mints EdDSA-signed JWTs. Self-contained; no network required.
- **Sequence-fixture parsing** (runner). `FixtureInputVariant` now
  prefers `Sequence` over `Single` when both could match (untagged
  serde otherwise greedily picked Single, even for fixtures where
  `sequence` is the meaningful field). A new top-level
  `FixtureInput::operation` field captures fixtures like `env-004`
  that declare the op once at the parent level and rely on
  per-step inheritance.

### Added — security

- **`accepted_identity_types` pre-handshake screening** (BUG-6, P1
  spec compliance). RFC-AITP-0003 §3.2 / §5 step 5: a fetching peer
  MUST verify that its own identity type appears in the target
  Manifest's `accepted_identity_types` before initiating the
  handshake. Pre-rc.1 the check happened only inside the responder's
  HELLO handler, so a pinned-key initiator against an OIDC-only peer
  would round-trip several messages just to learn the peer rejects
  it. New `aitp_manifest::check_identity_type_compatibility` is wired
  into `aitp::facade::run_initiator_handshake` and surfaces as
  `ManifestError::IncompatibleIdentityType` →
  `INCOMPATIBLE_IDENTITY_TYPE`. New regression tests in
  `crates/aitp-manifest/tests/identity_type_compat.rs`.
- **TCT verifier enforces issuer-Manifest expiry bound** (BUG-5, P1
  spec gap). RFC-AITP-0004 §4.3 / RFC-AITP-0005 §9: a peer-issued TCT
  MUST NOT outlive its issuer's published Manifest, because the
  issuer's keys could legitimately rotate at that point. Issuance
  has always enforced this; pre-rc.1 the *verifier* couldn't because
  `TctVerifyContext` had no field for the bound. Added
  `TctVerifyContext::issuer_manifest_expires_at: Option<Timestamp>`
  and `TctError::ExpiresAfterManifest`. The handshake state machine
  captures the peer Manifest's `expires_at` from `MUTUAL_HELLO`
  (responder side) and `MUTUAL_HELLO_ACK` (initiator side) and feeds
  it through to `verify_received_tct`. Adapter maps the new error to
  the `TCT_EXPIRES_AFTER_MANIFEST` code. New regression tests in
  `crates/aitp-tct/tests/manifest_expiry_bound.rs`. Breaking:
  `TctVerifyContext` literal construction now requires the new
  field; callers without a known issuer Manifest pass `None`
  (RFC-AITP-0005 §9: MAY skip when unavailable).
- **Handshake-time revocation enforcement** (BUG-3, P0 security gap).
  `PeerConfig::revocation_check: Option<&RevocationCheckFn>` is a
  new optional hook called inside `verify_received_tct` for every
  peer-issued TCT (`MUTUAL_HELLO_ACK`'s and `MUTUAL_COMMIT_ACK`'s
  TCT). Pre-rc.1, the inner `verify_tct` was always passed
  `revocation_check: None`, so revoked TCTs slipped through the
  Mutual Handshake even when the caller had a fully wired
  `RevocationCache` available. The hook is called with
  `(issuer_aid, jti)` so per-issuer caches can route correctly; an
  `Err(HandshakeError)` from the hook propagates as-is to surface
  fail-closed policy when the revocation source is unreachable. New
  regression tests in `crates/aitp-handshake/tests/revocation_hook.rs`.

### Fixed — interoperability

- **Responder grant policy receives real peer identity** (BUG-2, P0
  policy bypass). `Responder::on_commit` previously synthesized a
  placeholder `IdentityDescriptor` (kind=PinnedKey, empty proof) when
  issuing the peer's TCT, so any policy that branched on `kind`,
  `issuer`, `subject`, or OIDC claims silently saw the wrong identity
  on the responder side. The verified `hello.identity` is now
  captured into `ResponderState::AwaitingCommit` and handed to
  `issue_tct_for_peer` — RFC-AITP-0004 §4.1 grant-policy symmetry is
  now correct on both peers. New regression test
  `responder_grant_policy_sees_real_pinned_key_identity` asserts the
  responder's policy sees the same descriptor the initiator
  presented.
- **Manifest PoP signing input** (BUG-1, P0 interop). Builder and
  verifier now use the unified RFC-AITP-0001 §5.4.2 signing-input
  convention `sha256(base64url_decode(challenge))`. Pre-fix, both
  sides hashed the ASCII bytes of the base64url-encoded challenge —
  internally consistent but rejected by any spec-conformant external
  verifier. New regression tests in
  `crates/aitp-manifest/tests/pop_kat.rs`: KAT-driven check against
  `kat-manifest-pop-001` from `jcs-sha256.json`, builder cross-path
  verification, and a legacy-form rejection guard. Pre-rc.1 minted
  Manifests will fail verification under rc.1 and must be re-minted
  with `cargo run -p mint-signed-examples`.
- **CI vendored-schemas drift job**. `actions/checkout@v4` defaulted
  to depth 1, so the pinned historical spec commit was unreachable
  and `git checkout <PIN>` failed with `unable to read tree`. Now
  reads `tests/schemas/SPEC_VERSION` first and passes it as `ref:`
  so checkout fetches the exact commit.
- **`docs` job rustdoc warning**. Removed broken intra-doc link
  `crate::client::RevocationFetcher` in `aitp-transport-http` (no
  such item; revocation fetching uses the `RevocationProvider`
  trait).
- **`demo_runs_end_to_end` and `full_pinned_key_handshake_over_http`
  TCT(Expired) flake**. Both call sites captured `cfg.now` at
  startup; on slow CI runners the peer-issued TCT's `issued_at`
  landed strictly after the stale `now` and the verifier rejected
  it as `Expired`. `PeerConfig` is now rebuilt with
  `Timestamp::now()` immediately before each `on_hello_ack` /
  `on_commit_ack`.

## [v0.1.0-beta.1]

Production-readiness release. Phases 10–16 of the unified hardening
plan: key-resolution policy, manifest-cache correctness, revocation
end-to-end, HTTP transport hardening, conformance-fixture expansion,
TCT renewal, and beta-gate validation. No breaking wire-format
changes vs alpha.5; the additions are layered on top.

### Added — production layer

- **Key resolution policy** (RFC-AITP-0007).
  `aitp_transport_http::KeyResolutionPolicy` composes a configurable
  `PinnedIssuerKeyStore` + `JwksFetcher` + in-memory cache into a
  single sync `JwksResolver`. Resolution order: cache → pinned
  issuer store → `/.well-known/aitp-keys` → OIDC JWKS. Three
  fail modes — `FailClosed` (default), `FailOpen`, `SoftFail`.
- **Manifest cache correctness**. `ManifestFetcher::cached`
  now returns `None` for expired entries (RFC-AITP-0003 §4.2);
  new `maybe_replace_inline` enforces newer-`published_at`-only
  replacement to defeat rollback attempts.
- **Revocation policy + HTTP endpoint** (RFC-AITP-0008 §1.5).
  `RevocationCache` + `RevocationPolicy { fail_mode,
  max_staleness_secs, cache_ttl_secs }`; `RevocationListProducer`
  trait wires `GET /.well-known/aitp-revocation-list` onto
  `HandshakeServer`. New `REVOCATION_LIST_URI_EXT` extension
  key for Manifest discovery.
- **HTTP transport hardening**. `ManifestFetcher` enforces
  Content-Type, oversize cap (`DEFAULT_MAX_MANIFEST_BYTES = 256 KB`),
  structured `UpstreamStatus`/`WrongContentType`/`OversizedResponse`
  errors. `HandshakeServer` now emits AITP error envelopes
  (`{"error": {"code": "...", "message": "..."}}`) keyed by
  `aitp_core::ErrorCode`. Boundary checks (Content-Type, body cap,
  timestamp tolerance, replay deny list) run before payload parsing.
- **TCT renewal** (RFC-AITP-0005 §10). New
  `aitp_tct::TctRenewalPayload` + `build_renewal_request` /
  `process_renewal_request`. `HandshakeServer` mounts
  `POST /aitp/handshake/renew`. Renewal flow: existing TCT +
  fresh PoP; issuer mints new JTI bounded by Manifest expiry.
- **High-level `aitp::facade`** (feature `http-client`). New
  `run_initiator_handshake(InitiatorConfig) -> SessionContext`
  drives the four-message handshake from a peer Manifest URL.
  `renew_tct(holder_key, current, endpoint) -> TctEnvelope`
  is the renewal one-liner.

### Added — conformance fixtures

Eight new negative-path fixtures pin the alpha.5 security work
across implementations:

- `id-005` — pinned-key legacy proof (pre-v0.1 two-field input)
- `id-006` — pinned-key proof bound to wrong `pop_nonce`
- `id-007` — pinned-key proof from key not in trust store
- `mh-009` — manifest type mismatch (`oidc` hint, `pinned_key` proof)
- `man-003` — expired Manifest must not be served from cache
- `tct-005` — TCT `expires_at` after issuer Manifest expiry
- `rev-001` — stale revocation snapshot, fail-closed
- `rev-002` — stale revocation snapshot, soft-fail
- `env-004` — replayed `message_id` rejected at envelope boundary

`tools/mint-conformance-fixtures` extended with mint logic for each.
Output is byte-stable across re-mints.

### Added — regression tests

`crates/aitp-handshake/tests/p1_p8_regressions.rs` pins six per-bug
regressions: P1 legacy proof, P1 wrong receiver, P1 wrong nonce,
P3 untrusted-key trust-store enforcement, P4 type mismatch,
P7 grant-policy plumbing.

### Test counts

214+ passing, 0 failed, 2 ignored (alpha.5 was 177; +37 from P10–P16
units + integrations + regressions). All gates clean: fmt, clippy
--all-features --all-targets -- -D warnings, build --release.

## [Released] — v0.1.0-alpha.5

Security + spec-compliance hardening release. Phases 1–9 of the
unified production-hardening plan: every P0 and P1 item is in. Two
breaking wire-format changes; six new spec-compliance enforcements;
one new transport-layer defense.

### ⚠️ Breaking wire-format changes vs alpha.4

- **Pinned-key identity proof format** (RFC-AITP-0002 §3.1).
  Previously signed `sha256("{message_id}|{timestamp}")` —
  vulnerable to cross-peer / cross-handshake replay. Now signs
  `sha256(b"aitp-pinned-key-v1\0" || sender_aid || \0 || receiver_aid
  || \0 || message_id || \0 || timestamp_be_8 || \0 ||
  base64url_decode(pop_nonce))`. Captured signatures are now bound to
  the full five-tuple. Any pinned-key proof minted by alpha.4 or
  earlier WILL fail to verify under alpha.5.
- **Handshake round-2 PoP signing input** (RFC-AITP-0004 §3).
  Previously `sha256(nonce.as_bytes())`. Now
  `sha256(base64url_decode(nonce))`, matching the TCT downstream PoP
  rule from spec rc.2. Aligns the handshake's two PoP paths with each
  other and the spec.

### Added — spec compliance + security

- **`PresentedIdentity` API refactor.** New
  `IdentityPresentationContext` carries the (sender, receiver,
  message_id, timestamp, pop_nonce) tuple to `build_descriptor`.
  `Initiator::start` now takes the peer's AID up-front (callers must
  fetch the peer's Manifest first).
- **`PinnedKeyStore` trust enforcement** (RFC-AITP-0002 §3.2 step 1).
  New trait + `StaticPinnedKeyStore`; `PeerConfig.pinned_key_store`
  is consulted before honoring any pinned-key identity. `None` keeps
  the legacy key-possession-only behavior for local dev.
- **Identity-type/hint match** (RFC-AITP-0004 §5.1). The verifier
  now rejects when `identity.kind ≠ manifest.identity_hint.kind`,
  closing a type-confusion bypass.
- **TCT expiry bounded by Manifest** (RFC-AITP-0004 §4.3).
  `issue_tct_for_peer` caps the issued TCT's `expires_at` at the
  issuing peer's Manifest expiry. Refuses to issue if the issuing
  Manifest is already expired.
- **Identity-aware grant policy** (RFC-AITP-0004 §4.1). New
  `PeerConfig.grant_policy: Option<&'a GrantPolicyFn>` lets
  deployments derive identity-based capability restrictions on top
  of the `peer_requested ∩ self.offered` intersection. Empty result
  → `PolicyViolation`.
- **Message-ID replay deny list on `HandshakeServer`**
  (RFC-AITP-0001 §5.5). Per-server `seen_message_ids` map with
  TTL-based eviction (default 5-minute window). Duplicate message_ids
  in the window are rejected with `REPLAY_DETECTED`.
  `with_session_ttl_and_replay_window` for tests.
- **JwksFetcher hardening** (RFC-AITP-0007 §2). HTTPS enforced for
  both discovery and the resolved `jwks_uri`. All redirects refused
  outright. Non-2xx responses surface as structured errors.
  Configurable timeout via `JwksFetcher::with_timeout`. On OIDC
  discovery failure, falls back to AITP-native
  `<issuer>/.well-known/aitp-keys`.

### Migration from alpha.4

Three things to re-do:

1. **Re-issue pinned-key identity proofs** — anything cached under
   alpha.4's two-field format will fail to verify
2. **Re-mint conformance fixtures** with the new pinned-key proof
   format: `cargo run -p mint-conformance-fixtures`
3. **Update `Initiator::start` callers** to pass the peer's AID
   (fetched from the peer's Manifest before the handshake begins)

`PinnedKeyStore` and `grant_policy` are both opt-in (`None` defaults
keep alpha.4 behavior). No action needed unless you want them.

### Test counts

177 passing, 0 failed, 2 ignored (alpha.4 was 171; +6 from the new
pinned-key proof regression tests). All gates clean: fmt, clippy
--all-features --all-targets -- -D warnings, doc --no-deps, build
--release, deny check.

### Still deferred (Phases 10-16 from the unified plan)

- **P10**: Key-resolution policy struct (RFC-AITP-0007 fail modes)
- **P11**: Manifest cache correctness (expiry-aware, inline-replace
  semantics)
- **P12**: Revocation policy + `/.well-known/aitp-revocation-list`
  HTTP endpoint
- **P13**: HTTP transport hardening (content-type, max body, error
  envelopes)
- **P14**: Conformance fixture expansion (negative-path fixtures
  for every bug fixed in P1-P8)
- **P15**: TCT renewal flow + high-level `aitp` facade driver
- **P16**: beta.1 release gates + per-bug regression tests

Carved out into a follow-up phase; this release cuts at the P0/P1
boundary.

## [Released] — v0.1.0-alpha.4

Spec rc.3 alignment + paired follow-up release. The spec rc.3 commit
landed `kat-keypair-003`, the `__VALID_SIG__` placeholder rename in
three fixtures, and the `aitp-revocation-list.schema.json` that was
missing despite RFC-AITP-0008 §1.5 already defining the wire shape.
This release implements the consumer side of all three.

### Added

- **`aitp-tct::revocation` module.** New types `RevocationList`,
  `RevocationListEnvelope`, `RevocationEntry`,
  `VerifyRevocationListContext`. New helpers
  `sign_revocation_list` and `verify_revocation_list`. Includes a
  KAT byte-match test that reproduces the spec rc.2
  `kat-revocation-001` canonical bytes byte-for-byte.
- **`verify_revocation_snapshot` op** wired in `aitp-rs-adapter`.
- **`tools/mint-signed-examples`.** New workspace member that mints
  cryptographically valid AITP example artifacts (Manifest, TCT,
  delegation token, signed revocation snapshot) from the spec's
  pinned KAT keypairs. Output goes to the spec repo's
  `signed-examples/` directory with `_kat_input` companions per the
  rc.2 README. Closes BLOCKED-SPEC-EXAMPLE
  (agentidentitytrustprotocol#5). Includes 4 cryptographic-verify
  tests over its own output.
- **KAT vector for `kat-keypair-003`.** Now exercised by the existing
  iteration-over-vectors structure in
  `crates/aitp-crypto/tests/kat.rs`.
- **`aitp-revocation-list.schema.json` schema test** in
  `crates/aitp-tct/tests/schema.rs` (2 cases: populated entries +
  empty entries snapshot).

### Changed

- **`tests/schemas/SPEC_VERSION`** advanced to spec commit
  `<rc.3 hash>`.
- **`unsupported_op_yields_skip` runner test** now uses
  `future_op_reserved_for_v0_2` as its canary (was
  `verify_revocation_snapshot`, which is now actually supported).

### Closed PENDING items

- `NOTE-VERIFY-REVOCATION-SNAPSHOT` — closed by the new
  `aitp-tct::revocation` module + adapter wiring.
- `BLOCKED-SPEC-EXAMPLE` (#5) — closed in spirit by
  `tools/mint-signed-examples`; spec PR populating the
  `signed-examples/` directory expected as the next paired action.

### Still deferred

- `PHASE-B-FIXTURE-PR` — migrating the 22 conformance fixtures from
  placeholders to fully-minted real values. Carved out as
  `plans/phase-11-fixture-migration.md`. Substantial focused work
  (4–8 hours) requiring per-placeholder substitution logic plus an
  OIDC mock issuer; deferred to keep alpha.4 scope coherent.

## [Released] — v0.1.0-alpha.3

RFC v0.1.0-rc.2 alignment release. Tracks spec commit
`c0e45653e8ac49e06747c8c289c28520a46b29e3`. Two breaking wire-format
changes; one new required field; first KAT-anchored interop validation.

### ⚠️ Breaking wire-format changes

- **TCT PoP signing input.** RFC-AITP-0005 §6.1+§6.2 (rc.2) pins the
  PoP signing input to `sha256(base64url_decode(nonce))` — the
  **decoded raw bytes** of the nonce, not its ASCII string form.
  alpha.1 and alpha.2 used the ASCII bytes. Any TCT PoP signature
  produced by an alpha.1 or alpha.2 holder will fail to verify under
  alpha.3, and vice versa. Affects `aitp-tct::sign_pop_response` and
  `aitp-tct::verify_pop_response`.
- **`grant_proof.issued_at` is now REQUIRED.** RFC-AITP-0006 §3.1
  (rc.2) added `issued_at` as a required wire field on `grant_proof`,
  copied verbatim from the source TCT. Verifiers use the carried
  value to reconstruct the source TCT signing input — the previous
  TTL-guessing reconstruction (`expires_at - DEFAULT_TCT_TTL_SECS`)
  is gone. Delegations issued by alpha.2 will fail to deserialize
  under alpha.3 (missing field) and vice versa. Affects
  `aitp-delegation::GrantProof`, `DelegationBuilder`,
  `verify_delegation`.

### Added

- **Spec KAT tests.** `crates/aitp-crypto/tests/kat.rs` validates
  Ed25519 seed→pubkey→AID derivation and JWK thumbprint computation
  against `tests/schemas/known-answer/{keypairs,jwk-thumbprints}.json`.
  `crates/aitp-core/tests/kat.rs` validates JCS canonicalization +
  SHA-256 against `tests/schemas/known-answer/jcs-sha256.json`. All
  pass byte-for-byte against the spec's pinned reference values.
- **`scripts/sync-schemas.sh`** now also vendors
  `schemas/conformance/known-answer/*.json` into
  `tests/schemas/known-answer/`.

### Changed

- **`tests/schemas/SPEC_VERSION`** advanced from spec commit
  `367567f…` to `c0e45653e8ac49e06747c8c289c28520a46b29e3`.

### Closed PENDING items

- `BLOCKED-SPEC-DELEGATION-ISSUEDAT` — closed by spec rc.2.
- `SPEC-POP-INPUT-AMBIGUITY` — closed by spec rc.2 (pinned to
  decoded bytes).
- `SPEC-005`, `SPEC-006`, `SPEC-007` — KAT vectors landed in spec rc.2;
  KAT tests in `aitp-rs` exercise them.

### Migration from alpha.2

Re-issue any persisted TCTs (PoP signatures are now bound to a
different hash input). Re-issue any persisted delegation tokens
(missing `grant_proof.issued_at`). Re-pull the vendored schemas
(`scripts/sync-schemas.sh`).

## [Released] — v0.1.0-alpha.2

Spec-alignment release. Tracks AITP spec v0.1.0-rc.1 with post-alpha.1
corrections.

### Added

- **Schema-validation drift firewall.** Vendored AITP JSON Schemas under
  `tests/schemas/` (pinned to spec commit via `tests/schemas/SPEC_VERSION`).
  Per-crate `tests/schema.rs` validates fully-populated wire types
  against the spec schemas: `aitp-manifest`, `aitp-tct`,
  `aitp-delegation`, and `aitp-handshake` (all four mutual-handshake
  payloads). New CI job `spec-schemas` fails if vendored schemas drift
  from the pinned spec commit.
- **Conformance Tier B/C/D** in `aitp-rs-adapter`. New supported ops:
  `verify_envelope`, `verify_delegation_token` (Tier A); `generate_keypair`,
  `issue_manifest`, `issue_tct`, `issue_delegation_token`, `sign_envelope`
  (Tier B); `start_handshake` (initiator role), `process_handshake_message`,
  `revoke_tct` (Tier C); `set_clock`, `inject_revocation`, `dump_session`
  (Tier D). Round-trip integration tests in
  `crates/aitp-conformance/tests/runner_integration.rs`.
- **Handshake session expiry.** `HandshakeServer` now takes a
  `session_ttl: Duration` (default 60s via `DEFAULT_SESSION_TTL`).
  Inline sweep on each request drops expired entries; expired sessions
  on commit return 400 `session expired`.
  `HandshakeServer::with_session_ttl(...)` for tests.

### Changed

- **`serde_jcs` 0.1 → 0.2.** Upstream fixed RFC 8785 §3.2.3 UTF-16
  code-unit ordering for object keys; the previously-ignored
  `jcs_surrogate_pair_ordering` test now passes.

### Removed

- **`Manifest.description`** field. Was carried in the Rust types
  (and the builder, signing view, verifier) but was never in
  RFC-AITP-0003 §3.1/§3.2 or `aitp-manifest.schema.json` (which sets
  `additionalProperties: false`). Setting it would have produced wire
  bytes that fail spec validation. Breaking change for any caller that
  set it; none expected in alpha.1. The new
  `rejects_legacy_description_field` round-trip test guards against it
  reappearing.

### Known limitations carried from alpha.1

- Multi-hop delegation (RFC-AITP-0011 reserved for v0.2)
- Session Trust Bundle (RFC-AITP-0010 reserved)
- OIDC `cnf.jkt` requires DPoP-aware identity provider; no token-exchange
  proxy ships with this release
- Conformance fixtures at `agentidentitytrustprotocol/schemas/conformance/`
  still use the legacy placeholder shape; spec-side migration PR pending
- Responder-side handshake conformance ops deferred to alpha.3
  (initiator-side covers the most useful test scenarios)
- `verify_revocation_snapshot` is intentionally not in the adapter's
  supported_ops; v0.1 has no spec-defined revocation snapshot type

## [Released] — v0.1.0-alpha.1

First implementation milestone for the AITP Rust reference implementation.
Tracks AITP spec v0.1.0-rc.1.

### Added — protocol crates

- **`aitp-core`** — `Aid`, `AitpEnvelope`, `Sender`, `MessageType`,
  `Timestamp`, `ExtensionsMap`, `AitpError`, `ErrorCode` (32 pinned wire
  strings), strict unpadded `base64url` codec, JCS canonicalization wrapper
  (24 standard vectors + 3 property tests), and the RFC-AITP-0001 §5.4
  envelope signing-input helper.
- **`aitp-crypto`** — `AitpSigningKey` (generate/from_seed/sign),
  `AitpVerifyingKey` (from_aid/from_bytes/`verify_strict`), `Signature::parse`
  with strict 86-char + base64url-charset + no-padding gates, JWK thumbprint
  per RFC-AITP-0002 §2.2.1.
- **`aitp-manifest`** — `ManifestBuilder` with required-field +
  identity-hint validation; `verify_manifest` running the five steps from
  RFC-AITP-0003 §5; `ManifestEnvelope` HTTP wrapper.
- **`aitp-tct`** — `TctBuilder` with `audience == subject` and non-empty
  grants enforced at issuance and verification; `verify_tct` covering the
  RFC-AITP-0005 §9 order; `PopChallenge` / `PopResponse` plus
  `sign_pop_response` / `verify_pop_response` for downstream PoP.
- **`aitp-delegation`** — `DelegationBuilder` reusing A's source-TCT
  signature verbatim; `verify_delegation` running the 11 RFC-AITP-0006 §4
  checks. Single-hop only; multi-hop reserved for v0.2.
- **`aitp-handshake`** — `Initiator` and `Responder` state machines;
  `bootstrap_verify_peer` running RFC-AITP-0004 §5.1 steps 3–6;
  `verify_oidc` with pluggable `JwksResolver` trait; `verify_pinned_key`
  per RFC-AITP-0002 §3.1; `INSUFFICIENT_GRANTS` enforcement against
  `required_peer_capabilities`. Full pinned-key handshake test where both
  peers end up holding each other's TCT.
- **`aitp-transport-http`** — `ManifestFetcher` with HTTPS-on-the-wire
  (HTTP allowed for `localhost`/`127.0.0.1` only), `JwksFetcher` doing
  OIDC discovery → JWKS resolution, `ManifestServer` and `HandshakeServer`
  axum routers with `X-Aitp-Session-Id` correlation.
- **`aitp` (facade)** — re-exports + a working `cargo test --doc` example.

### Added — tooling

- `examples/two-agents` — end-to-end demo on `localhost`. `make demo` runs
  the four-message handshake and exercises a `demo.echo` capability over
  HTTP.
- `aitp-conformance` — subprocess-based runner with a 30s per-request
  timeout, `--filter`/`--tag`/`--output {text|json|tap}` CLI surface,
  and integration tests against the real `aitp-rs-adapter` binary.
- `aitp-rs-adapter` — Tier-A op dispatcher: `init`, `shutdown`,
  `verify_jcs`, `compute_jwk_thumbprint`, `verify_manifest`, `verify_tct`.
- Workspace standards: `rust-toolchain.toml`, `rustfmt.toml`,
  `clippy.toml`, `.editorconfig`, `.gitignore`, GitHub Actions CI
  (fmt + clippy + matrix test + doc + cargo-deny + cargo-audit),
  Dependabot, PR/issue templates, `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, `Makefile`.

### Changed

- Bumped MSRV from 1.75 → 1.88. Transitive deps (`time`, `time-macros`,
  `icu_*`, `idna_adapter`, `clap_lex`) now require edition2024.
- Dropped `secrecy::Secret<DalekSigningKey>` wrapper. `ed25519_dalek::SigningKey`
  already implements `ZeroizeOnDrop`; the wrapper required a bound
  (`DefaultIsZeroes`) the type doesn't satisfy. Net effect: same
  zeroization behaviour, fewer dependencies.
- `AitpEnvelope.extensions` removed (envelope schema is
  `additionalProperties: false`).
- `Tct.evidence_ref`, `Tct.extensions`, `DelegationToken.extensions`,
  `MutualHello*Payload.extensions` all removed (schemas forbid them).
- `TctBinding.cnf` documentation corrected: it is the subject's raw
  32-byte Ed25519 pubkey in 43-char base64url, not the JWK thumbprint
  (RFC-AITP-0005 §1 schema, §6.2 step 4).
- `IdentityProof` tagged-enum scaffold replaced with the schema's
  flat `IdentityDescriptor` struct.
- Mutual-handshake commit/commit-ack payloads use the
  `tct_for_peer: { tct: { ... } }` wrapper per the schema.

### Known limitations

- **`BLOCKED-JCS-SURROGATE`** — `serde_jcs` 0.1 sorts object keys by
  UTF-8 byte order rather than UTF-16 code-unit order (RFC 8785 §3.2.3).
  One vector is `#[ignore]`'d. Affects only objects that mix astral and
  BMP characters with the specific code-unit-vs-byte ordering inversion.
- **`BLOCKED-SPEC-DELEGATION-ISSUEDAT`** — `grant_proof` doesn't carry
  the source TCT's `issued_at`, but A's `grant_proof.signature` covers
  it. The verifier reconstructs as `expires_at - 3600` (default TTL).
  Tokens minted with non-default TTLs would fail cross-impl until the
  spec adds the field or pins a recipe.
- **`BLOCKED-CONF-TIERBCD`** — Conformance Tier B (issuance), Tier C
  (stateful flows), Tier D (test-only) ops are not yet wired into
  `aitp-rs-adapter`. Deferred to v0.1.0-alpha.2.
- **`BLOCKED-SPEC-FIXTURE-MIGRATION`** — The spec's
  `schemas/conformance/*.json` fixtures predate the runner's
  `input.operation` shape; they all `FAIL` with `input.operation
  missing` until migrated.
- **Multi-hop delegation** — RFC-AITP-0011 reserved.
- **Session Trust Bundle** — RFC-AITP-0010 reserved.

## [0.1.0-alpha.0] — initial scaffold

Architectural skeleton; no runnable functionality.
