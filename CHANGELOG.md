# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased] — v0.1.0-alpha.4

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
