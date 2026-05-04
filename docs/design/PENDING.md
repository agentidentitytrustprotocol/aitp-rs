# Pending Tasks and Open Questions

Snapshot of work not yet done in `aitp-rs`. Updated as tasks land.

## Spec-side dependencies

These belong in `agentidentitytrustprotocol/`, not in this repo, but
they unblock implementation work here.

- [x] **SPEC-005** — RESOLVED in spec rc.2 (#1). KAT vectors at
      `schemas/conformance/known-answer/jcs-sha256.json`. aitp-rs alpha.3
      validates against them in `crates/aitp-core/tests/kat.rs`.
- [x] **SPEC-006** — RESOLVED in spec rc.2 (#2). JWK thumbprint vectors
      at `schemas/conformance/known-answer/jwk-thumbprints.json`. Tested
      in `crates/aitp-crypto/tests/kat.rs`.
- [x] **SPEC-007** — RESOLVED in spec rc.2 (#3). Keypair vectors at
      `schemas/conformance/known-answer/keypairs.json`. Tested in
      `crates/aitp-crypto/tests/kat.rs`.
- [x] **BLOCKED-SPEC-DELEGATION-ISSUEDAT** — RESOLVED in spec rc.2 (#4).
      `grant_proof.issued_at` now REQUIRED on the wire. aitp-rs alpha.3
      added the field and uses the carried value.
- [ ] **BLOCKED-SPEC-EXAMPLE** — Still open (#5). Now actionable since
      kat-keypair-001 is pinned; `aitp-rs` could mint a real example
      manifest using `issue_manifest` with that seed.
      Tracked: agentidentitytrustprotocol/agentidentitytrustprotocol#5
- [x] **SPEC-POP-INPUT-AMBIGUITY** — RESOLVED in spec rc.2 (#6). Pinned
      to decoded raw bytes. aitp-rs alpha.3 fixed `aitp-tct::pop` to
      match. Breaking change vs alpha.1/alpha.2.

Without these, our implementation defines the de facto canonical form
rather than verifying against the spec's pinned form.

## Workspace bootstrap

- [x] **IMPL-001** — Workspace compiles cleanly with all crates' bodies
      implemented.
- [x] **IMPL-002** — CI on GitHub Actions: fmt + clippy + matrix test +
      doc + cargo-deny + cargo-audit + spec-schemas drift firewall
      (added in alpha.2).
- [x] **IMPL-003** — `cargo deny check` runs locally and passes
      (alpha.3 phase 9). Updated `deny.toml` to cargo-deny ≥ 0.18
      schema (removed deprecated `unlicensed` / `copyleft` /
      `allow-osi-fsf-free` / `default` license fields and the
      severity-style `unmaintained`). Allowlist now includes
      `CDLA-Permissive-2.0` for `webpki-roots`.
- [x] **IMPL-004** — MSRV is now **1.88** (forced up by transitive deps).

## Sprint 1 — `aitp-core`

- [x] **IMPL-005** — Implement `Aid::parse` and `Aid::from_ed25519`.
- [x] **IMPL-006** — Implement `Timestamp` freshness predicates.
- [x] **IMPL-007** — `AitpEnvelope` round-trips + `deny_unknown_fields`.
      Schema forbids top-level `extensions`; the original scaffold's
      `extensions` field has been removed. Added
      `envelope_signing_input` / `envelope_signing_digest` helpers per
      RFC-AITP-0001 §5.4.
- [x] **IMPL-008** — `ExtensionsMap` round-trip + skip-when-empty tests.
- [x] **IMPL-009** — Implement strict base64url decode.
- [x] **IMPL-010** — Wire up `serde_jcs` in `jcs::canonicalize`.
- [x] **IMPL-011** — JCS standard test vectors (24 vectors).
- [x] **IMPL-012** — JCS property tests (3 properties × 64 cases each).
- [x] **IMPL-013** — RESOLVED in alpha.3. Spec rc.2 published JCS+SHA-256
      KAT vectors; `crates/aitp-core/tests/kat.rs` validates against them.
- [x] **IMPL-014** — `ErrorCode` ↔ wire strings (32 pinned variants).

### `BLOCKED-JCS-SURROGATE` — RESOLVED in alpha.2

`serde_jcs` 0.2.0 (released 2026-03-25) fixed UTF-16 code-unit ordering
per RFC 8785 §3.2.3. The astral-vs-BMP test vector
`crates/aitp-core/tests/jcs_standard_vectors.rs::jcs_surrogate_pair_ordering`
is no longer `#[ignore]`'d and now passes. Bumped in alpha.2.

## Sprint 2 — `aitp-crypto`

- [x] **IMPL-015** — `AitpSigningKey` (generate, from_seed, sign).
- [x] **IMPL-016** — `AitpVerifyingKey` (from_aid, from_bytes, verify);
      uses `verify_strict` for cross-impl interop.
- [x] **IMPL-017** — `Signature::parse` with strict 86-char + base64url charset
      + no-padding checks.
- [x] **IMPL-018** — JWK thumbprint reproducibility tests.
- [x] **IMPL-019** — RESOLVED in alpha.3. Spec rc.2 published JWK thumbprint
      KAT vectors; `crates/aitp-crypto/tests/kat.rs::jwk_thumbprint_kat`
      validates against them.

## Sprint 3 — protocol crates

- [x] **IMPL-020** — Manifest type round-trips + deny-unknown-fields + HTTP wrapper.
- [x] **IMPL-021** — `ManifestBuilder` with required-field validation
      and identity-hint shape checks.
- [x] **IMPL-022** — `verify_manifest` in RFC-AITP-0003 §5 order.
- [ ] **IMPL-023** — Partially resolved by spec prep commit `0839c52`,
      which clarified that `examples/manifest/agent-b-manifest.json`
      *intentionally* keeps placeholders for documentation. Real signed
      examples land at `schemas/conformance/known-answer/signed-examples/`.
      Paired aitp-rs minting work (Phase 10) will populate that
      directory once `kat-keypair-003` is added to the spec.
      Tracked: agentidentitytrustprotocol/agentidentitytrustprotocol#5
- [x] **IMPL-024 .. IMPL-031** — `aitp-handshake` (Phase 3d). Includes
      full pinned-key handshake test where both peers end up holding
      each other's TCT.
- [x] **IMPL-032 .. IMPL-035** — `aitp-tct` (Phase 3b).
- [x] **IMPL-036 .. IMPL-038** — `aitp-delegation` (Phase 3c).

### Spec ambiguities — both resolved in spec rc.2

- **PoP signing input** — RESOLVED. Spec rc.2 pinned to
  `sha256(base64url_decode(nonce))`. aitp-rs alpha.3 implements this.
  History preserved here for archeology; live state is the rc.2 RFC
  text.
- **`BLOCKED-SPEC-DELEGATION-ISSUEDAT`** — RESOLVED. Spec rc.2 made
  `grant_proof.issued_at` REQUIRED on the wire. aitp-rs alpha.3 uses
  the carried value.

## Sprint 4 — HTTP transport and demo

- [x] **IMPL-039 .. IMPL-042** — `aitp-transport-http` client + server.
      `ManifestFetcher` allows HTTP for `localhost`/`127.0.0.1` only.
- [x] **BLOCKED-SERVER-SESSION-GC** — RESOLVED in alpha.2. `HandshakeServer`
      now accepts an explicit `session_ttl: Duration` (default
      `DEFAULT_SESSION_TTL = 60s`). Inline sweep on each request drops
      expired entries; expired sessions on a `commit` request return
      400 with body `session expired`. Tests in
      `crates/aitp-transport-http/tests/session_expiry.rs`.
- [x] **EX-001 .. EX-004** — `examples/two-agents` end-to-end demo.
      `make demo` runs the four-message handshake on `localhost` and
      invokes a `demo.echo` capability.

## Sprint 5 — conformance runner

- [x] **CONF-001 .. CONF-007** — `aitp-conformance` runner +
      `aitp-rs-adapter` subprocess adapter (Tier A only).
- [x] **BLOCKED-CONF-TIERBCD** — RESOLVED in alpha.2. Tier B (issuance:
      `generate_keypair`, `issue_manifest`, `issue_tct`,
      `issue_delegation_token`, `sign_envelope`), Tier C (`revoke_tct`,
      and initiator-side `start_handshake` /
      `process_handshake_message`), and Tier D (`set_clock`,
      `inject_revocation`, `dump_session`) all wired. Coverage tests in
      `crates/aitp-conformance/tests/runner_integration.rs`.
- [ ] **NOTE-RESPONDER-CONFORMANCE** — Responder-side handshake
      conformance (server-side `start_handshake role=responder`) is
      deferred to alpha.3. The adapter returns `OP_NOT_SUPPORTED` for
      that role today; initiator-side covers the most useful test
      scenarios.
- [x] **NOTE-VERIFY-REVOCATION-SNAPSHOT** — RESOLVED in alpha.4 phase 10.
      RFC-AITP-0008 §1.5 already defined the wire shape; spec rc.3
      added the missing `aitp-revocation-list.schema.json`. aitp-rs
      added `aitp-tct::revocation` module (`RevocationList`,
      `RevocationListEnvelope`, `sign_revocation_list`,
      `verify_revocation_list`), wired the
      `verify_revocation_snapshot` op, and added a KAT byte-match
      test that reproduces the spec rc.2 `kat-revocation-001`
      canonical bytes byte-for-byte.
- [ ] **NOTE-INPROCESS-ADAPTER-DEFERRED** — The in-process
      `Adapter` impl in `crates/aitp-conformance/src/adapter/in_process.rs`
      still has `todo!()` bodies. Subprocess adapter is the conformance
      path; in-process is for fast local development and not on the
      alpha.2 critical path.
- [ ] **BLOCKED-SPEC-FIXTURE-MIGRATION** — The spec's
      `schemas/conformance/*.json` fixtures predate the runner's wire
      protocol: they have no `input.operation` key and contain
      placeholder strings (`__NOW_MINUS_3600__`,
      `__VALID_ENVELOPE_SIG__`, placeholder AIDs). The runner exits
      with one `FAIL` per fixture until those are migrated. To be
      addressed in 7.5 of phase 7 (spec PR + minting script).

## Open architectural questions

These are decided but worth re-confirming before code lands.

| ID | Question | Current direction |
|---|---|---|
| Q-001 | License | Dual MIT OR Apache-2.0 ✓ |
| Q-002 | Async story | Sync core, async at HTTP edges ✓ |
| Q-003 | Repo location | `agentidentitytrustprotocol/aitp-rs` |
| Q-004 | crates.io reservation | Publish 0.1.0-alpha.0 stubs to claim names |
| Q-005 | JCS dep | `serde_jcs`, fork if needed ✓ |
| Q-006 | Error granularity | Per-crate errors → top-level `AitpError` via `From` ✓ |
| Q-007 | Manifest cache | Provide default, allow injection |
| Q-008 | Handshake rate limit | Deployment concern in v0.1 |
| Q-009 | Handshake endpoints | Two HTTPS endpoints per RFC-AITP-0011 §12 |
| Q-010 | OIDC `cnf.jkt` proxy | Post-rc.1 work |
| Q-011 | Pinned-key transcript bytes | Pin in spec, not here |
| Q-012 | Python binding | Wait for adoption signal (3-month checkpoint) |
| Q-013 | MACP integration | Approach in week 5 with working demo |
| Q-014 | Public announcement | rc.1 spec now, alpha.1 impl when demo runs |
| Q-015 | Working group | After first non-team contributor PR |
| Q-016 | Conformance via | Subprocess NDJSON ✓ |
| Q-017 | OIDC test issuer | Build a fixture issuer for handshake tests |

## v0.1.0-alpha.2 — RFC alignment phase

Local code complete. External actions still pending.

- [x] **D-1** — Removed `Manifest.description` field. Was in Rust types
      but not in `aitp-manifest.schema.json`; would have failed
      `additionalProperties: false` validation if set. Schema-test
      regression guard added.
- [x] **DRIFT-FIREWALL** — Vendored AITP JSON Schemas under
      `tests/schemas/` with pin file `SPEC_VERSION`, sync script
      `scripts/sync-schemas.sh`, and CI job `spec-schemas` that fails
      if vendored copies drift from the pinned spec commit. Per-crate
      `tests/schema.rs` for Manifest, TCT, Delegation, Mutual
      Handshake (4 payloads).
- [x] **PHASE-B-SPEC-ISSUES** — Filed 6 spec-side issues against
      `agentidentitytrustprotocol/agentidentitytrustprotocol` (#1–#6).
      See SPEC-005, SPEC-006, SPEC-007, BLOCKED-SPEC-DELEGATION-ISSUEDAT,
      BLOCKED-SPEC-EXAMPLE, SPEC-POP-INPUT-AMBIGUITY entries above.
- [ ] **PHASE-B-FIXTURE-PR** — Deferred to a follow-up session. The
      spec-fixture migration PR (`BLOCKED-SPEC-FIXTURE-MIGRATION`)
      should land after SPEC-005 (#1) is resolved, so the minted
      fixtures use the spec's pinned KAT seeds rather than ours.
      Sequence: spec lands #1 → we run a minting script against the
      pinned seeds → PR with migrated fixtures.

## Things explicitly out of scope for v0.1

- Multi-hop delegation (RFC-AITP-0011 — reserved).
- Session Trust Bundle (RFC-AITP-0010 — reserved).
- Protobuf wire format (in spec's `experimental/`, not here).
- Crypto agility beyond Ed25519.
- TEE / ZK extensions (RFC-AITP-0012 — extension points only).
- Async-everywhere API; we'll add async wrappers if needed.
- Browser-targeted WASM build.
