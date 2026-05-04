# Phase 10 — Spec rc.3 + paired aitp-rs follow-up

Executed 2026-05-03. This phase straddles two repos: spec-side commit
landing the rc.3 affordances, and the paired aitp-rs work that
consumes them. Most of phase 10 shipped here; the heaviest deferred
piece (the 22-fixture migration) was carved out as phase 11.

## Spec-side (committed locally to agentidentitytrustprotocol/, not
yet pushed)

One commit on the spec repo (`2e4d0d1`):

- **`kat-keypair-003`** added to
  `schemas/conformance/known-answer/keypairs.json`. Seed = `0xff × 32`.
  Pubkey, AID, and JWK thumbprint derived via aitp-rs alpha.3 and
  added to both `keypairs.json` and `jwk-thumbprints.json`.
- **`__VALID_SIG__` rename** in three fixtures (env-002, tct-002,
  tct-004). All three placed the token on a TCT signature field, so
  renamed to the existing normative `__VALID_TCT_SIG__`. mh-001 and
  env-003 verified self-contained (no placeholders, no further
  rename needed).
- **`schemas/json/aitp-revocation-list.schema.json`** added. The wire
  shape was already defined in RFC-AITP-0008 §1.5; the schema was
  missing. Matches the rc.2 KAT body byte-for-byte (the schema marks
  `version` as optional with `const="aitp/0.1"` since the rc.2 KAT
  body omits it; flagged for editorial reconciliation in the commit
  message).

## aitp-rs-side

Five themed commits land in aitp-rs:

- **10.4** — Re-ran `scripts/sync-schemas.sh`. `tests/schemas/SPEC_VERSION`
  advanced. Vendored: new revocation schema + new KAT vectors. Existing
  KAT iteration tests in `crates/aitp-crypto/tests/kat.rs` automatically
  picked up `kat-keypair-003` and `kat-jwk-thumb-003` and pass against
  both new vectors.
- **10.5** — `aitp-tct::revocation` module: `RevocationList`,
  `RevocationListEnvelope`, `RevocationEntry`,
  `VerifyRevocationListContext`, `sign_revocation_list`,
  `verify_revocation_list`. Five unit tests including a KAT byte-match
  that reproduces spec rc.2 `kat-revocation-001` canonical bytes
  byte-for-byte. Two schema tests against the new
  `aitp-revocation-list.schema.json`. `verify_revocation_snapshot` op
  wired in `aitp-rs-adapter`. The `unsupported_op_yields_skip`
  conformance test had to be updated since `verify_revocation_snapshot`
  is no longer the canonical "unsupported" op — switched its canary
  to `future_op_reserved_for_v0_2`.
- **10.6** — `tools/mint-signed-examples` new workspace member. Drives
  the protocol crates with the pinned KAT seeds and a fixed clock
  (`FIXED_NOW = 1_711_900_000`) to produce four signed example
  artifacts (Manifest, TCT, single-hop Delegation, Revocation
  Snapshot). Each output carries a top-level `_kat_input` companion
  per the spec's `signed-examples/README.md` so the byte sequence is
  reproducible. Output goes to the sibling spec repo's
  `signed-examples/` directory by default; overrideable via
  `AITP_SPEC_KAT_DIR`. Includes 4 cryptographic-verify integration
  tests over its own output (every minted artifact must verify
  through the production verify functions).
- **PENDING.md sweep** — closed `NOTE-VERIFY-REVOCATION-SNAPSHOT`,
  partially-closed `BLOCKED-SPEC-EXAMPLE` (the spec PR populating
  `signed-examples/` is the next paired action).
- **alpha.4 release prep** — bumped every Cargo.toml from
  `0.1.0-alpha.3` to `0.1.0-alpha.4`. CHANGELOG entry. Drafted
  `RELEASE_NOTES_v0.1.0-alpha.4.md`.

## Tasks deferred (with reasons)

- **10.7 — Migrate 22 conformance fixtures (PHASE-B-FIXTURE-PR).**
  Carved out as `plans/phase-11-fixture-migration.md`. Realistic 4–8
  hour focused work that requires per-placeholder substitution logic
  (some easy: `__NOW__`, `__VALID_*_SIG__`; some medium:
  `__TAMPERED_*`, `__INVALID_POP_*`; some hard: `__VALID_JWT__`,
  `__VALID_JWT_FROM_UNKNOWN_ISSUER__`,
  `__CAPTURED_PROOF_FROM_ORIGINAL_HANDSHAKE__` which need an OIDC
  mock issuer or a captured handshake proof). Plus per-fixture
  scenario knowledge to add the missing `input.operation` keys.
  Better as its own focused phase than half-done here.

## Final test counts

| Metric | alpha.3 phase 9 | alpha.4 phase 10 |
|---|---|---|
| Tests passing | 160 | **171** |
| Tests failed | 0 | 0 |
| Tests ignored | 2 | 2 |

Net +11: 5 revocation unit tests, 2 revocation schema tests, 4
signed-examples crypto-verify tests. Plus the existing KAT iteration
tests now exercise `kat-keypair-003` (no test count change but
internal validation count grows).

## Final lint/build/audit status

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | ✓ clean |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✓ clean |
| `cargo doc --workspace --no-deps --all-features` | ✓ clean |
| `cargo build --workspace --release` | ✓ clean |
| `cargo deny check` | ✓ advisories ok, bans ok, licenses ok, sources ok |

## Reviewer should check carefully

- The `aitp-revocation-list.schema.json` marks `version` as OPTIONAL
  even though RFC-AITP-0008 §1.5 says REQUIRED. This was forced by
  the rc.2 KAT body omitting the field. The spec commit message
  flags this as needing editorial reconciliation (either re-mint the
  KAT to include version, or amend the §1.5 text).
- The `aitp-tct::revocation` verifier returns
  `TctError::CnfMalformed` for an issuer-mismatch (we did not add a
  new error variant for v0.1 — there's no `IssuerMismatch` variant
  on `TctError` today). If a reviewer thinks this is too clever a
  reuse, adding an explicit variant is a trivial follow-up.
- The minting tool writes to a sibling-repo path by default. If the
  user's spec repo isn't a sibling, override with
  `AITP_SPEC_KAT_DIR`.

## Open follow-ups

- **Spec push** — the spec repo has one local commit
  (`Spec rc.3: kat-keypair-003, __VALID_SIG__ rename, revocation-list
  schema`) not yet pushed. User's call.
- **Spec-PR for signed-examples/** — the four files in
  `agentidentitytrustprotocol/schemas/conformance/known-answer/signed-examples/`
  are written but not yet committed in the spec repo. After spec
  rc.3 push, the user should commit those + open a PR (or push
  directly).
- **Phase 11** — `plans/phase-11-fixture-migration.md` carries the
  full prompt for the 22-fixture migration.
