# Phase 11 — Conformance fixture migration + spec rc.4 sync

Executed 2026-05-03 after the spec maintainer's `8b4c4eb` commit
landed three rc.4 affordances:

- `aitp-revocation-list.schema.json` made `version` and `signature`
  REQUIRED (matching TCT/Manifest/Delegation pattern)
- `kat-revocation-001` re-minted with the `version` field included;
  new SHA-256 `cbf40cd640287a72ce3b76b6e5c20b508c61381985d0a0bfd23079ece27d2cf8`
- `PLACEHOLDERS.md` gained normative sections: AID role mapping,
  reference clock pin (`__NOW__ = 1711900000`), `input.operation`
  registry per fixture-id prefix, tamper recipe (LSB-flip-of-last-
  raw-signature-byte)

This phase: closes the consumer side in aitp-rs and finishes the
PHASE-B-FIXTURE-PR work.

## Tasks completed

- **11.1 — Sync rc.4 + breaking RevocationList changes.**
  - `RevocationList.version` → REQUIRED `String` (was `Option`)
  - `RevocationListEnvelope.signature` → REQUIRED `String`;
    introduced `RevocationListSigningView` to mirror Manifest/TCT
    signing-view pattern
  - `verify_revocation_list` rejects `version != "aitp/0.1"`
  - KAT byte-match test updated to spec rc.4
    `kat-revocation-001` byte-for-byte
  - Re-minted all 4 signed examples; cryptographically verify

- **11.2 — `tools/mint-conformance-fixtures` binary.** Walks
  `agentidentitytrustprotocol/schemas/conformance/*.json` and
  applies the normative substitution rules in order:
  AID role placeholders → time placeholders → input.operation →
  nonces → JWTs → per-fixture sign/tamper/replay pass. Output is
  byte-stable for the same KAT seeds + reference clock.

- **11.3 — Hard placeholders.** Wired in 11.2:
  - All five OIDC JWT defects via a `JwtDefect` enum
  - `__CAPTURED_PROOF_FROM_ORIGINAL_HANDSHAKE__` mints a real
    pinned-key proof against the fixture's
    `captured_proof_context` tuple, embedded in a differently-tupled
    outbound envelope so verification fails per RFC-AITP-0002 §3.1
  - `__INVALID_POP_SIG_OVER_WRONG_NONCE__` mints a real signature
    over the wrong input

  Auxiliary fixes the migration surfaced:
  - Manifest PoP `challenge` field had wrong length (34 vs schema's
    required 22) in some fixtures; minter normalizes + re-signs
  - `env-002`'s `active_tct` was missing `issued_at`;
    `ensure_tct_binding` was extended to synthesize it

- **11.4 — Run + validate + commit + report.**
  - All 22 fixtures minted cleanly
  - 0 unsubstituted `__UPPER_SNAKE__` placeholders (excluding
    description / rationale text fields)
  - 0 leftover placeholder AIDs
  - 30 signed objects across 22 fixtures all validate against their
    spec schemas

## Final test counts

| Metric | alpha.4 phase 10 | alpha.4 phase 11 |
|---|---|---|
| Tests passing | 171 | 171 |

No new test count — phase 11 is authoring tool + spec material, not
new wire-format work. The KAT byte-match test was updated in place;
sign/verify round-trip continues to pass.

## Final lint/build/audit status

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | ✓ clean |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | ✓ clean |
| `cargo doc --workspace --no-deps --all-features` | ✓ clean |
| `cargo build --workspace --release` | ✓ clean |
| `cargo deny check` | ✓ all green |

## Spec-side state

22 fixtures minted in the spec working tree, **not committed**.
Backup at `/tmp/aitp-conformance-backup`. Suggested commit:

```
Spec rc.5: migrate 22 conformance fixtures to real signed values

Closes BLOCKED-SPEC-FIXTURE-MIGRATION / aitp-rs#PHASE-B-FIXTURE-PR.
Minted by aitp-rs/tools/mint-conformance-fixtures against KAT
keypairs 001/002/003 + reference clock 1711900000.
```

## Reviewer should check carefully

- Two fixture-only OIDC issuer secrets (HS256, hardcoded in the
  minter) for the `__VALID_JWT*` family. Not in spec; only aitp-rs
  knows them. Other-language adapters reading the migrated fixtures
  would need the same secrets — for v0.1 acceptable since aitp-rs is
  the only consumer.
- `someOtherAgent` placeholder maps to a fixture-only Ed25519 seed
  `0xab × 32`, NOT in `keypairs.json` — intentionally a third-party
  AID the verifier doesn't recognize.
- `__VALID_NONCE__` is deterministic per-fixture (SHA-256 of
  fixture id → base64url 16 bytes); re-mints reproduce.
- Manifest PoP `challenge` normalized to 22 chars when fixture
  supplied longer; original used as a seed for deterministic
  replacement.

## Open follow-ups

- Spec commit + push (22 fixture files)
- Conformance round-trip CI in aitp-rs (run runner against minted
  fixtures, assert 22/22 outcomes match)
- First cross-language adapter validates the whole setup
