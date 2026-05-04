# Phase 11 — Conformance fixture migration

You are migrating the 22 spec conformance fixtures at
`agentidentitytrustprotocol/schemas/conformance/*.json` from the
legacy placeholder shape to fully-minted real signed values per the
PLACEHOLDERS.md normative substitution rules.

This phase was carved out of phase 10 because it is genuinely 4–8
hours of focused work — substantially more than the rest of phase 10
combined — and the infrastructure it needs (KAT keypairs 001/002/003,
revocation snapshot type, minting binary pattern from
`tools/mint-signed-examples`) all landed in phase 10.

> **Spec-side prerequisites — DONE.** As of spec rc.3, the spec repo
> ships everything the minting tool reads in:
>
> - `schemas/conformance/known-answer/keypairs.json` carries
>   `kat-keypair-001` (seed `00…00`), `kat-keypair-002`
>   (seed `00..1f`), and `kat-keypair-003` (seed `ff…ff` →
>   `aid:pubkey:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU`).
> - `schemas/json/aitp-revocation-list.schema.json` defines the
>   signed snapshot type, with `version` and `signature` REQUIRED
>   (matches the TCT/Manifest pattern). Two illustrative examples
>   live under `examples/revocation/`.
> - `schemas/conformance/PLACEHOLDERS.md` pins the role mapping
>   (`agentA` → 001, `agentB` → 002, `agentC` → 003), the reference
>   clock for `__NOW__` (`1711900000`), the runner-facing
>   `input.operation` registry per fixture-id prefix, and the tamper
>   recipe for `__TAMPERED_*__` (sign-then-flip-LSB of last raw
>   signature byte).
> - `kat-revocation-001` in `known-answer/jcs-sha256.json` was
>   re-minted to include the `version` field; SHA-256 changed to
>   `cbf40cd640287a72ce3b76b6e5c20b508c61381985d0a0bfd23079ece27d2cf8`.
>
> Pull the spec at the rc.3 commit before running the minting tool.

## Required reading

In the spec repo:

1. `schemas/conformance/PLACEHOLDERS.md` — every `__UPPER_SNAKE__`
   token's normative substitution rule
2. Each of the 22 fixtures under `schemas/conformance/*.json` — they
   all have different shapes; understanding each scenario is mandatory
   before substituting
3. `schemas/conformance/known-answer/keypairs.json` — the three
   pinned KAT keypairs to mint against

In aitp-rs:

4. `tools/mint-signed-examples/src/main.rs` — the working minting
   pattern from phase 10 (drives the protocol crates directly with
   pinned seeds and clocks)
5. `crates/aitp-rs-adapter/src/main.rs` — the Tier-B issuance ops
   the new minting tool can also use
6. `docs/history/phases/phase-10-report.md` — what landed in phase 10
   and what specifically was deferred to here

## The work

Write `aitp-rs/tools/mint-conformance-fixtures/` as a new workspace
member. Mirrors the structure of `tools/mint-signed-examples`. The
binary:

1. Walks each `*.json` under `${AITP_SPEC_DIR}/schemas/conformance/`.
2. For each file:
   a. Identifies semantic role placeholders in the AIDs
      (`aid:pubkey:agentA_pubkey_AID_v01_placeholder_AAAAAAAAA` etc.)
      and substitutes per a fixture-specific role-to-KAT-seed map
      (see "Role mapping" below).
   b. Re-stamps any time placeholders (`__NOW__`, `__NOW_MINUS_<N>__`)
      with a fixed reference clock so re-mints are byte-stable.
   c. For each signature placeholder, runs the appropriate signing
      pass against the correct KAT keypair (substitutes happen
      *before* signing so the signing input includes real AIDs).
   d. For failure-injection placeholders (`__TAMPERED_*`,
      `__INVALID_POP_*`, `__CAPTURED_PROOF_FROM_ORIGINAL_HANDSHAKE__`),
      mints a known-good signed object first then mutates it
      according to the placeholder's documented break.
   e. Adds a top-level `input.operation` key (currently missing on
      every fixture) naming the conformance op the runner should
      invoke. The mapping is now pinned normatively at
      PLACEHOLDERS.md § "Operation key":
      - `env-*` → `verify_envelope`
      - `man-*` → `verify_manifest`
      - `tct-*` → `verify_tct`
      - `del-*` → `verify_delegation_token`
      - `id-*`, single-message `mh-*` → `verify_handshake_payload`
      - multi-step `mh-*` (sequence-form) → per-step `operation`
        keys; typical values are `start_handshake` and
        `process_handshake_message`.

      Runners MUST treat unknown operations as SKIP (not FAIL) so
      adapters can self-document supported ops without breaking
      runs.
3. Writes the result back to the same path.

## Role mapping

The mapping for placeholder agent identities is now pinned
normatively in the spec at
`schemas/conformance/PLACEHOLDERS.md` § "AID role mapping". Use it
verbatim — the table covers more roles than the original sketch:

| Fixture role | KAT keypair / source |
|---|---|
| `agentA` (initiator / TCT issuer in most fixtures) | `kat-keypair-001` |
| `agentB` (target / TCT subject) | `kat-keypair-002` |
| `agentC` (delegatee, where present) | `kat-keypair-003` |
| `issuingPeer` (alias of `agentA` in delegation fixtures) | `kat-keypair-001` |
| `worker_pubkey_AID_v01_placeholder_wwwwwwwww` | `kat-keypair-002` |
| `verifier_pubkey_…` / `victim_pubkey_…` (verifier in `id-*`) | `kat-keypair-001` |
| `attacker_pubkey_…` (`mh-002`) | One-shot fixture-only keypair (deterministic seed, e.g. `0xff` × 32 — but distinct from the KAT three; pick a fresh fixture-only seed and inline the result) |
| Identity issuer / OIDC issuer (for `__VALID_JWT__`) | Fixture-only keypair, not in `keypairs.json`. Public key inlined into the fixture's `accepted_trust_anchors` |
| Untrusted issuer (for `__VALID_JWT_FROM_UNKNOWN_ISSUER__`) | Second fixture-only keypair, NOT in `accepted_trust_anchors` |

Adjust only if a fixture's narrative requires a swap; deviations
should be documented in the migration commit message.

## Placeholder substitution catalog

Easy (≤ 30 min each):

- `__NOW__`, `__NOW_MINUS_3600__` — substitute with the pinned
  reference clock `1_711_900_000` (PLACEHOLDERS.md §
  "Reference clock for byte-stable minting"). This is now normative
  in the spec; do not pick a different value.
- `__VALID_ENVELOPE_SIG__`, `__VALID_TCT_SIG__`,
  `__VALID_MANIFEST_SIG__`, `__VALID_POP_SIG__` — re-sign the
  surrounding object after AID substitution.
- `__VALID_NONCE__`, `__VALID_NONCE_ECHO__` — generate a deterministic
  nonce (e.g., from a per-fixture seed) so re-mints reproduce.
- `__VALID_A_SIG__`, `__VALID_B_SIG__`,
  `__VALID_ISSUING_PEER_SIG__` — same as the specific sig placeholders
  but determined from surrounding context.

Medium (~1 hour each):

- `__TAMPERED_SIGNATURE__` / `__TAMPERED_SIG__` — sign properly, then
  flip the **least-significant bit of the last raw signature byte**
  before base64url-encoding. The recipe is now pinned normatively in
  PLACEHOLDERS.md § "Failure-injection placeholders".
- `__INVALID_POP_SIG__` — sign over the wrong challenge (use a
  different random nonce for the input).
- `__INVALID_POP_SIG_OVER_WRONG_NONCE__` — same idea but explicitly
  the COMMIT-side PoP nonce mismatch.

Hard (~2-3 hours total):

- `__VALID_JWT__` — needs a mock OIDC issuer keypair, JWT signing
  with proper claims (sub, iat, exp, nonce, cnf.jkt, aud). The
  `crates/aitp-handshake/tests/mock_oidc.rs` already has a working
  pattern; lift the relevant code into the minting tool.
- `__VALID_JWT_FROM_UNKNOWN_ISSUER__` — same as above but signed by
  a SECOND issuer key the verifier doesn't trust. The fixture's
  `trust_anchors` must NOT include that issuer's URI.
- `__JWT_MISSING_AUD_CLAIM__` / `__JWT_AUD_TARGETS_DIFFERENT_PEER__`
  / `__JWT_MISSING_CNF_JKT_CLAIM__` — mint a valid JWT then strip
  the aud claim / replace it / strip cnf.jkt before signing.

Hardest (~1-2 hours):

- `__CAPTURED_PROOF_FROM_ORIGINAL_HANDSHAKE__` — drive a real
  pinned-key handshake to capture a valid identity proof, then
  splice it into a fixture whose surrounding (sender, receiver,
  message_id, timestamp, pop_nonce) tuple is *different*. Tests
  cross-peer replay defense (RFC-AITP-0002 §3.1).

## Validation

After minting, every fixture MUST:

1. Validate against `schemas/json/aitp-*.schema.json` (no remaining
   placeholders, no schema violations).
2. Round-trip through the runner: when fed to
   `aitp-conformance run --target aitp-rs-adapter`, every fixture's
   actual outcome MUST match its `expected.outcome` and
   `expected.error_code`.

Add a CI job `conformance-runner` to aitp-rs that runs the migrated
fixtures and asserts a pass count of 22/22.

## Open the spec PR

After all 22 fixtures are minted and round-trip cleanly:

```sh
gh pr create -R agentidentitytrustprotocol/agentidentitytrustprotocol \
  --title "Spec rc.4: migrate 22 conformance fixtures to real signed values" \
  --body "..."
```

Body should reference the minting tool path + invocation, the spec
commit the fixtures were minted against (whichever spec hash had
PLACEHOLDERS.md, KATs, and the type definitions), and the rc.2/rc.3
issues this PR closes.

## Stop here

This phase ends with two artifacts:

1. `aitp-rs/tools/mint-conformance-fixtures/` (new) — checked in to
   aitp-rs, runnable, with its own integration tests
2. A spec PR rewriting the 22 fixtures

Do not push the spec PR without human review.

## Success gate

- `aitp-rs/tools/mint-conformance-fixtures` runs cleanly and produces
  byte-stable output for the same KAT seeds + clock
- All 22 fixtures validate against their corresponding schema
- All 22 fixtures pass the runner against `aitp-rs-adapter`
- A new aitp-rs CI job exercises the runner against the migrated
  fixtures
- Spec PR opened, awaiting review
- aitp-rs PENDING.md `PHASE-B-FIXTURE-PR` entry marked closed
