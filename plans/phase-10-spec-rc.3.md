# Phase 10 — Spec rc.3 prep + paired aitp-rs follow-up

You are executing this phase against the **spec repo**
(`agentidentitytrustprotocol/agentidentitytrustprotocol`), with paired
follow-ups in **`aitp-rs`** that consume the new spec values.

This phase exists because three spec-side gaps were surfaced while
implementing alpha.3 in `aitp-rs`. None of them require a wire-format
change; all are about completing the test-fixture and reference-vector
material so cross-implementation interop becomes byte-stable.

The goal is to land a new spec commit (`rc.3`) that the `aitp-rs`
adapter can mint signed examples and migrate conformance fixtures
against.

---

## Required reading

In the spec repo:

1. `schemas/conformance/PLACEHOLDERS.md` (the rc.2 prep commit's
   normative placeholder convention)
2. `schemas/conformance/known-answer/README.md` (KAT directory)
3. `schemas/conformance/known-answer/keypairs.json`
4. `schemas/conformance/known-answer/signed-examples/README.md` (paired
   PR target)
5. The 21 fixtures under `schemas/conformance/*.json` (focus on the 3
   that use `__VALID_SIG__` — see 10.2 below)
6. `rfcs/RFC-AITP-0008-revocation.md` (currently reserved-only)

In aitp-rs:

7. `docs/design/PENDING.md` — `BLOCKED-SPEC-EXAMPLE`,
   `PHASE-B-FIXTURE-PR`, `NOTE-VERIFY-REVOCATION-SNAPSHOT`
8. `docs/history/phases/phase-9-report.md` — what alpha.3 phase 9
   already shipped on the implementation side

---

## Tasks

### 10.1 — Add `kat-keypair-003` to spec keypairs.json

**Spec repo.** A third pinned Ed25519 keypair is required so the
single-hop delegation signed example
(`signed-examples/delegation/single-hop-001-002-003.json`) has three
distinct seeds for the three roles (delegator, delegatee, peer).

Append to `schemas/conformance/known-answer/keypairs.json`:

```json
{
  "id": "kat-keypair-003",
  "seed_hex": "<32-byte hex; pick a value visually distinct from 001/002, e.g. 0xff repeated or a notable byte sequence>",
  "pubkey_b64url": "<derive>",
  "aid": "aid:pubkey:<derive>"
}
```

Also extend `schemas/conformance/known-answer/jwk-thumbprints.json`
with `kat-jwk-thumb-003` referencing the new keypair.

Compute the derived values using any conformant implementation
(`aitp-rs-adapter` exposes `generate_keypair { seed: "<hex>" }` and
`compute_jwk_thumbprint { public_key: "..." }` for this purpose).
Update both JSON files in the same commit, plus the README's
"vectors" table.

The `aitp-rs` paired follow-up: extend
`crates/aitp-crypto/tests/kat.rs` so its
`keypair_kat_seed_to_pubkey_to_aid` and `jwk_thumbprint_kat` tests
both iterate over the new vector. They already use the array-of-vectors
shape, so the change is one more entry's worth of validation; the
vendored sync via `scripts/sync-schemas.sh` picks up the new files
automatically.

### 10.2 — Resolve `__VALID_SIG__` ambiguity in fixtures

**Spec repo.** Three fixtures use a placeholder `__VALID_SIG__` that
is **not** defined in `schemas/conformance/PLACEHOLDERS.md`:

- `env-002-policy-violation.json`
- `tct-002-expired.json`
- `tct-004-revoked.json`

A minting tool walking these files cannot decide which signing input
the placeholder covers (envelope? TCT? PoP?). Pick one of:

- **A. Add `__VALID_SIG__` as a normative alias.** Define in
  PLACEHOLDERS.md that it means "the contextually-correct signing
  input — envelope sig if the surrounding object is an envelope, TCT
  sig if the surrounding object is a TCT, etc." Minting tool
  dispatches on parent object shape.
- **B. Rename in the fixtures.** Replace each `__VALID_SIG__` with
  the specific token: `__VALID_ENVELOPE_SIG__` for `env-002`,
  `__VALID_TCT_SIG__` for `tct-002` and `tct-004`.

Path B is preferred — it's unambiguous and matches the existing
PLACEHOLDERS.md style. Path A introduces a runtime decision the
minting tool has to get right.

If you take path B, also audit `mh-001-replay-rejected.json` and
`env-003-key-resolution-failed.json` — they currently have **no**
placeholder tokens. Either they're complete (verify) or they're
shells with field gaps (replace with proper placeholder content per
PLACEHOLDERS.md).

### 10.3 — Define revocation-snapshot wire type in RFC-AITP-0008

**Spec repo.** RFC-AITP-0008 currently reserves the revocation
snapshot concept without defining its wire shape. Without it:

- `aitp-rs-adapter` cannot implement `verify_revocation_snapshot`
  (Tier-C op).
- The `signed-examples/revocation/` directory cannot be populated.
- The conformance runner SKIPs any fixture that asks for revocation
  snapshot operations.

Define the wire type in `rfcs/RFC-AITP-0008-revocation.md` and
`schemas/json/aitp-revocation-snapshot.schema.json`. Minimum fields:

- `version` — `"aitp/0.1"`.
- `issuer` — Aid of the issuing peer.
- `issued_at`, `expires_at` — Unix seconds.
- `entries` — array of `{tct_jti, revoked_at}` objects (may be empty
  for "no revocations" snapshots).
- `signature` — over JCS-canonical body excluding `signature`.

Use the same envelope wrapper pattern as TCT/manifest/delegation:
`{"revocation_snapshot": {...}}` outer object.

The `aitp-rs` paired follow-up:

- Add `crates/aitp-revocation` (or fold into `aitp-tct` if minimal)
  with `RevocationSnapshot`, `verify_revocation_snapshot` mirroring
  the existing verify-* shape.
- Wire `verify_revocation_snapshot` op in `aitp-rs-adapter`.
- Add the in-process adapter equivalent.
- Add a schema-validation test against the new
  `aitp-revocation-snapshot.schema.json`.
- Update PENDING.md `NOTE-VERIFY-REVOCATION-SNAPSHOT` with status.

If the spec maintainers prefer to defer RFC-0008 to v0.2, mark this
task `WONTFIX-FOR-V0.1` and remove `verify_revocation_snapshot` from
the conformance op vocabulary entirely (so other adapters know not to
expect it). Either is fine; pick deliberately.

---

## After spec changes land — paired aitp-rs work

These are the aitp-rs deliverables that depend on the spec rc.3
commit. They go in a new aitp-rs phase 11 (or extend phase 10's
report if that's cleaner):

### Mint signed examples (closes BLOCKED-SPEC-EXAMPLE / spec issue #5)

Write `aitp-rs/scripts/mint-signed-examples.rs` that:

1. Spawns or links the `aitp-rs-adapter` Tier-B issuance ops.
2. Uses `kat-keypair-001`, `002`, `003` seeds.
3. Mints:
   - `signed-examples/manifest/kat-keypair-001-manifest.json`
   - `signed-examples/tct/kat-keypair-001-issues-002.json`
   - `signed-examples/delegation/single-hop-001-002-003.json`
   - `signed-examples/revocation/kat-keypair-001-snapshot.json`
     (only if 10.3 defined the type; otherwise omit and document)
4. Each output gets the `_kat_input` companion at the top level per
   `signed-examples/README.md`.

Open a PR against the spec repo populating the directory.

### Migrate the 21 conformance fixtures (closes PHASE-B-FIXTURE-PR)

Write `aitp-rs/scripts/mint-conformance-fixtures.rs` that:

1. Walks each fixture under `agentidentitytrustprotocol/schemas/conformance/*.json`.
2. Identifies `__UPPER_SNAKE__` placeholders by name.
3. Substitutes per `PLACEHOLDERS.md` rules, using the pinned KAT
   keypairs and the spec's documented operations.
4. Writes the migrated fixture back.

Each placeholder family has its own substitution code path. Time
placeholders are easy. Signature placeholders require driving the
adapter's issuance ops. Failure-injection placeholders (e.g.
`__TAMPERED_SIGNATURE__`, `__CAPTURED_PROOF_FROM_ORIGINAL_HANDSHAKE__`)
require minting a known-good signed object then mutating one byte or
re-signing under a different key.

The script produces a deterministic, reproducible output: same input
fixtures + same KAT seeds + same clock = byte-identical migrated
fixtures. Document how to reproduce in
`scripts/mint-conformance-fixtures.md`.

Open a PR against the spec repo replacing the 21 files in a single
themed commit. Validate that the runner now passes all 21 against
`aitp-rs-adapter`.

---

## Stop here

Phase 10 is **two commits in the spec repo** (10.1 + 10.2 in one,
10.3 in another since it touches an RFC) plus the paired aitp-rs
work as separate phase 11.

Do not push commits without human review. Do not announce alpha.3
external to the project until both spec rc.3 and the paired aitp-rs
follow-ups are stable.

## Success gate

- spec rc.3 commit lands with kat-keypair-003, jwk-thumb-003, and
  the `__VALID_SIG__` resolution
- aitp-rs `crates/aitp-crypto/tests/kat.rs` passes against the
  expanded vectors
- Decision recorded for revocation snapshot (defined OR
  WONTFIX-FOR-V0.1)
- aitp-rs PENDING.md reflects the new spec state
