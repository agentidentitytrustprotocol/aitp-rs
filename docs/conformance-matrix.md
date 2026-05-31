# AITP v0.1 conformance matrix — `aitp-rs`

Per-fixture status of the `aitp-rs` reference implementation against the
spec's conformance suite (`schemas/conformance/` in the
[`agentidentitytrustprotocol`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol)
repo).

## Summary

| Tier | Fixtures | `aitp-rs` |
|---|---|---|
| `core` (required for v0.1) | 37 | **37 PASS** |
| `draft` — session bundle (`experimental-session-bundle`) | 3 | **3 PASS** (feature opt-in) |
| `draft` — multi-hop delegation (`experimental-multihop-delegation`) | 4 | **4 PASS** (feature opt-in) |
| **Total** | **44** | **44 PASS, 0 FAIL** |

Reproduce:

```bash
cargo build -p aitp-rs-adapter --all-features
# v0.1-strict: 37 PASS / 7 SKIP (draft fixtures) / 0 FAIL
cargo run -p aitp-conformance --all-features -- run \
  --target ./target/debug/aitp-rs-adapter \
  --fixtures-dir ../agentidentitytrustprotocol/schemas/conformance
# opt-in (Draft RFCs): 43 PASS / 1 SKIP (del-004, negated) / 0 FAIL
cargo run -p aitp-conformance --all-features -- run \
  --target ./target/debug/aitp-rs-adapter \
  --fixtures-dir ../agentidentitytrustprotocol/schemas/conformance \
  --feature experimental-multihop-delegation \
  --feature experimental-session-bundle
```

## v0.1 conformance gate

`aitp-conformance run` exits non-zero if any fixture marked
`required_for_v0_1: true` either fails or is SKIPped because the adapter
lacks the operation. A skip whose v0.1 assertion was negated by an
opted-in experimental feature (e.g. `del-004` under
`experimental-multihop-delegation`) is exempt. This stops CI from
silently regressing required coverage into a SKIP.

## Core fixtures (required for v0.1) — 37/37 PASS

| RFC | Fixtures | Notes |
|---|---|---|
| 0001 / 0007 — envelope & key resolution | `env-001`–`env-004` | Signature, replay, timestamp, key-resolution discovery order. |
| 0003 — manifest | `man-001`–`man-003` | Issuance + verification + expiry. |
| 0002 / 0004 — identity & handshake | `id-001`–`id-007`, `mh-001`–`mh-009`, `mh-success-001` | `verify_handshake_payload` op; pinned-key + OIDC identity proofs; four-message exchange; replay. |
| 0005 — TCT | `tct-002`–`tct-006` | Issuance, audience/expiry checks, revocation, downstream PoP round-trip. |
| 0005 §6.2 — PoP enforcement | `tct-007` | A grant the issuer marked PoP-required cannot be invoked without a valid `pop_response`. Exercised via the `authorize_capability_invocation` → `expect_pop_challenge_issued` → `withhold_pop_response` sequence. |
| 0008 — revocation | `rev-001`–`rev-003` | Stale snapshot (`fail_closed` / `soft_fail`), fresh snapshot. |
| 0008 §3.3 — revocation ordering | `rev-004` | An invalid TCT signature is rejected with `TCT_SIGNATURE_INVALID` before any revocation lookup. `verify_tct` verifies the signature ahead of the revocation hook. |
| 0006 — delegation | `del-001`, `del-003`, `del-004` | Single-hop verify; `del-004` pins the v0.1 multi-hop refusal (`DELEGATION_MULTIHOP_NOT_SUPPORTED`). |

## Draft fixtures (post-v0.1, opt-in) — 7/7 PASS under feature flags

| RFC | Fixtures | Feature |
|---|---|---|
| 0010 — Session Trust Bundle | `bundle-001`–`bundle-003` | `experimental-session-bundle` |
| 0011 — multi-hop delegation | `del-mh-001`–`del-mh-004` | `experimental-multihop-delegation` |

In v0.1-strict mode these 7 SKIP (`required_for_v0_1: false`). Opting
into the matching feature runs them; `del-004` then auto-skips because
its v0.1-strict assertion no longer applies.

## Notes

- Side-effect assertions (`side_effects` block on a fixture's
  `expected`, e.g. `rev-004`'s `revocation_lookup_called` and
  `tct-007`'s `pop_challenge_issued` / `capability_authorized`) are
  honored by the runner: any side effect the adapter reports in its
  result's `side_effects` object is asserted against the fixture, and a
  *reported* mismatch is a hard failure. Side effects the adapter does
  not instrument are skipped (treated as un-instrumented, never a
  silent pass). `tct-007` step 2's `pop_challenge_issued` is asserted
  this way; its step 3 outcome (`POP_RESPONSE_INVALID`) independently
  catches a PoP-skipping adapter.
- Fixture metadata (`status`, `feature`, `required_for_v0_1`) and the
  vendored schemas track the spec commit pinned in
  `tests/schemas/SPEC_VERSION`; re-run `scripts/sync-schemas.sh` after
  the spec commit advances.
- **P-256 (RFC-AITP-0001 §5.4.3) has no dedicated *conformance fixture*
  yet** — the `env-001`–`env-004` envelope fixtures are Ed25519. P-256 is
  instead covered locally by: the `kat-keypair-005-p256` vector
  (`tests/schemas/known-answer/keypairs.json`) exercised by
  `aitp-crypto`'s `p256_keypair_kat_scalar_pubkey_aid_and_signature`
  (scalar → pubkey → AID + tagged sign/verify); `aitp-tct`'s
  `p256_subject_round_trip_and_pop`; the pure-Rust OIDC handshakes
  `oidc_minter_handshake_p256_initiator` / `_p256_responder`
  (`aitp-handshake`); and the cross-language
  `test_p256_handshake_via_oidc_python_to_node` interop test. A future
  spec-repo `env-005` P-256 envelope fixture would fold this into the
  conformance gate; until then the drift check rides on `keypairs.json`.
