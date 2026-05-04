# Phase 3c Report — `aitp-delegation`

## Tasks completed

- IMPL-036 (type round-trips, deny-unknown-fields, no `extensions` per schema)
- IMPL-037 (`DelegationBuilder.build` reusing A's signature verbatim)
- IMPL-038 (`verify_delegation` running 11 spec checks)

## Test counts

| Suite | Count |
|---|---|
| `aitp-delegation` unit tests | 5 |
| `tests/round_trip.rs` | 11 |

All 16 tests pass.

## Decisions in this phase

1. **Source TCT body reconstruction.** RFC-AITP-0006 §3.1 specifies the
   wire fields of `grant_proof` but does not carry `issued_at` or the
   source TCT's `binding.cnf`. To re-verify A's signature on the source
   body, the verifier must reconstruct exactly the bytes A signed. Two
   missing pieces:
   - **`binding.cnf` of the source TCT** — known to be B's public key
     (the source TCT's subject is B, and binding.cnf is the subject's
     pubkey). We derive it from `delegation.issued_by`'s AID.
   - **`issued_at`** — not carried in `grant_proof`. We reconstruct as
     `expires_at - DEFAULT_TCT_TTL_SECS` (1 hour). This matches what
     `aitp-tct::TctBuilder` produces with the default TTL. **Recorded
     as `BLOCKED-SPEC-DELEGATION-ISSUEDAT` in `docs/design/PENDING.md`.**
     A clean spec resolution would either:
     - add `issued_at` to `grant_proof`, OR
     - normatively pin a reconstruction recipe.
2. **Self-delegation rejected at issuance and at verification**
   (`issued_by == delegatee` is forbidden — RFC-AITP-0006 §4.4 step 10).
3. **Scope subset checked at issuance and at verification**, defense-
   in-depth (the issuer can refuse to mint an over-scoped token; the
   verifier can refuse to honor one).
4. **Scope-cannot-exceed-grant_proof.expires_at** enforced at issuance
   (`expires_at = min(now+ttl, grant_proof.expires_at)`).

## `BLOCKED-SPEC-DELEGATION-ISSUEDAT` (new)

The source-TCT `issued_at` field is not carried in `grant_proof`, but
A's signature covers it. Without it, the verifier cannot recompute the
exact bytes A signed. We assume `issued_at = expires_at - 3600` (the
default TctBuilder TTL). Tokens minted with non-default TTLs would fail
this check across implementations.

Two clean fixes:
1. Add `issued_at: i64` to the `grant_proof` schema (one extra integer).
2. Or formalize the reconstruction recipe in RFC-AITP-0006 §6 with a
   pinned default TTL and a way to override it.

## Things the human reviewer should look at

1. The `SourceTctView` field set in `verifier.rs`. It must match
   `aitp-tct::TctSigningView` byte-for-byte (modulo JCS reordering).
2. The `binding.cnf` derivation in `binding_cnf_for_source` — we assume
   the source TCT's `binding.cnf` was the base64url of B's pubkey
   (because subject == audience in v0.1 and binding.cnf == subject's
   pubkey). If a future TCT profile breaks that invariant, this will
   silently drift.
3. The `expires_at <= grant_proof.expires_at` ordering. The
   implementation rejects tokens where `delegation.expires_at >
   grant_proof.expires_at` with `Expired`. The spec at §4.1 step 3 says
   `MUST be <= grant_proof.expires_at`. We enforce strictly.
