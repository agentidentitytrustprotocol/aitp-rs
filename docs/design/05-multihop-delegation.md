# 05 — Multi-hop delegation (RFC-AITP-0011)

> **Status: draft / opt-in.** The multi-hop verifier always compiles in
> `aitp-delegation`, but is **gated at runtime**: `VerifyDelegationContext`
> ships `max_hops = 0` (strict v0.1), so any non-empty `chain` is rejected
> unless a caller explicitly raises the cap. The language bindings expose it
> only under the `experimental-multihop-delegation` feature, via
> `verify_delegation_experimental_multihop` /
> `verifyDelegationExperimentalMultihop`. See [00](00-architecture.md) for why
> draft behavior must never be reachable from a default build.

## Motivation

Single-hop delegation (RFC-AITP-0006) lets B, holding a TCT from A, authorize C
to act with a subset of B's grants — verified by A. Multi-hop generalizes this
to an authority chain A → B → C → … → Z, where each hop delegates a (non-
expanding) subset of the previous hop's capabilities. The verifier (the root
grantor A) must be able to validate the entire lineage from a single token.

## Wire format (RFC-AITP-0011)

A `DelegationToken` carries two extra fields beyond the single-hop shape:

| Field | Meaning |
|---|---|
| `chain` | `Vec<DelegationStep>`, **oldest hop first**. Absent/empty ⇒ single-hop (v0.1). `chain[0].issuer` MUST equal `delegator` (A), rooting the chain. Holds the first *n−1* hops. |
| `chain_hash` | REQUIRED when `chain` is non-empty. `base64url(sha256(JCS([chain[0].source_tct_jti, …, chain[n-2].source_tct_jti])))` — a truncation-defense binding (§5). |

The **most-recent hop lives in the top-level `grant_proof`**, not in `chain`;
total hop count is `chain.len() + 1`. A `DelegationStep` is the same wire shape
as `GrantProof` (`issuer, subject, capabilities, issued_at, expires_at,
source_tct_jti, signature`). For `chain[0]` the signature is reused verbatim
from A's original source TCT; for later hops it is the issuer's signature over
the canonical step body.

## Verification algorithm (`verify_delegation` → `verify_multihop`)

`verify_delegation` routes to the multi-hop path when `chain` is non-empty.
Order of checks (each → a `DelegationError`):

1. **Hop gate.** `max_hops == 0` → `MultihopNotSupported` (the v0.1 strict
   default). Then `chain.len()+1 > max_hops` → `HopLimitExceeded`.
2. `audience == delegator == verifier_aid` → else `AudienceMismatch`.
3. `chain[0].issuer == verifier_aid` (chain is rooted at A) → else `InvalidGrantProof`.
4. JTI uniqueness across `chain` (collision defense) → else `ChainHashMismatch`.
5. **Expiry monotonicity.** Every hop's `expires_at` is in the future and
   non-increasing across hops; `grant_proof.expires_at` ≤ last chain hop;
   `token.expires_at` ≤ `grant_proof.expires_at`.
6. **Audience continuity.** `chain[i].subject == chain[i+1].issuer`;
   `chain[n-2].subject == grant_proof.issuer == issued_by`;
   `grant_proof.subject == delegatee`. (Note: unlike single-hop, the top-level
   `grant_proof` here is the *final hop*, so its `subject` is the delegatee.)
7. No self-delegation (`issued_by != delegatee`).
8. **Per-hop signatures.** `chain[0]` via source-TCT projection; later hops and
   the `grant_proof` via step-body signature.
9. **Transitive scope subsetting.** `chain[0].caps ⊇ … ⊇ grant_proof.caps ⊇ token.scope`.
10. **Per-hop revocation.** Every `source_tct_jti` (chain + grant_proof) is consulted.
11. **`chain_hash` recompute-and-compare** → else `ChainHashMismatch`.
12. Outer `signature` (covers `chain_hash`) verifies under `issued_by`'s key.
13. `cnf` decodes to the delegatee AID's compressed pubkey.

`DEFAULT_MAX_HOPS = 3` is the RFC §2 recommended ceiling (orchestrator →
planner → executor); deployments may pass a smaller value.

## Known limitations

- **Opt-in only.** A default build rejects every multi-hop token. The binding
  surface name carries the warning (`…ExperimentalMultihop`).
- Single-hop verification ignores `max_hops` entirely — a strict (`max_hops=0`)
  verifier still accepts a normal RFC-0006 single-hop delegation.
- Draft: excluded from the v0.1 conformance gate.

## SDK example

```python
# Default (strict v0.1): any non-empty chain is rejected.
aitp.verify_delegation(envelope_json, verifier_aid)   # → MULTIHOP_NOT_SUPPORTED

# Opt-in (built with experimental-multihop-delegation):
aitp.verify_delegation_experimental_multihop(envelope_json, verifier_aid, 3)
```

```js
verifyDelegation(envelopeJson, verifierAid);                       // strict
verifyDelegationExperimentalMultihop(envelopeJson, verifierAid, 3); // opt-in
```
