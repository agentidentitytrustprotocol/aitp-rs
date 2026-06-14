# Multi-hop delegation (RFC-AITP-0011)

> **Status: opt-in at the call site.** The multi-hop verifier always
> compiles in `aitp-delegation` and is **gated at runtime**:
> `VerifyDelegationContext` ships `max_hops = 0` (strict default), so any
> token carrying a `chain` claim is rejected unless a caller explicitly
> raises the cap. The language bindings expose it as
> `verify_delegation_multihop` / `verifyDelegationMultihop` (present in the
> default build); the strict single-hop `verify_delegation` remains the
> safe default verifier. See [architecture](architecture.md) for why
> multi-hop must never be reachable without an explicit call.

## Motivation

Single-hop delegation (RFC-AITP-0006) lets B — holding a TCT from A and the
companion grant voucher A minted alongside it — authorize C to act with a
subset of B's grants, verified by A. Multi-hop generalizes this to an
authority chain A → B → C → … → Z, where each hop delegates a
(non-expanding) subset of the previous hop's capabilities. The verifier (the
root grantor A) must be able to validate the entire lineage from a single
token, using only Manifest-resolved public keys for each hop's issuer plus
its own key for the root voucher.

## Wire format (RFC-AITP-0011)

Under v0.2 a multi-hop delegation token is an ordinary **delegation compact
JWS** (RFC-AITP-0006 §2, `typ: aitp-delegation+jwt`) whose claims carry two
extra entries. There are **no `DelegationStep` objects and no byte
reconstruction anywhere in the chain** — every hop is a complete delegation
JWS verified over its transmitted bytes.

| Claim | Meaning |
|---|---|
| `chain` | Array of **delegation compact JWS strings**, ordered oldest hop first (`chain[0]`), each carried **verbatim**. Absent/empty ⇒ single-hop (RFC-AITP-0006). Holds every prior hop except the outer token. |
| `chain_hash` | REQUIRED when `chain` is non-empty. `base64url(sha256(JCS([d_0, …, d_{k-1}])))` where each `d_i = base64url(sha256(ASCII(chain[i])))` — a digest-array commitment over the verbatim chain strings (§5). |
| `jti` | REQUIRED on **every** hop of a chain (each `chain[i]` and the outer token): a fresh UUID v4, the hop's revocation handle (§6). |

Each `chain[i]` is a complete delegation JWS with the RFC-AITP-0006 §2 claims
(`ver, iss, sub, aud, scope, exp, cnf`) plus `jti`. Exactly **one root of
authority**: `chain[0]` (the first hop, B → C) carries the `voucher` claim —
A's grant voucher, embedded verbatim — and every later hop and the outer token
MUST NOT carry `voucher`. The most-recent hop is the **outer token** D
presents; `total_hops = chain.length + 2` (the `+2` counts the outer hop and
the root peer-issuance attested by the voucher in `chain[0]`).

## Verification algorithm (`verify_delegation` → multi-hop path)

`verify_delegation` routes to the multi-hop path when `chain` is non-empty.
Let the hops oldest-first be `H = [chain[0], …, chain[k-1], outer]`. Order of
checks (each → a `DelegationError`):

1. **Hop gate.** `max_hops == 0` → `MultihopNotSupported` (the strict default).
   Then `total_hops (= chain.len()+2) > max_hops` → `HopLimitExceeded`, computed
   **before any signature work** so a long chain can't force unbounded effort.
2. **`chain_hash` recompute-and-compare** over the verbatim chain strings →
   else `ChainHashMismatch` (also if `chain` is non-empty and `chain_hash` is absent).
3. **Per hop `h` in `H`:**
   - **Standard JWS verification.** Strict parse; `typ == aitp-delegation+jwt`
     (else `TOKEN_TYP_MISMATCH`); sole `alg` derived from `h.iss`'s AID (else
     `TOKEN_ALG_MISMATCH`); signature verifies under `h.iss`'s Manifest-resolved
     key (else `InvalidSignature`) — over the verbatim entry bytes, never reconstructed.
   - **Common claims.** `ver` known; `aud == A` at every hop; `h.iss != h.sub`;
     `h.cnf.jkt` matches the key in `h.sub`; `h.jti` present and unique across all hops.
   - **Root authority (first hop only).** `chain[0]` carries `voucher`; verify it
     per RFC-AITP-0006 §4 steps 3–5: `typ == aitp-grant+jwt`, `voucher.iss == A`
     and signature valid under A's **own** key, `voucher.sub == chain[0].iss`
     (else `InvalidVoucher`), `voucher.exp` future and `chain[0].exp ≤ voucher.exp`.
   - **Continuity (every later hop).** `voucher` absent (else `InvalidVoucher`);
     `h.iss == previous_hop.sub`.
   - **Expiry monotonicity.** `h.exp` in the future and ≤ the preceding hop's
     `exp` (first hop: ≤ `voucher.exp`).
   - **Scope subsetting.** `chain[0].scope ⊆ voucher.grants`; `chain[i].scope ⊆
     chain[i-1].scope`; `outer.scope ⊆ chain[k-1].scope` — checked at **every**
     adjacent pair (else `ScopeExceeded`).
4. **Per-hop revocation** (the only stateful step, after all signature checks):
   `chain[0].voucher.src_jti` against A's own deny list; each hop's `jti` against
   the deny list of that hop's `iss` (RFC-AITP-0008). Any "revoked" → `SourceTctRevoked`.
5. **Proof of possession** against the presenting agent, with the bound key
   taken from the **outer** token's `sub` AID and checked against the outer `cnf.jkt`.

A per-hop structural failure not covered by a more specific code surfaces as
`InvalidVoucher` (the renamed v0.1 `INVALID_GRANT_PROOF` — that code no longer
exists). `DEFAULT_MAX_HOPS = 3` is the RFC §2 recommended ceiling
(orchestrator → planner → executor); deployments may pass a smaller value.

## Known limitations

- **Opt-in at the call site.** The default verifier (`verify_delegation`)
  rejects every token carrying a `chain` claim with
  `DELEGATION_MULTIHOP_NOT_SUPPORTED` (RFC-AITP-0006 §4), a structural
  rejection before any per-hop work. Multi-hop requires explicitly calling
  `verify_delegation_multihop` — a separate function, so the choice is
  always deliberate.
- Single-hop verification ignores `max_hops` entirely — a strict (`max_hops=0`)
  verifier still accepts a normal RFC-0006 single-hop delegation (a token with
  no `chain` claim).
- Draft RFC: excluded from the v0.2 conformance gate; the `del-mh-*`
  fixtures pass under the `multihop-delegation` conformance opt-in.

## SDK example

The delegation token is a compact JWS string; pass it (and the verifier's
own AID) to the verify call.

```python
# Default (strict): any token carrying a `chain` claim is rejected.
aitp.verify_delegation(delegation_jws, verifier_aid)   # → MULTIHOP_NOT_SUPPORTED

# Multi-hop (explicit opt-in at the call site):
aitp.verify_delegation_multihop(delegation_jws, verifier_aid, 3)
```

```js
verifyDelegation(delegationJws, verifierAid);                       // strict
verifyDelegationMultihop(delegationJws, verifierAid, 3); // multi-hop
```
