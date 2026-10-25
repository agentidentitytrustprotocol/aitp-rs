# Multi-hop delegation (RFC-AITP-0011)

> **Status: Draft, opt-in at the call site.**
> [RFC-AITP-0011](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0011-multihop-delegation.md)
> is a Community Standards Track (Draft) RFC outside v0.3 core conformance.
> The multi-hop verifier is always compiled into `aitp-delegation` and is
> **gated at runtime**: `VerifyDelegationContext::new` sets
> `max_delegation_hops = 0` (strict default), so any token carrying a `chain`
> claim is rejected unless the caller raises the cap with
> `VerifyDelegationContext::with_max_delegation_hops(n)`. In Rust there is
> one entry point, `verify_delegation`; the language bindings split it into
> the strict `verify_delegation` / `verifyDelegation` and an explicit
> `verify_delegation_multihop` / `verifyDelegationMultihop` (present in the
> default build via the bindings' `multihop-delegation` feature). See
> [architecture](architecture.md#why-multi-hop-delegation-is-unreachable-by-default)
> for why multi-hop must never be reachable without an explicit opt-in.

## Motivation

Single-hop delegation (RFC-AITP-0006) lets B — holding a TCT from A and the
companion grant voucher A minted alongside it — authorize C to act with a
subset of B's grants, verified by A. Multi-hop generalizes this to an
authority chain A → B → C → … → Z, where each hop delegates a
(non-expanding) subset of the previous hop's capabilities, and A validates
the whole lineage from a single token.

## Wire format

Defined in
[RFC-AITP-0011 §1](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0011-multihop-delegation.md#1-chain-encoding)
(claims `chain`, `chain_hash`, per-hop `jti`; exactly one root of authority —
the voucher in `chain[0]`) and §5 (`chain_hash` construction). A multi-hop
token is an ordinary `aitp-delegation+jwt` compact JWS; every hop is a
complete delegation JWS verified over its transmitted bytes, with no byte
reconstruction. `total_hops = chain.len() + 2` (§2).

`aitp-rs` specifics: claims deserialize into `DelegationClaims`
(`crates/aitp-delegation/src/types.rs`); the RFC §2 recommended ceiling is
exported as `DEFAULT_MAX_DELEGATION_HOPS = 3`, which with `+2` admits a
single-entry `chain` (the A → B → C → D example).

## Verification (`verify_delegation`, multi-hop path)

The normative order is
[RFC-AITP-0011 §2–§6](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0011-multihop-delegation.md#3-per-hop-verification).
How `crates/aitp-delegation/src/verifier.rs` runs it, with the
`DelegationError` variant each failure maps to:

0. **Strict gate** (`verify_delegation`, lines 137-160). With
   `max_delegation_hops == 0`: any `chain` claim (even `[]`) →
   `MultihopNotSupported` (`DELEGATION_MULTIHOP_NOT_SUPPORTED`); a `jti` claim
   on an otherwise single-hop token → `ClaimsMalformed`, because `jti` is not
   in the single-hop claim set (RFC-AITP-0011 §1.1). With the cap raised, a
   token with a non-empty `chain` takes the multi-hop path below; anything
   else takes the single-hop path, which resolves its issuer's key from the
   same Manifest source (RFC-AITP-0006 §4 step 1).
1. **Hop limit.** `chain.len() + 2 > max_delegation_hops` → `HopLimitExceeded`,
   before any signature work.
2. **`chain_hash`** recomputed over the verbatim chain strings; absent or
   different → `ChainHashMismatch`.
3. **Per hop**, oldest first, outer token last:
   - **JWS.** Strict parse; `typ == aitp-delegation+jwt`. The verification
     key comes from `h.iss`'s Manifest (RFC-AITP-0011 §3 step 1), looked up
     in the `with_issuer_manifests` source: the Manifest must exist, pass
     `verify_manifest` (RFC-AITP-0003 §5) and designate `h.iss`, else
     `KeyResolutionFailed` (`KEY_RESOLUTION_FAILED`, RFC-AITP-0007 §1). No
     source configured fails closed the same way. Then the sole `alg`
     derived from that key; signature → `InvalidSignature`. `ver` must be
     known → `VersionUnknown`.
   - **Common claims** (`check_hop_claims`): `aud` equals the verifier at every
     hop → `AudienceMismatch`; `iss != sub` → `SelfDelegation`; non-empty
     `scope` → `EmptyScope`; `cnf.jkt` matches the key in `sub` →
     `CnfMalformed`. `jti` present and unique across hops → else `InvalidVoucher`.
   - **Expiry.** `h.exp` in the future → else `Expired`.
   - **Root (first hop).** `chain[0]` carries `voucher` → else `InvalidVoucher`;
     the voucher verifies under the verifier's **own** key with
     `voucher.sub == chain[0].iss` → else `InvalidVoucher`; `voucher.exp` in
     the future and `chain[0].exp ≤ voucher.exp` → else `Expired`;
     `chain[0].scope ⊆ voucher.grants` → else `ScopeExceeded`.
   - **Later hops.** No `voucher` → else `InvalidVoucher`;
     `h.iss == previous.sub` → else `InvalidVoucher`; `h.exp ≤ previous.exp`
     → else `Expired`; `h.scope ⊆ previous.scope` → else `ScopeExceeded`.
   - **Nested-chain prefix consistency** (§1.1). A chain entry that carries
     its own `chain` must carry exactly the outer chain's prefix up to that
     entry, with a matching `chain_hash` → else `InvalidVoucher`.
4. **Revocation**, only after every signature check: `voucher.src_jti`
   against the `DelegationRevocation::Check` hook passed to
   `VerifyDelegationContext::new`, then each hop's `(iss, jti)` against
   `with_hop_revocation_check` → `SourceTctRevoked`. Revocation is
   `fail_closed` (RFC-AITP-0008 §3.1): a hook that cannot answer, or a
   multi-hop chain with no hop hook, gives `RevocationUnavailable`
   (`DELEGATION_SOURCE_TCT_REVOKED` on the wire).
   `DelegationRevocation::FailOpen` skips every lookup.

Proof of possession is not part of `verify_delegation`: the caller runs the
RFC-AITP-0006 §4 step 9 exchange against the presenting agent, with the
bound key from the **outer** token's `sub`
(`aitp_tct::sign_pop_response` / `verify_pop_response`).

## Known limitations

- **Opt-in at the call site.** The strict default rejects every `chain`-bearing
  token with `DELEGATION_MULTIHOP_NOT_SUPPORTED`
  ([RFC-AITP-0006 §4](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0006-delegation.md#4-verification-rules))
  and every `jti`-bearing single-hop token with `ClaimsMalformed`. A single-hop
  token with neither claim verifies normally whatever the cap.
- **Manifests are supplied, not fetched.** The verifier is synchronous and
  does no I/O: the caller provides the issuers' Manifests through an
  `aitp_manifest::ManifestResolver` (a `Vec<Manifest>`, a
  `HashMap<Aid, Manifest>`, or its own cache) and is responsible for
  obtaining them (RFC-AITP-0007 §1 lists the sources). Single-hop tokens
  need the delegator's Manifest from the same source (RFC-AITP-0006 §4
  step 1).
- **Draft, opt-in.** Outside the v0.2 conformance gate; the `del-mh-*`
  fixtures run only with `--feature experimental-multihop-delegation`. Pass/skip
  status: [conformance.md](conformance.md#v02-conformance-matrix).

## SDK example

The delegation token is a compact JWS string; pass it, the verifier's own
AID and the issuers' Manifests (`{"manifest": …}` envelope JSON strings) to
the verify call. The bindings surface failures as exceptions without a
structured code: Python raises `RuntimeError("delegation verification failed:
multi-hop delegation is not supported")`, Node throws an `Error` with the same
message.

```python
# Default (strict): any token carrying a `chain` claim is rejected.
aitp.verify_delegation(delegation_jws, verifier_aid, issuer_manifests)   # raises RuntimeError

# Multi-hop (explicit opt-in at the call site; max_delegation_hops defaults to 3):
aitp.verify_delegation_multihop(delegation_jws, verifier_aid, issuer_manifests, 3)
```

```js
verifyDelegation(delegationJws, verifierAid, issuerManifests);             // strict
verifyDelegationMultihop(delegationJws, verifierAid, issuerManifests, 3);   // multi-hop
```

```rust
use aitp_delegation::{verify_delegation, VerifyDelegationContext, DEFAULT_MAX_DELEGATION_HOPS};

// Any `ManifestResolver` (here a `Vec<Manifest>` of the hop issuers'
// Manifests): each hop verifies under its issuer's verified Manifest key.
let ctx = VerifyDelegationContext::new(&my_aid, now)
    .with_max_delegation_hops(DEFAULT_MAX_DELEGATION_HOPS)
    .with_issuer_manifests(&issuer_manifests);
let verified = verify_delegation(&delegation_jws, &ctx)?;
```
