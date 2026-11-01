# Multi-hop delegation (RFC-AITP-0011)

> **Status: Draft, in `aitp-experimental`.**
> [RFC-AITP-0011](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0011-multihop-delegation.md)
> is a Community Standards Track (Draft) RFC outside v0.3 core conformance.
> Multi-hop delegation is in the `aitp-experimental` crate
> (`aitp_experimental::delegation`): `ChainedDelegationBuilder` mints and
> extends chains and `verify_chained_delegation` verifies them. The stable
> `aitp::delegation::verify_delegation` rejects any token carrying a `chain`
> claim with `DELEGATION_MULTIHOP_NOT_SUPPORTED`. The language bindings
> expose the strict `verify_delegation` / `verifyDelegation` and, under
> their `experimental-multihop-delegation` feature (off by default, absent
> from the published packages), `verify_delegation_multihop` /
> `verifyDelegationMultihop`. See
> [architecture](architecture.md#why-multi-hop-delegation-is-unreachable-by-default).

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

`aitp-rs` specifics: claims deserialize into `ChainedDelegationClaims`
(`crates/aitp-experimental/src/delegation/types.rs`); the RFC §2 recommended
ceiling is exported as `DEFAULT_MAX_DELEGATION_HOPS = 3`, which with `+2`
admits a single-entry `chain` (the A → B → C → D example).
`ChainVerifyContext::new` sets it; `with_max_delegation_hops(n)` changes it.
`with_insecure_localhost_dangerous()` admits a loopback plain-HTTP issuer
Manifest for local development. It is off by default.

## Verification (`verify_chained_delegation`)

The normative order is
[RFC-AITP-0011 §2–§6](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0011-multihop-delegation.md#3-per-hop-verification).
How `crates/aitp-experimental/src/delegation/verifier.rs` runs it, with the
`ChainedDelegationError` variant each failure maps to (the checks shared
with single-hop report as `ChainedDelegationError::Delegation(DelegationError::…)`):

0. **Strict gate.** With `max_delegation_hops == 0`: any `chain` claim (even `[]`) →
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
   - **Common claims**: `aud` equals the verifier at every
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
   against the `RevocationSource::Check` hook passed to
   `ChainVerifyContext::new` (queried with the verifier's own AID), then
   each hop's `iss` and `jti` against `with_hop_revocation_check` →
   `SourceTctRevoked`. A soft-fail safe subset narrows
   `VerifiedChainedDelegation::effective_grants`; an empty intersection is
   `SafeSubsetEmpty` (`POLICY_VIOLATION`). Revocation is
   `fail_closed` (RFC-AITP-0008 §3.1): a hook that cannot answer, or a
   multi-hop chain with no hop hook, gives `RevocationUnavailable`
   (`DELEGATION_SOURCE_TCT_REVOKED` on the wire).
   `RevocationSource::FailOpen` skips every lookup.

Proof of possession is not part of `verify_chained_delegation`: the caller runs the
RFC-AITP-0006 §4 step 9 exchange against the presenting agent, with the
bound key from the **outer** token's `sub`
(`aitp::tct::sign_pop_response` / `verify_pop_response`).

## Known limitations

- **Stable `aitp` is single-hop.** `aitp::delegation::verify_delegation`
  rejects every `chain`-bearing token with `DELEGATION_MULTIHOP_NOT_SUPPORTED`
  ([RFC-AITP-0006 §4](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0006-delegation.md#4-verification-rules)),
  ahead of every other claim check, and every token carrying `jti` or
  `chain_hash` with `ClaimsMalformed` (`INVALID_ENVELOPE`). A single-hop
  token with none of these claims verifies the same way under both
  verifiers.
- **Manifests are supplied, not fetched.** The verifier is synchronous and
  does no I/O: the caller provides the issuers' Manifests through an
  `aitp::manifest::ManifestResolver` (a `Vec<Manifest>`, a
  `HashMap<Aid, Manifest>`, or its own cache) and is responsible for
  obtaining them (RFC-AITP-0007 §1 lists the sources). Single-hop tokens
  need the delegator's Manifest from the same source (RFC-AITP-0006 §4
  step 1).
- **Draft, opt-in.** Outside the core conformance gate; the `del-mh-*`
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
use aitp::tct::RevocationSource;
use aitp_experimental::delegation::{verify_chained_delegation, ChainVerifyContext};

// Any `ManifestResolver` (here a `Vec<Manifest>` of the hop issuers'
// Manifests): each hop verifies under its issuer's verified Manifest key.
let ctx = ChainVerifyContext::new(&my_aid, now, RevocationSource::Check(&is_revoked))
    .with_issuer_manifests(&issuer_manifests)
    .with_hop_revocation_check(&is_hop_revoked);
let verified = verify_chained_delegation(&delegation_jws, &ctx)?;
```
