# Phase 3c — `aitp-delegation`

You are working on the `aitp-rs` Rust reference implementation. This is
Phase 3c of 6.

**Your goal:** working single-hop delegation tokens, with all 11
verification checks correctly enforced.

---

## Required reading

1. `phase-3b-report.md`
2. `crates/aitp-delegation/src/*.rs` — current scaffold
3. AITP spec RFC-AITP-0006, specifically §3 (token schema), §4
   (verification rules), and the rationale for `grant_proof` not being
   the full TCT

---

## Decisions baked in

- **Single-hop only in v0.1.** Multi-hop is RFC-AITP-0011 (reserved).
  Reject any token whose `issued_by` is itself a delegatee.
- **`grant_proof` is a minimized object**, not the full TCT. It carries
  `issuer`, `subject`, `source_tct_jti`, `capabilities`, `expires_at`,
  `signature`. The signature is the same signature A produced over A's
  original TCT to B — the verifier reconstructs the TCT body and
  verifies that signature.
- **`grant_proof.subject MUST equal delegation.issued_by`.** This is
  what stops B from attaching C's grant proof and claiming to delegate
  C's authority.
- **`grant_proof.source_tct_jti` is mandatory.** Used for revocation
  lookup against the issuer's deny list.

---

## Global rules

[All 12 apply.]

- **Stop at the phase boundary.**

---

## Tasks

### 3c.1 — Verify type round-trips (IMPL-036)

The scaffolded types should round-trip. Add tests in `mod tests` of
`types.rs`:

- Round-trip a delegation token with `grant_proof` populated
- Reject delegation JSON with unknown top-level field
- Reject `grant_proof` with unknown field
- Verify that `source_tct_jti` is in the required fields list

### 3c.2 — Implement issuance (IMPL-037)

Add a `DelegationBuilder` to `crates/aitp-delegation/src/builder.rs`
(create the file). API:

```rust
pub struct DelegationBuilder<'a> {
    issuer_key: &'a AitpSigningKey,    // B's signing key
    held_tct: &'a Tct,                 // A's TCT to B (B holds this)
    delegatee: Option<Aid>,            // C's AID
    delegatee_pubkey: Option<AitpVerifyingKey>,  // C's key for cnf
    scope: Vec<String>,
    ttl_secs: i64,
    extensions: ExtensionsMap,
}

impl<'a> DelegationBuilder<'a> {
    pub fn new(issuer_key: &'a AitpSigningKey, held_tct: &'a Tct) -> Self;
    pub fn delegatee(mut self, c_aid: Aid) -> Self;
    pub fn delegatee_pubkey(mut self, c_key: AitpVerifyingKey) -> Self;
    pub fn scope(mut self, caps: impl IntoIterator<Item = impl Into<String>>) -> Self;
    pub fn ttl_secs(mut self, secs: i64) -> Self;
    pub fn build(self) -> Result<DelegationToken, DelegationError>;
}
```

`build()` does:

1. Validate required fields.
2. Sanity check at issuance time: `scope ⊆ held_tct.grants`, else
   `ScopeExceeded`. Better to fail at issuance than mint a token that
   will fail verification.
3. Construct `GrantProof` from `held_tct`:
   - `issuer = held_tct.issuer.clone()`        (this is A)
   - `subject = held_tct.subject.clone()`      (this is B)
   - `source_tct_jti = held_tct.jti`
   - `capabilities = held_tct.grants.clone()`
   - `expires_at = held_tct.expires_at`
   - `signature = held_tct.signature.clone()`
4. Set `delegator = held_tct.issuer.clone()` (A).
5. Set `audience = held_tct.issuer.clone()` (A — the verifier).
6. Set `issued_by = issuer_key.aid().clone()` (B).
7. Set `cnf = delegatee_pubkey.to_jwk_thumbprint()`.
8. Set `expires_at = min(now + ttl_secs, held_tct.expires_at)`.
9. Sign the delegation token with `issuer_key` over its JCS-canonical
   form (using the view-struct pattern from Phase 3b).

### 3c.3 — Implement `verify_delegation` (IMPL-038)

Run all 11 checks in `crates/aitp-delegation/src/verifier.rs`:

1. `delegation.audience == ctx.verifier_aid` (else `AudienceMismatch`)
2. `delegation.delegator == ctx.verifier_aid` (else `AudienceMismatch` —
   the delegator must be the verifier; if it isn't, the token wasn't
   meant for this verifier)
3. Reconstruct the source TCT body from `grant_proof` fields. Verify
   `grant_proof.signature` covers it using the verifier's own public
   key (since the verifier IS A, the original issuer). Else
   `InvalidGrantProof`.
4. `grant_proof.subject == delegation.issued_by` (else
   `InvalidGrantProof` — without this check, B could attach C's
   grant_proof to claim C's authority)
5. `grant_proof.expires_at` is in the future. Else `Expired`.
6. `delegation.expires_at <= grant_proof.expires_at`. Else `Expired`.
7. `scope ⊆ grant_proof.capabilities`. Else `ScopeExceeded`.
8. If `ctx.revocation_check` is `Some`, look up
   `grant_proof.source_tct_jti`. If revoked, `SourceTctRevoked`.
9. Verify the outer `delegation.signature` using
   `delegation.issued_by`'s public key (derived from the AID). Else
   `InvalidSignature`.
10. (PoP check) Caller is responsible for verifying the holder of the
    delegation (C) controls the key matching `cnf` — this happens at
    the operation invocation layer, not in `verify_delegation`. Note
    this in the function's rustdoc.
11. Reject multi-hop: if the spec defines a way to detect "this issuer
    is itself a delegatee" — the simplest check is that
    `delegation.issued_by != grant_proof.issuer` (B != A), which is
    legitimate. Multi-hop would mean stacking delegations, which the
    schema doesn't allow in v0.1 anyway. Document that v0.1's
    single-hop boundary is enforced by the schema, not a runtime
    check, and reference RFC-AITP-0011 (reserved for multi-hop).

### 3c.4 — Round-trip integration test

`crates/aitp-delegation/tests/round_trip.rs`:

- A issues TCT to B; B issues delegation to C; A verifies delegation,
  success
- Mutate scope to include a capability not in TCT.grants → `ScopeExceeded`
- Make `delegation.expires_at` later than `grant_proof.expires_at` →
  `Expired`
- Forge `grant_proof.subject` to be a different AID → `InvalidGrantProof`
- Tamper `delegation.signature` → `InvalidSignature`
- Tamper `grant_proof.signature` → `InvalidGrantProof`
- Revocation_check returns true for `source_tct_jti` →
  `SourceTctRevoked`
- Wrong verifier (audience != verifier_aid) → `AudienceMismatch`

---

## Format, lint, tests

```sh
cargo fmt --all
cargo clippy -p aitp-delegation --all-targets -- -D warnings
cargo test -p aitp-delegation
cargo test -p aitp-delegation --test round_trip
```

---

## Update PENDING.md

Check off: IMPL-036, 037, 038.

---

## Phase report

`phase-3c-report.md` — usual template. Specifically note:
- How you reconstructed the source TCT body for `grant_proof.signature`
  verification (this is the trickiest part — there are several plausible
  serialization choices; document yours)
- Whether your single-hop enforcement is schema-only or has a runtime
  check

---

## Success gate

- All tests pass
- Clippy clean
- Report and PENDING updated

## Stop here.
