# Phase 3b — `aitp-tct`

You are working on the `aitp-rs` Rust reference implementation. This is
Phase 3b of 6.

**Your goal:** working TCT issuance and verification, plus the downstream
PoP exchange types.

The TCT is the central trust artifact in AITP. Be careful here.

---

## Required reading

1. `phase-3a-report.md`
2. `crates/aitp-tct/src/*.rs` — current scaffold
3. AITP spec RFC-AITP-0005 (TCT), specifically:
   - §3 (required fields)
   - §5 (audience model — audience MUST equal subject for v0.1)
   - §6 (PoP and binding.cnf)
   - §9 (consumer verification)
4. `docs/design/01-jcs.md` — the "view struct without signature" pattern

---

## Critical decisions baked into the spec

These are settled. Do not re-derive.

- **Audience = subject** (Model 1, holder receipt). Every TCT has
  `audience == subject`. The verifier checks both that audience equals
  expected_audience AND that audience equals subject.
- **`binding.cnf` is REQUIRED.** Every v0.1 TCT has it. There is no
  bearer-TCT profile.
- **`grants` MUST be non-empty.** `minItems: 1`. Empty grants is a
  protocol violation.
- **`evidence_ref` is OPTIONAL** but if present has `sha256` and
  `description` fields.

---

## Global rules

[All 12 apply.]

- **Stop at the phase boundary.** Do not begin Phase 3c.

---

## Tasks

### 3b.1 — Verify type round-trips (IMPL-032)

The types are scaffolded. Add round-trip tests in `mod tests` of
`types.rs`:

- Round-trip a TCT with grants, no evidence_ref, no extensions
- Round-trip a TCT with evidence_ref present
- Round-trip a TCT with extensions present
- Round-trip a TCT with extensions absent — verify `"extensions":{}` is
  NOT in output JSON
- Reject TCT JSON with unknown top-level field
- Reject TCT JSON where `binding` has unknown field
- Reject TCT JSON with empty `grants` array (assuming the schema layer
  enforces minItems: 1; if serde alone doesn't enforce this, add a
  manual check at the deserialize layer or in the verifier)

### 3b.2 — Implement `TctBuilder::build` (IMPL-033)

File: `crates/aitp-tct/src/builder.rs`

In `build()`:

1. Validate required fields are set:
   - `subject` (else `MissingField("subject")`)
   - `audience` (else `MissingField("audience")`)
   - `subject_pubkey` (else `MissingField("subject_pubkey")`)
   - `grants` is non-empty (else `MissingField("grants")`)

2. v0.1 invariant: assert `subject == audience`. If not, return
   `MissingField("audience must equal subject in v0.1")` or add a new
   variant `InvalidAudience`. (Pick one and document.)

3. Compute `binding.cnf` as the JWK thumbprint of `subject_pubkey`:
   ```rust
   let cnf = subject_pubkey.to_jwk_thumbprint();
   ```

4. Set `issued_at = Timestamp::now()`, `expires_at = issued_at +
   ttl_secs`. Default `ttl_secs` is `DEFAULT_TCT_TTL_SECS` (1 hour).

5. Generate `jti = Uuid::new_v4()`.

6. `issuer = issuer_key.aid().clone()`.

7. Construct a `SignedTctView<'a>` struct that has every field of `Tct`
   EXCEPT `signature`. Use serde rename if needed to match the JCS
   output. The view struct is internal — it only exists to produce the
   exact bytes that get signed.

   ```rust
   #[derive(Serialize)]
   struct SignedTctView<'a> {
       version: &'a str,
       jti: &'a Uuid,
       issuer: &'a Aid,
       subject: &'a Aid,
       audience: &'a Aid,
       issued_at: &'a Timestamp,
       expires_at: &'a Timestamp,
       grants: &'a [String],
       binding: &'a TctBinding,
       #[serde(skip_serializing_if = "Option::is_none")]
       evidence_ref: Option<&'a EvidenceRef>,
       #[serde(skip_serializing_if = "ExtensionsMap::is_empty")]
       extensions: &'a ExtensionsMap,
   }
   ```

8. JCS-canonicalize the view struct. Sign with `issuer_key`. Set
   `signature` on the full Tct. Return.

### 3b.3 — Implement `verify_tct` (IMPL-034)

File: `crates/aitp-tct/src/verifier.rs`

Steps (match the order in the scaffold's TODO comment):

1. Check `version == "aitp/0.1"`. Else: error variant for
   `VersionUnknown` (add to `TctError` if missing).
2. Check `audience == ctx.expected_audience`. Else `AudienceMismatch`.
3. Also check `audience == subject` for v0.1 invariant. Else
   `AudienceMismatch`.
4. Check `expires_at` is in the future (relative to `Timestamp::now()`).
   Else `Expired`.
5. Check `issued_at` is in the past (else suggests clock skew or attack;
   reject with `Expired` for now — the protocol may add a separate
   "future-issued" code later).
6. Construct `SignedTctView` from the TCT (every field except
   signature). JCS-canonicalize it. Verify the signature with
   `ctx.issuer_pubkey`. Else `SignatureInvalid`.
7. If `ctx.revocation_check` is `Some`, call it with `tct.jti`. If true,
   return `Revoked`.
8. Return `Ok(tct)`.

### 3b.4 — Implement PoP types (IMPL-035)

`PopChallenge` and `PopResponse` are already scaffolded in `pop.rs`.
Verify they round-trip JSON correctly. Add a verifier function:

```rust
pub fn verify_pop_response(
    challenge: &PopChallenge,
    response: &PopResponse,
    subject_pubkey: &AitpVerifyingKey,
) -> Result<(), TctError> {
    // 1. tct_jti matches
    // 2. nonce_echo matches challenge.nonce
    // 3. challenge.expires_at is still valid (not stale)
    // 4. Construct PoP signing input — see RFC-AITP-0005 §6.2 if the
    //    spec defines exact byte sequence; otherwise use:
    //
    //      "aitp-pop-v1\0" || jti || "\0" || nonce || "\0" || subject
    //      || ("\0" || method || "\0" || resource || "\0" || body_sha256)?
    //
    //    Pick a concrete encoding and document it in the function's
    //    rustdoc. If the spec has a definitive answer, use that.
    //
    // 5. Verify response.signature over the input using subject_pubkey
}
```

If the spec's exact PoP signing input is unclear, document the choice in
rustdoc and add a `BLOCKED-SPEC-POP-INPUT` note in PENDING.md flagging
that this needs ratification.

### 3b.5 — Round-trip integration test

`crates/aitp-tct/tests/round_trip.rs`:

- Issue a TCT for a subject, verify it with the issuer's pubkey, success
- Wrong audience → `AudienceMismatch`
- Audience != subject (forge a TCT with these mismatched) → fails
- Tamper signature → `SignatureInvalid`
- Tamper a grant in the array → `SignatureInvalid` (proves grants are
  signed)
- Set `expires_at` 1 hour ago → `Expired`
- Use `revocation_check` returning `true` for the JTI → `Revoked`
- PoP challenge/response round-trip success
- PoP response with mismatched nonce → fails

---

## Format, lint, tests

```sh
cargo fmt --all
cargo clippy -p aitp-tct --all-targets -- -D warnings
cargo test -p aitp-tct
cargo test -p aitp-tct --test round_trip
```

---

## Update PENDING.md

Check off: IMPL-032, 033, 034, 035.

If you couldn't pin the PoP signing input from the spec, leave a
`BLOCKED-SPEC-POP-INPUT` entry.

---

## Phase report

`phase-3b-report.md` — same template as before, plus:
- Whether you used a "view struct" or a different approach for signing
  without the signature field. (View struct is recommended; if you
  diverged, explain.)
- The exact PoP signing input you chose (and whether it's pinned by the
  spec or your invention).

---

## Success gate

- All `aitp-tct` tests pass
- `round_trip.rs` passes
- Clippy clean
- Report and PENDING updated

## Stop here.
