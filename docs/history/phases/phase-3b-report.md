# Phase 3b Report — `aitp-tct`

## Tasks completed

- IMPL-032 (TCT type round-trips, deny-unknown-fields, evidence_ref/extensions
  no longer fields per schema)
- IMPL-033 (TctBuilder.build with view-struct signing)
- IMPL-034 (verify_tct in spec order)
- IMPL-035 (PopChallenge / PopResponse + sign / verify)

## Test counts

| Suite | Count |
|---|---|
| `aitp-tct` unit tests | 5 |
| `tests/round_trip.rs` | 13 |

All 18 tests pass.

## Spec deviations corrected from the original scaffold

| Symbol | Before | After | Source of truth |
|---|---|---|---|
| `Tct.evidence_ref` | Optional field | Removed | TCT schema (`additionalProperties: false`); not in RFC §1 |
| `Tct.extensions` | Optional field | Removed | Same |
| `TctBinding.cnf` doc | "Subject's JWK thumbprint" | "Subject's raw 32-byte Ed25519 public key, base64url-unpadded (43 chars)" | RFC-AITP-0005 §1 schema example, §6.2 step 4 |
| `TctBuilder.subject_pubkey` use | Was meant to feed thumbprint | Now feeds raw pubkey bytes | Same |

## Decisions in this phase

1. **`audience == subject` is enforced both at builder time and at
   verify time.** The builder rejects audience-subject mismatch; the
   verifier double-checks. Both are needed: a malicious peer could
   hand-craft a TCT with mismatched fields, and the verifier must catch
   that even though our builder wouldn't have produced one.
2. **`grants` non-empty is a v0.1 hard rule** (RFC-AITP-0004 §4.1). The
   builder rejects empty grants with `EmptyGrants`. The verifier also
   checks (defense in depth).
3. **PoP signing input** (RFC-AITP-0005 §6.2 step 3) is `sha256(nonce.as_bytes())`.
   `nonce` is already a base64url string, so `as_bytes()` is its ASCII
   byte sequence. We sign that 32-byte digest. Other implementations
   reading the spec might choose to sign over the decoded nonce bytes
   directly — that's a real ambiguity.
4. **`binding.cnf` byte-for-byte match check.** `verify_pop_response`
   confirms `binding.cnf` decodes to the same 32 bytes as the `subject`
   AID's pubkey (RFC-AITP-0005 §6.2 step 4). A TCT whose `cnf` somehow
   referenced a different pubkey than `subject` would still get rejected
   here.
5. **Revocation is pluggable.** `revocation_check: Option<&dyn Fn(&Uuid) -> bool>`
   keeps `aitp-tct` decoupled from any storage layer. The conformance
   runner and demo will provide concrete impls.

## PoP signing input — assumption recorded

RFC-AITP-0005 §6.2 step 3 reads:

> `verify(binding.cnf, sha256(nonce), pop_signature)`

This is ambiguous between:
- (a) `sha256(nonce_bytes)` where `nonce_bytes = nonce.as_bytes()` (the
  base64url string's ASCII representation), or
- (b) `sha256(decoded_nonce_bytes)` where the nonce gets base64url-decoded
  first.

This implementation chose **(a)** because it's the simpler reading of the
literal text and because the nonce string itself is already a fixed-length
canonical form (22 chars for a 128-bit value). Recorded as an assumption
in `docs/design/PENDING.md` so the spec authors can disambiguate.

## Things the human reviewer should look at

1. The `TctSigningView` field set and order — same JCS-determinism caveat
   as the Manifest view. Compare to the schema's `properties` listing.
2. The PoP signing input choice (a vs b above). Either choice is
   reasonable; the spec needs to pin one.
3. Whether `expires_at == issued_at + ttl_secs` is what the spec wants
   for the default 1-hour TTL. Some specs interpret "1 hour" as
   "now + 3600 with a small drift allowance" — we don't apply drift.
