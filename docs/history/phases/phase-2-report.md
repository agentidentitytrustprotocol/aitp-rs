# Phase 2 Report

## Tasks completed

- IMPL-015 (AitpSigningKey)
- IMPL-016 (AitpVerifyingKey, with `verify_strict`)
- IMPL-017 (Signature::parse with 86-char + charset + no-padding gates)
- IMPL-018 (JWK thumbprint, reproducibility tested)

## Tasks blocked

- **IMPL-019** — `BLOCKED-SPEC-006`. The AITP spec needs to publish an
  authoritative JWK-thumbprint known-answer hash for a pinned 32-byte
  Ed25519 public key in RFC-AITP-0002. Until then we test reproducibility
  but cannot test correctness against an external authority.

## Test counts

| Suite | Count |
|---|---|
| `aitp-crypto` unit tests | 7 |
| `tests/integration.rs` | 11 |

Active tests for `aitp-crypto`: **18**. All pass.

## Key decisions in this phase

1. **`verify_strict` is used everywhere** (`AitpVerifyingKey::verify`).
   Per the `ed25519-dalek` 2.x docs, `verify_strict` rejects non-canonical
   signatures and weak public keys (low-order points, identity element)
   — which matters for cross-implementation interop.
2. **`secrecy::Secret` is not used**. `ed25519_dalek::SigningKey` already
   implements `ZeroizeOnDrop`. Wrapping it in `Secret` required a bound
   (`DefaultIsZeroes`) that the type doesn't satisfy. Dropping `Secret`
   simplified the keys module without weakening zeroization (the inner
   secret bytes are still wiped on drop).
3. **`AitpSigningKey` is not `Clone`**. Cloning would defeat the
   single-owner zeroization model. There is a compile-marker test
   (`signing_key_is_not_clone`) that fails to typecheck if `Clone` is
   ever added.
4. **`Signature::parse` validates strictly**: exactly 86 chars, only the
   base64url alphabet `[A-Za-z0-9_-]`, no `=` padding. This catches
   senders that emit standard base64 instead of base64url, and matches
   the schema's `pattern: "^[A-Za-z0-9_-]{86}$"`.
5. **JWK form for thumbprint** is pinned per RFC-AITP-0002 §2.2.1:
   `{"crv":"Ed25519","kty":"OKP","x":"<aid-identifier>"}`, lex-sorted, no
   whitespace. This is implemented as a `format!()` template, not a
   serde-driven canonicalization, because we need byte-exact control —
   no implicit field reorderings.

## Surprises while reading the `ed25519-dalek` 2.x API

- `SigningKey::from_bytes(&[u8; 32])` is **infallible**; no `Result`. The
  seed is always valid since Ed25519 public-key derivation can't fail
  for arbitrary 32-byte input.
- `SigningKey::generate(rng)` requires `&mut R: CryptoRngCore`, satisfied
  by `rand::rngs::OsRng` from the workspace's `rand 0.8`.
- `Signature::from_bytes(&[u8; 64])` returns `Signature` directly, not
  `Result<Signature, _>` (it's just a type-tagged byte array).

## Things the human reviewer should look at

1. The `verify_strict` choice. Switching to non-strict `verify` would
   accept signatures other implementations reject — a footgun for interop
   but sometimes useful for legacy compatibility.
2. The pinned thumbprint format string. If a future spec change adds a
   field to the canonical JWK, this must change in lockstep.
3. The deletion of `secrecy`. Long-term, if we ever add a "load private
   key from bytes that came from a file/HSM/wallet" path, we'll likely
   want a `Secret<[u8; 32]>` for the seed prior to expansion. This is
   not yet needed for v0.1.
