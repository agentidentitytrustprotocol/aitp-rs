# Phase 2 — `aitp-crypto`

You are working on the `aitp-rs` Rust reference implementation. This is
Phase 2 of 6.

**Your goal:** working Ed25519 signing/verifying and JWK thumbprint, with
sign-verify round-trip tests proving correctness.

---

## Required reading

1. `phase-1-report.md` (in repo root) — what was completed
2. `docs/design/00-architecture.md` — `aitp-crypto`'s role
3. `crates/aitp-crypto/src/*.rs` — current scaffold
4. The `ed25519-dalek` v2.x API:
   <https://docs.rs/ed25519-dalek/2.1.1/>
5. The `secrecy` crate API:
   <https://docs.rs/secrecy/0.8/>

---

## Global rules

[All 12 global rules apply. Critical reminders:]

1. **Private keys MUST be wrapped in `Secret<>` from `secrecy`.** Never
   expose the inner key via Deref or accessor.
2. **No new dependencies.** `ed25519-dalek`, `secrecy`, `sha2`,
   `base64ct`, `rand` are all in `[workspace.dependencies]`.
3. **Tests with code, not after.**
4. **Stop at the phase boundary.** Do not begin Phase 3.

---

## Tasks

### 2.1 — `AitpSigningKey` (IMPL-015)

File: `crates/aitp-crypto/src/keys.rs`

Implement:

- **`generate()`** — uses `OsRng` from `rand`. Note that
  `ed25519-dalek` 2.x takes `&mut impl CryptoRngCore`. Be careful with
  RNG selection.
- **`from_seed(seed: &[u8; 32])`** — constructs from raw bytes for
  reproducible tests and persistent storage.
- **AID caching** — at construction time, derive the AID from
  `verifying_key().to_bytes()` and call `Aid::from_ed25519`. Store it.
  This avoids re-computing the AID on every `aid()` call.
- **`sign(message)`** — signs the message bytes (typically JCS canonical
  output), returns a `Signature` newtype wrapping the base64url-unpadded
  string.
- **`verifying_key()`** — returns the corresponding `AitpVerifyingKey`.

Wrap the `DalekSigningKey` in `Secret<>` from the `secrecy` crate. The
`Secret<DalekSigningKey>` field must NOT be exposed publicly.

Notes on `ed25519-dalek` 2.x API:
- `SigningKey::from_bytes(&[u8; 32])` takes the seed (no `Result`)
- `SigningKey::generate(rng)` takes `&mut R: CryptoRngCore`
- `SigningKey::sign(message)` is synchronous, returns
  `ed25519_dalek::Signature` directly
- `verifying_key()` returns `VerifyingKey` (32-byte public key)

### 2.2 — `AitpVerifyingKey` (IMPL-016)

Implement:

- **`from_aid(aid: &Aid)`** — extract 32 bytes via `to_ed25519_bytes()`,
  construct `DalekVerifyingKey::from_bytes()`. Map errors to
  `CryptoError::AidNotEd25519`.
- **`verify(message, sig)`** — parse the base64url signature into
  64 bytes, verify via `DalekVerifyingKey::verify_strict`. Map signature
  failures to `CryptoError::SignatureInvalid`.
- **`to_jwk_thumbprint()`** — already exists; just call into
  `crate::thumbprint::compute_jwk_thumbprint`.
- **`to_bytes()`** — return the 32-byte public key.

Use `verify_strict` (not `verify`) — strict verification rejects
non-canonical signatures and weak public keys, which matters for
interop.

### 2.3 — `Signature` newtype (IMPL-017)

- **`parse(s: &str)`** — validate:
  - Must be exactly 86 characters
  - Must contain only `[A-Za-z0-9_-]` (base64url alphabet)
  - Must NOT contain `=` padding
  - Must decode to exactly 64 bytes
- **`as_str(&self)`** — return the inner string slice
- **`into_string(self)`** — consume and return the inner String

Tests:
- Round-trip a 64-byte buffer through `parse`/`into_string`
- Reject 85-char input → `CryptoError::SignatureMalformed`
- Reject 87-char input → `CryptoError::SignatureMalformed`
- Reject input with `=` → `CryptoError::SignatureMalformed`
- Reject input with `+` or `/` (standard base64 chars, not base64url) →
  `CryptoError::SignatureMalformed`

### 2.4 — Sign/verify round-trip tests

Create `crates/aitp-crypto/tests/integration.rs` with:

- **Happy path:** generate key, sign message, verify with
  `from_aid(key.aid())`, succeeds
- **Wrong key:** generate two keys, sign with key A, verify with key B,
  fails
- **Mutated message:** sign message, mutate one byte, verify, fails
- **Empty message:** signing and verifying empty bytes works
- **Long message:** sign 1MB of random bytes, verify, succeeds
- **Reproducibility:** `from_seed([0x42; 32])` twice produces same AID
  and same signature for the same message

### 2.5 — Thumbprint tests (IMPL-018, partial IMPL-019)

`compute_jwk_thumbprint` is already implemented. Add to its existing
tests:

- Two different `AitpVerifyingKey` instances built from the same key
  bytes produce the same thumbprint
- The thumbprint of a known key (`[0x00; 32]`) is reproducible across
  runs (just pin whatever value comes out — the spec KAT will validate
  it later)

Mark IMPL-019 (full known-answer test against spec value) as `BLOCKED-
SPEC-006` since the AITP spec hasn't published the reference thumbprint
yet.

### 2.6 — `Drop` and zero-on-drop verification

Add a test confirming the `Secret<DalekSigningKey>` actually zeroes the
key bytes on drop. The `secrecy::Secret` type does this automatically,
but verify by:
- Creating a key in a scope
- Dropping it
- Confirming via `drop()` semantics that the test compiles and runs (we
  can't actually inspect freed memory, but we can verify the Drop trait
  fires by wrapping in something with a custom drop counter)

If verifying zero-on-drop is too involved, a simpler check: assert that
`AitpSigningKey` does NOT implement `Clone`. Cloning a key would defeat
the zeroing. (`secrecy::Secret` is not Clone by default.)

---

## Format, lint, and tests

```sh
cargo fmt --all
cargo clippy -p aitp-crypto --all-targets -- -D warnings
cargo test -p aitp-crypto
```

All clean and green.

---

## Update PENDING.md

Check off: IMPL-015, 016, 017, 018.

Mark IMPL-019 as `BLOCKED-SPEC-006`.

---

## Phase report

Write `phase-2-report.md` in the repo root following the same template
as Phase 1. Include:
- Test counts
- Confirmation that `AitpSigningKey` is not Clone
- Any clippy warnings worth noting (should be zero)
- Anything weird about the `ed25519-dalek` 2.x API that bit you
- Whether `verify_strict` is being used (it should be)

---

## Success gate

- `cargo test -p aitp-crypto` 100% pass
- `cargo test -p aitp-crypto --test integration` 100% pass
- Clippy clean
- `phase-2-report.md` written
- PENDING.md updated

## Stop here

Do not begin Phase 3.
