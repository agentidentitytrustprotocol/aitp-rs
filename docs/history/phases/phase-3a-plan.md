# Phase 3a — `aitp-manifest`

You are working on the `aitp-rs` Rust reference implementation. This is
Phase 3a of 6 (the protocol crates are split into 3a/3b/3c/3d).

**Your goal:** working Manifest issuance and verification.

---

## Required reading

1. `phase-2-report.md`
2. `crates/aitp-manifest/src/*.rs` — current scaffold
3. The AITP spec RFC-AITP-0003 (Manifest), specifically §3 (fields) and
   §5 (verification order). If the spec isn't checked into this repo,
   ask the human to provide RFC-AITP-0003 §5 text. The verification
   order is critical and non-obvious.

---

## Reference verification order (RFC-AITP-0003 §5)

When verifying a Manifest, run these checks in this exact order:

1. Version is `"aitp/0.1"`
2. `expires_at` is in the future
3. PoP signature: verify that the signature in `proof_of_possession`
   covers `sha256(challenge)` using the public key encoded in `aid`
4. Outer signature: verify that `signature` covers the JCS canonical
   form of the Manifest minus the `signature` field, using the public
   key encoded in `aid`
5. `identity_hint` shape: type is `oidc` or `pinned_key`; required
   fields for that type are present (`issuer` for oidc; `public_key` for
   pinned_key)

Identity-proof verification (the actual JWT or pinned-key signature
check) does NOT happen here. That happens later, during the Mutual
Handshake. The Manifest only carries an `identity_hint` — static
metadata, not a verifiable proof.

---

## Global rules

[All 12 apply. Critical reminders:]

1. **Wire-format invariants.** Manifest, IdentityHint, ManifestPop all
   need `#[serde(deny_unknown_fields)]`. Empty `extensions` must be
   omitted from canonical JSON.
2. **Signing without the signature field.** Use a "view struct" pattern:
   serialize a struct that has every field except `signature`, JCS-
   canonicalize that, sign. See `docs/design/01-jcs.md` end of file.
3. **Stop at the phase boundary.**

---

## Tasks

### 3a.1 — Verify type round-trips (IMPL-020)

The types are scaffolded. Add tests in `mod tests` of `types.rs`:

- Round-trip a Manifest with OIDC identity_hint
- Round-trip a Manifest with pinned_key identity_hint
- Round-trip a Manifest with extensions present
- Round-trip a Manifest with extensions absent (verify field is omitted
  from output JSON when empty)
- Reject a Manifest JSON with an unknown top-level field
- Reject a Manifest JSON with `proof_of_possession` having an unknown
  field

### 3a.2 — Implement `ManifestBuilder` (IMPL-021)

File: `crates/aitp-manifest/src/builder.rs`

Decide the builder API. Suggested:

```rust
pub struct ManifestBuilder<'a> {
    signing_key: &'a AitpSigningKey,
    handshake_endpoint: Option<Url>,
    accepted_trust_anchors: Vec<Url>,
    accepted_identity_types: Vec<String>,
    offered_capabilities: Vec<String>,
    required_peer_capabilities: Vec<String>,
    identity_hint: Option<IdentityHint>,
    ttl_secs: i64,
    display_name: Option<String>,
    extensions: ExtensionsMap,
}

impl<'a> ManifestBuilder<'a> {
    pub fn new(signing_key: &'a AitpSigningKey) -> Self { ... }
    pub fn handshake_endpoint(mut self, url: Url) -> Self { ... }
    pub fn identity_hint(mut self, hint: IdentityHint) -> Self { ... }
    pub fn offer(mut self, capability: impl Into<String>) -> Self { ... }
    pub fn require(mut self, capability: impl Into<String>) -> Self { ... }
    pub fn accept_trust_anchor(mut self, issuer: Url) -> Self { ... }
    pub fn ttl_secs(mut self, secs: i64) -> Self { ... }
    pub fn build(self) -> Result<Manifest, ManifestError> { ... }
}
```

`build()` does:
1. Validate required fields present (`handshake_endpoint`,
   `identity_hint`)
2. Generate a 16-byte (128-bit) random challenge using `rand::OsRng`,
   encode as unpadded base64url
3. Compute `sha256(challenge_bytes)`, sign with `signing_key`
4. Construct ManifestPop with the challenge string and signature
5. Construct the Manifest (signature field empty for now)
6. Construct a "view struct" with every field except signature
7. JCS-canonicalize the view, sign with `signing_key`
8. Set the signature field, return

Use `published_at = Timestamp::now()` and `expires_at = published_at +
ttl_secs`.

Default `accepted_identity_types` to `["oidc"]` if not set (per RFC-
AITP-0003 §3.2 default).

### 3a.3 — Implement `verify_manifest` (IMPL-022)

File: `crates/aitp-manifest/src/verifier.rs`

Implement the 5-step verification order from the top of this prompt.

Map failures to `ManifestError`:
- Step 1 fail → `VersionUnknown`
- Step 2 fail → `Expired`
- Step 3 fail → `PopFailed`
- Step 4 fail → `SignatureInvalid`
- Step 5 fail → use a new variant `IdentityHintMalformed` (add to
  `ManifestError`)

Steps 3 and 4 use the public key from `manifest.aid` via
`AitpVerifyingKey::from_aid(&manifest.aid)`. The same key signs both.

### 3a.4 — Round-trip integration test

Create `crates/aitp-manifest/tests/round_trip.rs`:

- Generate a key, build a Manifest, verify it, succeed
- Tamper with `signature` field (change one base64url char), verify, fail
  with `SignatureInvalid`
- Tamper with `proof_of_possession.signature`, verify, fail with
  `PopFailed`
- Tamper with `proof_of_possession.challenge`, verify, fail with
  `PopFailed`
- Set `expires_at` to 1 hour ago, verify, fail with `Expired`
- Set `version` to `"aitp/9.9"`, verify, fail with `VersionUnknown`
- Build a Manifest with empty extensions, verify the canonical form does
  NOT contain `"extensions":{}` (use `serde_json::to_string` then check
  the string)

### 3a.5 — Spec-example test (IMPL-023, partial)

If `examples/manifest/agent-b-manifest.json` exists in the AITP spec
repo and is accessible: write a test that loads it and verifies it.

If not: mark IMPL-023 as `BLOCKED-SPEC-EXAMPLE`. Do NOT block this
phase on it.

---

## Format, lint, tests

```sh
cargo fmt --all
cargo clippy -p aitp-manifest --all-targets -- -D warnings
cargo test -p aitp-manifest
cargo test -p aitp-manifest --test round_trip
```

---

## Update PENDING.md

Check off: IMPL-020, 021, 022.

IMPL-023: either checked off (if spec example was available) or
`BLOCKED-SPEC-EXAMPLE`.

---

## Phase report

Write `phase-3a-report.md`. Include the counts of tests, any decisions
about the builder API ergonomics, and anything you noticed about the
spec verification order that seems ambiguous.

---

## Success gate

- All `aitp-manifest` tests pass
- `round_trip.rs` integration test passes
- Clippy clean
- Report written, PENDING updated

## Stop here

Do not begin Phase 3b.
