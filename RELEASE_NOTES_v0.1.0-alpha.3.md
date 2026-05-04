# aitp-rs v0.1.0-alpha.3

Spec-rc.2-alignment release. Tracks
[`agentidentitytrustprotocol@c0e4565`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/commit/c0e4565).

The spec rc.2 closes 5 of the 6 cross-implementation ambiguities the
alpha.2 work surfaced; this release brings `aitp-rs` into alignment
and adds the first KAT-anchored interop validation.

## ⚠️ Breaking changes (wire format)

Two changes that break compatibility with alpha.1 and alpha.2
artifacts:

1. **TCT PoP signing input is now `sha256(base64url_decode(nonce))`.**
   alpha.1/alpha.2 hashed the ASCII byte string. PoP signatures from
   prior versions will not verify under alpha.3.
2. **Delegation tokens require `grant_proof.issued_at`.** Previously
   reconstructed by the verifier as `expires_at − 3600s`; now carried
   on the wire. Delegations issued by prior versions will fail to
   deserialize under alpha.3.

If you persist TCTs or delegation tokens in storage, re-issue them
under alpha.3. Live handshakes don't need any action — the entire
mutual handshake completes within ~1s and produces fresh artifacts.

## What's new

- **KAT tests against the spec's pinned reference values.** Three new
  files of vectors landed in spec rc.2 (Ed25519 keypair derivation,
  JWK thumbprints, JCS+SHA-256). `aitp-rs` now validates byte-for-byte
  against all three. This is the first time the implementation is
  anchored to spec-pinned values rather than just self-consistent
  with itself.
- **Schema-validation drift firewall** automatically caught the
  delegation `grant_proof.issued_at` change after `scripts/sync-schemas.sh`
  pulled the new spec, exactly as designed.

## Numbers

- 155 tests passing (152 alpha.2 + 3 new KAT tests), 0 failed, 2 ignored
- All checks clean: fmt, clippy, doc, build

## Spec-side dependencies still open

- **Issue #5 (BLOCKED-SPEC-EXAMPLE)** — example manifest still uses
  placeholder signatures. Now actionable since `kat-keypair-001` is
  pinned: `aitp-rs` could mint a real signed example using the
  `issue_manifest` op with that seed.
- **Spec-fixture migration PR** (PENDING.md `PHASE-B-FIXTURE-PR`) —
  the 21 conformance fixtures at `agentidentitytrustprotocol/schemas/conformance/*.json`
  still use placeholder shapes. Next concrete spec-side work.

## Try it

```sh
git clone https://github.com/agentidentitytrustprotocol/aitp-rs
cd aitp-rs
make demo
```

## Feedback

Cross-language adapters: this is the first release where you can run
a Tier-A conformance suite that's actually anchored to spec values.
If your adapter passes the KAT-anchored fixtures, you have evidence
of real interop, not just internal consistency. Open issues with
mismatches; we'll triage with the spec maintainers.
