# aitp-rs v0.1.0-alpha.4

Spec-rc.3 alignment + paired follow-up release. Tracks
[`agentidentitytrustprotocol`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol)
spec commit added in rc.3 (kat-keypair-003, __VALID_SIG__ rename,
aitp-revocation-list.schema.json).

This is a small surface release — most of the alpha.3 → alpha.4 delta
is consuming the spec rc.3 affordances rather than new wire-format
work. No breaking changes.

## What's new

- **Revocation snapshot type implemented.** `aitp-tct::revocation`
  provides `RevocationList`, `RevocationListEnvelope`,
  `sign_revocation_list`, `verify_revocation_list`. `aitp-rs-adapter`
  now declares `verify_revocation_snapshot` as a supported op. KAT
  byte-match test reproduces the spec rc.2 `kat-revocation-001`
  canonical bytes byte-for-byte — the implementation agrees with the
  spec on what the canonical form looks like.
- **`mint-signed-examples` tool.** A new workspace binary that
  produces real signed AITP artifacts (Manifest, TCT, single-hop
  Delegation, signed Revocation Snapshot) from the spec's pinned KAT
  keypairs. Each output carries a `_kat_input` companion so the byte
  sequence is reproducible by any future re-minter. Designed to
  populate the spec's `signed-examples/` directory. Includes 4
  cryptographic-verify tests over its own output, so a regression in
  any verifier is caught immediately.
- **KAT coverage now includes `kat-keypair-003`** (third pinned
  Ed25519 keypair, seed = 0xff × 32). Lets cross-implementation tests
  exercise three-party scenarios deterministically.

## Spec-side dependencies still open

- **PHASE-B-FIXTURE-PR** — migrate the 22 spec conformance fixtures
  from placeholders to fully-minted real values. Carved out as
  `plans/phase-11-fixture-migration.md`. The infrastructure for it
  exists (KAT keypairs, revocation type, `mint-signed-examples`
  pattern); the work is per-placeholder substitution logic plus
  OIDC JWT minting. Deferred from this release to keep scope
  coherent.

## Numbers

- 167 tests passing (alpha.3 was 160), 0 failed, 2 ignored
- New: 5 revocation unit tests, 2 revocation schema tests, 4
  signed-example crypto-verify tests, +1 keypair-003 KAT vector
  (consumed by existing iteration structure → +N validations
  internally, not +N tests externally)
- All gates clean: fmt, clippy, doc, build, deny

## Try it

```sh
git clone https://github.com/agentidentitytrustprotocol/aitp-rs
cd aitp-rs
make demo
# Or mint signed examples for the spec repo:
cargo run -p mint-signed-examples
```

## Feedback

The infrastructure-completion theme of alpha.4 means the most
interesting cross-implementation feedback now is: do KAT-anchored
verifiers in OTHER languages match these same canonical bytes? If
your adapter passes the keypair / JWK thumbprint / JCS+SHA-256 KATs
*and* the revocation-snapshot KAT byte-match, you have evidence of
real interop, not just internal consistency.
