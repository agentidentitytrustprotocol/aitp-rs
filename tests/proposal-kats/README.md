# Proposal KATs (interim)

`p256-pinned-key-2026-10.json` holds the candidate known-answer vectors for
spec proposal `rfcs/proposals/p256-pinned-key-and-signing-input-2026-10.md`
(agentidentitytrustprotocol#72, tracked here as #205).

The proposal's spec PRs A–D have not landed, so there is no spec commit for
`scripts/sync-schemas.sh` to vendor. Until then:

- `scripts/gen-proposal-kats.py` derives every value with pyca/cryptography
  (OpenSSL), sharing no code with the Rust crates. It asserts that it
  reproduces the proposal's own candidate value for
  `kat-pinned-key-proof-002-p256`.
- The Rust tests reproduce every value byte-for-byte with RustCrypto.

This directory lives outside `tests/schemas/`, so a schema sync never
overwrites it. Delete it once the spec PRs land and `SPEC_VERSION` points at
a spec commit that contains them, and switch the tests to the vendored
`tests/schemas/known-answer/` files. 0.14.0 is not tagged before then.
