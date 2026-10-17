# Proposal KATs (interim)

`p256-pinned-key-2026-10.json` holds the candidate known-answer vectors for
spec proposal `rfcs/proposals/p256-pinned-key-and-signing-input-2026-10.md`
(agentidentitytrustprotocol#72, tracked here as #205).

Spec PR A (b022013) has landed and is vendored: `kat-p256-jcs-sign-001`,
`kat-manifest-pop-002-p256`, `kat-keypair-001-tagged`, `kat-derived-uuid-001`
and `sig-001`..`sig-003` now come from `tests/schemas/known-answer/`, and
`crates/aitp-crypto/tests/proposal_kats.rs` reads the vendored copy first.
Its `proposal_copies_agree_with_vendored_vectors` test fails if a copy
here drifts from the vendored one.

Still interim, pending spec PRs B and D:

- `kat-pinned-key-proof-002-p256` and `kat-pinned-key-proof-003-tagged-ed25519` (PR B)
- `kat-tct-002-self-attestation` and `kat-tct-003-p256-self-attestation` (PR D)

`scripts/gen-proposal-kats.py` derives every value with pyca/cryptography
(OpenSSL), sharing no code with the Rust crates, and the Rust tests
reproduce each value byte for byte with RustCrypto. Delete this directory
once `SPEC_VERSION` points at a spec commit with PRs B and D. 0.14.0 is
not tagged before then.
