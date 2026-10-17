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

Spec PR B (652cdb9) has also landed and is vendored:
`kat-pinned-key-proof-002-p256` and `kat-pinned-key-proof-003-tagged-ed25519`.
The spec names their fields `signature` / `signature_b64url` /
`double_hash_signature_MUST_NOT_verify` where this file says `proof` /
`double_hash_proof_MUST_NOT_verify`; the agreement test maps the names.

Still interim, pending spec PR D:

- `kat-tct-002-self-attestation` and `kat-tct-003-p256-self-attestation`

`scripts/gen-proposal-kats.py` derives every value with pyca/cryptography
(OpenSSL), sharing no code with the Rust crates, and the Rust tests
reproduce each value byte for byte with RustCrypto. Delete this directory
once `SPEC_VERSION` points at a spec commit with PR D. 0.14.0 is
not tagged before then.
