# Signed Example Artifacts

This directory holds **real, cryptographically valid** AITP artifacts
minted from the pinned known-answer keypairs in
[`../keypairs.json`](../keypairs.json). It is the canonical location
for cross-implementation interop fixtures — files here MUST verify
under any conformant AITP v0.2 implementation, byte-for-byte, without
any placeholder substitution.

The portable trust artifacts (TCT, grant voucher, delegation token)
are compact JWS strings (RFC-AITP-0001 §5.4.5); their files pin the
exact compact string. The JCS-profile artifacts (Manifest, revocation
snapshot) pin the signed JSON object. The off-the-shelf JOSE smoke
test over the TCT artifact is documented in
[`../README.md`](../README.md).

## Why a separate directory

The sibling files under `examples/` use placeholder signature strings
so they remain human-readable and unambiguously not-real-keys. That is
useful for documentation but cannot serve as an interop test fixture —
a verifier rejects placeholder signatures, by design.

This directory closes that gap with the same canonical objects but
real signatures. An implementation that fails to verify any artifact
in here is non-conformant.

## Layout

```
signed-examples/
├── README.md                               (this file)
├── manifest/
│   └── kat-keypair-001-manifest.json       Manifest signed by kat-keypair-001 (JCS profile)
├── tct/
│   └── kat-keypair-001-issues-002.json     Peer-issued TCT compact JWS, kat-keypair-001 → 002
├── grant-voucher/
│   └── kat-voucher-001.json                Grant voucher compact JWS (companion of a two-grant TCT)
├── delegation/
│   └── single-hop-001-002-003.json         Single-hop delegation compact JWS (embeds kat-voucher-001)
└── revocation/
    └── kat-keypair-001-snapshot.json       Signed revocation snapshot (JCS profile)
```

Each file MUST:

1. Use only AIDs from [`../keypairs.json`](../keypairs.json) and
   `cnf.jkt` values from [`../jwk-thumbprints.json`](../jwk-thumbprints.json).
2. Validate against the corresponding JSON Schema under
   `schemas/json/` (for JWS artifacts: the decoded claims against the
   claims schema; the string against the compact-JWS pattern).
3. Be byte-identical to a re-mint produced by any conformant
   implementation given the same input parameters and the minting
   conventions below.

## Reproducibility

The minting input for each artifact (chosen `jti`, `iat`, `exp`,
grants, etc.) MUST be documented inside the file itself via a
`_kat_input` companion object so a re-minter can recover the exact
byte sequence without out-of-band knowledge. JWS artifact files also
carry a `decoded_claims` companion for human review.

`_kat_input` and `decoded_claims` are **not** part of the signed
artifact — they sit beside it at the top level of the file. The
artifact is the `tct_token` / `voucher_token` / `delegation_token`
string (JWS) or the signed object (JCS).

**JWS minting conventions for byte-stability** (minting conventions
only — verifiers never re-serialize, per RFC-AITP-0001 §5.4.5):

- protected header is exactly `{"alg":"<alg>","typ":"<typ>"}` in that
  member order, no whitespace;
- payload bytes are the RFC 8785 (JCS) canonical form of the claims
  object;
- `EdDSA` signs the ASCII signing input directly (RFC 8037 — no
  pre-hashing); `ES256` uses the JOSE raw `R || S` encoding.

## Stability

A populated file's byte sequence is stable for the AITP v0.2
lifecycle. Editing it (other than to fix a verified divergence from
the spec) is a breaking change to the conformance suite.
