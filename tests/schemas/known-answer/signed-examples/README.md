# Signed Example Artifacts

This directory holds **real, cryptographically valid** AITP artifacts
minted from the pinned known-answer keypairs in
[`../keypairs.json`](../keypairs.json). It is the canonical location
for cross-implementation interop fixtures — files here MUST verify
under any conformant AITP v0.3 implementation, byte-for-byte, without
any placeholder substitution.

The portable trust artifacts (TCT, grant voucher, delegation token)
are compact JWS strings (RFC-AITP-0001 §5.4.5); their files pin the
exact compact string. The JCS-profile artifacts (Manifest, revocation
snapshot, session bundle, envelope) pin the signed JSON object. The off-the-shelf
JOSE smoke test over the TCT artifact is documented in
[`../README.md`](../README.md).

## Why a separate directory

The sibling files under `examples/` use placeholder signature strings
so they remain human-readable and unambiguously not-real-keys. That is
useful for documentation but cannot serve as an interop test fixture —
a verifier rejects placeholder signatures, by design.

This directory closes that gap with the same canonical objects but
real signatures. An implementation that fails to verify any artifact
in here is non-conformant.

**Verify these files as committed. Do not re-mint them first.** A fixture
that is re-signed before it is verified proves only that an implementation
agrees with itself — it cannot detect a signing-input disagreement between
two implementations, because each one re-signs under its own convention and
then checks its own output. That is not a hypothetical: the revocation
snapshot here was signed over its transport wrapper for the whole of
v0.2-draft while every conformance fixture covering revocation passed on
both implementations, because those fixtures carry a placeholder signature
that each minting tool substitutes for itself. Re-minting is the escape
hatch that hid it.

For the three JCS-profile artifacts, the signature covers the **inner**
artifact body — never the `{"manifest": …}` / `{"revocation_list": …}` /
`{"session_bundle": …}` wrapper (RFC-AITP-0001 §5.4.1). `make kat-verify`
checks both directions: that each signature verifies over the inner body,
and that it *fails* over the wrapped form. A signature valid under both
shapes would pin nothing. This is the property the session bundle got
wrong through a full release — its schema placed `signature` beside the
wrapper instead of inside the body — until fixed in PR #30; the
`session-bundle/` fixture below and its bidirectional check are what
would have caught it.

The session bundle's inner body and coordinator signature are the same
pinned artifact as vector `kat-session-bundle-001` in
[`../jcs-sha256.json`](../jcs-sha256.json) (922 canonical bytes,
`sha256_hex` starting `b0e7a9e5…`) — restated here as a full, standalone,
schema-validating artifact rather than a replacement for that vector.

## Layout

```
signed-examples/
├── README.md                               (this file)
├── envelope/
│   ├── kat-keypair-001-envelope.json       env-007's envelope (non-empty extensions), Ed25519-signed by kat-keypair-001
│   └── kat-keypair-005-envelope.json       env-005's envelope, P-256-signed by kat-keypair-005-p256
├── manifest/
│   ├── kat-keypair-001-manifest.json       Manifest signed by kat-keypair-001 (JCS profile)
│   └── kat-keypair-005-manifest.json       Manifest signed by kat-keypair-005-p256 (JCS profile, P-256)
├── tct/
│   ├── kat-keypair-001-issues-002.json     Peer-issued TCT compact JWS, kat-keypair-001 → 002
│   ├── kat-keypair-005-issues-002.json     Peer-issued ES256 TCT compact JWS, kat-keypair-005-p256 → 002
│   ├── kat-keypair-001-self-attestation.json  Self-attestation TCT (RFC-AITP-0005 §5.3), kat-tct-002, EdDSA
│   └── kat-keypair-005-self-attestation.json  Self-attestation TCT, kat-tct-003, ES256 (kat-keypair-005-p256)
├── grant-voucher/
│   └── kat-voucher-001.json                Grant voucher compact JWS (companion of a two-grant TCT)
├── delegation/
│   └── single-hop-001-002-003.json         Single-hop delegation compact JWS (embeds kat-voucher-001)
├── revocation/
│   ├── kat-keypair-001-snapshot.json       Signed revocation snapshot (JCS profile)
│   └── kat-keypair-005-snapshot.json       Signed revocation snapshot (JCS profile, P-256)
└── session-bundle/
    └── kat-keypair-001-bundle.json         Signed session trust bundle (JCS profile)
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
carry a `decoded_claims` companion for human review. The three
JCS-profile files (`manifest/`, `revocation/`, `session-bundle/`) also
carry a `signing_input` companion — always `"body"` here, the same
declaration and vocabulary as the corresponding vector in
[`../jcs-sha256.json`](../jcs-sha256.json) — so the convention this
directory's whole layout exists to demonstrate is stated in the file,
not left to a reader of `scripts/verify-known-answer.mjs`.

`_kat_input`, `decoded_claims` and `signing_input` are **not** part of
the signed artifact — they sit beside it at the top level of the file.
The artifact is the `tct_token` / `voucher_token` / `delegation_token`
string (JWS) or the signed object (JCS).

**P-256 files.** Every file signed by `kat-keypair-005-p256` also
carries a `_must_not_verify` companion holding the signature a signer
that hashes the digest again (`e = SHA-256(d)`) would emit, which
RFC-AITP-0001 §5.4.6 forbids. `make kat-verify` requires each such value
to fail over the real signing input and to be a valid signature under
the double-hash reading, so it is a real negative.

**Envelope files.** Both envelope files declare
`"signing_input": "sig_input_v2"`: an envelope signs the 16 ASCII bytes
`aitp-envelope-v2`, one `0x00` byte, then JCS of the whole envelope
minus `signature` (RFC-AITP-0001 §5.4). Each file restates that input
as `sig_input_v2_hex`, `sig_input_v2_len_bytes` and
`sig_input_v2_sha256_hex`, and the signed object is its `envelope`
member. `kat-keypair-005-envelope.json` (`kat-envelope-001-p256`) is
exactly conformance fixture env-005's input envelope with the
`__VALID_ENVELOPE_SIG__` placeholder replaced;
`kat-keypair-001-envelope.json` (`kat-envelope-002-ed25519`) is exactly
env-007's envelope, whose `extensions` member is non-empty, and env-007
commits the same signature. `make kat-verify` asserts each envelope
agrees with its fixture member for member. Each file's
`_must_not_verify` also carries `v1_signature`, a valid signature over
the retired pipe-composed input `v1_sig_input`
(`message_id|timestamp|sender.agent_id|hex(sha256(JCS(payload)))`),
which MUST NOT verify over `sig_input_v2`. For `kat-envelope-001-p256`
that value is the signature the file pinned before issue #87.

All companions whose names begin with `_`, the `sig_input_v2_*`
companions, and `signing_input` are stripped before schema validation
(the envelope files validate their `envelope` member only).

**JWS minting conventions for byte-stability** (minting conventions
only — verifiers never re-serialize, per RFC-AITP-0001 §5.4.5):

- protected header is exactly `{"alg":"<alg>","typ":"<typ>"}` in that
  member order, no whitespace;
- payload bytes are the RFC 8785 (JCS) canonical form of the claims
  object;
- `EdDSA` signs the ASCII signing input directly (RFC 8037 — no
  pre-hashing); `ES256` uses the JOSE raw `R || S` encoding.

**P-256 minting conventions.** Every `p256.` and `ES256` signature here
uses RFC 6979 deterministic `k` and is low-S normalized
(RFC-AITP-0001 §5.4.7). JCS-profile `p256.` signatures use `e = d`, the
single SHA-256 digest of the signing input (§5.4.6). The P-256 files
are minted outside `scripts/regen-known-answer.py` and recomputed by
`scripts/recompute-known-answer-independent.py`.

## Stability

A populated file's byte sequence is stable for the AITP v0.3
lifecycle. Editing it (other than to fix a verified divergence from
the spec) is a breaking change to the conformance suite.
