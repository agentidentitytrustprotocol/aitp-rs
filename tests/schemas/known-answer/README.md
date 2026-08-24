# Known-Answer Test Vectors

Pinned reference values that every conformant AITP v0.2 implementation
MUST reproduce byte-for-byte. These vectors close interop ambiguities
that schema validation alone cannot catch — JCS canonical-byte ordering,
JWK thumbprint serialization, Ed25519 seed-to-AID derivation, and the
exact compact-JWS bytes of the portable trust artifacts.

## Files

| File | Purpose | Spec reference |
|---|---|---|
| [`keypairs.json`](keypairs.json) | Seed → public key → `aid:pubkey:` identifier (Ed25519 ×4, P-256 ×1) | RFC-AITP-0001 §5.3 |
| [`jwk-thumbprints.json`](jwk-thumbprints.json) | RFC 7638 thumbprints of the canonical JWK forms. **Load-bearing in v0.2:** these are the `cnf.jkt` values on TCTs and delegation tokens (RFC-AITP-0001 §5.4.4), as well as the OIDC identity binding's `cnf.jkt` | RFC-AITP-0001 §5.4.4, RFC-AITP-0002 §2.2.1 |
| [`jcs-sha256.json`](jcs-sha256.json) | **Signing inputs** — JCS canonical bytes (RFC 8785) and SHA-256 digests of the JCS-profile artifacts (Manifest, revocation snapshot, session bundle), the unified PoP signing-input vector, and the Draft multihop vectors. Each vector names its own signing input; see below | RFC-AITP-0001 §5.4.1–§5.4.2 |
| [`signed-examples/`](signed-examples/) | Real-signature artifacts minted from the pinned seeds: compact-JWS TCT, grant voucher, delegation token; JCS-signed Manifest and revocation snapshot | RFC-AITP-0005 §7/§8, RFC-AITP-0006 §6, RFC-AITP-0003 §6, RFC-AITP-0008 §1.5 |

The v0.1 `kat-tct-001` and `kat-delegation-001` JCS vectors are
**retired**: the v0.2 TCT and delegation token are compact JWS
(RFC-AITP-0001 §5.4.5) whose byte-exact pins live under
`signed-examples/`. There is no canonical form to reproduce for them —
the signature covers the transmitted bytes.

## What the JCS vectors pin: the signing input, not the wire shape

Three JCS-profile artifacts travel inside a JSON object whose key names
the artifact — `{"manifest": …}`, `{"revocation_list": …, "signature": …}`,
`{"session_bundle": …}`. That key is **transport routing metadata and is
never signed** (RFC-AITP-0001 §5.4.1). The vectors in
[`jcs-sha256.json`](jcs-sha256.json) pin the **signing input**: the inner
artifact body, carrying no signature of its own.

Every vector that carries pinned canonical bytes states this in its own
`signing_input` member, so the file answers the question rather than
leaving it to the reader:

| `signing_input` | Meaning |
|---|---|
| `"body"` | The vector's `object` **is** the signing input — the inner artifact body. This is the only correct value for a JCS-profile artifact. |
| `"envelope"` | The vector's `object` is the transport wrapper. **Non-conformant**; rejected by `make kat-verify`. Retained as a value only so the erratum that removed it is legible in history. |

This member is load-bearing, not documentation: `scripts/verify-known-answer.mjs`
reads it, recomputes the canonical bytes from the object it names, and
additionally proves that each pinned signature verifies over that shape and
**fails** over the other one. A vector that verified under both shapes would
be pinning nothing.

## How to use

For each vector, an implementation MUST:

1. Compute the same canonical form (or thumbprint, or AID, or compact
   JWS string) from the pinned input.
2. Compare byte-for-byte against the pinned output.
3. For the JCS-profile artifacts, use that same input **when signing** —
   these are signing-input vectors, not canonicalization exercises. An
   implementation that reproduces the bytes but signs a different object
   is still non-conformant, and will fail against every other
   implementation.

Any mismatch is a conformance bug.

## Checking these values

`make kat-verify` (also run by `make validate` and by CI) executes
[`scripts/verify-known-answer.mjs`](../../../scripts/verify-known-answer.mjs),
which recomputes every canonical byte sequence, re-derives every public key
and thumbprint, and verifies every pinned signature — including the
committed JCS-profile artifacts under `signed-examples/`, which MUST verify
**as committed, without re-minting**. Re-minting a fixture before verifying
it proves only that an implementation agrees with itself.

The script depends on nothing beyond Node's standard library; it is a
JCS + JOSE implementation independent of both `aitp-rs` and
`aitp-verifier-py`, so the pinned bytes are produced by one implementation
and checked by another.

## Off-the-shelf JOSE smoke test (v0.2)

The point of the JWS migration is that **non-AITP code can verify the
portable trust artifacts**. This is a documented conformance smoke
test: given only the issuer public key (from `keypairs.json`), any
standard JOSE tool MUST verify
[`signed-examples/tct/kat-keypair-001-issues-002.json`](signed-examples/tct/kat-keypair-001-issues-002.json)'s
`tct_token`. For example, with Node's built-in crypto (no AITP code
involved):

```js
const crypto = require('crypto');
const [h, p, s] = tct_token.split('.');
const key = crypto.createPublicKey({ format: 'jwk', key: {
  kty: 'OKP', crv: 'Ed25519', x: 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik' } });
crypto.verify(null, Buffer.from(`${h}.${p}`, 'ascii'), key,
              Buffer.from(s, 'base64url'));   // => true
```

Equivalent checks with PyJWT (`algorithms=["EdDSA"]`), `jose` (npm),
or jwt.io (paste token + OKP JWK) MUST succeed. The same applies to
the grant voucher (issuer key) and delegation token (delegator key).
An AITP verifier additionally enforces the `typ`/`alg`/claims rules
of RFC-AITP-0001 §5.4.5 — the smoke test demonstrates signature-level
interop, not full AITP verification.

## Why pin canonical bytes, not just the hash?

A SHA-256 mismatch tells you something is wrong but not where. Pinning
the canonical bytes (and, for JWS, the exact compact string) lets
implementations diff their output against the reference and locate the
divergence directly (sort order, number formatting, Unicode escaping,
header member order, payload serialization).

## Reproducibility note for JWS vectors

RFC 7515 does not require any particular payload serialization — a
verifier never re-serializes. To make re-mints byte-stable, the minting
recipe for these vectors fixes (a) the protected header as exactly
`{"alg":"EdDSA","typ":"<typ>"}` in that member order, and (b) the
payload bytes as the RFC 8785 (JCS) canonical form of the claims
object. This is a **minting convention only**, not a protocol
requirement (RFC-AITP-0001 §5.4.5).

## Stability

These vectors are stable for AITP v0.2. New vectors MAY be added; an
existing vector's output MUST NOT change without an RFC bump. If JCS
or JWK Thumbprint specifications change in a way that breaks these
vectors, AITP will issue a major version bump.

**Invoked once so far.** `kat-manifest-001`, `kat-revocation-001` and
`kat-session-bundle-001` were regenerated when it was found that they
pinned the transport wrapper rather than the signing input the RFCs
specified. That correction carries a patch bump of the four RFCs whose
citations moved (`0.2.0-draft` → `0.2.1-draft`), and `CHANGELOG.md`
publishes the old and new bytes, digests and signatures so a consumer
pinning them can tell which copy they hold. Note the direction: the
requirement did not change, the artifacts were wrong — which is why it
is a patch bump and not a protocol or schema-namespace break.
