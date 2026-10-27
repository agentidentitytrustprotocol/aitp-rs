# Known-Answer Test Vectors

Pinned reference values that every conformant AITP v0.3 implementation
MUST reproduce byte-for-byte. These vectors close interop ambiguities
that schema validation alone cannot catch — JCS canonical-byte ordering,
JWK thumbprint serialization, Ed25519 seed-to-AID derivation, the
exact compact-JWS bytes of the portable trust artifacts, what a P-256
signature signs (RFC-AITP-0001 §5.4.6), and which signatures a strict
verifier rejects (§5.4.7).

## Files

| File | Purpose | Spec reference |
|---|---|---|
| [`keypairs.json`](keypairs.json) | Seed → public key → `aid:pubkey:` identifier (Ed25519 ×5, P-256 ×1), plus `kat-keypair-001-tagged`, which pins the algorithm-tagged `aid:pubkey:ed25519:` spelling of kat-keypair-001 beside its untagged one | RFC-AITP-0001 §5.3 |
| [`oidc-test-issuers.json`](oidc-test-issuers.json) | Seed → Ed25519 public key → JWK of the OIDC test issuers that sign the corpus's identity JWTs: `kat-oidc-issuer-001` (`https://auth.openai.com`, trusted) and `kat-oidc-issuer-002-unknown` (signs `__VALID_JWT_FROM_UNKNOWN_ISSUER__`, never trusted). Issuer keys, not AIDs | RFC-AITP-0002 §2, [PLACEHOLDERS.md](../PLACEHOLDERS.md) |
| [`jwk-thumbprints.json`](jwk-thumbprints.json) | RFC 7638 thumbprints of the canonical JWK forms. **Load-bearing in v0.3:** these are the `cnf.jkt` values on TCTs and delegation tokens (RFC-AITP-0001 §5.4.4), as well as the OIDC identity binding's `cnf.jkt` | RFC-AITP-0001 §5.4.4, RFC-AITP-0002 §2.2.1 |
| [`jcs-sha256.json`](jcs-sha256.json) | **Signing inputs** — JCS canonical bytes (RFC 8785) and SHA-256 digests of the JCS-profile artifacts (Manifest, revocation snapshot, session bundle), the unified PoP signing-input vector, the Draft multihop vectors, and the derived-identifier vector `kat-derived-uuid-001` (RFC-AITP-0005 §2.2). Each vector names its own signing input; see below. Also the single-hash P-256 vectors `kat-p256-jcs-sign-001`, `kat-manifest-pop-002-p256` and `kat-pinned-key-proof-002-p256`, each with the double-hash value that MUST NOT verify, and the pinned-key proof vectors `kat-pinned-key-proof-001` (Ed25519, untagged AID) and `kat-pinned-key-proof-003-tagged-ed25519` (Ed25519, `aid:pubkey:ed25519:` AID), the SPIFFE X509-SVID proof vector `kat-spiffe-x509-proof-001` (leaf key kat-keypair-003, sender kat-keypair-002; MUST NOT verify over the pinned-key input of the same tuple), and the Draft renewal PoP vectors `kat-renewal-pop-001` (Ed25519) and `kat-renewal-pop-002-p256` | RFC-AITP-0001 §5.4.1–§5.4.2, RFC-AITP-0005 §2.2, RFC-AITP-0001 §5.4.6, RFC-AITP-0002 §3.1, §6.4.1, RFC-AITP-0013 §3.1 |
| [`signature-strictness.json`](signature-strictness.json) | Raw (public key, message, signature) tuples that a lax verifier accepts and a strict one MUST reject: Ed25519 small-order key (`sig-001`), Ed25519 `S ≥ L` (`sig-002`), P-256 high-S (`sig-003`) | RFC-AITP-0001 §5.4.7 |
| [`signed-examples/`](signed-examples/) | Real-signature artifacts minted from the pinned seeds: compact-JWS TCT, grant voucher, delegation token; JCS-signed Manifest, revocation snapshot and session bundle; and P-256 (`kat-keypair-005-p256`) siblings: an envelope, Manifest, revocation snapshot and `ES256` TCT; an Ed25519 envelope with a non-empty `extensions` member (`kat-envelope-002-ed25519`); and two self-attestation TCTs (`kat-tct-002` EdDSA, `kat-tct-003` ES256) | RFC-AITP-0005 §5.3/§7/§8, RFC-AITP-0006 §6, RFC-AITP-0003 §6, RFC-AITP-0008 §1.5, RFC-AITP-0010 §3, RFC-AITP-0001 §5.4 |

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

The §5.4.7 rules are checked by the script's own BigInt arithmetic
(Ed25519 range, encoding and small-order checks, the cofactorless
equation, P-256 range and low-S checks), never by trusting the result of
`crypto.verify` alone, which differs across Node and OpenSSL versions.
Where both apply, the script requires its BigInt result and
`crypto.verify` to agree. Each strictness vector must be accepted by a
lax check and rejected by the strict one; a vector a lax verifier also
rejects would test nothing.

The P-256 vectors are not produced by `scripts/regen-known-answer.py`,
whose Python reference implementation signs Ed25519 only. They were
minted with python-ecdsa (RFC 6979 deterministic `k`, low-S) and are
recomputed from the committed inputs by
[`scripts/recompute-known-answer-independent.py`](../../../scripts/recompute-known-answer-independent.py),
run by `make kat-independent` (part of `make validate` and CI) and
built on python-ecdsa and a pure-Python RFC 8032 Ed25519. It shares no code with the Node checker.

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
`{"alg":"<alg>","typ":"<typ>"}` in that member order, and (b) the
payload bytes as the RFC 8785 (JCS) canonical form of the claims
object. This is a **minting convention only**, not a protocol
requirement (RFC-AITP-0001 §5.4.5). `ES256` signatures additionally
use RFC 6979 deterministic `k` and low-S normalization (§5.4.7), so
a re-mint reproduces them byte for byte.

## Stability

These vectors are stable for AITP v0.3. The rule is: **additions only,
except a security fix under [SECURITY.md](../../../SECURITY.md).**

- New vectors and signed examples MAY be added.
- No existing vector's output, no signed example and no known-answer
  keypair changes, except as part of a security fix handled under
  [SECURITY.md](../../../SECURITY.md#security-fixes-that-change-the-wire).
  Such a fix ships with a published advisory, and `CHANGELOG.md` lists
  each old and new value so a consumer pinning them can tell which copy
  they hold.
- If the JCS or JWK Thumbprint specifications change in a way that
  breaks these vectors, AITP issues a new protocol revision.

The same rule is quoted in [`VERSIONING.md`](../../../VERSIONING.md)
(Change classes and What is frozen).

**Earlier rule, invoked once.** On the v0.2 line the rule allowed an
existing output to change with an RFC bump. It was used once:
`kat-manifest-001`, `kat-revocation-001` and `kat-session-bundle-001`
were regenerated when it was found that they pinned the transport
wrapper rather than the signing input the RFCs specified. That
correction carried a patch bump of the four RFCs whose citations moved
(`0.2.0-draft` → `0.2.1-draft`), and `CHANGELOG.md` publishes the old
and new bytes, digests and signatures so a consumer pinning them can
tell which copy they hold. Note the direction: the requirement did not
change, the artifacts were wrong — which is why it was a patch bump and
not a protocol or schema-namespace break. On the `aitp/0.3` line such a
correction to a frozen vector is taken only as a security fix.

**Re-minted for `aitp/0.3`.** The `aitp/0.3` revision changed the
literal inside every signed artifact, so every vector and signed example
that carries it was re-minted by script with the same keys, `jti`s and
timestamps. That is a protocol revision, not a use of the rule above.
`CHANGELOG.md` lists each old and new output, and the `aitp/0.2` values
stay in the frozen v0.2 line (commit `f9ee7ea`).

### Draft vectors

A vector or signed example pinned for a **Draft** RFC carries
`"draft": true`. Today these are `kat-multihop-chain-001` and
`kat-multihop-truncation-001` (RFC-AITP-0011),
`kat-session-bundle-001` with
[`signed-examples/session-bundle/`](signed-examples/session-bundle/)
(RFC-AITP-0010), and `kat-renewal-pop-001` and
`kat-renewal-pop-002-p256` (RFC-AITP-0013).

- A draft entry is **outside the frozen set** until its RFC reaches
  Release Candidate. Until then it may change with its RFC: the change
  takes a `Version:` bump on that RFC, and `CHANGELOG.md` lists the old
  and new values.
- When the RFC reaches Release Candidate, the tag is removed in the same
  change, and from then on the entry follows the rule above.
- Everything else is in the frozen set. Any digest or manifest of the
  frozen set covers untagged entries only.
- An implementation reproduces draft entries exactly like the others.
  The tag says how the entry may change, not whether it is checked.

`make kat-verify` checks the tag in both directions: every listed draft
entry carries exactly `true`, and no other entry carries a `draft`
member. A frozen vector cannot leave the frozen set by being tagged.

### The frozen-set manifest (`make kat-frozen`)

[`scripts/kat-frozen.py`](../../../scripts/kat-frozen.py) records the
frozen set as a **per-vector manifest**, using the Python standard
library only. A digest of whole files would not work: draft vectors
share files such as `jcs-sha256.json` with frozen ones, so adding one
would change it.

- **Entries.** Each object in the `vectors` array of a top-level
  `*.json` file here, keyed by its `id`, and each
  `signed-examples/**/*.json` file as a whole, keyed by its path from
  this directory (for example
  `signed-examples/tct/kat-keypair-001-issues-002.json`). Entries with
  `"draft": true` are left out.
- **Per-vector hash.** `sha256(JCS(entry))`, lowercase hex: the SHA-256
  of the RFC 8785 canonical form of the parsed entry. It does not depend
  on whitespace, member order or line endings, so macOS and Linux give
  the same value.
- **Overall digest.** `sha256(JCS(vectors))`, over the id-sorted
  manifest object.

`make kat-frozen` prints the manifest as JSON on stdout, and that output
is exactly what `FROZEN.json` holds:

```json
{
  "manifest_version": 1,
  "hash": "sha256(JCS(entry))",
  "digest": "<sha256 hex of JCS(vectors)>",
  "vectors": { "<id>": "<sha256 hex>", "…": "…" }
}
```

`FROZEN.json` does not exist yet. It is written when the core RFCs reach
Release Candidate. Until then, `make kat-frozen-check` (part of
`make validate` and CI) only computes and prints the digest, and CI also
prints the full manifest. Once `FROZEN.json` exists, the check fails
when:

- an id it lists is missing;
- an id it lists has a different hash;
- an id it lists now carries `"draft": true`;
- its `digest` does not match its own `vectors`.

New ids pass, draft or not, because the rule is additions only.
`make kat-frozen-test` runs the check against a temporary copy of this
directory with a generated `FROZEN.json`. Its cases include a mutated
frozen vector and a deleted frozen id, which must fail, and an appended
vector, which must pass.
