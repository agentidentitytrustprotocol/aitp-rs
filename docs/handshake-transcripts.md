# Handshake wire transcripts

This document captures the exact bytes flowing between two peers during a
successful four-message Mutual Handshake (RFC-AITP-0004), and the bytes
each peer signs at every step. It is intended for cross-language
implementers who want to debug interop failures without reading code.

The transcript below is generated mechanically from the
`crates/aitp-handshake/tests/full_handshake.rs::full_pinned_key_handshake`
test (pinned-key identity, fixed seeds, fixed clock = 1 700 000 000).
Re-run that test if you change any signing-input convention; the test
must still produce TCTs that round-trip.

## Identities

```
Alice (initiator)
  seed       = [0xA1] * 32
  AID        = aid:pubkey:<derived>
Bob (responder)
  seed       = [0xB2] * 32
  AID        = aid:pubkey:<derived>
```

Concrete AIDs come from `AitpSigningKey::from_seed(...).aid()` and are
deterministic per the seed.

## Round 1

### M1 — `mutual_hello` (Alice → Bob)

**Envelope shape:**

```json
{
  "version": "aitp/0.2",
  "message_type": "mutual_hello",
  "message_id": "<uuid v4 — alice picks>",
  "timestamp": 1700000000,
  "sender": { "agent_id": "<alice AID>" },
  "payload": {
    "identity": {
      "type": "pinned_key",
      "subject": "alice",
      "proof": "<base64url(sign(alice_priv, sha256(pinned_key_proof_input)))>",
      "public_key": "<base64url(alice_pubkey_bytes)>"
    },
    "manifest": { /* alice's full Manifest, inline */ },
    "requested_grants": ["demo.echo"],
    "pop_nonce": "<22-char base64url, 128 random bits>"
  },
  "signature": "<base64url(sign(alice_priv, sha256(envelope_signing_input)))>"
}
```

**Signed inputs in M1.** Every entry below is hashed with SHA-256 and
then Ed25519-signed. The preimage definitions are **normative in the
spec** — reproduced here only as a debugging aid. The authoritative
section is in the last column; if this table and the RFC ever disagree,
the RFC wins. (`||` is byte concatenation, `\0` a single null byte; the
`|` inside the envelope `format!` is a literal pipe character.)

| Signature field | Preimage (hashed with SHA-256, then signed) | Normative source |
|---|---|---|
| `payload.identity.proof` (pinned-key) | `"aitp-pinned-key-v1\0" \|\| sender_aid \|\| "\0" \|\| receiver_aid \|\| "\0" \|\| message_id \|\| "\0" \|\| timestamp_be_8 \|\| "\0" \|\| base64url_decode(pop_nonce)` | RFC-AITP-0002 §3.1 |
| `payload.manifest.proof_of_possession.signature` | `base64url_decode(challenge)` — the raw decoded nonce bytes, **not** the base64url string | RFC-AITP-0001 §5.4.2 |
| `payload.manifest.signature` | `JCS(manifest_without_signature_field)` | RFC-AITP-0001 §5.4.1 |
| `signature` (envelope) | `format!("{}|{}|{}|{}", message_id, timestamp, sender_aid, hex(sha256(JCS(payload))))` | RFC-AITP-0001 §5.4.1 |

Two byte-encoding rules cause most cross-language interop failures, so
they are called out explicitly:

- **JCS canonicalisation** (RFC 8785): lex-sorted keys at every depth, no
  whitespace, ECMAScript number formatting. See [JCS](jcs.md).
- **PoP / nonce inputs are hashed over the *decoded* nonce bytes**, never
  the base64url string. RFC-AITP-0001 §5.4.2 is the unified rule for all
  four PoP sites (pinned-key proof, manifest PoP, handshake
  `pop_signature`, downstream PoP) and explicitly marks hashing the
  base64url form as non-conformant.

### M2 — `mutual_hello_ack` (Bob → Alice)

```json
{
  "version": "aitp/0.2",
  "message_type": "mutual_hello_ack",
  "message_id": "<bob's mid>",
  "timestamp": 1700000000,
  "sender": { "agent_id": "<bob AID>" },
  "payload": {
    "identity": { /* bob's pinned-key proof bound to bob's mid+timestamp */ },
    "manifest": { /* bob's Manifest */ },
    "requested_grants": ["demo.echo"],
    "pop_nonce": "<bob's 22-char nonce>",
    "pop_nonce_echo": "<alice's pop_nonce from M1>"
  },
  "signature": "<bob's envelope signature>"
}
```

**Critical interop note.** Bob's identity proof in M2 binds Bob's **ack**
envelope's `message_id` and `timestamp` (and `sender_aid = Bob`,
`receiver_aid = Alice`) — not M1's. The two-agent demo originally got this
wrong because the helper that wrapped envelopes generated fresh
`message_id` / `timestamp` after the identity proof was already built.
Build the proof and the envelope with the **same** `(message_id,
timestamp)` pair. See `examples/two-agents/src/lib.rs::sign_envelope_with`.

## Round 2

### M3 — `mutual_commit` (Alice → Bob)

```json
{
  "version": "aitp/0.2",
  "message_type": "mutual_commit",
  "message_id": "<alice's commit mid>",
  "timestamp": 1700000000,
  "sender": { "agent_id": "<alice AID>" },
  "payload": {
    "tct": "<compact JWS string — Alice's TCT for Bob, opaque>",
    "grant_voucher": "<compact JWS string — Alice's voucher for Bob, opaque>",
    "pop_signature": "<base64url(sign(alice_priv, sha256(base64url_decode(bob_pop_nonce))))>",
    "pop_nonce_echo": "<bob's pop_nonce from M2>"
  },
  "signature": "<alice envelope sig>"
}
```

The `tct` (and the companion `grant_voucher`) are carried as **opaque
compact JWS strings** (RFC-AITP-0001 §5.4.5). The envelope is still a
JCS-profile object — its outer `signature` covers the JCS canonicalization of
the payload, with the TCT and voucher strings included **verbatim** (the
canonicalizer never parses or re-encodes them). Decoding the TCT yields the
registered JWT claims `ver, jti, iss, sub, aud, iat, exp` plus `grants` and
`cnf: {"jkt": …}` — see [Outcome](#outcome). The TCT's own signature is the
third JWS segment, computed over `ASCII(header.payload)` by Alice's key — there
is no embedded `signature` field and no JCS step for the TCT itself. An issuer
that forbids the subject from delegating omits `grant_voucher`.

**Signed inputs in M3** (each hashed with SHA-256, then Ed25519-signed):

| Field | Preimage | Normative source |
|---|---|---|
| `payload.tct` (JWS signature segment) | `ASCII(base64url(header) \|\| "." \|\| base64url(claims))` — no canonicalization | RFC-AITP-0001 §5.4.5 |
| `payload.grant_voucher` (JWS signature segment) | `ASCII(base64url(header) \|\| "." \|\| base64url(claims))` | RFC-AITP-0001 §5.4.5 |
| `payload.pop_signature` | `base64url_decode(bob_pop_nonce)` — the raw decoded nonce bytes | RFC-AITP-0001 §5.4.2 |
| `signature` (envelope) | same recipe as M1 | RFC-AITP-0001 §5.4.1 |

The `pop_signature` preimage is the **raw bytes obtained by
base64url-decoding the 22-char nonce string** — *not* the ASCII bytes of
the base64url form. RFC-AITP-0001 §5.4.2 makes this the unified,
normative rule across every PoP site and explicitly flags hashing the
base64url string as non-conformant. (The shortened renewal exchange,
[TCT renewal](tct-renewal.md), uses the identical construction.)

### M4 — `mutual_commit_ack` (Bob → Alice)

Mirror image of M3. Bob's TCT (and voucher) for Alice; Bob's `pop_signature`
over `sha256(base64url_decode(alice_pop_nonce))`; `pop_nonce_echo` equals
Alice's M1 nonce.

## Outcome

After M4 verifies on Alice's side (decoded TCT claims shown):

```
Alice holds: TCT { iss=Bob,   sub=Alice, aud=Alice,
                   grants=["demo.echo"], cnf={"jkt": thumbprint(alice_key)} }
             + grant voucher { iss=Bob,   sub=Alice, src_jti=<Alice's TCT jti> }
Bob holds:   TCT { iss=Alice, sub=Bob,   aud=Bob,
                   grants=["demo.echo"], cnf={"jkt": thumbprint(bob_key)} }
             + grant voucher { iss=Alice, sub=Bob,   src_jti=<Bob's TCT jti> }
```

Note `aud == sub` on a v0.2 TCT (RFC-AITP-0005 §2). Each peer verifies the
other's TCT by:

1. resolving the issuer's public key from `manifest.aid` (the
   manifests exchanged inline in M1/M2 are cached for the duration of
   `manifest.expires_at`) — or, since the TCT is a standard compact JWS,
   directly from the issuer AID with any JOSE library;
2. checking the JWS `typ == aitp-tct+jwt` and deriving the sole acceptable
   `alg` from the issuer AID, then Ed25519-verifying the signature segment over
   the `ASCII(header.payload)` bytes **as transmitted** — no canonicalization,
   no reconstruction;
3. confirming `cnf.jkt` equals the RFC 7638 thumbprint of the key encoded in
   `sub`.

## Bytes you can reproduce

Run:

```sh
cargo test -p aitp-handshake --test full_handshake -- --nocapture
```

The test seeds keys deterministically (`[0xA1] * 32`, `[0xB2] * 32`) and
pins `now = 1_700_000_000`, so re-running it always produces the same
TCTs.
