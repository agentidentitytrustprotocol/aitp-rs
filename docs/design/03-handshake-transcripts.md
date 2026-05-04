# 03 — Handshake wire transcripts

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
  "version": "aitp/0.1",
  "message_type": "mutual_hello",
  "message_id": "<uuid v4 — alice picks>",
  "timestamp": 1700000000,
  "sender": { "agent_id": "<alice AID>" },
  "payload": {
    "identity": {
      "type": "pinned_key",
      "subject": "alice",
      "proof": "<base64url(sign(alice_priv, sha256(<message_id>|<timestamp>)))>",
      "public_key": "<base64url(alice_pubkey_bytes)>"
    },
    "manifest": { /* alice's full Manifest, inline */ },
    "requested_grants": ["demo.echo"],
    "pop_nonce": "<22-char base64url, 128 random bits>"
  },
  "signature": "<base64url(sign(alice_priv, sha256(envelope_signing_input)))>"
}
```

**Signed inputs in M1:**

| Signature field | Bytes signed (then SHA-256'd, then Ed25519-signed) |
|---|---|
| `payload.identity.proof` (pinned-key) | `format!("{}|{}", message_id, timestamp.0).as_bytes()` |
| `payload.manifest.proof_of_possession.signature` | `<challenge>.as_bytes()` (the 22-char base64url challenge string itself) |
| `payload.manifest.signature` | `JCS(manifest_without_signature_field)` |
| `signature` (envelope) | `format!("{}|{}|{}|{}", message_id, timestamp.0, sender_aid_str, hex(sha256(JCS(payload))))` |

JCS canonicalisation per RFC 8785: lex-sorted keys at every depth, no
whitespace, ECMAScript number formatting.

### M2 — `mutual_hello_ack` (Bob → Alice)

```json
{
  "version": "aitp/0.1",
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

**Critical interop note.** Bob's identity proof in M2 is signed over
Bob's **ack** envelope's `message_id` and `timestamp` — not over M1's.
The two-agent demo originally got this wrong because the helper that
wrapped envelopes generated fresh `message_id` / `timestamp` after the
identity proof was already built. Build the proof and the envelope with
the **same** `(message_id, timestamp)` pair. See
`examples/two-agents/src/lib.rs::sign_envelope_with`.

## Round 2

### M3 — `mutual_commit` (Alice → Bob)

```json
{
  "version": "aitp/0.1",
  "message_type": "mutual_commit",
  "message_id": "<alice's commit mid>",
  "timestamp": 1700000000,
  "sender": { "agent_id": "<alice AID>" },
  "payload": {
    "tct_for_peer": {
      "tct": {
        "version": "aitp/0.1",
        "jti": "<uuid>",
        "issuer": "<alice AID>",
        "subject": "<bob AID>",
        "audience": "<bob AID>",
        "issued_at": 1700000000,
        "expires_at": 1700003600,
        "grants": ["demo.echo"],
        "binding": { "cnf": "<bob_pubkey_base64url>" },
        "signature": "<alice_sig over JCS(tct_without_signature)>"
      }
    },
    "pop_signature": "<base64url(sign(alice_priv, sha256(bob_pop_nonce.as_bytes())))>",
    "pop_nonce_echo": "<bob's pop_nonce from M2>"
  },
  "signature": "<alice envelope sig>"
}
```

**Signed inputs in M3:**

| Field | Signing input |
|---|---|
| `payload.tct_for_peer.tct.signature` | `JCS(tct_without_signature_field)` |
| `payload.pop_signature` | `sha256(bob_pop_nonce.as_bytes())` |
| `signature` (envelope) | same recipe as M1 |

`bob_pop_nonce.as_bytes()` is the **ASCII bytes of the 22-char base64url
nonce string**, not the 16 bytes the nonce decodes to. This is the
choice this implementation pins; spec ambiguity recorded in
`docs/design/PENDING.md`.

### M4 — `mutual_commit_ack` (Bob → Alice)

Mirror image of M3. Bob's TCT for Alice; Bob's `pop_signature` over
`sha256(alice_pop_nonce.as_bytes())`; `pop_nonce_echo` equals Alice's
M1 nonce.

## Outcome

After M4 verifies on Alice's side:

```
Alice holds: TCT { issuer=Bob, subject=Alice, audience=Alice,
                   grants=["demo.echo"], binding.cnf=alice_pubkey_b64 }
Bob holds:   TCT { issuer=Alice, subject=Bob, audience=Bob,
                   grants=["demo.echo"], binding.cnf=bob_pubkey_b64 }
```

Each peer verifies the other's TCT by:

1. resolving the issuer's public key from `manifest.aid` (the
   manifests exchanged inline in M1/M2 are cached for the duration of
   `manifest.expires_at`);
2. JCS-canonicalising the TCT minus its `signature` field, SHA-256'ing,
   and Ed25519-verifying with the issuer's public key.

## Bytes you can reproduce

Run:

```sh
cargo test -p aitp-handshake --test full_handshake -- --nocapture
```

The test seeds keys deterministically (`[0xA1] * 32`, `[0xB2] * 32`) and
pins `now = 1_700_000_000`, so re-running it always produces the same
TCTs.
