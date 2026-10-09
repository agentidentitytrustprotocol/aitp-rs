# Handshake wire transcripts

This page shows the messages two peers exchange in a successful
four-message Mutual Handshake
([RFC-AITP-0004](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0004-mutual-handshake.md)). For each
signature it names the `aitp-rs` function that builds the signing input.
It is for implementers in other languages who are debugging an interop
failure. The RFCs define the bytes. This page tells you where `aitp-rs`
builds them.

The shapes below follow the
`crates/aitp-handshake/tests/full_handshake.rs::full_pinned_key_handshake`
test, which uses pinned-key identity, fixed key seeds and a fixed clock of
1 700 000 000. That test is a round-trip check, not a byte transcript. It
prints nothing, and some values change on every run (see
[Bytes you can reproduce](#bytes-you-can-reproduce)).

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

**Signed inputs in M1.** Each byte layout is defined in the RFC section
linked in the last column. That section is the authority, and this page
does not restate it. The middle column names the `aitp-rs` code that
builds the input.

| Signature field | `aitp-rs` implementation | Normative source |
|---|---|---|
| `payload.identity.proof` (pinned-key) | `pinned_key_proof_input` (`crates/aitp-handshake/src/identity_pinned.rs`) | [RFC-AITP-0002 §3.1](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0002-identity.md#31-proof-format) |
| `payload.manifest.proof_of_possession.signature` | the PoP step in `crates/aitp-manifest/src/builder.rs` | [RFC-AITP-0001 §5.4.2](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md#542-pop-signing-input-convention) |
| `payload.manifest.signature` | `manifest_signing_bytes` (`crates/aitp-manifest/src/builder.rs`) | [RFC-AITP-0003 §6.1](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0003-manifest.md#61-what-is-signed) |
| `signature` (envelope) | `aitp_core::envelope_signing_input` / `envelope_signing_digest` (`crates/aitp-core/src/envelope.rs`) | [RFC-AITP-0001 §5.4](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md#54-signature) |

Two encoding details cause most interop failures:

- **The pinned-key proof encodes `timestamp` as an ASCII decimal
  string**, for example `"1700000000"`, not as an 8-byte big-endian
  integer. Older RFC text said big-endian, and an earlier `aitp-rs`
  shipped that bug. The RFC-AITP-0002 §3.1 erratum and the
  `kat-pinned-key-proof-001` vector (checked by
  `crates/aitp-handshake/tests/pinned_key_proof_kat.rs`) pin the ASCII
  form.
- **PoP and nonce inputs are hashed over the *decoded* nonce bytes**,
  never over the base64url string. RFC-AITP-0001 §5.4.2 makes this one
  rule for every PoP site. Canonical JSON follows RFC 8785; see
  [JCS](jcs.md).

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
timestamp)` pair. The `envelope_with` helpers in
`crates/aitp-handshake/tests/full_handshake.rs` and
`examples/two-agents/src/bin/oidc-demo.rs` show the pattern: the caller
passes in the `message_id` and timestamp it already used for the payload.

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

**Signed inputs in M3:**

| Field | `aitp-rs` implementation | Normative source |
|---|---|---|
| `payload.tct` (JWS signature segment) | `aitp_crypto::jws::sign_compact`, called from `crates/aitp-tct/src/builder.rs` | [RFC-AITP-0001 §5.4.5](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md#545-compact-jws-profile-portable-trust-artifacts), [RFC-AITP-0005 §7.1](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0005-tct.md#71-what-is-signed) |
| `payload.grant_voucher` (JWS signature segment) | `aitp_crypto::jws::sign_compact`, same builder | [RFC-AITP-0001 §5.4.5](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md#545-compact-jws-profile-portable-trust-artifacts) |
| `payload.pop_signature` | `sign_pop` (`crates/aitp-handshake/src/state_machine.rs`) | [RFC-AITP-0001 §5.4.2](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md#542-pop-signing-input-convention) |
| `signature` (envelope) | same as M1 | [RFC-AITP-0001 §5.4](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md#54-signature) |

The two JWS segments are **not** hashed with SHA-256 before signing.
`sign_compact` signs the ASCII `header.payload` bytes directly
(`crates/aitp-crypto/src/jws.rs`). For `EdDSA` that is plain Ed25519. For
`ES256` the SHA-256 step is part of the algorithm itself. The envelope,
the Manifest and the PoP signatures, by contrast, do sign a SHA-256
digest, as their RFC sections specify. The shortened renewal exchange
([TCT renewal](tct-renewal.md)) builds its PoP input the same way as
`pop_signature`.

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
other's TCT in the order set by
[RFC-AITP-0005 §7.2](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0005-tct.md#72-verification-order).
In short:

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

`full_handshake.rs` is not a byte transcript. Run it like this:

```sh
cargo test -p aitp-handshake --test full_handshake
```

It checks that all four messages verify and that each side ends up holding
the TCT it should. Only the key seeds (`[0xA1] * 32`, `[0xB2] * 32`) and
the clock (`NOW = 1_700_000_000`) are fixed. Every run uses fresh random
`message_id`s (`Uuid::new_v4()`), `pop_nonce`s and TCT `jti`s, so the
signatures differ from run to run. Its test-only `envelope_with` helper
also stamps envelopes `"aitp/0.1"`. Production code uses
`aitp_core::PROTOCOL_VERSION` (`"aitp/0.2"`), which is the shape shown
above.

For bytes that are fixed and pinned, use the spec's known-answer
vectors:

- `tests/schemas/known-answer/jcs-sha256.json` covers the JCS-profile
  signing inputs and `kat-pinned-key-proof-001`.
- [`known-answer/signed-examples/`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/conformance/known-answer/signed-examples/README.md)
  holds real signed artifacts, including compact-JWS TCTs and vouchers.
  `tools/mint-signed-examples` reproduces them byte for byte.
