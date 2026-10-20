# Upgrading from 0.16 to 0.17

0.17.0 adopts protocol revision **`aitp/0.3`** at spec commit `bf00e75`
([#253](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/253),
[#254](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/254)).
Two things change on the wire. The envelope signature now covers the whole
envelope except `signature` (signing input v2), and every artifact carries
the literal `aitp/0.3` instead of `aitp/0.2`. The cutover is strict: 0.17
rejects every `aitp/0.2` artifact.

It is a breaking release in three ways:

- **On the wire.** A 0.17 peer and a 0.16 peer cannot talk to each other.
  Upgrade both sides together.
- **In Rust.** `aitp_core::envelope_signing_input` and
  `envelope_signing_digest` take the envelope, and `EnvelopeParseError`
  has a new variant.
- **For anyone who vendors the spec's vectors or fixtures.** Every signed
  vector was re-minted.

The spec's own migration notes are in its
[`VERSIONING.md`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/VERSIONING.md#migrating-from-aitp02-to-aitp03).
The per-crate `crates/*/CHANGELOG.md` files are the authoritative record
of what shipped. The root [`CHANGELOG.md`](../CHANGELOG.md) has a summary.

## 1. Wire incompatibility and the strict `aitp/0.2` → `aitp/0.3` cutover

`aitp_core::PROTOCOL_VERSION` is now `"aitp/0.3"`. Every producer stamps
it. That covers envelopes, Manifests, revocation snapshots, session
bundles (`DEFAULT_BUNDLE_VERSION` is the same constant), and the `ver`
claim of TCTs, grant vouchers and delegation tokens. Every checker
compares against the same constant. There is no dual-accept window: an
`aitp/0.2` artifact is as unknown as `aitp/9.9`, even when its signature
is valid (spec fixture env-011).

A 0.16 peer fails against a 0.17 peer in two ways:

- **Its artifacts carry `aitp/0.2`.** They are rejected on their version,
  with the code in the table below.
- **Its envelopes are signed over the retired pipe input.** Restamping
  `version` alone does not help. An `aitp/0.3` envelope whose signature
  covers the 0.16 input fails with `INVALID_SIGNATURE` (section 2).

| Artifact | Member | Rust error | Wire code (HTTP server, conformance adapter) |
|---|---|---|---|
| Envelope | `version` | `EnvelopeParseError::UnknownVersion` (pinned admission: `AdmissionError::UnknownVersion`) | `UNKNOWN_VERSION` |
| Agent Manifest | `version` | `ManifestError::VersionUnknown` | `MANIFEST_VERSION_UNKNOWN` |
| Revocation snapshot | `version` | `TctError::VersionUnknown` | `UNKNOWN_VERSION` |
| Session trust bundle | `version` | `SessionBundleError::VersionMismatch` | `BUNDLE_VERSION_MISMATCH` |
| TCT | `ver` | `TctError::VersionUnknown` | `UNKNOWN_VERSION` |
| Grant voucher | `ver` | `TctError::VersionUnknown` | `UNKNOWN_VERSION` |
| Delegation token (single-hop, and every hop of a multi-hop chain) | `ver` | `DelegationError::VersionUnknown` | `UNKNOWN_VERSION` |

The Rust variants are not new. Only the value they reject has changed.
The one new variant is `EnvelopeParseError::UnknownVersion` (section 5).
An envelope with no `version` at all, `{}` included, is now
`UNKNOWN_VERSION`. 0.16 reported it as `INVALID_ENVELOPE`. A JSON value
that is not an object is still `INVALID_ENVELOPE`.

## 2. Envelope signing input v2

RFC-AITP-0001 §5.4 replaces the envelope signing input:

```text
sig_input_v2 = "aitp-envelope-v2" || 0x00 || JCS(envelope_without_signature)
d            = sha256(sig_input_v2)
signature    = base64url(SIGN_alg(sender_private_key, d))   ; SIGN_alg per §5.4.6
```

- `envelope_without_signature` is the envelope with `signature` removed
  and every other member kept: `version`, `message_type`, `message_id`,
  `timestamp`, `sender`, `payload`, and `extensions` when present.
- The domain tag is the 16 ASCII bytes `aitp-envelope-v2`
  (`aitp_core::ENVELOPE_SIGNING_DOMAIN_TAG`), then one `0x00` byte.
- `d` is hashed exactly once. The algorithm-tagged signature format
  (§5.4.3) and verification strictness (§5.4.7) are unchanged.

The 0.16 input was the pipe-composed string
`message_id|timestamp|sender.agent_id|hex(sha256(JCS(payload)))`. It is
gone from every signer, verifier and minter in the workspace.

**What is authenticated now.** `version`, `message_type` and `extensions`
are inside the signature. 0.16 shipped the v0.2 erratum
([`upgrading-0.16.md` section 6](upgrading-0.16.md#6-spec-pin-and-the-v02-envelope-erratum)),
which said receivers MUST NOT treat those members as sender-authenticated.
Under `aitp/0.3` they are. Changing any of them after signing breaks the
signature, and spec fixtures env-008 (`extensions`) and env-009
(`message_type`) pin this. Absent `extensions` and `"extensions": {}` are
different inputs, so a relay must not add or drop an empty map.

**Attach `extensions` before you sign.** In 0.16 you could add
`extensions` to an envelope after `sign_envelope*` returned, and the
signature still verified. In 0.17 that envelope fails verification. Build
the envelope first, then sign it with the new
`aitp_envelope::sign_prepared_envelope` (or `sign_prepared_envelope_async`
for a KMS or HSM backend):

```rust
use aitp_core::{AitpEnvelope, ExtensionsMap, MessageType, Sender, Timestamp, PROTOCOL_VERSION};
use aitp_crypto::AitpSigner;

// 0.16: extensions were unsigned, so adding them afterwards was harmless
let mut env = aitp_envelope::sign_envelope(&key, MessageType::Tct, payload)?;
env.extensions = Some(ext);

// 0.17: attach them first, then sign the whole envelope
let unsigned = AitpEnvelope {
    version: PROTOCOL_VERSION.into(),            // "aitp/0.3"
    message_type: MessageType::Tct,
    message_id: uuid::Uuid::new_v4(),
    timestamp: Timestamp::now(),
    sender: Sender { agent_id: key.aid().clone() },
    payload,
    extensions: Some(ext),
    signature: String::new(),                    // ignored and replaced
};
let env = aitp_envelope::sign_prepared_envelope(&key, unsigned)?;
```

`sign_prepared_envelope` refuses three things before the backend is
called: a `version` other than `PROTOCOL_VERSION`, a `message_id` that is
not UUID v4, and a `sender.agent_id` that is not the signer's AID. It
lives in `aitp-envelope` only. `aitp-transport-http` does not re-export
it, so import it from `aitp_envelope`. `sign_envelope`,
`sign_envelope_with` and their async forms keep their signatures. They
build an envelope with no `extensions` and sign it over the v2 input.
`verify_envelope_signature` is also unchanged in signature, and it now
checks the v2 input.

## 3. The receive check order

RFC-AITP-0001 §5.4 fixes the order in which a receiver checks an
envelope, and the first failure is reported:

1. **`version`.** Absent, not a string, or not `aitp/0.3` →
   `UNKNOWN_VERSION`. This runs before the member set is looked at.
2. **Member set and structure.** A member outside the schema →
   `UNKNOWN_FIELD`. Any other structural defect → `INVALID_ENVELOPE`.
3. **Signature** over `sig_input_v2` → `INVALID_SIGNATURE`.

`aitp_core::parse_envelope_wire` now runs step 1 before step 2. 0.16 ran
the member-set check first. The caller runs step 3 on the envelope it
returns. Every receive path parses envelopes with `parse_envelope_wire`,
so the order holds in:

- pinned-key admission (`aitp-handshake`)
- the `aitp-transport-http` server
- the `aitp` facade's response path
- the conformance adapter, `verify_handshake_payload` included
- the Python and Node handshake entry points

Two consequences:

- An envelope with both an unknown `version` and an unknown member
  reports `UNKNOWN_VERSION`. 0.16 reported `UNKNOWN_FIELD`.
- A `version` changed after signing is `UNKNOWN_VERSION` when the new
  value is unknown (env-010), and `INVALID_SIGNATURE` when it is known.

The spec places these three steps inside the RFC-AITP-0009 §3.1 endpoint
order, after the replay, rate-limit and timestamp checks. Section 4 covers
how the HTTP handshake server applies that order.

## 4. The HTTP handshake server's receive order

In 0.16, `HandshakeServer`'s `/aitp/handshake/hello` and
`/aitp/handshake/commit` routes (`aitp-transport-http`) checked
Content-Type and parsed and validated the envelope before they looked at
the replay deny list, the rate limit or the timestamp window. 0.17 runs
the RFC-AITP-0009 §3.1 order, and the RFC-AITP-0001 §5.4 envelope steps
sit inside it
([#255](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/255),
[#259](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/259)).
The first failure is reported:

| Step | Check | Failure |
|---|---|---|
| 0 | Read the body under `DEFAULT_MAX_BODY_BYTES` (256 KiB) and `DEFAULT_BODY_READ_TIMEOUT` (5 s), then parse the JSON with the duplicate-key check. A parse failure is held until step 4. | `INVALID_ENVELOPE` for an oversized or slow body |
| 1 | Replay deny list on `message_id` | `REPLAY_DETECTED` |
| 2 | Rate limit, keyed on the transport source and the self-asserted `sender.agent_id` | HTTP 429, empty body |
| 3 | Timestamp window (`DEFAULT_TIMESTAMP_TOLERANCE_SECS`, 300 s) | `TIMESTAMP_EXPIRED` |
| 4 | Content-Type must be `application/json`, then the JSON failure held from step 0 | `INVALID_ENVELOPE` |
| 5 | `version`, then the member set and structure (`parse_envelope_wire`), then whether `message_type` matches the route | `UNKNOWN_VERSION` / `UNKNOWN_FIELD` / `INVALID_ENVELOPE` |
| 6 | Envelope signature, in the hello or commit handler | `INVALID_SIGNATURE` |

There is no API change. `HandshakeServer::enforce_rate_limit`, the router
and `RateLimitConfig` keep their signatures. What changes is what the two
endpoints return.

**The code reported when more than one check fails.** A replayed envelope
now gets `REPLAY_DETECTED`, and one outside the window gets
`TIMESTAMP_EXPIRED`, even if it also has any of these:

- an unknown or absent `version`;
- an unknown member, or a malformed structure;
- an unregistered `message_type`, or the wrong one for the route;
- the wrong Content-Type.

0.16 reported `UNKNOWN_VERSION`, `UNKNOWN_FIELD` or `INVALID_ENVELOPE`
for those. A test that sends a stale or replayed envelope with a second
defect must expect the new code.

**Fall-through for members that cannot be read.** Steps 1 to 3 read
their member from the raw JSON, before any schema work. When the member
is missing or the wrong type, the step is skipped and step 5 reports the
problem. This follows aitp-verifier-py at `f335f4f`.

- `message_id` is checked against the deny list only if it is a string
  that parses as a UUID.
- `timestamp` is checked against the window only if it is a JSON integer
  that fits in `i64`. A missing, string, float or out-of-range value
  skips step 3, and step 5 reports `INVALID_ENVELOPE`. `i64::MIN` is a
  readable value and fails the window with `TIMESTAMP_EXPIRED`.
- `sender.agent_id` keys the per-AID bucket only if it is a valid AID.
  Otherwise only the transport key is rate limited.
- A body that is not JSON, or that has a duplicate key, skips steps 1
  and 3. It is rate limited on the transport key, then rejected with
  `INVALID_ENVELOPE` at step 4.
- A missing `version` is `UNKNOWN_VERSION`, as in section 3.

**Malformed requests now count against the rate limit.** Every request
whose body was read reaches step 2 before any structural check. That
includes bodies that are not JSON, have an unknown version or are
malformed, and envelopes sent to the wrong route. Each such request uses
up the source's per-source budget, and the per-AID budget too when
`sender.agent_id` is a valid AID. Once the budget is spent, the server
answers HTTP 429 with an empty body, not an error envelope. If you sized
`RateLimitConfig` from well-formed traffic, allow for this. A body that
is too large or too slow to read is refused at step 0, so it does not
count.

**A malformed envelope consumes its `message_id`.** The deny list now
records a readable `message_id` before the version and structure checks,
so an envelope that is rejected later still uses up its id. 0.16 already
recorded the id before the signature check, so an unauthenticated sender
could already consume one. This gives an attacker nothing new.

**Deviation: the body-size limit runs first.** RFC-AITP-0009 §3.1 puts
the body-size bound in step 4, with Content-Type. The server applies it
while reading the body, before steps 1 to 3, because those steps read
members of the body and the bound has to hold during the read. The
Content-Type check stays at step 4.

Pinned-key admission (`admit_wire`) already ran in this order and is
unchanged. The `aitp` facade and the Python and Node bindings keep no
replay or timestamp state, so they have no §3.1 step to reorder. The
conformance adapter's `verify_envelope` op now applies a fixture's
`tolerance_seconds` window before `parse_envelope_wire`.

## 5. `aitp-core` API changes

**`envelope_signing_input` and `envelope_signing_digest` take the
envelope.** They used to take four parameters. Each now takes one
parameter, `&AitpEnvelope`, and ignores the value of its `signature`
member, so a signer can call them on an envelope whose `signature` is
still empty. The return types are unchanged:
`Result<Vec<u8>, jcs::JcsError>` and `Result<[u8; 32], jcs::JcsError>`.

```rust
use aitp_core::{envelope_signing_digest, envelope_signing_input, AitpEnvelope};

// 0.16
let input = envelope_signing_input(&env.message_id, env.timestamp, &env.sender.agent_id, &env.payload)?;
let digest = envelope_signing_digest(&env.message_id, env.timestamp, &env.sender.agent_id, &env.payload)?;

// 0.17
let input = envelope_signing_input(&env)?;    // "aitp-envelope-v2" || 0x00 || JCS(env minus signature)
let digest = envelope_signing_digest(&env)?;  // sha256(input), the 32 bytes handed to SIGN_alg
```

If you computed the digest by hand to sign with your own backend, set
every member first, `extensions` included, then compute the digest.
`ENVELOPE_SIGNING_DOMAIN_TAG` is a new public constant, also re-exported
at the crate root.

**`EnvelopeParseError::UnknownVersion(String)` is new.** It carries the
offending value as JSON text (`"aitp/0.2"`, `3`, `null`), or `<absent>`
when the member is missing. `EnvelopeParseError` is not
`#[non_exhaustive]`, so an exhaustive `match` must add the arm:

```rust
use aitp_core::{parse_envelope_wire, CheckedJson, EnvelopeParseError};

// 0.16
match parse_envelope_wire(&wire) {
    Ok(env) => { /* step 3: verify the signature */ }
    Err(EnvelopeParseError::UnknownField(_)) => { /* UNKNOWN_FIELD */ }
    Err(EnvelopeParseError::Malformed(_)) => { /* INVALID_ENVELOPE */ }
}

// 0.17
match parse_envelope_wire(&wire) {
    Ok(env) => { /* step 3: verify the signature */ }
    Err(EnvelopeParseError::UnknownVersion(_)) => { /* UNKNOWN_VERSION */ }
    Err(EnvelopeParseError::UnknownField(_)) => { /* UNKNOWN_FIELD */ }
    Err(EnvelopeParseError::Malformed(_)) => { /* INVALID_ENVELOPE */ }
}
```

`cargo-semver-checks` flags exactly these two changes on `aitp-core`
(`function_parameter_count_changed` and `enum_variant_added`).

## 6. Python and Node

The binding functions keep their signatures. What you can observe:

- **Everything they emit says `aitp/0.3`.** That includes
  `build_manifest()` / `buildManifest()`, `sign_revocation_list()` /
  `signRevocationList()`, handshake envelopes, TCTs and delegations. A
  test that asserts on the literal must be updated.
- **Inbound handshake envelopes are checked for their version first.**
  `process_hello`, `process_hello_ack` and the commit steps (Python), and
  `processHello`, `processHelloAck` and the commit steps (Node), reject an
  envelope whose `version` is not `aitp/0.3`. Python raises `ValueError`,
  and Node throws an `Error`. The message is
  `invalid envelope JSON: unknown protocol version "aitp/0.2"` (or
  `<absent>` when `version` is missing). The version check comes before
  the member-set check, so an `aitp/0.2` envelope with an unknown member
  reports the version, not `unknown field`.
- **A caller that builds hello envelopes by hand must stamp `aitp/0.3`.**
  If you only pass along the JSON that `build_hello()` / `buildHello()`
  returned, you need no change.
- **Manifests and revocation snapshots.** An `aitp/0.2` Manifest passed
  to `verify_manifest_json` / `verifyManifestJson` fails with code
  `version_unknown`. Python raises `ManifestVerificationError`. An
  `aitp/0.2` snapshot passed to `verify_revocation_list` /
  `verifyRevocationList` also fails with `version_unknown`; Python raises
  `RevocationVerificationError`. These codes existed in 0.16. Only the
  value that triggers them has changed.
- **TCTs, delegations and session bundles.** An `aitp/0.2` artifact fails
  verification with the existing error, for example `TCT verification
  failed: TCT version is not supported` or `bundle verification failed:
  bundle version mismatch`.

## 7. Re-minted vectors and fixtures

The literal sits inside every signed artifact, so every signature
changed. If you vendor any of these, re-vendor them from spec `bf00e75`.
Do not patch bytes by hand.

- **`tests/schemas/`** is the full `schemas/` tree at `bf00e75`, and
  `tests/schemas/SPEC_VERSION` names that commit. The JSON Schema `$id`
  namespace is now `https://aitp.dev/schema/v0.3/`. `make schemas-check`
  reports no drift.
- **Known-answer vectors** (`tests/schemas/known-answer/`). The digests
  in `jcs-sha256.json` and every file under `signed-examples/` were
  re-minted: delegation, grant voucher, Manifests, revocation snapshots,
  session bundle and TCTs. `jwk-thumbprints.json` and
  `signature-strictness.json` changed only their `$comment`, so their
  values are the same as in 0.16.
- **Envelope KATs.** `kat-envelope-001-p256`
  (`signed-examples/envelope/kat-keypair-005-envelope.json`) was re-minted
  for the v2 input. `kat-envelope-002-ed25519`
  (`signed-examples/envelope/kat-keypair-001-envelope.json`) is new and
  carries `extensions`. `crates/aitp-crypto/tests/signing_input_kats.rs`
  reproduces the spec's v2 signing input, its length, its digest and its
  signatures. Each KAT also keeps its v1 signature over the retired pipe
  input, and the test asserts that the v1 signature no longer verifies.
- **Conformance fixtures** (`schemas/conformance/` in the spec repo). Every
  fixture changed its literal. env-007 now carries a real signature, and
  env-008 to env-011 are the new envelope fixtures (sections 2 and 3).
- **Cross-implementation bundle** (`tests/xcheck-fixtures/session-bundle/`).
  `kat-keypair-001-bundle.json` was re-minted by aitp-verifier-py
  `f335f4f` against spec `bf00e75`, with the command in that directory's
  README. The old `aitp/0.2` bundle is kept byte for byte as
  `kat-keypair-001-bundle-aitp-0.2.json`, and
  `committed_aitp_0_2_bundle_is_rejected_by_the_strict_cutover` asserts
  that 0.17 refuses it with `SessionBundleError::VersionMismatch`.

## 8. Conformance and cross-implementation checks

At pin `bf00e75` (102 fixtures), the rs adapter passes 79, fails 0 and
skips 23 in the strict run (no `--feature`, default `--profile v0.2`).
All 78 `required_for_v0_2` core fixtures pass, env-007 to env-011
included. With all four features it passes 100 and skips 2: `del-004`
and `del-007`, which the multi-hop feature negates. See
[`conformance.md`](conformance.md).

The `--profile v0.2` name and the fixture key `required_for_v0_2` stay.
The spec kept the key on purpose, and for `aitp/0.3` it marks the core
tier. So the runner's default profile is the `aitp/0.3` core gate. If you
run `aitp-conformance` against your own adapter, your adapter must speak
`aitp/0.3`.

`tests/AITP_VERIFIER_PY_VERSION` moves from aitp-verifier-py `43cf702`
to `f335f4f`, the merge of its #65, which adds `aitp/0.3`. The CI
`xcheck` job pipes `xcheck-mint` into `scripts/xcheck-verify.py` at that
pin.

## 9. Claim strings

The spec renames the claim strings to "AITP v0.3 self-attestation" and
"AITP v0.3 pinned-admission". No `aitp-rs` code emits or checks either
string, so nothing changes here.
