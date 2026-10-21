# Upgrading from 0.18 to 0.19

0.19.0 tightens how the Python and Node bindings handle UUIDs
([#279](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/279),
which closes
[#272](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/272)).
It also makes the conformance adapter follow the spec's rule for a
revocation snapshot it cannot use
([#278](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/278),
which closes
[#271](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/271)).
The protocol revision is still `aitp/0.3`, and the wire format does not
change, so 0.19 and 0.18 peers interoperate.

It is a breaking release for **binding users only**. The Rust crates'
public API and behaviour do not change. Under the pre-1.0 convention a
breaking change bumps the minor version, so the whole lockstep set moves
to 0.19.0.

- **Strict ids.** A `message_id` or `session_id` that the bindings sign
  must be a lowercase hyphenated UUID v4 (section 1).
- **Normalized deny lists.** Each `revoked_jtis` entry is normalized
  before lookup, and an entry that is not a UUID is an error
  (section 2). This also fixes a **revocation bypass in the Python
  binding**: an uppercase or braced entry never matched, so the TCT it
  named was accepted.

The per-crate `crates/*/CHANGELOG.md` files are the authoritative record
of what shipped. The root [`CHANGELOG.md`](../CHANGELOG.md) has a summary.

## Who is affected

| You... | Affected by | Action |
|---|---|---|
| pass `messageId` / `message_id` to `signEnvelope` / `sign_envelope` | section 1 | Pass a lowercase UUID v4 unchanged |
| set `SessionBundleBuilder.sessionId()` / `.session_id()` | section 1 | Pass a lowercase UUID v4 unchanged |
| pass `revoked_jtis` / `revokedJtis` to a binding verify or renewal call | section 2 | Remove entries that are not UUIDs; any UUID text form now matches |
| use the Python binding with `revoked_jtis` | section 2 | Upgrade: uppercase or braced entries were silently ignored |
| run the conformance adapter, or compare its revocation results | section 3 | A discarded snapshot now follows `revocation_policy.mode` |
| vendor the spec's fixtures or run the conformance or xcheck jobs | section 4 | Update to spec `59407d2` and verifier-py `138b79d` |

If you generate ids with `randomUUID()` or `str(uuid.uuid4())`, pass them
unchanged, and keep only real `jti` values in deny lists, nothing changes
for you except the Python fix.

## 1. The bindings sign only canonical UUID v4 ids

The `message_id` of an envelope and the `session_id` of a session bundle
are signed, and the spec schemas require the lowercase hyphenated v4
form. 0.18 accepted uppercase, braced, `urn:uuid:` and unhyphenated
input and signed it lowercased, so the signed id differed from the id
the caller held. A bundle `session_id` of any UUID version was signed
too, which the bundle schema rejects.

0.19 parses both with `aitp_core::ids::parse_v4`, the same check the
Rust builders run:

| Call | Node | Python |
|---|---|---|
| Envelope signing | `signEnvelope(type, payload, { messageId })` | `sign_envelope(type, payload, message_id=)` |
| Session bundle | `SessionBundleBuilder.sessionId()` | `SessionBundleBuilder.session_id()` |

A non-canonical value throws (Node) or raises `ValueError` (Python):

```text
message_id is not a lowercase UUID v4: …
session_id is not a lowercase UUID v4: …
```

**Migration.** Pass the generator's output as is:

```js
// Node
agent.signEnvelope("mutual_hello", payloadJson, { messageId: crypto.randomUUID() });
```

```python
# Python
agent.sign_envelope("mutual_hello", payload_json, message_id=str(uuid.uuid4()))
```

If you store ids in another form, convert them to the lowercase
hyphenated form before you sign (in Python, `str(uuid.UUID(s))`). The
id must also be version 4.

## 2. `revoked_jtis` entries are normalized, and garbage fails closed

A deny list is a lookup key, not a signed value, so it stays lenient
about text form, now in both bindings. Each `revoked_jtis` /
`revokedJtis` entry is parsed as any RFC 9562 text form and compared
with the canonical `jti`. This applies to:

- `verifyTct` / `verify_tct` and their `Cached` variants;
- `verifyDelegation` / `verify_delegation` and their multi-hop variants;
- `processRenewalRequest` / `process_renewal_request`.

**Security fix (Python).** Python's TCT and delegation checks compared
strings. An uppercase or braced entry never matched the lowercase `jti`
in the token, so a TCT the caller meant to revoke was **accepted**. Node
and renewal already normalized. If you run the Python binding and fill
`revoked_jtis` from a source that is not lowercase (a database, a UI,
another library), upgrade.

**Fail closed.** An entry that is not a UUID at all now throws (Node) or
raises `ValueError` (Python):

```text
revoked_jtis entry is not a UUID: …
```

0.18 dropped such an entry in Node and never matched it in Python, so a
list made only of bad entries quietly turned the gate off. Renewal
already refused one.

**Migration.** Make sure every entry is a UUID. Text form does not
matter any more.

## 3. The conformance adapter treats a discarded snapshot as absent

Spec `53b92c0` (RFC-AITP-0008 0.3.1-draft, §1.5 and §3.1) says a
revocation snapshot discarded for any reason (structure, unknown member,
version, signature, expiry, issuer, staleness) counts as absent, and
`revocation_policy.mode` decides. 0.18's adapter skipped such a snapshot
and verified the token as if nothing were revoked.

| Adapter op | `fail_closed` (default) | `fail_open` | `soft_fail` |
|---|---|---|---|
| `verify_tct` | `TCT_REVOKED` | accepted | grants narrowed to `safe_grants` (`POLICY_VIOLATION` if none are left) |
| multi-hop `verify_delegation_token`, a hop issuer's snapshot (RFC-AITP-0011 §6) | `DELEGATION_SOURCE_TCT_REVOKED` | accepted | `DELEGATION_SOURCE_TCT_REVOKED` |

Three related changes:

- The verifier's own deny list (RFC-AITP-0006 §4 step 7) is local state
  that the policy does not govern. A snapshot for it that fails
  verification reports the snapshot's own code
  (`REVOCATION_SNAPSHOT_SIGNATURE_INVALID`,
  `REVOCATION_SNAPSHOT_INVALID` or `UNKNOWN_FIELD`), whatever the mode.
- A `verify_tct` snapshot is checked against the TCT's issuer, not the
  snapshot's own `issuer` field.
- A `revocation_snapshots[]` entry with no `issuer_aid`, a malformed
  one, or no `snapshot` is `INVALID_REQUEST`. 0.18 skipped it.

`verify_revocation_snapshot` still reports the snapshot's own code.

**Fixtures with no revocation input.** Spec `59407d2` (#98, #99)
documents the conformance convention: a fixture that supplies no
revocation input for an issuer is not testing revocation for that
issuer, and that issuer reads "not revoked". This covers the verifier's
own list as well as each hop issuer, and it is why `del-001` and
`del-mh-001` expect success with no snapshot. The adapter already
behaves this way: only a supplied entry can deny a `jti` or mark an
issuer absent.

**Deployments.** The convention is for fixtures only. In a deployment, a
hop issuer's snapshot that cannot be obtained follows the mode, so
`fail_closed` refuses. The library already does this:
`aitp_transport_http::RevocationCache::check` looks up each
`(jti, issuer)` pair and applies the mode when it has no usable snapshot
for that issuer: under `FailClosed` it returns an error. To get the
spec's behaviour in multi-hop verification, wrap it as the per-hop check
and treat an error as revoked:

```rust
let hop_check = |issuer: &Aid, jti: &Uuid| cache.is_revoked(jti, issuer, now).unwrap_or(true);
let ctx = VerifyDelegationContext::new(&verifier_aid, now)
    .with_hop_revocation_check(&hop_check);
``` The adapter is not published, so section 3
does not change any library API or behaviour.

## 4. Spec pin, conformance and cross-implementation checks

`tests/schemas/SPEC_VERSION` moves from `299f89a` to `59407d2` in two
steps. The first step, to `53b92c0` (spec #97, in
[#280](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/280)),
adds four fixtures:

- `tct-022-invalid-snapshot-fail-closed` and
  `tct-023-invalid-snapshot-fail-open` (core);
- `del-008-own-snapshot-signature-invalid` (core);
- `del-mh-006-invalid-hop-snapshot-fail-closed` (draft, needs
  `experimental-multihop-delegation`).

The second step, to `59407d2` (spec #98 and #99, in this release's
notes PR), changes only docs and fixture descriptions: the per-issuer
convention in section 3 and the RFC-AITP-0011 §6 wording. No schema,
vector or fixture expectation changes. The vendored schemas and
known-answer vectors are unchanged at both steps.

At pin `59407d2` (108 fixtures), the rs adapter passes 83, fails 0 and
skips 25 in the strict run. With all four features it passes 106, fails
0 and skips 2. All four new fixtures pass. See
[`conformance.md`](conformance.md).

`tests/AITP_VERIFIER_PY_VERSION` moves from aitp-verifier-py `e335348`
to `138b79d`. Its #68 and #69 apply the same discarded-snapshot rule,
and #70 the per-issuer fixture convention, so it agrees with section 3.
The CI `xcheck` job runs against that pin.
