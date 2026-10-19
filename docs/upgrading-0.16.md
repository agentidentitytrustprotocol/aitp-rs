# Upgrading from 0.15 to 0.16

0.16.0 closes the four known gaps that 0.15.0 listed
([`upgrading-0.15.md` section 11](upgrading-0.15.md#11-known-deviations-and-follow-ups)).
Single-hop delegation now verifies under the key the issuer's Manifest
designates. The Python and Node bindings and the conformance adapter
require the coordinator's Manifest to verify a session bundle. Python's
`DelegationVerified` gains `cnf_jkt`. The spec pin moves from `cfd2f16`
to `ab214d2`.

It is a breaking release for every caller that verifies delegations, and
for binding callers that verify session bundles. Each section below names
the change and shows the code before and after for Rust, Python and Node.
Section 3 says where to get the Manifests these calls now need. The
per-crate `crates/*/CHANGELOG.md` files are the authoritative record of
what shipped. The root [`CHANGELOG.md`](../CHANGELOG.md) has a summary.

## 1. Single-hop delegation verifies under the issuer's Manifest key

RFC-AITP-0006 §4 step 1 verifies a delegation token under the issuer key
"resolved from that issuer's Manifest". 0.15 did that for multi-hop
chains only (RFC-AITP-0011 §3 step 1). A single-hop token was still
verified under the key encoded in the issuer's AID, and no Manifest was
read. 0.16 sends both paths through the same check
([#237](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/237),
[#246](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/246)).

Every `verify_delegation` call now needs the delegator's Manifest. The
delegator is the token's `iss`: the agent that holds your TCT and
delegated part of it. These cases fail with
`DelegationError::KeyResolutionFailed` (`KEY_RESOLUTION_FAILED`,
RFC-AITP-0007 §1):

- no Manifest source configured (`source: ManifestError::NotFound`)
- no Manifest for the issuer (`source: ManifestError::NotFound`)
- a Manifest that fails `verify_manifest` (RFC-AITP-0003 §5) at the
  context's `now`, for example `source: ManifestError::Expired`
- a Manifest that does not designate the issuer
  (`source: ManifestError::AidMismatch`)

A token signed by a key other than the one the Manifest designates is
still `DelegationError::InvalidSignature`.

**Rust.**

```rust
// 0.15: single-hop needed no Manifest
let ctx = VerifyDelegationContext::new(&my_aid, now)
    .with_revocation_check(&is_revoked);
let verified = verify_delegation(token, &ctx)?;

// 0.16
let issuer_manifests: Vec<Manifest> = vec![delegator_manifest];   // see section 3
let ctx = VerifyDelegationContext::new(&my_aid, now)
    .with_revocation_check(&is_revoked)
    .with_issuer_manifests(&issuer_manifests);   // Vec<Manifest>, [Manifest], HashMap<Aid, Manifest>,
                                                 // or your own ManifestResolver
let verified = verify_delegation(token, &ctx)?;
```

`with_issuer_manifests` is the same builder that multi-hop used in 0.15,
so a multi-hop context that already has it needs no change. One resolver
can serve both paths. When several Manifests designate one AID, the
newest `published_at` wins (RFC-AITP-0007 §1).

**Python.** `issuer_manifests` is a new required third argument: a list
of `{"manifest": {…}}` envelope JSON strings. `revoked_jtis` moves to the
fourth position.

```python
# 0.15
verified = aitp.verify_delegation(token, my_aid, revoked)
verified = aitp.verify_delegation(token, my_aid, revoked_jtis=revoked)

# 0.16
verified = aitp.verify_delegation(token, my_aid, [delegator_manifest], revoked)
verified = aitp.verify_delegation(token, my_aid, [delegator_manifest], revoked_jtis=revoked)
```

The old positional call `verify_delegation(token, aid, revoked)` now
raises `TypeError`, because a set is not a list of strings. A Manifest
that is not valid envelope JSON raises `ValueError`. A verification
failure, including `KEY_RESOLUTION_FAILED`, raises `RuntimeError`.

**Node.**

```js
// 0.15
const verified = verifyDelegation(token, myAid, revokedJtis)

// 0.16
const verified = verifyDelegation(token, myAid, [delegatorManifestJson], revokedJtis)
```

An old three-argument call passes the revocation list where the
Manifests belong, and it throws because those strings are not Manifest
JSON.

`verify_delegation_multihop` / `verifyDelegationMultihop` already took
`issuer_manifests` in 0.15 and are unchanged.

## 2. Bindings: the coordinator Manifest is required for session bundles

RFC-AITP-0010 §5 step 5 takes the coordinator key from the coordinator's
verified Manifest. In 0.15 the Manifest was a trailing optional argument
in Python and Node. Without it the bindings fell back to
`CoordinatorKeySource::UnverifiedAidDangerous`. 0.16 makes it a required
third argument, and the bindings always use
`CoordinatorKeySource::Manifest`. There is no AID-only fallback
([#238](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/238),
[#247](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/247)).

**Python.**

```python
# 0.15
outcome = aitp.verify_session_bundle(bundle_json, my_aid)
outcome = aitp.verify_session_bundle(bundle_json, my_aid, now, check)
outcome = aitp.verify_session_bundle(bundle_json, my_aid, coordinator_manifest_json=manifest_json)

# 0.16: verify_session_bundle(bundle_json, verifier_aid, coordinator_manifest_json,
#                             now_unix_secs=None, revocation_check=None)
outcome = aitp.verify_session_bundle(bundle_json, my_aid, coordinator_manifest)
outcome = aitp.verify_session_bundle(bundle_json, my_aid, coordinator_manifest, now, check)
outcome = aitp.verify_session_bundle(bundle_json, my_aid, coordinator_manifest_json=manifest_json)  # unchanged
```

- A call with no Manifest raises `TypeError`. So does a call that passes
  `now_unix_secs` third, because an int is not a str.
- A Manifest for an AID other than the bundle's `coordinator` raises
  `RuntimeError` (`coordinator manifest aid does not match bundle
  coordinator`). A Manifest that fails verification also raises
  `RuntimeError`. One that is not valid envelope JSON raises
  `ValueError`.

**Node.**

```js
// 0.15
verifySessionBundle(bundleJson, myAid)
verifySessionBundle(bundleJson, myAid, nowUnixSecs, revocationCheck)
verifySessionBundle(bundleJson, myAid, undefined, undefined, coordinatorManifestJson)

// 0.16: verifySessionBundle(bundleJson, verifierAid, coordinatorManifestJson,
//                           nowUnixSecs?, revocationCheck?)
verifySessionBundle(bundleJson, myAid, coordinatorManifestJson)
verifySessionBundle(bundleJson, myAid, coordinatorManifestJson, nowUnixSecs, revocationCheck)
```

A missing or `null` Manifest, or a number in third position (an old
positional `nowUnixSecs`), throws. Move `nowUnixSecs` and
`revocationCheck` back one position.

**Rust.** The library API is unchanged.
`VerifySessionBundleContext::coordinator_key` was already required in
0.15, and `CoordinatorKeySource::UnverifiedAidDangerous` stays for
offline callers that pin the coordinator out of band. It is not §5 step 5
conformant, and neither the adapter nor the bindings use it any more. If
you chose it only because you had no Manifest at hand, switch now:

```rust
// 0.15 and 0.16: AID-only, not RFC-AITP-0010 §5 step 5 conformant
coordinator_key: CoordinatorKeySource::UnverifiedAidDangerous,

// 0.16 recommended
let coordinator_manifest = fetcher.fetch(&coordinator_origin).await?;   // see section 3
let ctx = VerifySessionBundleContext {
    verifier_aid: &me,
    now,
    revocation_check: None,
    coordinator_key: CoordinatorKeySource::Manifest(&coordinator_manifest),
};
let outcome = verify_session_bundle(&bundle, &ctx)?;
```

The switch turns on the Manifest expiry cap. Read section 4 before you
make it.

**Conformance adapter** (`aitp-rs-adapter`, not published). The
`verify_session_bundle` op requires `params.coordinator_manifest`, as a
bare Manifest body or a `{"manifest": …}` envelope. A missing Manifest,
or `SessionBundleError::CoordinatorManifestMismatch` (a Manifest for
another AID), is reported as `KEY_RESOLUTION_FAILED` (RFC-AITP-0007 §1).
In 0.15 that was `SESSION_BUNDLE_INVALID`. A Manifest that fails
verification still reports its own code, such as `MANIFEST_EXPIRED`.
Fixture `bundle-007` now runs and passes. The Rust library's
`SessionBundleError` is unchanged; this mapping is the adapter's own.

## 3. Where to get the Manifests

Both changes need a peer's signed Manifest. Pass it as the
`{"manifest": {…}}` envelope JSON in the bindings, or as an
`aitp_manifest::Manifest` in Rust. The verifier re-verifies it, so it can
come from any channel, but it must be current:

- **Fetch it.** `aitp_transport_http::ManifestFetcher::fetch(&origin)`
  GETs `/.well-known/aitp-manifest` and returns a verified `Manifest`.
  From Python or Node, GET the same URL and pass the response body.
- **Keep the one from the handshake.** The `mutual_hello` and
  `mutual_hello_ack` payloads carry the sender's Manifest
  (RFC-AITP-0009), and the initiator fetched the responder's Manifest
  before it started. The original grantor that verifies a delegation has
  already handshaken with the delegator, because the delegator holds the
  grantor's TCT. A participant that verifies a session bundle has already
  handshaken with the coordinator.
- **In-process, tests and demos.** Use the peer's own
  `build_manifest()` / `buildManifest()` output, or
  `ManifestBuilder::build()` in Rust.

In Rust, a `HashMap<Aid, Manifest>` cache, or your own `ManifestResolver`,
can serve every verification. The verifier is synchronous and does no
I/O, so you must refresh the cache yourself.

## 4. Gotcha: the Manifest expiry now caps participant TCTs

With a coordinator Manifest, every participant TCT's `exp` must be no
later than the Manifest's `expires_at` (RFC-AITP-0005 §10.4). The
AID-only path cannot apply that cap. In 0.15 the bindings took that path
whenever you left the Manifest out, and Rust took it under
`UnverifiedAidDangerous`, so those callers never hit the check. Now the
bindings always apply it. A bundle that verified under 0.15 can fail
under 0.16 with:

- Python: `RuntimeError: bundle verification failed: participant TCT
  verification failed: …` (the TCT error `TCT expires_at exceeds issuer
  Manifest expires_at`)
- Node: the same message, thrown
- Rust: `SessionBundleError::TctVerification(TctError::ExpiresAfterManifest)`
- adapter: `BUNDLE_PARTICIPANT_TCT_INVALID`

A TCT issued in a handshake is already capped at issuance by the
issuer's Manifest in force at the time (RFC-AITP-0004 §4.3). The check
bites in two cases:

- **The Manifest you pass is not the one the TCTs were issued under.** A
  Manifest with an earlier `expires_at` fails, for example a stale cached
  copy, or one built separately for verification with a shorter TTL. Pass
  the coordinator's *current* Manifest.
- **TCTs issued outside the handshake.** `issue_tct_for_delegatee` /
  `issueTctForDelegatee` and direct `TctBuilder` use take a TTL that the
  Manifest does not bound. The binding defaults are one hour for both the
  Manifest and the TCT (`ttl_secs` / `ttlSecs` 3600), so a TCT issued
  after the Manifest outlives it. Give the coordinator's Manifest a TTL
  that outlives the TCTs it issues. The docs samples and tests now use
  24 hours: `build_manifest(…, ttl_secs=24 * 3600)` /
  `buildManifest({ …, ttlSecs: 86400 })`.

Delegation (section 1) has no equivalent cap. There the Manifest only
has to be valid at the context's `now`.

## 5. Python: `DelegationVerified.cnf_jkt`

([#240](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/240),
[#244](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/244))

Python's `DelegationVerified` names the delegatee's `cnf.jkt` (the
RFC 7638 thumbprint) `cnf_jkt`, matching Node's `cnfJkt` and the
`compute_aid_jkt` helper. `cnf` stays as a deprecated alias. It returns
the same value and emits a `DeprecationWarning` that points at your line.
It may be removed in a later breaking release. This change is not
breaking.

```python
# 0.15
jkt = verified.cnf
# 0.16
jkt = verified.cnf_jkt
```

```js
// Node: unchanged
const jkt = verified.cnfJkt
```

```rust
// Rust: unchanged
let jkt = &verified.claims.cnf.jkt;
```

## 6. Spec pin and the v0.2 envelope erratum

The pin in `tests/schemas/SPEC_VERSION` moves from `cfd2f16` to
`55bafe0`
([#246](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/246))
and then to `ab214d2`
([#248](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/248)).

- At `55bafe0` the delegation fixtures carry `input.issuer_manifests`
  ([#239](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/239)),
  and fixture `del-mh-005` is new.
- `ab214d2` is a text-only erratum to RFC-AITP-0001 §5.4 (0.2.13-draft)
  and RFC-AITP-0012 §6 (0.2.2-reserved). The `aitp/0.2` envelope signing
  input covers `message_id`, `timestamp`, `sender.agent_id` and
  `payload` only. An on-path party can change `version`, `message_type`
  or `extensions` without breaking the signature. Receivers MUST NOT
  treat those members as sender-authenticated, and MUST NOT base a trust
  decision on envelope `extensions`. No wire bytes or fixture outcomes
  change.

`aitp-rs` already complies, and no code changed.
`aitp_core::envelope::envelope_signing_input` builds
`message_id|timestamp|sender.agent_id|hex(sha256(JCS(payload)))`. The
library and the transport read `message_type` only to dispatch a message
or reject one of the wrong type, and nothing reads envelope `extensions`.
If your own code branches on envelope `extensions`, or authorizes based
on `message_type`, move whatever you rely on into `payload`.

## 7. Conformance adapter authors

- At the new pin, a delegation fixture's `issuer_manifests` are the
  verifier's only Manifest source. The rs adapter no longer synthesizes
  stand-in Manifests for the `kat-keypair-*` issuers
  ([#239](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/239)).
  A missing Manifest is `KEY_RESOLUTION_FAILED`.
- `verify_session_bundle` needs `coordinator_manifest` (section 2).
- `SubprocessAdapter` now turns a per-request `OP_NOT_SUPPORTED` into a
  SKIP, as `InProcessAdapter` already did. In 0.15 it was a FAIL. The
  v0.2 gate still fails the run if a required fixture is skipped.

At pin `ab214d2` the rs adapter passes 75, fails 0 and skips 23 in the
strict run. With all four features it passes 96 and skips 2 (`del-004`
and `del-007`, which the multi-hop feature negates). See
[`conformance.md`](conformance.md).

## 8. Known follow-ups

- **Error ordering.** Single-hop tokens now go through the same
  Manifest lookup as multi-hop hops. It runs after `typ` and member-set
  validation but before the `alg` pin. A token with a wrong `alg` from an
  issuer that has no Manifest reports `KEY_RESOLUTION_FAILED`, not a
  signature error. Both fail closed.
- **Fuzz target.** `fuzz/fuzz_targets/delegation_verify.rs` configures
  no resolver. Single-hop inputs now also stop at key resolution, after
  the structural checks the target exercises.
