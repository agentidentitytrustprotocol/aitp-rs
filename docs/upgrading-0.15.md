# Upgrading from 0.14 to 0.15

0.15.0 brings `aitp-rs` up to spec pin `cfd2f16` and closes the
conformance gaps found after 0.14: duplicate-key and unknown-field
checks enforced by the type system, ListRevoked served by default,
RFC-AITP-0009 §3.1 handshake defaults, the RFC-AITP-0010 §5 session-bundle
check order, Manifest-resolved multi-hop keys, hardened TCT renewal, and
a conformance runner that gates on v0.2. The Node and Python bindings
also line up with each other.

It is a breaking release. Every section below names the change, shows
the code before and after, and adds an operator note where a default
changed. The per-crate `crates/*/CHANGELOG.md` files are the
authoritative record of what shipped. The root
[`CHANGELOG.md`](../CHANGELOG.md) has a summary.

## 1. Wire parsers take `CheckedJson`

RFC-AITP-0001 §5.4.5 rejects duplicate JSON keys. A `serde_json::Value`
has already dropped a repeated key, so a parser that takes `&Value`
cannot check it. 0.15 adds `aitp_core::CheckedJson`, a JSON document
already checked for duplicate keys at any depth, and the wire parsers
take it instead of `&serde_json::Value`
([#146](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/146),
[#227](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/227)):

- `aitp_core::parse_envelope_wire`
- `aitp_manifest::parse_manifest_wire`
- `aitp_tct::parse_revocation_snapshot_wire`
- `aitp_session_bundle::parse_session_bundle_wire` and the new
  `parse_session_bundle_envelope` (see section 7)
- `aitp_handshake::admission::PinnedAdmission::admit_wire` and
  `admit_wire_at`

```rust
// 0.14
let value: serde_json::Value = serde_json::from_slice(body)?;
let manifest = aitp_manifest::parse_manifest_wire(&value)?;
let admitted = admission.admit_wire(&value, &source).await?;

// 0.15
use aitp_core::CheckedJson;
let doc = CheckedJson::from_slice(body)?;            // or text.parse::<CheckedJson>()?
let manifest = aitp_manifest::parse_manifest_wire(&doc)?;
let admitted = admission.admit_wire(&doc, &source).await?;
```

- Build a `CheckedJson` from the raw bytes or text, never from a
  `Value`. There is deliberately no `From<Value>`.
- `CheckedJsonError` is the error (its `Display` is the reason).
- `as_value()`, `into_value()`, `Deref<Target = Value>` and
  `AsRef<Value>` give you the parsed document. `member(key)` returns a
  sub-document that is still a `CheckedJson`.

## 2. Bindings: new `unknown_field` error code, stricter peer JSON

The Node and Python bindings now send every piece of peer JSON through
`CheckedJson` and the matching `parse_*_wire`
([#152](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/152),
[#227](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/227)).
A member outside the schema (RFC-AITP-0001 §7) now has its own code:

| Entry point | 0.14 | 0.15 |
|---|---|---|
| Node `verifyManifestJson` | `error.code == "malformed"` | `error.code == "unknown_field"` |
| Node `verifyRevocationList` | `malformed` | `unknown_field` |
| Python `verify_manifest_json` | `ValueError` | `ManifestVerificationError` with `code == "unknown_field"` |
| Python `verify_revocation_list` | `RevocationVerificationError(code="malformed")` | `RevocationVerificationError(code="unknown_field")` |

A duplicate key is still `malformed` (Node, Python revocation) or
`ValueError` (Python Manifest).

```python
# 0.15
try:
    aitp.verify_manifest_json(envelope_json)
except aitp.ManifestVerificationError as e:
    if e.code == "unknown_field":
        ...  # a member outside the schema
```

```js
// 0.15
try {
  verifyManifestJson(envelopeJson)
} catch (e) {
  if (e.code === 'unknown_field') { /* a member outside the schema */ }
}
```

The revocation verifier and the revocation signing-bytes entry points
now apply the wire parser's checks too, such as UUID v4 `entries[].jti`.
The four handshake-envelope entry points now check payload member sets.
Input that 0.14 accepted may now be rejected.

## 3. Pinned admission: 429 for rate limits, 503 for `CHALLENGE_REFUSED`

At spec pin `cfd2f16`, RFC-AITP-0002 §3.4 requires HTTP 429 for a
rate-limited challenge request or presentation, and a client must be
able to tell that apart from `CHALLENGE_REFUSED`
([#226](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/226),
[#229](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/229)).

- `PinnedAdmission::challenge` / `challenge_at` over the per-source limit
  now return `AdmissionError::RateLimited { retry_after }`, the same
  variant as a rate-limited presentation.
- `RefusalCause::RateLimited` is removed. `ChallengeRefused` now means
  only that the outstanding-nonce bound was reached
  (`RefusalCause::AtCapacity`).
- `AdmissionError::http_status()` returns `Some(503)` for
  `ChallengeRefused` (it returned `None`) and `Some(429)` for
  `RateLimited`.
- New `AdmissionError::retry_after()`: the `Retry-After` value. For a
  refusal whose store gave no hint it falls back to `MAX_NONCE_TTL`.
- New `AdmissionError::http_body()`: `{"error":"CHALLENGE_REFUSED"}` for
  a refusal, `None` (empty body) for a 429.
- `RateLimited`'s `Display` text is now "rate limit exceeded" (was
  "presentation rate limit exceeded").

```rust
// 0.14
match admission.challenge(&source).await {
    Err(AdmissionError::ChallengeRefused { cause: RefusalCause::RateLimited, .. }) => /* 429 */,
    Err(AdmissionError::ChallengeRefused { .. }) => /* refused */,
    // ...
}

// 0.15: let the error pick the status, header and body
match admission.challenge(&source).await {
    Ok(challenge) => respond_ok(challenge),
    Err(e) => match e.http_status() {
        Some(status) => respond(
            status,                          // 429 or 503
            e.retry_after(),                 // Retry-After
            e.http_body().unwrap_or(""),     // "" for 429
        ),
        None => respond_error_envelope(e.code()),
    },
}
```

**Operator note.** If your embedding server answered a refusal with 429,
switch it to 503 with `Retry-After` and the `http_body()` body. The
metric labels (`rate_limited`, `at_capacity`) are unchanged.
`aitp-transport-http` has no pinned-admission route; these helpers are
for the server that embeds `PinnedAdmission`.

## 4. ListRevoked is served by default

RFC-AITP-0005 §11 and RFC-AITP-0008 §1.4 (spec `876e124`) require every
TCT issuer to serve `ListRevoked` and to advertise its URL in the signed
Manifest under `rfc-aitp-0008.revocation_list_uri`
([#225](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/225),
[#230](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/230)).

- `HandshakeServer::router()` now always mounts
  `GET /.well-known/aitp-revocation-list`, exported as
  `aitp_transport_http::REVOCATION_LIST_PATH`. In 0.14 the route appeared
  only after `with_revocation_producer`.
- With no `RevocationListProducer` attached, the route serves an empty
  snapshot signed by the server's key (RFC-AITP-0008 §1.5), valid for an
  hour and re-signed every 60 s. If the signer fails the route answers
  503 with an empty body; it never serves an unsigned list.
- New `ManifestBuilder::revocation_list_uri(url)` sets the advertisement
  before signing. `REVOCATION_LIST_URI_EXT` now lives in `aitp_manifest`;
  `aitp_transport_http::REVOCATION_LIST_URI_EXT` re-exports it.
- New `RevocationCache::for_issuer_manifest(manifest, policy, make_provider)`
  polls the advertised URL. With no key, or a non-HTTPS value, it builds
  `RevocationCache::offline`, so `RevocationFailMode` decides.

```rust
// 0.14
let manifest = ManifestBuilder::new(&key) /* … */ .build()?;
let server = HandshakeServer::new(/* … */)
    .with_revocation_producer(producer);         // route only with a producer

// 0.15
use aitp_transport_http::REVOCATION_LIST_PATH;
let manifest = ManifestBuilder::new(&key)
    /* … */
    .revocation_list_uri(origin.join(REVOCATION_LIST_PATH)?)   // absolute https URL
    .build()?;
let server = HandshakeServer::new(/* … */);      // route always mounted
// .with_revocation_producer(producer)           // required once you can revoke
```

**Operator notes.**

- If you mounted your own handler at `/.well-known/aitp-revocation-list`
  next to `router()`, remove it and attach a `RevocationListProducer`,
  or axum panics on the overlapping route.
- The default empty list says "nothing is revoked". If your deployment
  can revoke TCTs, attach a producer backed by your deny list.
- Advertise the URL. A server whose Manifest lacks it logs a `warn!` at
  `router()`. Peers still accept the Manifest but treat your revocation
  status as unavailable, which under the default FailClosed means they
  reject your TCTs once they check revocation.

## 5. `HandshakeServer` and `ManifestFetcher` defaults

RFC-AITP-0009 §3.1 and RFC-AITP-0003 §4.1 defaults
([#198](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/198),
[#231](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/231)).
Rate limiting was already on by default in 0.14 and is unchanged.

**The session sweeper starts automatically.** `router()` starts a
background sweeper every `DEFAULT_SESSION_SWEEP_INTERVAL` (30 s). Outside
a Tokio runtime it starts on the first HELLO instead. It starts at most
once per server and exits when the server is dropped.

```rust
// 0.14: sweep on request only, unless you spawned it yourself
let app = server.router();

// 0.15: on by default; opt out or tune it
let app = server.without_session_sweeper().router();              // 0.14 behaviour
let app = server.with_session_sweep_interval(Duration::from_secs(10)).router();
// Duration::ZERO also disables it. Calling spawn_session_sweeper by hand
// before router() replaces the automatic one.
```

**`DEFAULT_MAX_SESSIONS` is 1 000** (was 10 000), the §3.1 recommended
maximum of concurrent in-flight handshakes. A responder past the cap
evicts the oldest half-finished handshakes sooner. Raise it with
`.with_max_sessions(n)`.

**`allow_insecure_localhost` defaults to `false`.** `ManifestFetcher::new()`
now rejects `http://localhost` and `http://127.0.0.1` with
`FetchError::InsecureUrl`. The facade's `InitiatorConfig` gains
`allow_insecure_localhost` (default `false`) and
`.with_insecure_localhost(bool)`.

```rust
// 0.14: http://localhost accepted by default
let fetcher = ManifestFetcher::new();
let ctx = run_initiator_handshake(InitiatorConfig::new(/* … */)).await?;

// 0.15: local development opts in explicitly
let fetcher = ManifestFetcher::new().with_insecure_localhost(true);
let ctx = run_initiator_handshake(
    InitiatorConfig::new(/* … */).with_insecure_localhost(true),
).await?;
```

**Operator note.** Production needs no change if every peer is HTTPS.
Local demos, CI and tests that talk to a plain-HTTP localhost peer must
opt in. `HostGuard::default()` is still `GuardMode::WarnPrivate`.

## 6. Bindings API parity

The Node and Python bindings now agree with each other and with their
stubs
([#199](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/199),
[#232](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/232)).

**Node: issued TCTs come with their grant voucher.**
`AitpAgent.processRenewalRequest` and `AitpAgent.issueTctForDelegatee`
return a `JsIssuedTct`, `{ tct, grantVoucher }`, instead of a bare
compact JWS. 0.14 dropped the voucher, so a renewed or delegated holder
on Node could not delegate (RFC-AITP-0005 §8).

```js
// 0.14
const tct = agent.issueTctForDelegatee(verified)
// 0.15
const { tct, grantVoucher } = agent.issueTctForDelegatee(verified)
// same for agent.processRenewalRequest(...); deliver grantVoucher with the TCT
```

**Python: keyword names match the stub.**

```python
# 0.14
agent.build_renewal_request(current_tct_envelope_json=token)
session.process_hello_ack(hello_ack_json, _session_id=sid)
# 0.15
agent.build_renewal_request(current_tct_token=token)
session.process_hello_ack(hello_ack_json, session_id=sid)
```

Positional calls are unaffected, and Python return shapes are unchanged
(`{"tct", "grant_voucher"}` JSON, as before). In `aitp.pyi`,
`revoked_jtis` on the delegation verifiers is typed `RevokedJtis`
(`set[str] | frozenset[str]`), the two types the binding accepts. A new
test, `bindings/aitp-py/tests/test_stub_signatures.py`, compares every
stub signature with the compiled extension.

Other binding changes are listed with their feature: the coordinator
Manifest argument (section 7), `issuer_manifests` (section 8) and
renewal (section 9).

## 7. Session bundle: §5 check order and coordinator Manifest

([#197](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/197),
[#195](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/195),
[#233](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/233))

**New required field `coordinator_key`.** `VerifySessionBundleContext`
gains `coordinator_key: CoordinatorKeySource`, which chooses how
RFC-AITP-0010 §5 step 5 runs:

- `CoordinatorKeySource::Manifest(&m)`: the verifier re-runs
  `aitp_manifest::verify_manifest` on the coordinator's Manifest
  (RFC-AITP-0003 §5), requires `m.aid == bundle.coordinator`, and
  resolves the key from `m.aid`.
- `CoordinatorKeySource::UnverifiedAidDangerous`: the key comes from the
  coordinator AID alone, as in 0.14. Not §5 step 5 conformant.

```rust
// 0.14
let ctx = VerifySessionBundleContext { verifier_aid: &me, now, revocation_check: None };

// 0.15
let coordinator_manifest = fetcher.fetch(&coordinator_origin).await?;   // ManifestFetcher
let ctx = VerifySessionBundleContext {
    verifier_aid: &me,
    now,
    revocation_check: None,
    coordinator_key: CoordinatorKeySource::Manifest(&coordinator_manifest),
    // or CoordinatorKeySource::UnverifiedAidDangerous to keep 0.14 behaviour
};
let outcome = verify_session_bundle(&bundle, &ctx)?;
```

New `SessionBundleError` variants: `CoordinatorManifest(ManifestError)`
(reported as the Manifest's own code, such as `MANIFEST_EXPIRED`) and
`CoordinatorManifestMismatch` (`SESSION_BUNDLE_INVALID`). The enum is not
`#[non_exhaustive]`, so exhaustive matches need both arms.

**New check order and error precedence.** `verify_session_bundle` runs:
1 version, 2 expiry, 3 expiry-window invariant, 4 participants non-empty,
5 coordinator Manifest, 6 bundle signature, 7 per-participant TCTs (with
per-pair revocation), 8 self-membership.

- An input that fails both the window check and the non-empty check now
  reports `ExpiryWindowInvariant` first. Step 3 has nothing to check on
  an empty roster, so an empty bundle still reports `EmptyParticipants`.
- `NotMember` is reported last, after the signature and every
  participant TCT verify. A forged bundle that omits the verifier now
  gives `BUNDLE_INVALID_SIGNATURE`, not `BUNDLE_NOT_MEMBER`.

**TCT expiry cap.** With `CoordinatorKeySource::Manifest`, the Manifest's
`expires_at` caps every participant TCT (RFC-AITP-0005 §10.4). A TCT with
a later `exp` fails with `TctVerification(TctError::ExpiresAfterManifest)`.

**HTTP: envelope only.** `SessionBundleServer`'s `POST /aitp/session/bundle`
goes through the new `parse_session_bundle_envelope`. It rejects a bare
body with 400 `SESSION_BUNDLE_INVALID` and stores nothing
(RFC-AITP-0010 §4.3.1). Clients must send `{"session_bundle": {…}}`.
`parse_session_bundle_wire` still accepts a bare body for in-process
callers.

**Advertise `bundle_uri`.** Coordinators should advertise the endpoint
in their Manifest:

```rust
use aitp_session_bundle::{advertise_bundle_uri, bundle_uri_from_manifest};
use aitp_transport_http::SessionBundleServer;

let builder = ManifestBuilder::new(&key) /* … */;
let manifest = advertise_bundle_uri(builder, &SessionBundleServer::bundle_uri(&origin)?).build()?;

// consumer: None means do not probe /aitp/session/bundle (§4.3.1)
let url = bundle_uri_from_manifest(&coordinator_manifest);
```

`bundle_uri_from_manifest` accepts HTTPS, or `http://localhost` /
`http://127.0.0.1`. `SESSION_BUNDLE_PATH` is the route's path.

**Bindings.** `verify_session_bundle` gains a trailing optional
coordinator Manifest. Existing calls keep working and use the AID-only
path:

```python
# Python 0.15
aitp.verify_session_bundle(bundle_json, my_aid, coordinator_manifest_json=manifest_json)
```

```js
// Node 0.15
verifySessionBundle(bundleJson, myAid, undefined, undefined, coordinatorManifestJson)
```

The conformance adapter's `verify_session_bundle` op takes an optional
`coordinator_manifest` the same way.

## 8. Multi-hop delegation resolves hop keys from Manifests

RFC-AITP-0011 §3 step 1 verifies each hop under the key "resolved from
that issuer's Manifest". 0.14 used the key encoded in the AID and never
read a Manifest
([#202](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/202),
[#234](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/234)).

A `VerifyDelegationContext` with `max_delegation_hops > 0` that verifies a
chain-bearing token now fails unless it has the hop issuers' Manifests:

```rust
// 0.14
let ctx = VerifyDelegationContext::new(&my_aid, now)
    .with_max_delegation_hops(DEFAULT_MAX_DELEGATION_HOPS);

// 0.15
let issuer_manifests: Vec<Manifest> = /* fetched, e.g. with ManifestFetcher */;
let ctx = VerifyDelegationContext::new(&my_aid, now)
    .with_max_delegation_hops(DEFAULT_MAX_DELEGATION_HOPS)
    .with_issuer_manifests(&issuer_manifests);   // Vec<Manifest>, [Manifest], HashMap<Aid, Manifest>,
                                                 // or your own ManifestResolver
let verified = verify_delegation(token, &ctx)?;
```

- New in `aitp-manifest`: the `ManifestResolver` trait
  (`fn resolve_manifest(&self, aid: &Aid) -> Option<Manifest>`) and
  `resolve_verified_manifest(resolver, aid, ctx)`. When several Manifests
  match, the newest `published_at` wins (RFC-AITP-0007 §1). The resolved
  Manifest must pass `verify_manifest` and designate the hop's AID.
- New `DelegationError::KeyResolutionFailed { issuer, source: ManifestError }`,
  wire code `KEY_RESOLUTION_FAILED`. It covers no resolver configured,
  no Manifest for the issuer (`source: ManifestError::NotFound`), a
  Manifest that fails verification, and one that does not designate the
  hop's `iss` (`source: ManifestError::AidMismatch`). A Manifest whose key
  does not match the signature is still `InvalidSignature`.
- New `ManifestError::NotFound`, wire code `MANIFEST_NOT_FOUND`.
- `aitp-delegation` now depends on `aitp-manifest`.
- Single-hop verification is unchanged (see section 11).

**Bindings.** The multi-hop verifiers gain a required third positional
argument, a list of the hop issuers' `{"manifest": {…}}` envelope JSON
strings, for example each issuer's `build_manifest()` / `buildManifest()`
output:

```python
# 0.14
aitp.verify_delegation_multihop(token, verifier_aid, 3)
# 0.15
aitp.verify_delegation_multihop(token, verifier_aid, issuer_manifests, 3)
```

```js
// 0.14
verifyDelegationMultihop(token, verifierAid, 3)
// 0.15
verifyDelegationMultihop(token, verifierAid, issuerManifests, 3)
```

An old positional call such as `(token, verifier_aid, 3)` now fails with
a type error rather than verifying under the wrong key.

## 9. TCT renewal is replay-guarded and re-evaluated

TCT renewal now meets RFC-AITP-0004 §8.1
([#196](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/196),
[#235](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/235)).
Renewal stays behind the `experimental-renewal` feature.

**`process_renewal_request` is async and takes a `RenewalContext`.**

```rust
// 0.14
let issued = process_renewal_request(&request, &issuer_key, manifest_expires_at, now, ttl_secs)?;

// 0.15
use aitp_core::nonce_store::InMemoryNonceStore;
use aitp_tct::{process_renewal_request, RenewalContext};

let nonce_store = InMemoryNonceStore::new(10_000);       // share one store across replicas
let is_revoked = |jti: &uuid::Uuid| deny_list.contains(jti);
let ctx = RenewalContext::new(
    manifest.expires_at,
    &manifest.offered_capabilities,                       // current offered grants
    &is_revoked,
    &nonce_store,
    now,
)
.ttl_secs(ttl_secs);                                      // optional; also .grant_policy(..), .without_voucher()
let issued = process_renewal_request(&request, &issuer_key, &ctx).await?;
```

- **16-byte `pop_nonce`.** A `pop_nonce` that does not decode to exactly
  16 bytes is `TctError::RenewalNonceMalformed`. Each accepted nonce is
  recorded until the presented TCT's `exp`, only after PoP and TCT
  verification pass. A repeat is `TctError::RenewalReplayed`
  (`REPLAY_DETECTED`). A store failure is `TctError::RenewalNonceStore`.
- **No more waivers.** The presented TCT is checked against the
  revocation callback (`TCT_REVOKED`) and the issuer's current Manifest
  expiry (`TCT_EXPIRES_AFTER_MANIFEST`).
- **Grants are re-evaluated.** The old grants are intersected with the
  Manifest's current offered capabilities, then passed through the
  optional grant policy. None left is `TctError::RenewalGrantsWithdrawn`
  (`POLICY_VIOLATION`).
- `NonceStore` moved to `aitp_core::nonce_store`. The
  `aitp_handshake::admission` path still re-exports it.

**The fixed `/aitp/handshake/renew` route is gone.** `HandshakeServer`
mounts the renewal route only at the path of its Manifest's
`rfc-aitp-0005.renew_uri` (`aitp_transport_http::RENEW_URI_EXT`). With
no advertisement, there is no route.

```rust
// 0.14: POST /aitp/handshake/renew was always mounted
// 0.15: advertise it, and the route is mounted at that URL's path
use aitp_transport_http::RENEW_URI_EXT;
let manifest = ManifestBuilder::new(&key)
    /* … */
    .extension(RENEW_URI_EXT, "https://issuer.example/aitp/handshake/renew".into())
    .build()?;
let server = HandshakeServer::new(/* … */)
    .with_renewal_nonce_store(shared_store)          // Arc<dyn NonceStore>
    .with_renewal_grant_policy(policy);              // optional, Arc<RenewalGrantPolicyFn>
```

**Specific error codes.** Renewal failures that all returned
`TCT_SIGNATURE_INVALID` in 0.14 now return their own codes, such as
`REPLAY_DETECTED`, `TCT_REVOKED`, `TCT_EXPIRED`,
`TCT_EXPIRES_AFTER_MANIFEST`, `POP_RESPONSE_INVALID`, `POLICY_VIOLATION`
and `INVALID_ENVELOPE`. A full replay guard is a local 503. The full
table is in [`tct-renewal.md`](tct-renewal.md). The renew route also goes
through the server's per-source rate limit.

**The facade takes the issuer Manifest.** `aitp::facade::renew_tct` posts
only to the Manifest's advertised `renew_uri`, and only if it is
`https`. With no usable `renew_uri` it returns the new
`FacadeError::RenewalNotAdvertised` without sending anything; run a full
handshake instead (§8.1 forbids probing). `FacadeError` is not
`#[non_exhaustive]`, so exhaustive matches need the new arm.

```rust
// 0.14
let renewed = renew_tct(&holder_key, current, &peer_handshake_endpoint).await?;
// 0.15
let renewed = renew_tct(&holder_key, current, &issuer_manifest).await?;
// local development only: also accepts http://localhost / http://127.0.0.1
let renewed = renew_tct_with_insecure_localhost(&holder_key, current, &issuer_manifest).await?;
```

`renew_uri_from_manifest(manifest, allow_insecure_localhost)` reads the
advertisement if you drive renewal yourself.

**Bindings.** Python and Node `process_renewal_request` now need
`build_manifest()` / `buildManifest()` first, drop grants the Manifest
no longer offers (raising when none are left), take an optional
`revoked_jtis`, and raise on a replayed nonce (a process-wide in-memory
guard).

```python
# 0.15
agent.build_manifest(...)
issued = agent.process_renewal_request(request_json, manifest_exp, ttl, revoked_jtis={"…"})
```

```js
// 0.15
agent.buildManifest(/* … */)
const { tct, grantVoucher } = agent.processRenewalRequest(requestJson, manifestExp, ttl, revokedJtis)
```

**Operator notes.**

- To keep offering renewal, add `RENEW_URI_EXT` to the server's
  Manifest. Holders that still post to `/aitp/handshake/renew` without
  an advertisement get 404.
- Behind a load balancer, pass one shared store to
  `with_renewal_nonce_store`. The default guard holds per replica only.
- The server takes revocation from its attached
  `RevocationListProducer`. With none attached it serves the empty list
  from section 4, so nothing is revoked.
- `aitp-core` gains an optional `metrics` feature;
  `aitp-handshake/metrics` enables it.

## 10. Conformance runner gates on v0.2

`aitp-conformance run` now gates on `required_for_v0_2` by default
(RFC-AITP-0001 §10 item 9)
([#194](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/194),
[#236](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/236)).
A v0.2-required fixture that fails, or is skipped (for example because
the adapter answers `OP_NOT_SUPPORTED`), exits 1.

```sh
# 0.14: gated on required_for_v0_1
aitp-conformance run --target ./my-adapter --fixtures-dir ./schemas/conformance
# 0.15: v0.2 gate by default; the old gate is still available
aitp-conformance run --target ./my-adapter --fixtures-dir ./schemas/conformance                   # v0.2
aitp-conformance run --target ./my-adapter --fixtures-dir ./schemas/conformance --profile v0.1    # v0.1
```

- Any FAIL still fails the run under either profile.
- A required fixture skipped because an enabled feature negates it
  (`del-007` under multi-hop in v0.2, `del-004` in v0.1) is exempt, and
  the runner now lists each exemption on stderr.
- A fixture with no `required_for_v0_2` metadata counts as required.
- `aitp_conformance::fixture::Fixture` has a new public field,
  `required_for_v0_2: bool`. The crate is not published.

At pin `cfd2f16` the rs adapter passes 75, fails 0 and skips 21 in the
strict run, and passes 94 and skips 2 with all four features. See
[`conformance.md`](conformance.md).

## 11. Known deviations and follow-ups

These are known gaps in 0.15.0, each tracked by an issue.

> **Resolved in 0.16.0:** #237, #238, #239 and #240. See
> [`upgrading-0.16.md`](upgrading-0.16.md).

- **Single-hop delegation still uses the AID key**
  ([#237](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/237)).
  RFC-AITP-0006 §4 step 1 asks for the issuer key "resolved from that
  issuer's Manifest" for single-hop delegation too. 0.15 resolves from
  Manifests only on the multi-hop path (section 8). See
  [`multihop-delegation.md`](multihop-delegation.md).
- **The session-bundle Manifest step is still optional in the adapter
  and bindings**
  ([#238](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/238)).
  When no coordinator Manifest is passed, the conformance adapter and the
  Python and Node `verify_session_bundle` fall back to
  `CoordinatorKeySource::UnverifiedAidDangerous`. Making it mandatory is
  a further breaking change.
- **The `del-mh-*` fixtures carry no Manifests**
  ([#239](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/239)).
  To keep them passing without editing vendored fixtures, the adapter
  synthesizes Manifests for kat-keypair-001/002/003. It already reads an
  `issuer_manifests` param, and a supplied Manifest overrides a
  synthesized one, so a spec follow-up can add them.
- **`DelegationVerified.cnf` (Python) vs `cnfJkt` (Node)**
  ([#240](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/240)).
  The two bindings name the same field differently.
- **Multi-hop error ordering.** The Manifest lookup runs after `typ` and
  member-set validation but before the `alg` pin. A hop with a wrong
  `alg` from an issuer that has no Manifest reports
  `KEY_RESOLUTION_FAILED`, not a signature error. Both fail closed.
- **Fuzz target.** `fuzz/fuzz_targets/delegation_verify.rs` configures no
  resolver, so multi-hop inputs stop at key resolution, after the
  structural checks the target exercises.

## 12. Smaller changes

- The spec pin moves from `db7d860` to `cfd2f16`. No vendored schema or
  KAT bytes changed. New fixtures `id-023` and `tct-021` pass with no
  code change.
- The conformance adapter reports a wire code before an `http_status`,
  so `id-016` still sees `CHALLENGE_REFUSED`.
- A weekly `bump-verifier-py` workflow opens a PR when
  `tests/AITP_VERIFIER_PY_VERSION` falls behind `aitp-verifier-py` `main`
  ([#149](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/149),
  [#228](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/228)).
- `aitp-transport-http` has a crate README that marks DPoP and token
  exchange as unsupported, and stale rustdoc and `--help` text is fixed
  ([#200](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/200),
  [#151](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/151),
  [#219](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/219)).
- The root `CHANGELOG.md` is split into one section per release
  ([#201](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/201),
  [#220](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/220)).
