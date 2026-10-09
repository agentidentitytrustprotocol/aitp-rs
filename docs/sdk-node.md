# Node SDK — feature guide

This page is a feature-by-feature pointer into [`bindings/aitp-node`](../bindings/aitp-node).
Each section names the RFC, the Cargo feature flag (if any), and a short
example. The auto-generated
[`index.d.ts`](../bindings/aitp-node/index.d.ts) has the full TypeScript
signatures.

The Python SDK covers the same operations; see [`sdk-python.md`](sdk-python.md)
and its [Python vs Node differences](sdk-python.md#python-vs-node-differences)
table.

The JavaScript blocks on this page run as one connected flow. Names defined
in an earlier block (`alice`, `bob`, `tctJws`, …) are reused later. CI runs
every block as written, through
[`bindings/aitp-node/tests/test_docs_samples.mjs`](../bindings/aitp-node/tests/test_docs_samples.mjs).
That test fails if a block here changes without the test changing too. The
test imports from `../index.js` instead of the package name.

## Install

```bash
npm install @agentidentitytrustprotocol/aitp
```

Prebuilt native binaries are published for macOS (x64, arm64) and Linux GNU
(x64, arm64). For the current version, see the
[releases](https://github.com/agentidentitytrustprotocol/aitp-rs/releases) or
`bindings/aitp-node/package.json`.

## Build

```bash
npm install
npm run build:debug                  # full surface (all capabilities)
npm run build:minimal:debug          # minimal surface (--no-default-features)
# Release variants:
npm run build
npm run build:minimal
```

## Default surface

### Mutual handshake (RFC-AITP-0004)

```javascript
import { AitpAgent } from '@agentidentitytrustprotocol/aitp';

const alice = AitpAgent.generate();
const bob   = AitpAgent.generate();
const bobManifest = bob.buildManifest({
  displayName: 'bob',
  handshakeEndpoint: 'https://bob.example/aitp/handshake/',
  offeredCaps: ['demo.echo'],
});
alice.buildManifest({
  displayName: 'alice',
  handshakeEndpoint: 'https://alice.example/aitp/handshake/',
  offeredCaps: ['demo.write'],
});
// 4 messages — each call's output is the next peer's input.
const s = alice.newSession(), r = bob.newResponder();
const hello = s.buildHello(bobManifest, ['demo.echo']);
const { ackJson, sessionId } = r.processHello(hello);
const commit = s.processHelloAck(ackJson, sessionId);
const { ackJson: cack, completed: bobSide } = r.processCommit(commit);  // bobSide: what alice issued to bob
const held = s.complete(cack);
const tctJws     = held.tct;           // compact JWS issued by bob — store / present this
const claims     = held.claims;        // decoded { iss, sub, aud, grants, iat, exp, jti }
const voucherJws = held.grantVoucher;  // compact JWS, or undefined if bob disallowed delegation
```

`complete()` and `processCommit().completed` return a `JsCompletedHandshake`
object. Its `claims` field is a subset of the TCT claim set: it omits `ver`
and `cnf`. The full claim set is defined in
[RFC-AITP-0005 §2](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0005-tct.md#2-claims).
The session classes are exported as `JsInitiatorSession` and
`JsResponderSession`.

`newSession(jwks?, opts?)` and `newResponder(jwks?, opts?)` accept
`opts.trustAnchors`, which overrides the agent manifest's
`accepted_trust_anchors` for that one session. The
[OIDC section](#oidc-identity-rfc-aitp-0002) shows when you need it.

<a id="tct-verification-rfc-aitp-0005-9"></a>

### TCT verification (RFC-AITP-0005 §7.2)

A TCT is an opaque compact JWS string. `verifyTct` runs the verification order
in
[RFC-AITP-0005 §7.2](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0005-tct.md#72-verification-order).
It returns `{ peerAid, grants, expiresAt, jti }`, where `peerAid` is the
issuer. The spec integration guide,
[Step 2: Verify locally](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/docs/integration-guide.md#step-2-verify-locally),
explains what a verifier checks and why.

```javascript
// Holder-receipt model — the verifier's AID is the agent's own AID (default).
const ident = alice.verifyTct(tctJws, 'demo.echo');
console.log(ident.peerAid === bob.aid, ident.grants);   // true [ 'demo.echo' ]

// Presented-TCT model — a resource server checking a TCT a peer presented
// (e.g. in `X-AITP-TCT`). The expected audience is the TCT's subject (aud == sub).
const presented = bob.verifyTct(tctJws, 'demo.echo', alice.aid);

// Revocation gate: pass the revoked TCT `jti`s. Verifiers SHOULD supply it —
// omitting it accepts a revoked-but-unexpired TCT.
try {
  alice.verifyTct(tctJws, 'demo.echo', null, [ident.jti]);
} catch (err) {
  console.log(err.message);   // TCT verification failed: TCT jti is revoked
}
```

A failed verification throws an `Error`. Its `code` is napi's generic
`GenericFailure`, not an AITP error code. The Rust core does have
`ErrorCode::TctRevoked` and the other TCT codes, but the binding exposes them
only in the message text. Do not branch on that text.

#### Cached verification (`TctStore`)

`verifyTctCached` is an `AitpAgent` method. Use it when a verifier sees the
same TCT on many requests:

```javascript
import { TctStore } from '@agentidentitytrustprotocol/aitp';

const store = new TctStore(1024);
alice.verifyTctCached(tctJws, 'demo.echo', store);
alice.verifyTctCached(tctJws, 'demo.echo', store);   // signature check skipped
console.log(store.len());   // 1
```

The cache key is the SHA-256 of the exact token bytes, so only a
byte-identical token can hit. Expiry, audience, required grant and
`revokedJtis` are re-checked on every call, including cache hits.

#### Verifying without this SDK

A TCT verifies under any stock JOSE library (node
[`jose`](https://github.com/panva/jose)) given only the issuer's public key.
See [architecture.md § Debugging a TCT](architecture.md#debugging-a-tct). For
an independent implementation of the full check, see
[`aitp_verifier/tct.py`](https://github.com/agentidentitytrustprotocol/aitp-verifier-py/blob/main/aitp_verifier/tct.py)
and
[`aitp_verifier/jws.py`](https://github.com/agentidentitytrustprotocol/aitp-verifier-py/blob/main/aitp_verifier/jws.py)
in `aitp-verifier-py`.

### Delegation (RFC-AITP-0006)

`buildDelegation` takes the grant voucher the delegator received in the
handshake (`held.grantVoucher` above). The delegatee's key binding comes from
its AID, so you pass no public key. The voucher model is described in
[RFC-AITP-0006](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0006-delegation.md)
and
[RFC-AITP-0005 §8](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0005-tct.md#8-grant-voucher).

```javascript
import { verifyDelegation } from '@agentidentitytrustprotocol/aitp';

const carol = AitpAgent.generate();
// alice delegates part of what bob granted her to carol.
const delegationJws = alice.buildDelegation(voucherJws, carol.aid, ['demo.echo']);

// bob (the original grantor) verifies and mints carol a TCT of her own.
const revoked = [];   // bob's deny list, e.g. jtis from verified revocation snapshots
const verified = verifyDelegation(delegationJws, bob.aid, revoked);
const carolTct = bob.issueTctForDelegatee(verified);   // bare compact-JWS string
console.log(carol.verifyTct(carolTct, 'demo.echo').peerAid === bob.aid);   // true
```

The signature is `buildDelegation(voucherToken, delegateeAid, scope, ttlSecs?)`.
`verifyDelegation(token, verifierAid, revokedJtis?)` is strict single-hop: it
rejects any token that carries a multi-hop `chain`. Pass `revokedJtis`. If
you omit it, a delegation whose source TCT has been revoked is still
redeemed. For multi-hop chains, see
[Multi-hop delegation](#multi-hop-delegation-rfc-aitp-0011-feature-multihop-delegation).

### Manifest verification

```javascript
import { verifyManifestJson } from '@agentidentitytrustprotocol/aitp';

verifyManifestJson(bobManifest);   // returns undefined on success

try {
  verifyManifestJson(bobManifest, 4_102_444_800);   // year 2100
} catch (err) {
  console.log(err.code);   // expired
}
```

- **Verification failures** throw an `Error` whose `code` is one of
  `signature_invalid`, `pop_failed`, `aid_mismatch`, `expired`,
  `version_unknown`, `identity_hint_malformed`,
  `incompatible_identity_type` or `malformed`. Branch on `error.code`, not on
  `error.message`.
- **Unparseable JSON** also gives `malformed`.
- **Unknown members** (the `UNKNOWN_FIELD` case) come back as `malformed`;
  there is no separate code
  ([#152](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/152)).
- **The optional second argument** `nowUnixSecs` overrides the verification
  clock.

### Revocation lists (RFC-AITP-0008)

```javascript
import { randomUUID } from 'node:crypto';
import { verifyRevocationList, revocationSigningBytes } from '@agentidentitytrustprotocol/aitp';

const snapshot = bob.signRevocationList(
  [{ jti: randomUUID(), reason: 'compromised' }],   // jti must be a UUID
  600,
);
verifyRevocationList(snapshot, bob.aid);   // pin the expected issuer
try {
  verifyRevocationList(snapshot, alice.aid);
} catch (err) {
  console.log(err.code);   // issuer_mismatch
}

revoked.push(...JSON.parse(snapshot).revocation_list.entries.map((e) => e.jti));
const signedBytes = revocationSigningBytes(snapshot);   // Buffer: JCS of the inner body
```

`signRevocationList` entries take `jti` (a UUID string), plus optional
`revokedAt` (unix seconds, defaulting to now) and `reason`.

`verifyRevocationList(envelopeJson, expectedIssuerAid, nowUnixSecs?)` returns
on success. On failure it throws an `Error` whose `code` is one of
`signature_invalid`, `issuer_mismatch`, `version_unknown`, `expired` or
`malformed`. An invalid `expectedIssuerAid` throws with napi's generic `GenericFailure`
code instead.

The function checks only that the snapshot is authentic and has not expired.
It does not decide whether the snapshot is fresh enough. That policy belongs
to you; see
[RFC-AITP-0008 §3](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0008-revocation.md#3-revocation-policy)
and the spec's
[operational guidance](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/docs/operational-guidance.md#revocation-lookup-revocation_policymode).

### OIDC identity (RFC-AITP-0002)

```javascript
import { JwksProvider, computeAidJkt } from '@agentidentitytrustprotocol/aitp';

// You fetch the IdP's JWKS yourself; the SDK does no HTTP.
const jwks = new JwksProvider({ 'https://idp.example/': [idpJwk] });
const dave = AitpAgent.generate();
dave.buildManifest({
  displayName: 'dave',
  handshakeEndpoint: 'https://dave.example/aitp/handshake/',
  offeredCaps: ['demo.write'],
  identityType: 'oidc',
  oidcIssuer: 'https://idp.example/',
  oidcSubject: 'dave',
});

// Synchronous callback: return a fresh JWT bound to this handshake and dave's key.
const mint = (popNonce) =>
  myIdp.mintJwtSync({ sub: 'dave', aud: bob.aid, nonce: popNonce, cnfJkt: computeAidJkt(dave.aid) });

const sess = dave.newSession(jwks);
const oidcHello = sess.buildHello(bobManifest, ['demo.echo'], mint);

// bob's manifest accepts no OIDC issuer by default, so his responder must
// trust the IdP explicitly.
const responder = bob.newResponder(jwks, { trustAnchors: ['https://idp.example/'] });
const oidcAck = responder.processHello(oidcHello);
```

The `oidcMintJwt` callback is **synchronous**. It runs on the main thread
inside the `buildHello` / `processHello` call, so do not pass an async
function. It receives the handshake's `pop_nonce` and returns a compact JWT.
The claims that JWT must carry are defined in
[RFC-AITP-0002 §2.2](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0002-identity.md#22-required-jwt-claims).
`computeAidJkt(aid)` computes the `cnf.jkt` value for an Ed25519 or P-256 AID.

### P-256 signing suite (RFC-AITP-0001 §5.4.3)

```javascript
const erin = AitpAgent.generate({ suite: 'p256' });   // aid:pubkey:p256:…
const erinAgain = AitpAgent.fromSeed(Buffer.alloc(32, 7), { suite: 'p256' });   // deterministic

try {
  erin.buildManifest({
    displayName: 'erin',
    handshakeEndpoint: 'https://erin.example/aitp/handshake/',
    offeredCaps: ['demo.echo'],
  });   // pinned_key is the default identityType
} catch (err) {
  console.log(err.message);   // pinned_key identity_hint with a P-256 agent key is not supported; …
}
```

The P-256-specific factory methods that existed before v0.2 were removed in
favour of the `suite` option. Every other method works the same with a P-256 agent. Signature formats
are defined in
[RFC-AITP-0001 §5.4.3](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md#543-algorithm-tagged-signature-wire-format-jcs-profile-only)
for the JCS profile and in
[§5.4.5](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md#545-compact-jws-profile-portable-trust-artifacts)
for compact JWS.

**SDK restriction:** this SDK's `buildManifest` can only emit a `pinned_key`
identity hint for an Ed25519 key, so P-256 agents must use
`identityType: 'oidc'`. The protocol itself does not impose this: the v0.2
manifest schema accepts a P-256 `public_key`.

## Additional capabilities (on by default)

These ship in the default build. A `--no-default-features` build drops all of
them; add back by named Cargo feature: `renewal`, `session-bundle`,
`spki-pinning`, `multihop-delegation`.

### TCT renewal (RFC-AITP-0013 / RFC-AITP-0004 §8.1, feature `renewal`)

```javascript
const req = alice.buildRenewalRequest(tctJws);   // the held TCT compact JWS
const freshTct = bob.processRenewalRequest(
  req, Math.floor(Date.now() / 1000) + 86_400, 3600,
);   // bare compact-JWS string — no grant voucher
```

- **Return value:** `processRenewalRequest` returns only the fresh TCT. The
  Python binding also returns the re-minted grant voucher.
- **Status:** RFC-AITP-0013 is *Planned* and the RFC-AITP-0004 §8.1 renewal
  extension is non-normative.
- **Before you expose renewal:** read
  [tct-renewal.md § Known limitations](tct-renewal.md#known-limitations),
  tracked in
  [#196](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/196).

### Multi-hop delegation (RFC-AITP-0011, feature `multihop-delegation`)

```javascript
import { verifyDelegationMultihop } from '@agentidentitytrustprotocol/aitp';

const verifiedMultihop = verifyDelegationMultihop(delegationJws, bob.aid, 3, revoked);
```

This is an opt-in verifier that accepts RFC-AITP-0011 chains up to
`maxDelegationHops` total hops, with a default of 3. A single-hop token also
verifies, and `0` reverts to strict single-hop. See
[multihop-delegation.md](multihop-delegation.md).

### Session Trust Bundle (RFC-AITP-0010, feature `session-bundle`)

```javascript
import { SessionBundleBuilder, verifySessionBundle } from '@agentidentitytrustprotocol/aitp';

const bundle = new SessionBundleBuilder(bob)   // bob coordinates
  .sessionId(randomUUID())                     // optional; defaults to a fresh UUID
  .issuedAt(Math.floor(Date.now() / 1000))     // optional; defaults to now
  .participant(alice.aid, tctJws)              // TCTs bob issued to each member
  .participant(carol.aid, carolTct)
  .build();
const outcome = verifySessionBundle(bundle, alice.aid);
console.log(outcome.kind);   // clear  (fields: kind, activeAids, droppedAids)

const checked = verifySessionBundle(bundle, alice.aid, null, (jti) => revoked.includes(jti));
```

`verifySessionBundle(bundleEnvelopeJson, verifierAid, nowUnixSecs?, revocationCheck?)`
returns `{ kind: 'clear' | 'degraded', activeAids, droppedAids }`.
`revocationCheck` is called with each participant TCT's `jti` and returns
`true` if that TCT is revoked. See [session-bundle.md](session-bundle.md).

### SPKI cert pinning (HPKP-style, feature `spki-pinning`)

```javascript
import { computeSpkiHash, SpkiPinVerifier } from '@agentidentitytrustprotocol/aitp';

const pin = computeSpkiHash(certDerBuffer);       // 32-byte Buffer
const verifier = new SpkiPinVerifier([pin]);
console.log(verifier.isPinned(certDerBuffer), verifier.isPinned(otherCertDer));   // true false
```

Wire `verifier.isPinned()` into your HTTP client's `checkServerIdentity` hook
(e.g. an `undici.Agent` `connect` option). The SDK does no HTTP itself.

## Tests + interop

```bash
npm install
npm run build:debug
npm test                       # node --test over bindings/aitp-node/tests
cd ../interop && pytest -v     # cross-language interop (see bindings/interop/README.md)
```

See [`bindings/interop/README.md`](../bindings/interop/README.md) for what the
interop suite covers.
