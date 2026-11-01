# aitp — Node.js SDK

Node.js bindings for the **Agent Identity & Trust Protocol (AITP)**, built on
the pure-Rust [`aitp-rs`](https://github.com/agentidentitytrustprotocol/aitp-rs)
protocol crates via [NAPI-rs](https://napi.rs).

A thin SDK: an `AitpAgent` plus initiator/responder session objects. Their
methods take and return JSON strings (the HTTP request/response bodies) and
compact-JWS strings (TCTs, grant vouchers, delegation tokens). Agent code
never handles a Rust type across the FFI boundary. The API is the camelCase
counterpart of the Python SDK (`buildManifest` ↔ `build_manifest`); the two
differ in a few return shapes, listed in
[Python vs Node differences](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/main/docs/sdk-python.md#python-vs-node-differences).

The feature-by-feature guide, with an example for every capability, is
[`docs/sdk-node.md`](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/main/docs/sdk-node.md).

## Install

```bash
npm install @agentidentitytrustprotocol/aitp
```

Prebuilt native binaries ship for macOS (x64, arm64) and Linux GNU (x64,
arm64).

## Build from source

This crate is **not** part of the `aitp-rs` Cargo workspace. Build it with
the [NAPI-rs CLI](https://napi.rs) and a Rust toolchain:

```bash
npm install
npm run build:debug                  # default `.node`, as published
npm run build:experimental           # adds the experimental features
npm run build:minimal:debug          # without SPKI pinning
# Release:
npm run build
npm run build:minimal                # --no-default-features
```

The build produces the platform `.node` binary and regenerates `index.js`
and `index.d.ts`, which cover the default surface. `build:experimental`
writes `experimental.js` and `experimental.d.ts` instead, which add the
experimental API and are not in the published package.

### Cargo features

The published `.node` is the default build:

- handshake, TCT, delegation, manifest verification and OIDC identity
- revocation-list signing and verification
- envelope signing and verification
- SPKI pinning (feature `spki-pinning`, on by default)

The experimental features are off by default and are not in the published
package. A source build enables them one by one, or all with `experimental`
(`npm run build:experimental`). They carry no stability promise.

| Feature                            | Enables                                                   | RFC                  |
|------------------------------------|-----------------------------------------------------------|----------------------|
| `spki-pinning` (default)           | `computeSpkiHash`, `SpkiPinVerifier`                      | HPKP (RFC 7469)      |
| `experimental-renewal`             | `AitpAgent.buildRenewalRequest` / `processRenewalRequest` | RFC-AITP-0013 (Draft) |
| `experimental-session-bundle`      | `SessionBundleBuilder`, `verifySessionBundle`             | RFC-AITP-0010 (Draft) |
| `experimental-multihop-delegation` | `verifyDelegationMultihop`                                | RFC-AITP-0011 (Draft) |

## Usage

```javascript
import { AitpAgent } from '@agentidentitytrustprotocol/aitp';

const initiator = AitpAgent.generate();
const responder = AitpAgent.generate();

initiator.buildManifest({
  displayName: 'initiator',
  handshakeEndpoint: 'https://localhost:8100/aitp/handshake/',
  offeredCaps: ['demo.echo'],
});
const respManifest = responder.buildManifest({
  displayName: 'responder',
  handshakeEndpoint: 'https://localhost:8200/aitp/handshake/',
  offeredCaps: ['demo.write'],
});

// Each side trusts the other's pinned key by AID. Without `pinnedKeys`
// every pinned_key peer is rejected (fail closed).
const sess  = initiator.newSession(null, { pinnedKeys: [responder.aid] });
const rsess = responder.newResponder(null, { pinnedKeys: [initiator.aid] });

// Four-message mutual handshake — each call's output is the next peer's input.

const hello                   = sess.buildHello(respManifest, ['demo.write']);
const { ackJson: helloAck, sessionId } = rsess.processHello(hello);
const commit                  = sess.processHelloAck(helloAck, sessionId);
const { ackJson: commitAck }   = rsess.processCommit(commit, []);
const completed                = sess.complete(commitAck, []);
// completed = { tct, claims, grantVoucher? }
// `tct` is an opaque compact-JWS string; `claims` is the decoded TCT.

// Each peer now holds a TCT the other issued it.
const ident = initiator.verifyTct(completed.tct, 'demo.write', undefined, []);
console.log(ident.peerAid, ident.grants);

// `completed.grantVoucher` (when present) is what you pass to
// `buildDelegation(grantVoucher, delegateeAid, scope)` to delegate.
```

In a real deployment each message moves over HTTP. `buildHello` returns the
body for `POST /aitp/handshake/hello`. `processHello` returns the response
body plus the value for the `X-Aitp-Session-Id` header, and so on.

## API

The generated `index.d.ts` describes the full public surface; the table below
summarizes it. Manifests, revocation lists and handshake envelopes cross the
boundary as JSON strings. **TCTs, grant vouchers and delegations are opaque
compact-JWS token strings** (`header.payload.signature`).

| Export                    | Feature | Notes |
|---------------------------|:-------:|-------|
| `AitpAgent`               | default | `generate(opts?)` / `fromSeed(buffer, opts?)` (`opts.suite = "ed25519" \| "p256"`), `aid`, `buildManifest(opts)` (`opts.revocationListUri`), `newSession(jwks?, opts?)`, `newResponder(jwks?, opts?)` (`opts.trustAnchors`, `opts.pinnedKeys`, `opts.insecureLocalhostDangerous`), `verifyTct(token, grant, expectedAudience?, revokedJtis?, revocation?, pop?)`, `verifyTctCached(token, grant, store, expectedAudience?, revokedJtis?, revocation?, pop?)` (`pop = { challenge, response }`, the presented-TCT path), `newPopChallenge(tctToken, ttlSecs?)`, `signPopResponse(challengeJson)`, `buildDelegation(voucherToken, delegateeAid, scope, ttlSecs?)`, `issueTctForDelegatee(verified, ttlSecs?)` → `{ tct, grantVoucher? }`, `signEnvelope(messageType, payloadJson, opts?)` (`opts.extensionsJson`, `opts.messageId`, `opts.timestamp`), `signRevocationList(entries, expiresInSecs?)` |
| `JsInitiatorSession`      | default | Returned by `newSession`. `buildHello(peerManifest, grants, oidcMintJwt?)`, `processHelloAck(...)`, `complete(...)` → `{ tct, claims, grantVoucher? }` |
| `JsResponderSession`      | default | Returned by `newResponder`. `processHello(hello, oidcMintJwt?)` → `{ ackJson, sessionId }`, `processCommit(commit)` → `{ ackJson, completed: { tct, claims, grantVoucher? } }` |
| `TctStore`                | default | Cache for `AitpAgent.verifyTctCached()`. A byte-identical, still-valid TCT skips the signature check; the key is the SHA-256 of the token bytes |
| `JwksProvider`            | default | OIDC JWKS map. `upsert(issuer, keys)`, `remove(issuer)`, `issuers()` |
| `verifyDelegation(token, verifierAid, issuerManifests, revokedJtis?, revocation?, insecureLocalhostDangerous?)` | default | RFC-AITP-0006, strict single-hop; rejects any multi-hop `chain`. Verifies under the key the delegator's Manifest designates (`issuerManifests`: `{"manifest": ...}` JSON strings). Returns `{ delegator, delegatee, issuedBy, grants, expiresAt, cnfJkt }` |
| `verifyManifestJson(json, nowUnixSecs?, insecureLocalhostDangerous?)` | default | Throws an `Error` with `code` (e.g. `signature_invalid`, `expired`, `unknown_field`, `malformed`) |
| `verifyEnvelope(json, expectedSenderAid)` | default | Verifies an `aitp/0.3` envelope's signature against a pinned sender, in the RFC-AITP-0001 §5.4 check order. Throws an `Error` with `code` (`UNKNOWN_VERSION`, `UNKNOWN_FIELD`, `INVALID_ENVELOPE`, `INVALID_SIGNATURE`). Replay and timestamp checks stay with the caller; see [Envelope signatures](../../docs/sdk-node.md#envelope-signatures-rfc-aitp-0001-54) |
| `verifyRevocationList(json, expectedIssuerAid, nowUnixSecs?)` | default | Verifies a revocation snapshot against a pinned issuer. Throws an `Error` with `code` |
| `revocationSigningBytes(json)` | default | The exact bytes a revocation snapshot's signature covers |
| `verifyPopResponse(challengeJson, responseJson, tctToken)` | default | RFC-AITP-0005 §6.2 checks only (not the TCT itself); returns the proven holder AID. Throws with `code` `POP_CHALLENGE_INVALID` or `POP_RESPONSE_INVALID` |
| `computeAidJkt(aid)`      | default | RFC 7638 thumbprint of an AID's key, for an OIDC JWT's `cnf.jkt` |
| `buildRenewalRequest()` / `processRenewalRequest()` | `experimental-renewal` | RFC-AITP-0013 (Draft). `processRenewalRequest` → `{ tct, grantVoucher? }` |
| `SessionBundleBuilder`, `verifySessionBundle(json, verifierAid, coordinatorManifestJson, nowUnixSecs?, revocationCheck?)` | `experimental-session-bundle` | RFC-AITP-0010. Verifies under the key the coordinator's Manifest designates (`coordinatorManifestJson`: `{"manifest": ...}` JSON, required) |
| `computeSpkiHash()`, `SpkiPinVerifier` | `spki-pinning` | HPKP-style outbound pinning |
| `verifyDelegationMultihop(token, verifierAid, issuerManifests, maxDelegationHops?, revokedJtis?, revocation?, insecureLocalhostDangerous?)` | `experimental-multihop-delegation` | RFC-AITP-0011 multi-hop opt-in |

`verifyTct` returns `{ peerAid, grants, expiresAt, jti }`, where `peerAid` is
the issuer.

### Revocation

`verifyTct` and `verifyTctCached` take a `revokedJtis` argument, an array of
revoked TCT `jti` strings, and an optional final `revocation` argument
(`'fail_closed'`, the default, or `'fail_open'`). A TCT whose `jti` is in the
array is rejected, even if its signature, audience and expiry are otherwise
valid:

```javascript
// not executed: fragment; see docs/sdk-node.md § TCT verification for the runnable flow
const revoked = ['11111111-2222-4333-8444-555555555555'];
agent.verifyTct(tctToken, 'demo.write', null, revoked);  // throws if revoked
```

**Obligation.** The SDK does **not** fetch or maintain the revoked set for
you. Supplying it is the caller's responsibility: source it from a
revocation snapshot you fetched and checked with `verifyRevocationList`
(issue one with `signRevocationList`).

The set is passed up-front rather than through a JS callback invoked per
`jti`, so that it stays sound under napi threading constraints.

Revocation is `fail_closed` (RFC-AITP-0008 §3.1): if you omit `revokedJtis`,
every TCT is rejected with `code` `'TCT_REVOKED'`, because an unknown status
counts as revoked. Pass `[]` when the issuer's list is empty, or
`'fail_open'` only when the deployment has no revocation source.

As an issuer, advertise your list: `buildManifest({ ..., revocationListUri })`
puts `rfc-aitp-0008.revocation_list_uri` in your signed Manifest, as
RFC-AITP-0005 §11 and RFC-AITP-0008 §1.4 require. Use an absolute HTTPS URL,
conventionally your origin plus `REVOCATION_LIST_PATH`.

### UUID inputs

Identifiers that are signed or sent are **strict**: `signEnvelope`'s
`opts.messageId`, `SessionBundleBuilder.sessionId()` and the `jti` of each
`signRevocationList` entry must be the lowercase hyphenated UUID v4 wire form
(`xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx`). Uppercase, braced, `urn:uuid:`,
unhyphenated and non-v4 forms throw, naming the field; they are never
normalized, so what you pass is what goes on the wire.

A `revokedJtis` list (on `verifyTct`, `verifyTctCached`,
`processRenewalRequest`, `verifyDelegation` and `verifyDelegationMultihop`)
is a **lenient** lookup key: each entry may be in any RFC 9562 text form and
is normalized before matching, so `'{11111111-2222-4333-8444-555555555555}'`
revokes the same TCT as the lowercase form. An entry that is not a UUID at
all throws (`revoked_jtis entry is not a UUID`) rather than being ignored.
The Python SDK behaves identically.

### OIDC identity and P-256

See
[OIDC identity](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/main/docs/sdk-node.md#oidc-identity-rfc-aitp-0002)
and
[P-256 signing suite](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/main/docs/sdk-node.md#p-256-signing-suite-rfc-aitp-0001-543).
The `oidcMintJwt` callback is synchronous.

> **Breaking change in v0.2:** the P-256-specific factory methods were
> removed in favor of the parameterized `generate({ suite })` /
> `fromSeed(seed, { suite })` API, which matches the Python SDK's
> `AitpAgent.generate(suite="p256")`. To migrate, call
> `AitpAgent.generate({ suite: 'p256' })` or
> `AitpAgent.fromSeed(seed, { suite: 'p256' })`.

`pinned_key` identities work with Ed25519 and P-256 keys. For P-256 the
manifest's `public_key` is the 33-byte SEC1 compressed point.

### Pinned keys (`opts.pinnedKeys`)

A session accepts a `pinned_key` peer only if the peer's AID is in the
`pinnedKeys` array passed to `newSession` / `newResponder`
(RFC-AITP-0002 §3.2: the key must be in the verifier's local trust store,
checked before the proof). Omitted or `[]` trusts no pinned key, so every
`pinned_key` peer is rejected. An entry that is not a valid AID throws.

> **Upgrading to 0.14:** possession-only pinned-key verification is gone.
> Pass the peer's AID, e.g. `agent.newSession(null, { pinnedKeys: [peer.aid] })`,
> or the handshake fails with `IDENTITY_FAILED`.

## Tests

```bash
npm install
npm run build:debug
npm test                 # node --test tests/*.mjs
```

`tests/test_docs_samples.mjs` runs every JavaScript block in
[`docs/sdk-node.md`](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/main/docs/sdk-node.md)
and the Usage block above.

The cross-language interop suite (Python ↔ Node) lives in
[`bindings/interop`](https://github.com/agentidentitytrustprotocol/aitp-rs/tree/main/bindings/interop).
Run it with `make interop` from the repo root.
