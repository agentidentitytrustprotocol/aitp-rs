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
npm run build:debug                  # full `.node` (all capabilities)
npm run build:minimal:debug          # minimal `.node` (core surface only)
# Release:
npm run build                        # full release (all capabilities)
npm run build:minimal                # minimal release (--no-default-features)
```

The build produces the platform `.node` binary and regenerates `index.js`
and `index.d.ts`. The generated TypeScript typings in `index.d.ts` cover the
full surface; a `--no-default-features` build narrows it.

### Cargo features

By default the published `.node` ships the **full** capability surface:

- handshake, TCT, delegation, manifest verification and OIDC identity
- revocation-list signing and verification
- TCT renewal, session bundles, SPKI pinning and multi-hop delegation

Each capability below is a named feature, all on by default. A minimal build
can opt out with `--no-default-features`:

| Feature               | Enables                                                                  | RFC                  |
|-----------------------|--------------------------------------------------------------------------|----------------------|
| `renewal`             | `AitpAgent.buildRenewalRequest` / `processRenewalRequest`                | RFC-AITP-0013 (Planned) |
| `session-bundle`      | `SessionBundleBuilder`, `verifySessionBundle`                            | RFC-AITP-0010 (Draft) |
| `spki-pinning`        | `computeSpkiHash`, `SpkiPinVerifier`                                     | HPKP (RFC 7469)      |
| `multihop-delegation` | `verifyDelegationMultihop`                                               | RFC-AITP-0011 (Draft) |

Capabilities whose RFC has not graduated make no wire-stability promise
across binding versions.

## Usage

```javascript
import { AitpAgent } from '@agentidentitytrustprotocol/aitp';

const initiator = AitpAgent.generate();
const responder = AitpAgent.generate();

initiator.buildManifest({
  displayName: 'initiator',
  handshakeEndpoint: 'http://localhost:8100/aitp/handshake/',
  offeredCaps: ['demo.echo'],
});
const respManifest = responder.buildManifest({
  displayName: 'responder',
  handshakeEndpoint: 'http://localhost:8200/aitp/handshake/',
  offeredCaps: ['demo.write'],
});

// Four-message mutual handshake — each call's output is the next peer's input.
const sess  = initiator.newSession();
const rsess = responder.newResponder();

const hello                   = sess.buildHello(respManifest, ['demo.write']);
const { ackJson: helloAck, sessionId } = rsess.processHello(hello);
const commit                  = sess.processHelloAck(helloAck, sessionId);
const { ackJson: commitAck }   = rsess.processCommit(commit);
const completed                = sess.complete(commitAck);
// completed = { tct, claims, grantVoucher? }
// `tct` is an opaque compact-JWS string; `claims` is the decoded TCT.

// Each peer now holds a TCT the other issued it.
const ident = initiator.verifyTct(completed.tct, 'demo.write');
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
| `AitpAgent`               | default | `generate(opts?)` / `fromSeed(buffer, opts?)` (`opts.suite = "ed25519" \| "p256"`), `aid`, `buildManifest(opts)`, `newSession(jwks?, opts?)`, `newResponder(jwks?, opts?)` (`opts.trustAnchors`), `verifyTct(token, grant, expectedAudience?, revokedJtis?)`, `verifyTctCached(token, grant, store, expectedAudience?, revokedJtis?)`, `buildDelegation(voucherToken, delegateeAid, scope, ttlSecs?)`, `issueTctForDelegatee(verified, ttlSecs?)` (bare compact JWS), `signRevocationList(entries, expiresInSecs?)` |
| `JsInitiatorSession`      | default | Returned by `newSession`. `buildHello(peerManifest, grants, oidcMintJwt?)`, `processHelloAck(...)`, `complete(...)` → `{ tct, claims, grantVoucher? }` |
| `JsResponderSession`      | default | Returned by `newResponder`. `processHello(hello, oidcMintJwt?)` → `{ ackJson, sessionId }`, `processCommit(commit)` → `{ ackJson, completed: { tct, claims, grantVoucher? } }` |
| `TctStore`                | default | Cache for `AitpAgent.verifyTctCached()`. A byte-identical, still-valid TCT skips the signature check; the key is the SHA-256 of the token bytes |
| `JwksProvider`            | default | OIDC JWKS map. `upsert(issuer, keys)`, `remove(issuer)`, `issuers()` |
| `verifyDelegation(token, verifierAid, revokedJtis?)` | default | RFC-AITP-0006, strict single-hop; rejects any multi-hop `chain`. Returns `{ delegator, delegatee, issuedBy, grants, expiresAt, cnfJkt }` |
| `verifyManifestJson(json, nowUnixSecs?)` | default | Throws an `Error` with `code` (e.g. `signature_invalid`, `expired`, `malformed`) |
| `verifyRevocationList(json, expectedIssuerAid, nowUnixSecs?)` | default | Verifies a revocation snapshot against a pinned issuer. Throws an `Error` with `code` |
| `revocationSigningBytes(json)` | default | The exact bytes a revocation snapshot's signature covers |
| `computeAidJkt(aid)`      | default | RFC 7638 thumbprint of an AID's key, for an OIDC JWT's `cnf.jkt` |
| `buildRenewalRequest()` / `processRenewalRequest()` | `renewal` | RFC-AITP-0013 (Planned). `processRenewalRequest` returns a bare compact-JWS TCT |
| `SessionBundleBuilder`, `verifySessionBundle(json, verifierAid, nowUnixSecs?, revocationCheck?)` | `session-bundle` | RFC-AITP-0010 |
| `computeSpkiHash()`, `SpkiPinVerifier` | `spki-pinning` | HPKP-style outbound pinning |
| `verifyDelegationMultihop(token, verifierAid, maxDelegationHops?, revokedJtis?)` | `multihop-delegation` | RFC-AITP-0011 multi-hop opt-in |

`verifyTct` returns `{ peerAid, grants, expiresAt, jti }`, where `peerAid` is
the issuer.

### Revocation

`verifyTct` and `verifyTctCached` take an optional final `revokedJtis`
argument, an array of revoked TCT `jti` strings. A TCT whose `jti` is in the
array is rejected, even if its signature, audience and expiry are otherwise
valid:

```javascript
// not executed: fragment; see docs/sdk-node.md § TCT verification for the runnable flow
const revoked = ['11111111-2222-3333-4444-555555555555'];
agent.verifyTct(tctToken, 'demo.write', null, revoked);  // throws if revoked
```

**Obligation.** The SDK does **not** fetch or maintain the revoked set for
you. Supplying it is the caller's responsibility: source it from a
revocation snapshot you fetched and checked with `verifyRevocationList`
(issue one with `signRevocationList`).

The set is passed up-front rather than through a JS callback invoked per
`jti`, so that it stays sound under napi threading constraints.

If you omit the argument, the revocation gate is **off** and an unexpired but
revoked TCT will pass. Wire `revokedJtis` in wherever revocation matters.

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

> **Note.** `pinned_key` identities are Ed25519-only **in this SDK**. The
> v0.2 manifest schema itself accepts a P-256 `public_key`, but
> `buildManifest` cannot emit one. P-256 agents must therefore use
> `identityType: 'oidc'`.

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
