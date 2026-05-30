# aitp — Node.js SDK

Node.js bindings for the **Agent Identity & Trust Protocol (AITP)**, built on
the pure-Rust `aitp-rs` protocol crates via [NAPI-rs](https://napi.rs).

A thin SDK: an `AitpAgent` plus initiator/responder session objects whose
methods take and return JSON strings — the HTTP request/response bodies — so
agent code never handles a Rust type across the FFI boundary. The API is the
symmetric counterpart of the Python SDK (`buildManifest` ↔ `build_manifest`).

## Build

This crate is **not** part of the `aitp-rs` Cargo workspace. Build it with
the [NAPI-rs CLI](https://napi.rs):

```bash
npm install
npm run build:debug                  # default `.node` (v0.1 surface only)
npm run build:experimental:debug     # default + post-v0.1 features
# Release:
npm run build                        # default release
npm run build:experimental           # default + experimental, release
```

This produces `aitp.node` and `index.js` in the package root. Generated
TypeScript typings (`index.d.ts`) include the experimental surface only
when the artifact was built with the `experimental` feature.

### Cargo features

The default `.node` exposes the v0.1 surface (handshake, TCT, delegation,
manifest verify, revocation-list signing, OIDC identity). Three post-v0.1
capabilities live behind opt-in Cargo features:

| Feature                   | Enables                                                                  | RFC                  |
|---------------------------|--------------------------------------------------------------------------|----------------------|
| `experimental-renewal`    | `AitpAgent.buildRenewalRequest` / `processRenewalRequest`                | RFC-AITP-0005 §10    |
| `experimental-bundle`     | `SessionBundleBuilder`, `verifySessionBundle`                            | RFC-AITP-0010        |
| `experimental-pinning`    | `computeSpkiHash`, `SpkiPinVerifier`                                     | HPKP (RFC 7469)      |
| `experimental` (umbrella) | All three above                                                          |                      |

Each post-v0.1 capability does **not** promise wire stability until the
underlying RFC graduates.

## Usage

```javascript
import { AitpAgent } from 'aitp';

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
const initiatorHeldTct         = sess.complete(commitAck);

// Each peer now holds a TCT the other issued it.
const ident = initiator.verifyTct(initiatorHeldTct, 'demo.write');
console.log(ident.peerAid, ident.grants);
```

In a real deployment each message moves over HTTP: `buildHello` returns the
`POST /aitp/handshake/hello` body, `processHello` returns the response body
plus the value for the `X-Aitp-Session-Id` header, and so on.

## API

The full public surface is described in the generated `index.d.ts`; below
is a summary. All `*Json` parameters and return values are JSON strings.

| Type                      | Default? | Notes                                                                                                          |
|---------------------------|:--------:|----------------------------------------------------------------------------------------------------------------|
| `AitpAgent`               |    ✅    | `generate(opts?)` / `fromSeed(buffer, opts?)` (`opts.suite = "ed25519" \| "p256"`), `aid`, `buildManifest(opts)`, `newSession(jwks?, opts?)`, `newResponder(jwks?, opts?)`, `verifyTct(...)`, `buildDelegation(...)`, `issueTctForDelegatee(...)`, `signRevocationList(...)` |
| `InitiatorSession`        |    ✅    | `buildHello(peerManifest, grants, oidcMintJwt?)`, `processHelloAck(...)`, `complete(...)`                       |
| `ResponderSession`        |    ✅    | `processHello(hello, oidcMintJwt?)` → `{ ackJson, sessionId }`, `processCommit(commit)` → `{ ackJson, tctJson }` |
| `TctIdentity`             |    ✅    | `peerAid`, `grants`, `expiresAt`, `jti`                                                                          |
| `DelegationVerified`      |    ✅    | `delegator`, `delegatee`, `issuedBy`, `grants`, `expiresAt`, `cnf`                                              |
| `JwksProvider`            |    ✅    | OIDC JWKS map. `upsert(issuer, keys)`, `remove(issuer)`, `issuers()`                                            |
| `verifyDelegation()`      |    ✅    | RFC-AITP-0006                                                                                                   |
| `verifyManifestJson()`    |    ✅    | Control-plane manifest enrollment                                                                               |
| `buildRenewalRequest()` / `processRenewalRequest()`           | `experimental-renewal` | RFC-AITP-0005 §10 |
| `SessionBundleBuilder`, `verifySessionBundle()`               | `experimental-bundle`  | RFC-AITP-0010      |
| `computeSpkiHash()`, `SpkiPinVerifier`                        | `experimental-pinning` | HPKP outbound pinning |

### OIDC identity (RFC-AITP-0002)

```javascript
import { AitpAgent, JwksProvider } from 'aitp';

const jwks = new JwksProvider({
  'https://idp.example/': [{ kty: 'OKP', crv: 'Ed25519', x: '...', kid: 'k1', alg: 'EdDSA' }],
});

const agent = AitpAgent.generate();
agent.buildManifest({
  displayName: 'alice',
  handshakeEndpoint: 'https://alice.example/aitp/handshake/',
  offeredCaps: ['demo.echo'],
  identityType: 'oidc',
  oidcIssuer: 'https://idp.example/',
  oidcSubject: 'alice',
});
const sess = agent.newSession(jwks);

const mintJwt = (nonce) => myIdp.mintJwtSync({ nonce, sub: 'alice', aud: peerAid });
const hello = sess.buildHello(peerManifest, ['demo.echo'], mintJwt);
```

### P-256 signing (RFC-AITP-0001 §5.4.3)

```javascript
const agent = AitpAgent.generate({ suite: 'p256' });   // aid:pubkey:p256:<44>
// Deterministic from a seed:
const seeded = AitpAgent.fromSeed(seed, { suite: 'p256' });
// All other methods identical; signatures emitted as `p256.<86b64u>`.
```

> **Breaking change in v0.2:** `AitpAgent.generateP256()` and
> `AitpAgent.fromP256Seed(seed)` were removed in favor of the
> parameterized `generate({ suite })` / `fromSeed(seed, { suite })`
> API. This matches the Python SDK's
> `AitpAgent.generate(suite="p256")` shape — CLAUDE.md mandates SDK
> symmetry. Migration: replace `generateP256()` with
> `generate({ suite: 'p256' })` and `fromP256Seed(seed)` with
> `fromSeed(seed, { suite: 'p256' })`.

> **Note.** In v0.1 the `pinned_key` identity_hint embeds an Ed25519 raw
> public key. P-256 agents must therefore use `identityType: 'oidc'` until
> the manifest's identity_hint shape is extended.

## Tests

```bash
npm install
npm run build:debug
npm test                 # node --test tests/*.mjs
```

The cross-language interop suite (Python ↔ Node) lives in
[`../interop`](../interop) — run it with `make interop` from the repo root.
