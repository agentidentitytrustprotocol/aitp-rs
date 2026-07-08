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
npm run build:debug                  # full `.node` (all capabilities)
npm run build:minimal:debug          # minimal `.node` (core surface only)
# Release:
npm run build                        # full release (all capabilities)
npm run build:minimal                # minimal release (--no-default-features)
```

This produces `aitp.node` and `index.js` in the package root. Generated
TypeScript typings (`index.d.ts`) cover the full surface; a
`--no-default-features` build narrows it accordingly.

### Cargo features

The published `.node` ships the **full** capability surface by default —
handshake, TCT, delegation, manifest verify, revocation-list signing, OIDC
identity, **plus** TCT renewal, session bundles, SPKI pinning, and multi-hop
delegation. Each capability is a named feature (all on by default) so a
minimal build can opt out with `--no-default-features`:

| Feature               | Enables                                                                  | RFC                  |
|-----------------------|--------------------------------------------------------------------------|----------------------|
| `renewal`             | `AitpAgent.buildRenewalRequest` / `processRenewalRequest`                | RFC-AITP-0013    |
| `session-bundle`      | `SessionBundleBuilder`, `verifySessionBundle`                            | RFC-AITP-0010        |
| `spki-pinning`        | `computeSpkiHash`, `SpkiPinVerifier`                                     | HPKP (RFC 7469)      |
| `multihop-delegation` | `verifyDelegationMultihop`                                               | RFC-AITP-0011        |

Capabilities whose underlying RFC has not yet graduated do not promise wire
stability across binding versions.

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

In a real deployment each message moves over HTTP: `buildHello` returns the
`POST /aitp/handshake/hello` body, `processHello` returns the response body
plus the value for the `X-Aitp-Session-Id` header, and so on.

## API

The full public surface is described in the generated `index.d.ts`; below
is a summary. Manifests, revocation lists, and handshake envelopes cross
the boundary as JSON strings; **TCTs, grant vouchers, and delegations are
opaque compact-JWS token strings** (`header.payload.signature`).

| Type                      | Default? | Notes                                                                                                          |
|---------------------------|:--------:|----------------------------------------------------------------------------------------------------------------|
| `AitpAgent`               |    ✅    | `generate(opts?)` / `fromSeed(buffer, opts?)` (`opts.suite = "ed25519" \| "p256"`), `aid`, `buildManifest(opts)`, `newSession(jwks?, opts?)`, `newResponder(jwks?, opts?)`, `verifyTct(token, grant, expectedAudience?, revokedJtis?)`, `buildDelegation(voucherToken, delegateeAid, scope, ttlSecs?)`, `issueTctForDelegatee(...)`, `signRevocationList(...)` |
| `InitiatorSession`        |    ✅    | `buildHello(peerManifest, grants, oidcMintJwt?)`, `processHelloAck(...)`, `complete(...)` → `{ tct, claims, grantVoucher? }` |
| `ResponderSession`        |    ✅    | `processHello(hello, oidcMintJwt?)` → `{ ackJson, sessionId }`, `processCommit(commit)` → `{ ackJson, completed: { tct, claims, grantVoucher? } }` |
| `TctIdentity`             |    ✅    | `peerAid` (issuer), `grants`, `expiresAt`, `jti`                                                                |
| `DelegationVerified`      |    ✅    | `delegator`, `delegatee`, `issuedBy`, `grants`, `expiresAt`, `cnfJkt`                                           |
| `JwksProvider`            |    ✅    | OIDC JWKS map. `upsert(issuer, keys)`, `remove(issuer)`, `issuers()`                                            |
| `TctStore` / `verifyTctCached()` | ✅ | Hot-path verify cache: skips the signature check for a byte-identical, still-valid TCT (keyed by SHA-256 of the token bytes) |
| `verifyDelegation()`      |    ✅    | RFC-AITP-0006 — strict single-hop; rejects any multi-hop `chain`                                               |
| `verifyManifestJson()`    |    ✅    | Control-plane manifest enrollment                                                                               |
| `buildRenewalRequest()` / `processRenewalRequest()`           | `renewal` | RFC-AITP-0013 |
| `SessionBundleBuilder`, `verifySessionBundle()`               | `session-bundle`  | RFC-AITP-0010      |
| `computeSpkiHash()`, `SpkiPinVerifier`                        | `spki-pinning` | HPKP outbound pinning |
| `verifyDelegationMultihop()`                      | `multihop-delegation` | RFC-AITP-0011 (draft) multi-hop opt-in |

### Revocation

`verifyTct` / `verifyTctCached` accept an optional final `revokedJtis`
argument — an array of revoked TCT `jti` strings. Any TCT whose `jti` is in
the array is rejected even if its signature, audience, and expiry are
otherwise valid:

```javascript
const revoked = ['11111111-2222-3333-4444-555555555555'];
agent.verifyTct(tctToken, 'demo.write', null, revoked);  // throws if revoked
```

**Obligation.** The SDK does **not** fetch or maintain the revoked set for
you; supplying it is the caller's responsibility. Source it from a
`RevocationList` you fetched and verified out-of-band (issue one with
`signRevocationList`). The set is passed up-front (rather than via a JS
callback invoked per-`jti`) to stay sound under napi threading constraints.
Omitting the argument leaves the revocation gate **off** — an unexpired but
revoked TCT will pass, so wire `revokedJtis` in wherever revocation matters.

### OIDC identity (RFC-AITP-0002)

```javascript
import { AitpAgent, JwksProvider } from '@agentidentitytrustprotocol/aitp';

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
