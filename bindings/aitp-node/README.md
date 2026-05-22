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
npm run build:debug      # or `npm run build` for a release artifact
```

This produces `aitp.node` and `index.js` in the package root.

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

| Type               | Members                                                                                          |
|--------------------|--------------------------------------------------------------------------------------------------|
| `AitpAgent`        | `generate()`, `fromSeed(buffer)`, `aid`, `buildManifest(opts)`, `newSession()`, `newResponder()`, `verifyTct(tctJson, requiredGrant)` |
| `InitiatorSession` | `buildHello(peerManifest, grants)`, `processHelloAck(ack, sessionId)`, `complete(commitAck)`      |
| `ResponderSession` | `processHello(hello)` → `{ ackJson, sessionId }`, `processCommit(commit)` → `{ ackJson, tctJson }` |
| `TctIdentity`      | `peerAid`, `grants`, `expiresAt`, `jti`                                                          |

## Tests

```bash
npm install
npm run build:debug
npm test                 # node --test tests/*.mjs
```

The cross-language interop suite (Python ↔ Node) lives in
[`../interop`](../interop) — run it with `make interop` from the repo root.
