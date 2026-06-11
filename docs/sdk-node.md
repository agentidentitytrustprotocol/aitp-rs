# Node SDK — feature guide

This page is a feature-by-feature pointer into [`bindings/aitp-node`](../bindings/aitp-node).
Each section names the RFC, the Cargo feature flag (if any), and a
~5-line example. Full TypeScript signatures live in the auto-generated
`bindings/aitp-node/index.d.ts`.

The Python SDK has a symmetric surface; see [`sdk-python.md`](sdk-python.md).

## Build

```bash
npm run build:debug                  # default surface
npm run build:experimental:debug     # adds post-v0.1 features
# Release variants:
npm run build
npm run build:experimental
```

## Default surface (v0.1)

### Mutual handshake (RFC-AITP-0004)

```javascript
import { AitpAgent } from 'aitp';

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
const s = alice.newSession(), r = bob.newResponder();
const hello = s.buildHello(bobManifest, ['demo.echo']);
const { ackJson, sessionId } = r.processHello(hello);
const commit = s.processHelloAck(ackJson, sessionId);
const { ackJson: cack } = r.processCommit(commit);
const aliceHeld = s.complete(cack);
```

### TCT verification (RFC-AITP-0005 §9)

```javascript
// Holder-receipt model (default).
const ident = agent.verifyTct(tctJson, 'demo.echo');

// Presented-TCT model — for a resource server checking a TCT a peer
// presented in `X-AITP-TCT`. Pass the TCT's own subject AID.
const presented = agent.verifyTct(tctJson, 'demo.echo', peerAid);
```

### Delegation (RFC-AITP-0006)

```javascript
import { verifyDelegation } from 'aitp';

const env = b.buildDelegation(tctBHoldsFromA, c.aid, cPubkey, ['demo.write']);
const verified = verifyDelegation(env, a.aid);
const freshTctForC = a.issueTctForDelegatee(verified);
```

### Manifest verification

```javascript
import { verifyManifestJson } from 'aitp';
verifyManifestJson(manifestEnvelopeJson);   // throws on failure
```

### Revocation-list signing

```javascript
const envelope = issuer.signRevocationList(
  [{ jti: 'uuid-here', reason: 'compromised' }],
  600,
);
```

### OIDC identity (RFC-AITP-0002)

```javascript
import { JwksProvider } from 'aitp';

const jwks = new JwksProvider({ 'https://idp.example/': [myJwk] });
agent.buildManifest({
  ...,
  identityType: 'oidc',
  oidcIssuer: 'https://idp.example/',
  oidcSubject: 'alice',
});
const sess = agent.newSession(jwks);
const hello = sess.buildHello(peerManifest, grants, (nonce) =>
  myIdp.mintJwtSync({ nonce, sub: 'alice', aud: peerAid }),
);
```

The `oidcMintJwt` callback is **synchronous** — it runs on the libuv main
thread inside the `buildHello` / `processHello` call. Do not pass an async
function.

### P-256 signing suite (RFC-AITP-0001 §5.4.3)

```javascript
const agent = AitpAgent.generateP256();           // aid:pubkey:p256:<44>
const det   = AitpAgent.fromP256Seed(seedBuf);
```

P-256 produces `p256.<86-char-b64url>` signatures; an algorithm-agile
verifier on the other side accepts them. **Caveat:** the v0.1 manifest's
`pinned_key` identity_hint embeds an Ed25519 public key only, so P-256
agents must use `identityType: 'oidc'`.

## Experimental surface (Cargo `--features experimental`)

### TCT renewal (RFC-AITP-0013 / RFC-AITP-0004 §8.1, feature `experimental-renewal`)

```javascript
const req = holder.buildRenewalRequest(currentTctEnvelopeJson);
const fresh = issuer.processRenewalRequest(req, manifestExpUnixSecs, newTtlSecs);
```

### Session Trust Bundle (RFC-AITP-0010, feature `experimental-bundle`)

```javascript
import { SessionBundleBuilder, verifySessionBundle } from 'aitp';

const envelope = new SessionBundleBuilder(coordinator)
  .participant(alice.aid, aliceTct)
  .participant(bob.aid, bobTct)
  .build();
const outcome = verifySessionBundle(envelope, alice.aid);
// { kind: 'clear' | 'degraded', activeAids: [...], droppedAids: [...] }
```

### SPKI cert pinning (HPKP-style, feature `experimental-pinning`)

```javascript
import { computeSpkiHash, SpkiPinVerifier } from 'aitp';

const pin = computeSpkiHash(certDerBuffer);       // 32-byte Buffer
const verifier = new SpkiPinVerifier([pin]);
verifier.isPinned(otherCertDer);                  // true / false
```

Wire `verifier.isPinned()` into your HTTP client's `checkServerIdentity`
hook (e.g. `undici.Agent({ connect: { ... } })`). The SDK does no HTTP.

## Tests + interop

```bash
npm install
npm run build:experimental:debug
npm test                       # 25 binding tests (node --test)
cd ../interop && pytest -v     # 12 cross-language interop tests (1 deliberately skipped)
```
