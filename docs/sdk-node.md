# Node SDK — feature guide

This page is a feature-by-feature pointer into [`bindings/aitp-node`](../bindings/aitp-node).
Each section names the RFC, the Cargo feature flag (if any), and a
~5-line example. Full TypeScript signatures live in the auto-generated
`bindings/aitp-node/index.d.ts`.

The Python SDK has a symmetric surface; see [`sdk-python.md`](sdk-python.md).

## Build

```bash
npm run build:debug                  # default surface
npm run build:experimental:debug     # adds the draft/opt-in features
# Release variants:
npm run build
npm run build:experimental
```

## Default surface

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
const held = s.complete(cack);
// v0.2: completion exposes the peer-issued TCT (opaque compact JWS), its
// decoded claims, and the optional companion grant voucher.
const tctJws     = held.tct.token;       // compact JWS string — store / present this
const claims     = held.tct.claims;      // decoded {ver, jti, iss, sub, aud, iat, exp, grants, cnf}
const voucherJws = held.grantVoucher;    // compact JWS string, or null if delegation disallowed
```

### TCT verification (RFC-AITP-0005 §9)

A TCT is an opaque compact JWS string. `verifyTct` parses it strictly
(`typ == aitp-tct+jwt`, AID-pinned `alg`, signature over the transmitted bytes)
and returns the verified identity.

```javascript
// Holder-receipt model (default).
const ident = agent.verifyTct(tctJws, 'demo.echo');

// Presented-TCT model — for a resource server checking a TCT a peer
// presented in `X-AITP-TCT`. Pass the TCT's own subject AID (== sub).
const presented = agent.verifyTct(tctJws, 'demo.echo', peerAid);

// Optional revocation gate (F-1): pass the set of revoked TCT `jti`s; a TCT
// whose jti is listed is rejected with TCT_REVOKED.
const gated = agent.verifyTct(tctJws, 'demo.echo', undefined, ['<revoked-uuid>']);
```

A TCT also verifies under any stock JOSE library (node `jose`) given only the
issuer's public key. See [architecture.md](architecture.md#debugging-a-tct).

### Delegation (RFC-AITP-0006)

Delegation embeds the **grant voucher** A minted alongside B's TCT — pass the
voucher string B holds; nothing is reconstructed.

```javascript
import { verifyDelegation } from 'aitp';

const delegationJws = b.buildDelegation(voucherBHoldsFromA, c.aid, cPubkey, ['demo.write']);
const verified = verifyDelegation(delegationJws, a.aid);
const freshTctForC = a.issueTctForDelegatee(verified);   // compact JWS string
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
verifier on the other side accepts them. **Caveat:** the manifest's
`pinned_key` identity_hint embeds an Ed25519 public key only, so P-256
agents must use `identityType: 'oidc'`.

## Experimental surface (Cargo `--features experimental`)

### TCT renewal (RFC-AITP-0013 / RFC-AITP-0004 §8.1, feature `experimental-renewal`)

```javascript
// currentTct is the holder's TCT compact JWS string.
const req = holder.buildRenewalRequest(currentTct);
const { tct: freshTct, grantVoucher } = issuer.processRenewalRequest(
  req, manifestExpUnixSecs, newTtlSecs,
);
```

### Session Trust Bundle (RFC-AITP-0010, feature `experimental-bundle`)

```javascript
import { SessionBundleBuilder, verifySessionBundle } from 'aitp';

const envelope = new SessionBundleBuilder(coordinator)
  .participant(alice.aid, aliceTct)   // aliceTct: compact JWS string
  .participant(bob.aid, bobTct)       // bobTct:   compact JWS string
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
