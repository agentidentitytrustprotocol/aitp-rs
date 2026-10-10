// Executable documentation samples — Node SDK.
//
// Every ```javascript block in `docs/sdk-node.md` and the Usage block of
// `bindings/aitp-node/README.md` is pasted below VERBATIM (indented one
// level, minus its `import` lines, which live at the top of this file and
// point at `../index.js` instead of the package name), inside a function
// whose header comment names the doc section it comes from. The blocks form
// one connected flow, so each section function receives the names the
// earlier sections defined.
//
// Two guards keep docs and binding in step:
//   * running the sections exercises every documented call against the
//     built binding, so an API change breaks this file;
//   * the "every doc block is executed here" test re-reads the docs and
//     asserts each block appears here unchanged, so a doc edit breaks this
//     file until the copy here is updated (and thereby executed).
//
// A doc block whose first line is `// not executed: <reason>` is exempt from
// the second guard. Hermetic: the OIDC IdP is an in-process mock and the
// certificates are generated in-test. No network.
//
// Build first:  npm run build:debug
// Then run:     node --test tests/*.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { generateKeyPairSync, randomUUID, sign as cryptoSign } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import forge from 'node-forge';

import {
  AitpAgent,
  JwksProvider,
  SessionBundleBuilder,
  SpkiPinVerifier,
  TctStore,
  computeAidJkt,
  computeSpkiHash,
  revocationSigningBytes,
  verifyDelegation,
  verifyDelegationMultihop,
  verifyManifestJson,
  verifyRevocationList,
  verifySessionBundle,
} from '../index.js';

const THIS_FILE = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(THIS_FILE), '../../..');
const DOC = path.join(REPO_ROOT, 'docs', 'sdk-node.md');
const README = path.join(REPO_ROOT, 'bindings', 'aitp-node', 'README.md');

const HAS_RENEWAL = typeof AitpAgent.generate().buildRenewalRequest === 'function';
const HAS_MULTIHOP = typeof verifyDelegationMultihop === 'function';
const HAS_BUNDLE = typeof SessionBundleBuilder === 'function';
const HAS_PINNING = typeof computeSpkiHash === 'function';

/** Run `fn`, returning [its result, the lines it console.log'd]. */
function captureLogs(fn) {
  const lines = [];
  const original = console.log;
  console.log = (...args) =>
    lines.push(args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' '));
  try {
    return [fn(), lines];
  } finally {
    console.log = original;
  }
}

// ── Test doubles the doc blocks assume (`myIdp`, `idpJwk`, certs) ──────────

function mockIdp() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const x = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
  const jwk = { kty: 'OKP', crv: 'Ed25519', x, kid: 'k1', alg: 'EdDSA', use: 'sig' };
  const mintJwtSync = ({ sub, aud, nonce, cnfJkt }) => {
    const now = Math.floor(Date.now() / 1000);
    const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const signingInput = `${enc({ alg: 'EdDSA', typ: 'JWT', kid: 'k1' })}.${enc({
      iss: 'https://idp.example/', sub, aud, iat: now, exp: now + 600, nonce, cnf: { jkt: cnfJkt },
    })}`;
    return `${signingInput}.${cryptoSign(null, Buffer.from(signingInput), privateKey).toString('base64url')}`;
  };
  return { jwk, mintJwtSync };
}

function selfSignedDer() {
  // Same approach as tests/test_pinning.mjs.
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + 86_400_000);
  const attrs = [{ name: 'commonName', value: 'docs.example' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), 'binary');
}

// ── docs/sdk-node.md sections, in page order ───────────────────────────────

function mutualHandshake() {
  // docs/sdk-node.md § Mutual handshake (RFC-AITP-0004)
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
  return { alice, bob, bobManifest, s, r, bobSide, held, tctJws, claims, voucherJws };
}

function tctVerification(ns) {
  // docs/sdk-node.md § TCT verification (RFC-AITP-0005 §7.2)
  const { alice, bob, tctJws } = ns;
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
  return { ...ns, ident, presented };
}

function cachedVerification(ns) {
  // docs/sdk-node.md § TCT verification › Cached verification (`TctStore`)
  const { alice, tctJws } = ns;
  const store = new TctStore(1024);
  alice.verifyTctCached(tctJws, 'demo.echo', store);
  alice.verifyTctCached(tctJws, 'demo.echo', store);   // signature check skipped
  console.log(store.len());   // 1
  return { ...ns, store };
}

function delegation(ns) {
  // docs/sdk-node.md § Delegation (RFC-AITP-0006)
  const { alice, bob, voucherJws } = ns;
  const carol = AitpAgent.generate();
  // alice delegates part of what bob granted her to carol.
  const delegationJws = alice.buildDelegation(voucherJws, carol.aid, ['demo.echo']);

  // bob (the original grantor) verifies and mints carol a TCT of her own.
  const revoked = [];   // bob's deny list, e.g. jtis from verified revocation snapshots
  const verified = verifyDelegation(delegationJws, bob.aid, revoked);
  const carolTct = bob.issueTctForDelegatee(verified);   // bare compact-JWS string
  console.log(carol.verifyTct(carolTct, 'demo.echo').peerAid === bob.aid);   // true
  return { ...ns, carol, delegationJws, revoked, verified, carolTct };
}

function manifestVerification(ns) {
  // docs/sdk-node.md § Manifest verification
  const { bobManifest } = ns;
  verifyManifestJson(bobManifest);   // returns undefined on success

  try {
    verifyManifestJson(bobManifest, 4_102_444_800);   // year 2100
  } catch (err) {
    console.log(err.code);   // expired
  }
  return ns;
}

function revocationLists(ns) {
  // docs/sdk-node.md § Revocation lists (RFC-AITP-0008)
  const { alice, bob, revoked } = ns;
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
  return { ...ns, snapshot, signedBytes };
}

function oidcIdentity(ns) {
  // docs/sdk-node.md § OIDC identity (RFC-AITP-0002)
  const { bob, bobManifest } = ns;
  const myIdp = mockIdp();
  const idpJwk = myIdp.jwk;
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
  return { ...ns, dave, sess, responder, oidcAck };
}

function p256Suite(ns) {
  // docs/sdk-node.md § P-256 signing suite (RFC-AITP-0001 §5.4.3)
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
  return { ...ns, erin, erinAgain };
}

function tctRenewal(ns) {
  // docs/sdk-node.md § Additional capabilities › TCT renewal (feature `renewal`)
  const { alice, bob, tctJws } = ns;
  const req = alice.buildRenewalRequest(tctJws);   // the held TCT compact JWS
  const freshTct = bob.processRenewalRequest(
    req, Math.floor(Date.now() / 1000) + 86_400, 3600,
  );   // bare compact-JWS string — no grant voucher
  return { ...ns, freshTct };
}

function multihop(ns) {
  // docs/sdk-node.md § Additional capabilities › Multi-hop delegation
  const { bob, delegationJws, revoked } = ns;
  const verifiedMultihop = verifyDelegationMultihop(delegationJws, bob.aid, 3, revoked);
  return { ...ns, verifiedMultihop };
}

function sessionBundle(ns) {
  // docs/sdk-node.md § Additional capabilities › Session Trust Bundle
  const { alice, bob, carol, tctJws, carolTct, revoked } = ns;
  const bundle = new SessionBundleBuilder(bob)   // bob coordinates
    .sessionId(randomUUID())                     // optional; defaults to a fresh UUID
    .issuedAt(Math.floor(Date.now() / 1000))     // optional; defaults to now
    .participant(alice.aid, tctJws)              // TCTs bob issued to each member
    .participant(carol.aid, carolTct)
    .build();
  const outcome = verifySessionBundle(bundle, alice.aid);
  console.log(outcome.kind);   // clear  (fields: kind, activeAids, droppedAids)

  const checked = verifySessionBundle(bundle, alice.aid, null, (jti) => revoked.includes(jti));
  return { ...ns, bundle, outcome, checked };
}

function spkiPinning() {
  // docs/sdk-node.md § Additional capabilities › SPKI cert pinning
  const certDerBuffer = selfSignedDer();
  const otherCertDer = selfSignedDer();
  const pin = computeSpkiHash(certDerBuffer);       // 32-byte Buffer
  const verifier = new SpkiPinVerifier([pin]);
  console.log(verifier.isPinned(certDerBuffer), verifier.isPinned(otherCertDer));   // true false
  return { pin, verifier };
}

function readmeUsage() {
  // bindings/aitp-node/README.md § Usage
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
  return { responder, completed, ident };
}

const throughDelegation = () => delegation(mutualHandshake());

// ── Tests ──────────────────────────────────────────────────────────────────

test('docs: mutual handshake', () => {
  const ns = mutualHandshake();
  assert.equal(typeof ns.tctJws, 'string');
  assert.equal(ns.tctJws.split('.').length, 3);
  assert.deepEqual(Object.keys(ns.claims).sort(), ['aud', 'exp', 'grants', 'iat', 'iss', 'jti', 'sub']);
  assert.equal(ns.claims.iss, ns.bob.aid);
  assert.equal(typeof ns.voucherJws, 'string');
  assert.equal(typeof ns.bobSide.tct, 'string');
  assert.equal(ns.bobSide.claims.iss, ns.alice.aid);
});

test('docs: TCT verification', () => {
  const [ns, logs] = captureLogs(() => tctVerification(mutualHandshake()));
  assert.equal(logs[0], 'true ["demo.echo"]');
  assert.match(logs[1], /^TCT verification failed/);
  // Documented: TCT failures carry napi's generic code, not an AITP one.
  assert.throws(
    () => ns.alice.verifyTct(ns.tctJws, 'demo.echo', null, [ns.ident.jti]),
    (e) => e instanceof Error && e.code === 'GenericFailure',
  );
  assert.equal(ns.presented.peerAid, ns.bob.aid);
});

test('docs: cached verification', () => {
  const [, logs] = captureLogs(() => cachedVerification(mutualHandshake()));
  assert.deepEqual(logs, ['1']);
});

test('docs: delegation', () => {
  const [ns, logs] = captureLogs(throughDelegation);
  assert.deepEqual(logs, ['true']);
  assert.equal(ns.carolTct.split('.').length, 3);
  assert.equal(ns.verified.delegatee, ns.carol.aid);
});

test('docs: manifest verification', () => {
  const [ns, logs] = captureLogs(() => manifestVerification(mutualHandshake()));
  assert.deepEqual(logs, ['expired']);
  assert.throws(() => verifyManifestJson(ns.bobManifest, 4_102_444_800), (e) => e.code === 'expired');
  // Documented in the same section: unparseable JSON is `malformed`.
  assert.throws(() => verifyManifestJson('not json'), (e) => e.code === 'malformed');
});

test('docs: revocation lists', () => {
  const [ns, logs] = captureLogs(() => revocationLists(throughDelegation()));
  assert.equal(logs.at(-1), 'issuer_mismatch');
  assert.equal(ns.revoked.length, 1);
  assert.ok(Buffer.isBuffer(ns.signedBytes));
});

test('docs: OIDC identity', () => {
  const ns = oidcIdentity(mutualHandshake());
  const commit = ns.sess.processHelloAck(ns.oidcAck.ackJson, ns.oidcAck.sessionId);
  const { ackJson } = ns.responder.processCommit(commit);
  assert.equal(ns.sess.complete(ackJson).tct.split('.').length, 3);
});

test('docs: P-256 signing suite', () => {
  const [ns, logs] = captureLogs(() => p256Suite(mutualHandshake()));
  assert.ok(ns.erin.aid.startsWith('aid:pubkey:p256:'));
  assert.equal(ns.erinAgain.aid, AitpAgent.fromSeed(Buffer.alloc(32, 7), { suite: 'p256' }).aid);
  assert.match(logs[0], /not supported/);
});

test('docs: TCT renewal', { skip: !HAS_RENEWAL }, () => {
  const ns = tctRenewal(mutualHandshake());
  assert.equal(typeof ns.freshTct, 'string');
  assert.equal(ns.freshTct.split('.').length, 3);
  assert.notEqual(ns.freshTct, ns.tctJws);
});

test('docs: multi-hop delegation', { skip: !HAS_MULTIHOP }, () => {
  const [ns] = captureLogs(() => multihop(throughDelegation()));
  assert.equal(ns.verifiedMultihop.delegatee, ns.carol.aid);
});

test('docs: session trust bundle', { skip: !HAS_BUNDLE }, () => {
  const [ns, logs] = captureLogs(() => sessionBundle(revocationLists(throughDelegation())));
  assert.equal(logs.at(-1), 'clear');
  assert.equal(ns.checked.kind, 'clear'); // nothing in `revoked` names a member TCT
});

test('docs: SPKI cert pinning', { skip: !HAS_PINNING }, () => {
  const [, logs] = captureLogs(spkiPinning);
  assert.deepEqual(logs, ['true false']);
});

test('docs: README usage', () => {
  const [ns, logs] = captureLogs(readmeUsage);
  assert.equal(ns.ident.peerAid, ns.responder.aid);
  assert.match(logs[0], /demo\.write/);
});

// ── Drift guard: every doc block must be pasted (and so executed) above ────

// Substring match: catches changed arguments and new blocks; deleting only the
// first/last line of a block, or editing the import line, is not detected.
function docBlocks(file) {
  let text = readFileSync(file, 'utf8');
  if (file === README) {
    // Only the README's Usage section is mirrored.
    text = text.split('## Usage')[1].split('\n## ')[0];
  }
  const blocks = [...text.matchAll(/^```javascript\n([\s\S]*?)^```/gm)].map((m) => m[1]);
  return blocks
    .filter((b) => !b.startsWith('// not executed:'))
    .map((b) =>
      b
        .split('\n')
        .filter((line) => !/^import .* from '[^']+';$/.test(line))
        .join('\n')
        .replace(/^\n+/, ''),
    );
}

for (const file of [DOC, README]) {
  test(`docs: every javascript block in ${path.basename(file)} is executed here`, {
    skip: !existsSync(file) && `${file} not present (outside the repo checkout)`,
  }, () => {
    const source = readFileSync(THIS_FILE, 'utf8');
    const blocks = docBlocks(file);
    assert.ok(blocks.length > 0, `no javascript blocks found in ${file}`);
    for (const block of blocks) {
      const indented = block.replace(/^(?=.)/gm, '  ');
      assert.ok(
        source.includes(indented),
        `a javascript block in ${path.relative(REPO_ROOT, file)} is not mirrored verbatim in ` +
          `${path.basename(THIS_FILE)}; copy it into the matching section function:\n${block}`,
      );
    }
  });
}
