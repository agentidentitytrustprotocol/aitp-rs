// The loopback opt-in on `verifyManifestJson`, sessions and delegation.
// Mirrors bindings/aitp-py/tests/test_insecure_localhost.py.
//
// `handshake_endpoint` must be HTTPS (RFC-AITP-0003 §5 step 2). A plain-HTTP
// loopback endpoint verifies only under `insecureLocalhostDangerous`, and any
// other plain-HTTP endpoint never does.

import test from 'node:test';
import assert from 'node:assert/strict';

import { AitpAgent, JwksProvider, verifyDelegation, verifyManifestJson } from '../index.js';
import { HAS_MULTIHOP, verifyDelegationMultihop } from './_experimental.mjs';

const LOOPBACK = ['http://localhost:8100/aitp/handshake/', 'http://127.0.0.1:8100/aitp/handshake/'];
const NOT_LOOPBACK = [
  'http://example.com/aitp/handshake/',
  'http://playground:8000/aitp/handshake/',
  'http://localhost.example.com/aitp/handshake/',
  'http://192.168.1.10:8100/aitp/handshake/',
  'ftp://localhost/aitp/handshake/',
];
const CAP = 'demo.write';

const manifest = (agent, handshakeEndpoint) =>
  agent.buildManifest({ displayName: 'peer', handshakeEndpoint, offeredCaps: [CAP] });

const codeOf = (fn) => {
  try {
    fn();
  } catch (e) {
    return e.code;
  }
  return 'NO_ERROR';
};

for (const endpoint of LOOPBACK) {
  test(`verifyManifestJson needs the opt-in for ${endpoint}`, () => {
    const m = manifest(AitpAgent.generate(), endpoint);
    assert.equal(codeOf(() => verifyManifestJson(m)), 'malformed');
    verifyManifestJson(m, null, true);
  });
}

for (const endpoint of NOT_LOOPBACK) {
  test(`verifyManifestJson opt-in does not admit ${endpoint}`, () => {
    const m = manifest(AitpAgent.generate(), endpoint);
    assert.equal(codeOf(() => verifyManifestJson(m, null, true)), 'malformed');
  });
}

test('an unknown Manifest version keeps its code', () => {
  const env = JSON.parse(manifest(AitpAgent.generate(), 'https://a.example/h'));
  env.manifest.version = 'aitp/9.9';
  const bad = JSON.stringify(env);
  assert.equal(codeOf(() => verifyManifestJson(bad)), 'version_unknown');

  const [a, b] = [AitpAgent.generate(), AitpAgent.generate()];
  manifest(a, 'https://a.example/h');
  const sess = a.newSession(null, { pinnedKeys: [b.aid] });
  assert.equal(codeOf(() => sess.buildHello(bad, [CAP])), 'MANIFEST_VERSION_UNKNOWN');
});

function handshake(a, b, endpoint, optInA, optInB) {
  manifest(a, endpoint);
  const bManifest = manifest(b, endpoint);
  const sess = a.newSession(null, { pinnedKeys: [b.aid], insecureLocalhostDangerous: optInA });
  const rsess = b.newResponder(null, { pinnedKeys: [a.aid], insecureLocalhostDangerous: optInB });
  const hello = sess.buildHello(bManifest, [CAP]);
  const { ackJson, sessionId } = rsess.processHello(hello);
  const commit = sess.processHelloAck(ackJson, sessionId);
  const { ackJson: commitAck } = rsess.processCommit(commit, []);
  return sess.complete(commitAck, []);
}

test('a handshake over loopback completes with the opt-in on both sides', () => {
  const done = handshake(AitpAgent.generate(), AitpAgent.generate(), LOOPBACK[0], true, true);
  assert.ok(done.tct);
});

test('an initiator without the opt-in refuses a loopback peer', () => {
  const [a, b] = [AitpAgent.generate(), AitpAgent.generate()];
  assert.equal(codeOf(() => handshake(a, b, LOOPBACK[0], undefined, true)), 'MANIFEST_INVALID');
});

for (const [name, mutate, code] of [
  ['tampered', (m) => { m.display_name = 'tampered'; }, 'MANIFEST_SIGNATURE_INVALID'],
  ['bad expiry', (m) => { m.expires_at = 0; }, 'MANIFEST_INVALID'],
  ['unknown version', (m) => { m.version = 'aitp/99.0'; }, 'MANIFEST_VERSION_UNKNOWN'],
]) {
  test(`buildHello refuses an unverifiable peer Manifest: ${name}`, () => {
    const [a, b] = [AitpAgent.generate(), AitpAgent.generate()];
    manifest(a, 'https://a.example/h');
    const env = JSON.parse(manifest(b, 'https://b.example/h'));
    mutate(env.manifest);
    const s = a.newSession(null, { pinnedKeys: [b.aid] });
    assert.equal(codeOf(() => s.buildHello(JSON.stringify(env), [CAP])), code);
  });
}

test('buildHello codes a peer Manifest outside the wire grammar', () => {
  const [a, b] = [AitpAgent.generate(), AitpAgent.generate()];
  manifest(a, 'https://a.example/h');
  const env = JSON.parse(manifest(b, 'https://b.example/h'));
  const s = a.newSession(null, { pinnedKeys: [b.aid] });
  const withMember = (k, v) =>
    JSON.stringify({ manifest: { ...env.manifest, [k]: v } });
  assert.equal(codeOf(() => s.buildHello(withMember('display_name', null), [CAP])), 'MANIFEST_INVALID');
  assert.equal(codeOf(() => s.buildHello(withMember('brandnew', 1), [CAP])), 'UNKNOWN_FIELD');
  assert.equal(codeOf(() => s.buildHello('not json', [CAP])), 'MANIFEST_INVALID');
});

test('buildHello refuses a peer that does not accept this identity type', () => {
  const [a, b] = [AitpAgent.generate(), AitpAgent.generate()];
  manifest(a, 'https://a.example/h');
  const peer = b.buildManifest({
    displayName: 'b',
    handshakeEndpoint: 'https://b.example/h',
    offeredCaps: [CAP],
    acceptedIdentityTypes: ['oidc'],
  });
  const s = a.newSession(null, { pinnedKeys: [b.aid] });
  assert.equal(codeOf(() => s.buildHello(peer, [CAP])), 'INCOMPATIBLE_IDENTITY_TYPE');
});

test('buildHello verifies before minting an OIDC token', () => {
  const [a, b] = [AitpAgent.generate(), AitpAgent.generate()];
  a.buildManifest({
    displayName: 'a',
    handshakeEndpoint: 'https://a.example/h',
    offeredCaps: [CAP],
    identityType: 'oidc',
    oidcIssuer: 'https://idp.example/',
    oidcSubject: 'a',
  });
  const env = JSON.parse(manifest(b, 'https://b.example/h'));
  env.manifest.display_name = 'tampered';
  let minted = false;
  const s = a.newSession(new JwksProvider({}), { pinnedKeys: [b.aid] });
  assert.throws(() =>
    s.buildHello(JSON.stringify(env), [CAP], () => {
      minted = true;
      return 'x';
    }),
  );
  assert.equal(minted, false);
});

test('buildHello checks the identity type before minting', () => {
  const [a, b] = [AitpAgent.generate(), AitpAgent.generate()];
  a.buildManifest({
    displayName: 'a',
    handshakeEndpoint: 'https://a.example/h',
    offeredCaps: [CAP],
    identityType: 'oidc',
    oidcIssuer: 'https://idp.example/',
    oidcSubject: 'a',
  });
  const peer = manifest(b, 'https://b.example/h');
  let minted = false;
  const s = a.newSession(new JwksProvider({}), { pinnedKeys: [b.aid] });
  const code = codeOf(() =>
    s.buildHello(peer, [CAP], () => {
      minted = true;
      return 'x';
    }),
  );
  assert.equal(code, 'INCOMPATIBLE_IDENTITY_TYPE');
  assert.equal(minted, false);
});

test('a session works after a refused buildHello', () => {
  const [a, b] = [AitpAgent.generate(), AitpAgent.generate()];
  manifest(a, 'https://a.example/h');
  const good = manifest(b, 'https://b.example/h');
  const env = JSON.parse(good);
  env.manifest.display_name = 'tampered';
  const s = a.newSession(null, { pinnedKeys: [b.aid] });
  assert.throws(() => s.buildHello(JSON.stringify(env), [CAP]));
  const r = b.newResponder(null, { pinnedKeys: [a.aid] });
  const { ackJson, sessionId } = r.processHello(s.buildHello(good, [CAP]));
  assert.ok(s.processHelloAck(ackJson, sessionId));
});

test('buildHello refuses a loopback peer before anything is sent', () => {
  const [a, b] = [AitpAgent.generate(), AitpAgent.generate()];
  manifest(a, LOOPBACK[0]);
  const peer = manifest(b, LOOPBACK[0]);
  const s = a.newSession(null, { pinnedKeys: [b.aid] });
  assert.equal(codeOf(() => s.buildHello(peer, [CAP])), 'MANIFEST_INVALID');
  const allowed = a.newSession(null, { pinnedKeys: [b.aid], insecureLocalhostDangerous: true });
  assert.ok(allowed.buildHello(peer, [CAP]));
});

test('a responder without the opt-in refuses a loopback peer', () => {
  const [a, b] = [AitpAgent.generate(), AitpAgent.generate()];
  assert.equal(codeOf(() => handshake(a, b, LOOPBACK[0], true, false)), 'MANIFEST_INVALID');
});

for (const endpoint of NOT_LOOPBACK) {
  test(`the session opt-in does not admit ${endpoint}`, () => {
    const [a, b] = [AitpAgent.generate(), AitpAgent.generate()];
    assert.equal(codeOf(() => handshake(a, b, endpoint, true, true)), 'MANIFEST_INVALID');
  });
}

// B holds A's voucher from a handshake over HTTPS Manifests, and delegates to C.
function delegation() {
  const [a, b, c] = [AitpAgent.generate(), AitpAgent.generate(), AitpAgent.generate()];
  manifest(b, 'https://b.example/aitp/handshake/');
  const aManifest = manifest(a, 'https://a.example/aitp/handshake/');
  const sess = b.newSession(null, { pinnedKeys: [a.aid] });
  const rsess = a.newResponder(null, { pinnedKeys: [b.aid] });
  const hello = sess.buildHello(aManifest, [CAP]);
  const { ackJson, sessionId } = rsess.processHello(hello);
  const commit = sess.processHelloAck(ackJson, sessionId);
  const { ackJson: commitAck } = rsess.processCommit(commit, []);
  const { grantVoucher } = sess.complete(commitAck, []);
  return { a, b, token: b.buildDelegation(grantVoucher, c.aid, [CAP]) };
}

test('verifyDelegation needs the opt-in for a loopback issuer', () => {
  const { a, b, token } = delegation();
  const issuer = manifest(b, LOOPBACK[0]);
  assert.throws(() => verifyDelegation(token, a.aid, [issuer], []));
  const verified = verifyDelegation(token, a.aid, [issuer], [], null, true);
  assert.deepEqual(verified.grants, [CAP]);
});

test('the delegation opt-in admits only loopback', () => {
  const { a, b, token } = delegation();
  const issuer = manifest(b, NOT_LOOPBACK[0]);
  assert.throws(() => verifyDelegation(token, a.aid, [issuer], [], null, true));
});

test('multi-hop verification takes the opt-in', { skip: !HAS_MULTIHOP }, () => {
  const { a, b, token } = delegation();
  const issuer = manifest(b, LOOPBACK[0]);
  assert.throws(() => verifyDelegationMultihop(token, a.aid, [issuer], null, []));
  const verified = verifyDelegationMultihop(token, a.aid, [issuer], null, [], null, true);
  assert.deepEqual(verified.grants, [CAP]);
});

test('an unknown-version Manifest does not fail the other issuers', () => {
  const [a, b, c] = [AitpAgent.generate(), AitpAgent.generate(), AitpAgent.generate()];
  const bManifest = manifest(b, 'https://b.example/aitp/handshake/');
  const aManifest = manifest(a, 'https://a.example/aitp/handshake/');
  const sess = b.newSession(null, { pinnedKeys: [a.aid] });
  const rsess = a.newResponder(null, { pinnedKeys: [b.aid] });
  const { ackJson, sessionId } = rsess.processHello(sess.buildHello(aManifest, [CAP]));
  const commit = sess.processHelloAck(ackJson, sessionId);
  const { ackJson: commitAck } = rsess.processCommit(commit, []);
  const { grantVoucher } = sess.complete(commitAck, []);
  const token = b.buildDelegation(grantVoucher, c.aid, [CAP]);
  const unknown = JSON.parse(manifest(AitpAgent.generate(), 'https://o.example/h'));
  unknown.manifest.version = 'aitp/99.0';
  const ok = verifyDelegation(token, a.aid, [JSON.stringify(unknown), bManifest], []);
  assert.deepEqual(ok.grants, [CAP]);
  const alone = JSON.parse(bManifest);
  alone.manifest.version = 'aitp/99.0';
  assert.throws(() => verifyDelegation(token, a.aid, [JSON.stringify(alone)], []));
});
