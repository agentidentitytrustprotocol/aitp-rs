// TctStore — cached TCT verification (Node SDK).
//
// A byte-identical, already-verified, still-valid TCT skips the signature
// check; tampered bytes miss the cache and are fully (re-)verified.

import test from 'node:test';
import assert from 'node:assert/strict';

import { AitpAgent, TctStore } from '../index.js';

const GRANT = 'demo.write';

function heldTct() {
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
    offeredCaps: [GRANT],
  });
  const sess = initiator.newSession();
  const rsess = responder.newResponder();
  const hello = sess.buildHello(respManifest, [GRANT]);
  const { ackJson: helloAck, sessionId } = rsess.processHello(hello);
  const commit = sess.processHelloAck(helloAck, sessionId);
  const { ackJson: commitAck } = rsess.processCommit(commit);
  const tct = sess.complete(commitAck);
  return { initiator, tct };
}

test('cached verify matches cold verify and populates', () => {
  const { initiator, tct } = heldTct();
  const store = new TctStore(128);
  assert.equal(store.len(), 0);

  const cold = initiator.verifyTct(tct, GRANT);
  const warm = initiator.verifyTctCached(tct, GRANT, store);
  assert.equal(warm.peerAid, cold.peerAid);
  assert.deepEqual(warm.grants, cold.grants);
  assert.equal(warm.jti, cold.jti);
  assert.equal(store.len(), 1);

  // A cache hit returns the same identity.
  const again = initiator.verifyTctCached(tct, GRANT, store);
  assert.equal(again.jti, cold.jti);
  assert.equal(store.len(), 1);
});

test('tampered bytes miss the cache and are rejected', () => {
  // Security: a tampered envelope hashes differently, so it cannot be served
  // from a cache populated by the genuine token — it is fully re-verified and
  // fails.
  const { initiator, tct } = heldTct();
  const store = new TctStore(128);
  initiator.verifyTctCached(tct, GRANT, store);

  const env = JSON.parse(tct);
  const sig = env.tct.signature;
  env.tct.signature = (sig[0] !== 'A' ? 'A' : 'B') + sig.slice(1);
  const tampered = JSON.stringify(env);

  assert.throws(() => initiator.verifyTctCached(tampered, GRANT, store));
});

test('missing grant rejected even with a warm cache', () => {
  const { initiator, tct } = heldTct();
  const store = new TctStore(128);
  initiator.verifyTctCached(tct, GRANT, store);
  assert.throws(() => initiator.verifyTctCached(tct, 'demo.not-granted', store));
});

test('eviction respects maxEntries', () => {
  const store = new TctStore(1);
  const a = heldTct();
  const b = heldTct();
  a.initiator.verifyTctCached(a.tct, GRANT, store);
  assert.equal(store.len(), 1);
  b.initiator.verifyTctCached(b.tct, GRANT, store);
  assert.equal(store.len(), 1);
});

test('maxEntries=0 throws', () => {
  assert.throws(() => new TctStore(0));
});

test('clear empties the cache', () => {
  const { initiator, tct } = heldTct();
  const store = new TctStore(128);
  initiator.verifyTctCached(tct, GRANT, store);
  assert.equal(store.len(), 1);
  store.clear();
  assert.equal(store.len(), 0);
});
