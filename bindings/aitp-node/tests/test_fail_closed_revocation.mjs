// Fail-closed revocation (RFC-AITP-0008 §3.1) — Node SDK.
//
// Revocation defaults to `fail_closed`: a verifier with no `revokedJtis` has
// no revocation status, and an unknown status counts as revoked. The failure
// carries the same `code` as a listed jti, and its message says "revocation
// source unavailable" so the two stay distinguishable. `'fail_open'` is the
// explicit opt-out.

import test from 'node:test';
import assert from 'node:assert/strict';

import { AitpAgent, TctStore } from '../index.js';

const GRANT = 'demo.write';
const UNAVAILABLE = /revocation source unavailable/;

const revoked = (code, message = /./) => (err) =>
  err.code === code && message.test(err.message);

function agents() {
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
    offeredCaps: [GRANT],
  });
  const sess = initiator.newSession(null, { pinnedKeys: [responder.aid] });
  const rsess = responder.newResponder(null, { pinnedKeys: [initiator.aid] });
  const hello = sess.buildHello(respManifest, [GRANT]);
  const { ackJson: helloAck, sessionId } = rsess.processHello(hello);
  const commit = sess.processHelloAck(helloAck, sessionId);
  return { initiator, sess, rsess, commit };
}

function heldTct() {
  const { initiator, sess, rsess, commit } = agents();
  const { ackJson } = rsess.processCommit(commit, []);
  return { initiator, tct: sess.complete(ackJson, []).tct };
}

// ── TCT verification ─────────────────────────────────────────────────────

test('verifyTct without revokedJtis fails closed', () => {
  const { initiator, tct } = heldTct();
  assert.throws(() => initiator.verifyTct(tct, GRANT), revoked('TCT_REVOKED', UNAVAILABLE));
  assert.throws(
    () => initiator.verifyTct(tct, GRANT, null, undefined, 'fail_closed'),
    revoked('TCT_REVOKED', UNAVAILABLE),
  );
});

test('a listed jti has the same code and a different message', () => {
  const { initiator, tct } = heldTct();
  const { jti } = initiator.verifyTct(tct, GRANT, null, []);
  assert.throws(
    () => initiator.verifyTct(tct, GRANT, null, [jti]),
    (err) => err.code === 'TCT_REVOKED' && !UNAVAILABLE.test(err.message),
  );
});

test("revocation: 'fail_open' opts out; a supplied list still wins", () => {
  const { initiator, tct } = heldTct();
  const { jti, grants } = initiator.verifyTct(tct, GRANT, null, undefined, 'fail_open');
  assert.ok(grants.includes(GRANT));
  assert.throws(
    () => initiator.verifyTct(tct, GRANT, null, [jti], 'fail_open'),
    revoked('TCT_REVOKED'),
  );
});

test('an unknown revocation mode throws', () => {
  const { initiator, tct } = heldTct();
  assert.throws(() => initiator.verifyTct(tct, GRANT, null, [], 'maybe'), /fail_open/);
});

test('a warm cache entry does not bypass fail_closed', () => {
  const { initiator, tct } = heldTct();
  const store = new TctStore(16);
  initiator.verifyTctCached(tct, GRANT, store, null, []);
  assert.equal(store.len(), 1);
  assert.throws(
    () => initiator.verifyTctCached(tct, GRANT, store),
    revoked('TCT_REVOKED', UNAVAILABLE),
  );
  const ident = initiator.verifyTctCached(tct, GRANT, store, null, undefined, 'fail_open');
  assert.ok(ident.grants.includes(GRANT));
});

// ── Handshake completion ─────────────────────────────────────────────────

test('processCommit without revokedJtis fails closed', () => {
  const { rsess, commit } = agents();
  assert.throws(() => rsess.processCommit(commit), revoked('TCT_REVOKED', UNAVAILABLE));
});

test('complete without revokedJtis fails closed', () => {
  const { sess, rsess, commit } = agents();
  const { ackJson } = rsess.processCommit(commit, []);
  assert.throws(() => sess.complete(ackJson), revoked('TCT_REVOKED', UNAVAILABLE));
});

test("handshake completes under revocation: 'fail_open'", () => {
  const { sess, rsess, commit } = agents();
  const { ackJson } = rsess.processCommit(commit, undefined, 'fail_open');
  assert.equal(sess.complete(ackJson, undefined, 'fail_open').tct.split('.').length, 3);
});
