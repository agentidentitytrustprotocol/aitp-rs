// TCT renewal (RFC-AITP-0005 §10) — Node SDK.
//
// Gated by the `experimental-renewal` Cargo feature. Build the dev
// artifact with `npm run build:experimental:debug`. This test no-ops
// itself when the binding was built without the feature.

import test from 'node:test';
import assert from 'node:assert/strict';

import { AitpAgent } from '../index.js';

const HAS_RENEWAL =
  typeof AitpAgent.generate().buildRenewalRequest === 'function';

function issuedPair() {
  const a = AitpAgent.generate();
  const b = AitpAgent.generate();
  const aManifest = a.buildManifest({
    displayName: 'A',
    handshakeEndpoint: 'http://localhost:9301/aitp/handshake/',
    offeredCaps: ['demo.write'],
  });
  b.buildManifest({
    displayName: 'B',
    handshakeEndpoint: 'http://localhost:9302/aitp/handshake/',
    offeredCaps: ['demo.echo'],
  });
  // B initiates against A → at the end B holds A-issued TCT.
  const sess = b.newSession();
  const rsess = a.newResponder();
  const hello = sess.buildHello(aManifest, ['demo.write']);
  const { ackJson: helloAck, sessionId } = rsess.processHello(hello);
  const commit = sess.processHelloAck(helloAck, sessionId);
  const { ackJson: commitAck } = rsess.processCommit(commit);
  const bHeld = sess.complete(commitAck);
  return { a, b, bHeld };
}

test('TCT renewal round-trips (experimental)', { skip: !HAS_RENEWAL }, () => {
  const { a, b, bHeld } = issuedPair();
  const req = b.buildRenewalRequest(bHeld);
  const now = Math.floor(Date.now() / 1000);
  const fresh = a.processRenewalRequest(req, now + 86_400, 3600);
  const oldT = JSON.parse(bHeld);
  const newT = JSON.parse(fresh);
  assert.notEqual(newT.tct.jti, oldT.tct.jti);
  assert.equal(newT.tct.subject, oldT.tct.subject);
  assert.deepEqual(newT.tct.grants, oldT.tct.grants);
});

test(
  'renewal with wrong holder key rejected (experimental)',
  { skip: !HAS_RENEWAL },
  () => {
    const { a, bHeld } = issuedPair();
    const attacker = AitpAgent.generate();
    const badReq = attacker.buildRenewalRequest(bHeld);
    const now = Math.floor(Date.now() / 1000);
    assert.throws(() =>
      a.processRenewalRequest(badReq, now + 86_400, 3600),
    );
  },
);
