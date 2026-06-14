// TCT renewal (RFC-AITP-0005 §10) — Node SDK.
//
// Gated by the `renewal` Cargo feature. Build the dev
// artifact with `npm run build`. This test no-ops
// itself when the binding was built without the feature.

import test from 'node:test';
import assert from 'node:assert/strict';

import { AitpAgent } from '../index.js';
import { decodeJwsPayload } from './_jws.mjs';

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
  // `complete()` yields { tct, claims, grantVoucher? }; the renewal API
  // takes the opaque TCT token string.
  const bHeld = sess.complete(commitAck).tct;
  return { a, b, bHeld };
}

test('TCT renewal round-trips', { skip: !HAS_RENEWAL }, () => {
  const { a, b, bHeld } = issuedPair();
  const req = b.buildRenewalRequest(bHeld);
  const now = Math.floor(Date.now() / 1000);
  const fresh = a.processRenewalRequest(req, now + 86_400, 3600);
  // Both TCTs are compact-JWS tokens; decode the claims to compare.
  const oldT = decodeJwsPayload(bHeld);
  const newT = decodeJwsPayload(fresh);
  assert.notEqual(newT.jti, oldT.jti);
  assert.equal(newT.sub, oldT.sub);
  assert.deepEqual(newT.grants, oldT.grants);
});

test(
  'renewal with wrong holder key rejected',
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
