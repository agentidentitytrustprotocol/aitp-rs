// Session Trust Bundle (RFC-AITP-0010) — Node SDK.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  AitpAgent,
  SessionBundleBuilder,
  verifySessionBundle,
} from '../index.js';

const HAS_BUNDLE = typeof SessionBundleBuilder === 'function';

function handshakeToCoordinator(participant, coordinator, coordManifest) {
  const sess = participant.newSession();
  const rsess = coordinator.newResponder();
  const hello = sess.buildHello(coordManifest, ['session.member']);
  const { ackJson: helloAck, sessionId } = rsess.processHello(hello);
  const commit = sess.processHelloAck(helloAck, sessionId);
  const { ackJson: commitAck } = rsess.processCommit(commit);
  return sess.complete(commitAck);
}

function setup() {
  const coord = AitpAgent.generate();
  const alice = AitpAgent.generate();
  const bob = AitpAgent.generate();
  const coordManifest = coord.buildManifest({
    displayName: 'coordinator',
    handshakeEndpoint: 'http://localhost:9601/aitp/handshake/',
    offeredCaps: ['session.member'],
  });
  alice.buildManifest({
    displayName: 'alice',
    handshakeEndpoint: 'http://localhost:9602/aitp/handshake/',
    offeredCaps: ['x'],
  });
  bob.buildManifest({
    displayName: 'bob',
    handshakeEndpoint: 'http://localhost:9603/aitp/handshake/',
    offeredCaps: ['x'],
  });
  const aliceTct = handshakeToCoordinator(alice, coord, coordManifest);
  const bobTct = handshakeToCoordinator(bob, coord, coordManifest);
  return { coord, alice, bob, aliceTct, bobTct };
}

test('session bundle round-trips (experimental)', { skip: !HAS_BUNDLE }, () => {
  const { coord, alice, bob, aliceTct, bobTct } = setup();
  const envelope = new SessionBundleBuilder(coord)
    .participant(alice.aid, aliceTct)
    .participant(bob.aid, bobTct)
    .build();
  const parsed = JSON.parse(envelope);
  assert.equal(parsed.session_bundle.coordinator, coord.aid);

  const outcome = verifySessionBundle(envelope, alice.aid);
  assert.equal(outcome.kind, 'clear');
  assert.ok(outcome.activeAids.includes(alice.aid));
  assert.ok(outcome.activeAids.includes(bob.aid));
  assert.equal(outcome.droppedAids.length, 0);

  const outsider = AitpAgent.generate();
  assert.throws(() => verifySessionBundle(envelope, outsider.aid));
});

// Regression: napi Ref leak. Previously, passing a revocationCheck
// callback and having verifySessionBundle error out BEFORE iterating
// participants (e.g. envelope JSON malformed) would panic napi-rs's
// Ref drop impl. Trigger the early-error path here.
test(
  'revocationCheck Ref unrefs cleanly on early error (experimental)',
  { skip: !HAS_BUNDLE },
  () => {
    let called = false;
    const cb = (_jti) => {
      called = true;
      return false;
    };
    assert.throws(() =>
      verifySessionBundle('not json', 'aid:pubkey:irrelevant', null, cb),
    );
    assert.equal(called, false);
  },
);

test(
  'revocation drops a participant (experimental)',
  { skip: !HAS_BUNDLE },
  () => {
    const { coord, alice, bob, aliceTct, bobTct } = setup();
    const envelope = new SessionBundleBuilder(coord)
      .participant(alice.aid, aliceTct)
      .participant(bob.aid, bobTct)
      .build();
    const revokedJti = JSON.parse(bobTct).tct.jti;
    const outcome = verifySessionBundle(
      envelope,
      alice.aid,
      null,
      (jti) => jti === revokedJti,
    );
    assert.equal(outcome.kind, 'degraded');
    assert.ok(outcome.activeAids.includes(alice.aid));
    assert.ok(outcome.droppedAids.includes(bob.aid));
  },
);
