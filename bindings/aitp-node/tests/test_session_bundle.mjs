// Session Trust Bundle (RFC-AITP-0010) — Node SDK.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  AitpAgent,
  SessionBundleBuilder,
  verifySessionBundle,
} from '../index.js';
import { decodeJwsPayload } from './_jws.mjs';

const HAS_BUNDLE = typeof SessionBundleBuilder === 'function';

function handshakeToCoordinator(participant, coordinator, coordManifest) {
  const sess = participant.newSession(null, { pinnedKeys: [coordinator.aid] });
  const rsess = coordinator.newResponder(null, { pinnedKeys: [participant.aid] });
  const hello = sess.buildHello(coordManifest, ['session.member']);
  const { ackJson: helloAck, sessionId } = rsess.processHello(hello);
  const commit = sess.processHelloAck(helloAck, sessionId);
  const { ackJson: commitAck } = rsess.processCommit(commit);
  // `complete()` yields { tct, claims, ... }; the bundle takes the
  // opaque TCT token string.
  return sess.complete(commitAck).tct;
}

function setup() {
  const coord = AitpAgent.generate();
  const alice = AitpAgent.generate();
  const bob = AitpAgent.generate();
  const coordManifest = coord.buildManifest({
    displayName: 'coordinator',
    handshakeEndpoint: 'http://localhost:9601/aitp/handshake/',
    offeredCaps: ['session.member'],
    // Caps every participant TCT (RFC-AITP-0005 §10.4): outlive them.
    ttlSecs: 24 * 3600,
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
  return { coord, coordManifest, alice, bob, aliceTct, bobTct };
}

test('session bundle round-trips', { skip: !HAS_BUNDLE }, () => {
  const { coord, coordManifest, alice, bob, aliceTct, bobTct } = setup();
  const envelope = new SessionBundleBuilder(coord)
    .participant(alice.aid, aliceTct)
    .participant(bob.aid, bobTct)
    .build();
  const parsed = JSON.parse(envelope);
  assert.equal(parsed.session_bundle.coordinator, coord.aid);

  const outcome = verifySessionBundle(envelope, alice.aid, coordManifest);
  assert.equal(outcome.kind, 'clear');
  assert.ok(outcome.activeAids.includes(alice.aid));
  assert.ok(outcome.activeAids.includes(bob.aid));
  assert.equal(outcome.droppedAids.length, 0);

  const outsider = AitpAgent.generate();
  assert.throws(() => verifySessionBundle(envelope, outsider.aid, coordManifest));
});

// RFC-AITP-0010 §5 step 5 (#238): the coordinator Manifest is
// mandatory and must designate the bundle's coordinator.
test('coordinator Manifest is required and checked', { skip: !HAS_BUNDLE }, () => {
  const { coord, alice, bob, aliceTct, bobTct } = setup();
  const envelope = new SessionBundleBuilder(coord)
    .participant(alice.aid, aliceTct)
    .participant(bob.aid, bobTct)
    .build();

  // No AID-only fallback: omitting it (or passing null) throws.
  assert.throws(() => verifySessionBundle(envelope, alice.aid));
  assert.throws(() => verifySessionBundle(envelope, alice.aid, null));

  // A Manifest for another AID resolves no coordinator key.
  const outsider = AitpAgent.generate();
  const otherManifest = outsider.buildManifest({
    displayName: 'outsider',
    handshakeEndpoint: 'http://localhost:9604/aitp/handshake/',
    offeredCaps: ['x'],
  });
  assert.throws(
    () => verifySessionBundle(envelope, alice.aid, otherManifest),
    /coordinator manifest aid does not match/,
  );

  // A malformed Manifest is rejected before verification.
  assert.throws(
    () => verifySessionBundle(envelope, alice.aid, '{}'),
    /invalid coordinator manifest JSON/,
  );
});

// Regression: napi Ref leak. Previously, passing a revocationCheck
// callback and having verifySessionBundle error out BEFORE iterating
// participants (e.g. envelope JSON malformed) would panic napi-rs's
// Ref drop impl. Trigger the early-error path here.
test(
  'revocationCheck Ref unrefs cleanly on early error',
  { skip: !HAS_BUNDLE },
  () => {
    let called = false;
    const cb = (_jti) => {
      called = true;
      return false;
    };
    assert.throws(() =>
      verifySessionBundle('not json', 'aid:pubkey:irrelevant', '{}', null, cb),
    );
    assert.equal(called, false);
  },
);

test(
  'revocation drops a participant',
  { skip: !HAS_BUNDLE },
  () => {
    const { coord, coordManifest, alice, bob, aliceTct, bobTct } = setup();
    const envelope = new SessionBundleBuilder(coord)
      .participant(alice.aid, aliceTct)
      .participant(bob.aid, bobTct)
      .build();
    const revokedJti = decodeJwsPayload(bobTct).jti;
    const outcome = verifySessionBundle(
      envelope,
      alice.aid,
      coordManifest,
      null,
      (jti) => jti === revokedJti,
    );
    assert.equal(outcome.kind, 'degraded');
    assert.ok(outcome.activeAids.includes(alice.aid));
    assert.ok(outcome.droppedAids.includes(bob.aid));
  },
);
