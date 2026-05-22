// In-process exercise of the full four-message AITP handshake.
//
// Build first:  napi build --platform   (produces ../index.js + .node)
// Then run:     node --test tests/
//
// No HTTP — the JSON each step produces is fed straight into the peer.

import test from 'node:test';
import assert from 'node:assert/strict';

import { AitpAgent } from '../index.js';

function agents() {
  const initiator = AitpAgent.generate();
  const responder = AitpAgent.generate();
  const initManifest = initiator.buildManifest({
    displayName: 'initiator',
    handshakeEndpoint: 'http://localhost:8100/aitp/handshake/',
    offeredCaps: ['demo.echo'],
  });
  const respManifest = responder.buildManifest({
    displayName: 'responder',
    handshakeEndpoint: 'http://localhost:8200/aitp/handshake/',
    offeredCaps: ['demo.write'],
  });
  return { initiator, responder, initManifest, respManifest };
}

test('full handshake yields mutual TCTs', () => {
  const { initiator, responder, respManifest } = agents();

  const sess = initiator.newSession();
  const rsess = responder.newResponder();

  const hello = sess.buildHello(respManifest, ['demo.write']);
  const { ackJson: helloAck, sessionId } = rsess.processHello(hello);
  const commit = sess.processHelloAck(helloAck, sessionId);
  const { ackJson: commitAck, tctJson: responderHeldTct } =
    rsess.processCommit(commit);
  const initiatorHeldTct = sess.complete(commitAck);

  // The initiator holds a TCT issued by the responder for demo.write.
  const ident = initiator.verifyTct(initiatorHeldTct, 'demo.write');
  assert.equal(ident.peerAid, responder.aid);
  assert.ok(ident.grants.includes('demo.write'));

  // The responder holds a TCT issued by the initiator for demo.echo.
  const respIdent = responder.verifyTct(responderHeldTct, 'demo.echo');
  assert.equal(respIdent.peerAid, initiator.aid);
  assert.ok(respIdent.grants.includes('demo.echo'));
});

test('verifyTct rejects a missing grant', () => {
  const { initiator, responder, respManifest } = agents();
  const sess = initiator.newSession();
  const rsess = responder.newResponder();

  const hello = sess.buildHello(respManifest, ['demo.write']);
  const { ackJson: helloAck, sessionId } = rsess.processHello(hello);
  const commit = sess.processHelloAck(helloAck, sessionId);
  const { ackJson: commitAck } = rsess.processCommit(commit);
  const tct = sess.complete(commitAck);

  assert.throws(() => initiator.verifyTct(tct, 'demo.not-granted'));
});

test('fromSeed is deterministic', () => {
  const seed = Buffer.alloc(32, 7);
  assert.equal(AitpAgent.fromSeed(seed).aid, AitpAgent.fromSeed(seed).aid);
});

test('fromSeed rejects a wrong-length seed', () => {
  assert.throws(() => AitpAgent.fromSeed(Buffer.alloc(31, 0)));
});

test('newSession before buildManifest throws', () => {
  assert.throws(() => AitpAgent.generate().newSession());
});
