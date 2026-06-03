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

test('initiator rejects peer substitution', () => {
  // RFC-AITP-0004 peer-AID binding: the initiator authenticates the peer
  // it targeted. A HELLO_ACK from a different (well-signed) peer must be
  // rejected — the session must not silently bind to the wrong AID.
  const initiator = AitpAgent.generate();
  const real = AitpAgent.generate();
  const mallory = AitpAgent.generate();
  const realManifest = real.buildManifest({
    displayName: 'real',
    handshakeEndpoint: 'http://localhost:8200/aitp/handshake/',
    offeredCaps: ['demo.write'],
  });
  const malloryManifest = mallory.buildManifest({
    displayName: 'mallory',
    handshakeEndpoint: 'http://localhost:8300/aitp/handshake/',
    offeredCaps: ['demo.write'],
  });

  // Session s1 targets `real`.
  const s1 = initiator.newSession();
  s1.buildHello(realManifest, ['demo.write']);

  // Mallory legitimately answers a DIFFERENT session that targeted her,
  // producing a fully-valid HELLO_ACK signed under her own AID.
  const s2 = initiator.newSession();
  const helloForMallory = s2.buildHello(malloryManifest, ['demo.write']);
  const malloryResp = mallory.newResponder();
  const { ackJson: malloryAck, sessionId: mallorySession } =
    malloryResp.processHello(helloForMallory);

  // Feeding Mallory's HELLO_ACK into s1 (which targeted `real`) must be
  // rejected: the signed sender AID is not the intended peer.
  assert.throws(() => s1.processHelloAck(malloryAck, mallorySession));
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

test('verifyTct presented-TCT mode honors expectedAudience', () => {
  const { initiator, responder, respManifest } = agents();
  const sess = initiator.newSession();
  const rsess = responder.newResponder();
  const hello = sess.buildHello(respManifest, ['demo.write']);
  const { ackJson: helloAck, sessionId } = rsess.processHello(hello);
  const commit = sess.processHelloAck(helloAck, sessionId);
  const { ackJson: commitAck } = rsess.processCommit(commit);
  const tct = sess.complete(commitAck);

  // In v0.1 the TCT's audience equals its subject (initiator.aid). A resource
  // server verifying a TCT presented by the initiator passes initiator.aid as
  // expectedAudience.
  const presented = initiator.verifyTct(tct, 'demo.write', initiator.aid);
  assert.equal(presented.peerAid, responder.aid);

  // Wrong expectedAudience must reject.
  assert.throws(() => initiator.verifyTct(tct, 'demo.write', responder.aid));
});
