// P-256 signing suite (RFC-AITP-0001 §5.4.3) — Node SDK.
//
// The Node SDK matches the Python SDK's parameterized factory
// (`generate({ suite })` / `fromSeed(seed, { suite })`) per the
// CLAUDE.md "intentionally symmetric" mandate.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';

import { AitpAgent, verifyManifestJson } from '../index.js';

test('generate({suite:"p256"}) yields a p256-prefixed AID', () => {
  const a = AitpAgent.generate({ suite: 'p256' });
  assert.ok(a.aid.startsWith('aid:pubkey:p256:'), a.aid);
});

test('fromSeed({suite:"p256"}) is deterministic', () => {
  const seed = Buffer.alloc(32, 7);
  assert.equal(
    AitpAgent.fromSeed(seed, { suite: 'p256' }).aid,
    AitpAgent.fromSeed(seed, { suite: 'p256' }).aid,
  );
});

test('Ed25519 generate remains the default factory', () => {
  const a = AitpAgent.generate();
  assert.ok(a.aid.startsWith('aid:pubkey:'));
  assert.ok(!a.aid.includes('p256:'));
});

test('generate with explicit suite:"ed25519" matches the default', () => {
  const a = AitpAgent.generate({ suite: 'ed25519' });
  assert.ok(a.aid.startsWith('aid:pubkey:'));
  assert.ok(!a.aid.includes('p256:'));
});

test('generate rejects an unknown suite name', () => {
  assert.throws(() => AitpAgent.generate({ suite: 'rsa' }));
});

test('fromSeed({suite:"p256"}) rejects a 31-byte seed', () => {
  assert.throws(() => AitpAgent.fromSeed(Buffer.alloc(31, 0), { suite: 'p256' }));
});

test('fromSeed (default Ed25519) rejects a 31-byte seed', () => {
  assert.throws(() => AitpAgent.fromSeed(Buffer.alloc(31, 0)));
});

// ── P-256 pinned_key identity (0.14) ────────────────────────────────────

function build(suite, name, port, offers) {
  const agent = AitpAgent.generate({ suite });
  const manifest = agent.buildManifest({
    displayName: name,
    handshakeEndpoint: `https://localhost:${port}/aitp/handshake/`,
    offeredCaps: offers,
  });
  return { agent, manifest };
}

test('P-256 pinned_key manifest carries the 33-byte compressed point', () => {
  const { agent, manifest } = build('p256', 'erin', 8300, ['demo.echo']);
  const hint = JSON.parse(manifest).manifest.identity_hint;
  assert.equal(hint.type, 'pinned_key');
  assert.equal(hint.public_key.length, 44);
  assert.equal(agent.aid, `aid:pubkey:p256:${hint.public_key}`);
  verifyManifestJson(manifest);
});

for (const [initSuite, respSuite] of [
  ['p256', 'p256'],
  ['ed25519', 'p256'],
  ['p256', 'ed25519'],
]) {
  test(`pinned_key handshake ${initSuite} -> ${respSuite} succeeds`, () => {
    const { agent: initiator } = build(initSuite, 'initiator', 8100, ['demo.echo']);
    const { agent: responder, manifest: respManifest } = build(respSuite, 'responder', 8200, ['demo.write']);
    const sess = initiator.newSession(null, { pinnedKeys: [responder.aid] });
    const rsess = responder.newResponder(null, { pinnedKeys: [initiator.aid] });
    const hello = sess.buildHello(respManifest, ['demo.write']);
    const { ackJson, sessionId } = rsess.processHello(hello);
    const commit = sess.processHelloAck(ackJson, sessionId);
    const { ackJson: commitAck, completed: respDone } = rsess.processCommit(commit, []);
    const initDone = sess.complete(commitAck, []);
    assert.equal(initiator.verifyTct(initDone.tct, 'demo.write', undefined, []).peerAid, responder.aid);
    assert.equal(responder.verifyTct(respDone.tct, 'demo.echo', undefined, []).peerAid, initiator.aid);
  });
}

test('P-256 pinned_key initiator is rejected without pinnedKeys', () => {
  const { agent: initiator } = build('p256', 'initiator', 8100, ['demo.echo']);
  const { agent: responder, manifest: respManifest } = build('p256', 'responder', 8200, ['demo.write']);
  const hello = initiator
    .newSession(null, { pinnedKeys: [responder.aid] })
    .buildHello(respManifest, ['demo.write']);
  assert.throws(() => responder.newResponder().processHello(hello), /trust store/);
});
