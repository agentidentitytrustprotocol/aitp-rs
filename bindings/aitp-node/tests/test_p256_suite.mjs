// P-256 signing suite (RFC-AITP-0001 §5.4.3) — Node SDK.
//
// The Node SDK matches the Python SDK's parameterized factory
// (`generate({ suite })` / `fromSeed(seed, { suite })`) per the
// CLAUDE.md "intentionally symmetric" mandate.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';

import { AitpAgent } from '../index.js';

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
