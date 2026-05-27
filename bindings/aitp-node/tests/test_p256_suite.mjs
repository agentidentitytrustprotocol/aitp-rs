// P-256 signing suite (RFC-AITP-0001 §5.4.3) — Node SDK.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';

import { AitpAgent } from '../index.js';

test('generateP256 yields a p256-prefixed AID', () => {
  const a = AitpAgent.generateP256();
  assert.ok(a.aid.startsWith('aid:pubkey:p256:'), a.aid);
});

test('fromP256Seed is deterministic', () => {
  const seed = Buffer.alloc(32, 7);
  assert.equal(
    AitpAgent.fromP256Seed(seed).aid,
    AitpAgent.fromP256Seed(seed).aid,
  );
});

test('Ed25519 generate remains the default factory', () => {
  const a = AitpAgent.generate();
  assert.ok(a.aid.startsWith('aid:pubkey:'));
  assert.ok(!a.aid.includes('p256:'));
});

test('fromP256Seed rejects a 31-byte seed', () => {
  assert.throws(() => AitpAgent.fromP256Seed(Buffer.alloc(31, 0)));
});
