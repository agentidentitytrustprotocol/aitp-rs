// A clock argument that is not a finite number is refused, not read as 0.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { AitpAgent, verifyManifestJson, verifyRevocationList } from '../index.js';
const NON_FINITE = [NaN, Infinity, -Infinity];
// Signed for a pinned time; expired since 2024.
const EXPIRED_MANIFEST = readFileSync(
  new URL('../../../crates/aitp-experimental/tests/fixtures/a2a/manifest.json', import.meta.url),
  'utf8',
);

function refused(fn, name) {
  assert.throws(fn, new RegExp(`${name} must be finite`));
}

test('verifyManifestJson refuses a non-finite clock', () => {
  for (const bad of NON_FINITE) {
    refused(() => verifyManifestJson(EXPIRED_MANIFEST, bad), 'nowUnixSecs');
  }
  // The real clock, and an explicit time inside the validity window.
  assert.throws(() => verifyManifestJson(EXPIRED_MANIFEST), (e) => e.code === 'expired');
  verifyManifestJson(EXPIRED_MANIFEST, 1_711_900_100);
});

test('verifyRevocationList refuses a non-finite clock', () => {
  const issuer = AitpAgent.generate();
  const snapshot = issuer.signRevocationList([]);
  for (const bad of NON_FINITE) {
    refused(() => verifyRevocationList(snapshot, issuer.aid, bad), 'nowUnixSecs');
  }
  verifyRevocationList(snapshot, issuer.aid);
  verifyRevocationList(snapshot, issuer.aid, Date.now() / 1000);
});

test('signEnvelope refuses a non-finite timestamp', () => {
  const agent = AitpAgent.generate();
  for (const bad of NON_FINITE) {
    refused(() => agent.signEnvelope('tct', '{}', { timestamp: bad }), 'timestamp');
  }
  const signed = JSON.parse(agent.signEnvelope('tct', '{}', { timestamp: 1_700_000_000 }));
  assert.equal(signed.timestamp, 1_700_000_000);
});

test('signRevocationList refuses a non-finite revokedAt', () => {
  const agent = AitpAgent.generate();
  const jti = '770e8400-e29b-41d4-a716-446655440000';
  for (const bad of NON_FINITE) {
    refused(() => agent.signRevocationList([{ jti, revokedAt: bad }]), 'revoked_at');
  }
});
