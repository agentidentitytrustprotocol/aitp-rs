// Revocation-list signing — Node SDK.
//
// Mirrors bindings/aitp-py/tests/test_revocation.py: build a list with
// two entries, parse it back, and confirm the entries and expiry window
// survive the round-trip.
//
// Build first:  npm run build:debug
// Then run:     node --test tests/

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { AitpAgent } from '../index.js';

function issuer() {
  const a = AitpAgent.generate();
  a.buildManifest({
    displayName: 'issuer',
    handshakeEndpoint: 'http://localhost:8100/aitp/handshake/',
    offeredCaps: ['demo.echo'],
  });
  return a;
}

test('signRevocationList round-trips two entries', () => {
  const iss = issuer();
  const jtiA = randomUUID();
  const jtiB = randomUUID();

  const envelopeJson = iss.signRevocationList(
    [
      { jti: jtiA, reason: 'compromised' },
      { jti: jtiB, revokedAt: 1_700_000_000 },
    ],
    600,
  );

  const env = JSON.parse(envelopeJson);
  const body = env.revocation_list;
  assert.equal(body.issuer, iss.aid);
  assert.equal(body.version, 'aitp/0.2');
  assert.equal(body.entries.length, 2);

  const jtis = new Set(body.entries.map((e) => e.jti));
  assert.deepEqual(jtis, new Set([jtiA, jtiB]));

  const byJti = Object.fromEntries(body.entries.map((e) => [e.jti, e]));
  assert.equal(byJti[jtiB].revoked_at, 1_700_000_000);
  assert.equal(byJti[jtiA].reason, 'compromised');

  // Expiry is published_at + 600.
  assert.equal(body.expires_at - body.published_at, 600);

  // Envelope carries a non-empty signature string.
  assert.equal(typeof env.signature, 'string');
  assert.ok(env.signature.length > 0);
});

test('signRevocationList rejects a bad UUID', () => {
  assert.throws(() => issuer().signRevocationList([{ jti: 'not-a-uuid' }]));
});
