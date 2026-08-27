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

// ── Verification ─────────────────────────────────────────────────────────
//
// The verify half was missing until 0.6.0: both this binding and the Python
// one exposed signRevocationList and neither exposed verifyRevocationList,
// even though verify_revocation_snapshot is a Tier C conformance operation
// the Rust adapter implements. Three downstream repos then hand-rolled,
// skipped, or faked verification, and the 0.5.0 signing-input change crossed
// a whole release family with one accidental interlock in its way.

import { readFileSync } from 'node:fs';
import { generateKeyPairSync, createHash, sign as edSign } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyRevocationList, revocationSigningBytes } from '../index.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

// RFC 8785 reduces to sorted-key compact JSON for these bodies: ASCII strings
// and integer numbers only, no floats, no escapes.
function canon(value) {
  if (Array.isArray(value)) return '[' + value.map(canon).join(',') + ']';
  if (value && typeof value === 'object') {
    return (
      '{' +
      Object.keys(value)
        .sort()
        .map((k) => JSON.stringify(k) + ':' + canon(value[k]))
        .join(',') +
      '}'
    );
  }
  return JSON.stringify(value);
}

function causeOf(fn) {
  try {
    fn();
  } catch (err) {
    // `err.code` is the contract. Deliberately NOT parsed out of
    // `err.message`: a caller string-matching an error message is pinning
    // program output as an expected value, which is the bug class this
    // binding exists to remove. If the cause channel ever regresses to a
    // message prefix, this returns 'GenericFailure' and every cause
    // assertion below fails loudly rather than silently passing.
    return err.code;
  }
  throw new Error('expected verification to fail, but it succeeded');
}

test('verifyRevocationList accepts a freshly signed snapshot', () => {
  const a = issuer();
  const env = a.signRevocationList([{ jti: randomUUID() }], 600);
  assert.equal(verifyRevocationList(env, a.aid), undefined);
});

test('verifyRevocationList verifies the committed spec vector as committed', () => {
  // Cross-implementation check: verified AS COMMITTED, never re-minted. A
  // suite where the same code signs and verifies passes under any
  // self-consistent convention — including a wrong one, which is how an
  // aitp-rs issuer and an aitp-verifier-py consumer disagreed on the wire
  // while both suites stayed green.
  const snap = JSON.parse(
    readFileSync(
      path.join(
        REPO_ROOT,
        'tests/schemas/known-answer/signed-examples/revocation/kat-keypair-001-snapshot.json',
      ),
      'utf8',
    ),
  );
  delete snap._kat_input; // a minting companion, never part of the wire object

  // Issuer comes from the keypair vector, NOT from the snapshot — deriving it
  // from the envelope would make the issuer-binding check tautological.
  const keypairs = JSON.parse(
    readFileSync(path.join(REPO_ROOT, 'tests/schemas/known-answer/keypairs.json'), 'utf8'),
  );
  const findAid = (node) => {
    if (Array.isArray(node)) return node.map(findAid).find(Boolean);
    if (node && typeof node === 'object') {
      if (node.id === 'kat-keypair-001' && node.aid) return node.aid;
      return Object.values(node).map(findAid).find(Boolean);
    }
    return undefined;
  };
  const aid = findAid(keypairs);
  assert.ok(aid, 'kat-keypair-001 not found in keypairs.json');

  assert.equal(verifyRevocationList(JSON.stringify(snap), aid, 1_711_900_100), undefined);
});

test('every failure cause is recoverable without parsing prose', () => {
  const a = issuer();
  const other = issuer();
  const env = a.signRevocationList([{ jti: randomUUID() }], 600);

  assert.equal(causeOf(() => verifyRevocationList(env, other.aid)), 'issuer_mismatch');

  const tampered = JSON.parse(env);
  tampered.revocation_list.entries = [];
  assert.equal(
    causeOf(() => verifyRevocationList(JSON.stringify(tampered), a.aid)),
    'signature_invalid',
  );

  const badVersion = JSON.parse(env);
  badVersion.revocation_list.version = 'aitp/9.9';
  assert.equal(
    causeOf(() => verifyRevocationList(JSON.stringify(badVersion), a.aid)),
    'version_unknown',
  );

  assert.equal(causeOf(() => verifyRevocationList(env, a.aid, 99_999_999_999)), 'expired');
  assert.equal(causeOf(() => verifyRevocationList('not json at all', a.aid)), 'malformed');
});

test('issuer_mismatch is distinct from malformed', () => {
  // The same cause until 0.6.0 (both CnfMalformed). An attacker serving their
  // own correctly-signed list and a corrupt fetch are different events; a
  // caller that cannot separate them cannot alert on the first without
  // drowning in the second.
  const a = issuer();
  const other = issuer();
  const env = a.signRevocationList([{ jti: randomUUID() }], 600);

  assert.equal(verifyRevocationList(env, a.aid), undefined);
  assert.equal(causeOf(() => verifyRevocationList(env, other.aid)), 'issuer_mismatch');
  assert.equal(causeOf(() => verifyRevocationList('{}', a.aid)), 'malformed');
});

test('a wrapped-form signature is rejected', () => {
  // The 0.5.0 break, from the verifier's side. Up to 0.4.x the signing input
  // was JCS({"revocation_list": body}) — the transport wrapper. The signer
  // here is node:crypto, deliberately independent of the code under test.
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const aid = 'aid:pubkey:' + raw.toString('base64url');

  const now = Math.floor(Date.now() / 1000);
  const body = {
    version: 'aitp/0.2',
    issuer: aid,
    published_at: now,
    expires_at: now + 600,
    entries: [{ jti: randomUUID(), revoked_at: now }],
  };

  const digest = (s) => createHash('sha256').update(Buffer.from(s)).digest();
  const wrappedSig = edSign(null, digest(canon({ revocation_list: body })), privateKey);
  const legacy = JSON.stringify({
    revocation_list: body,
    signature: wrappedSig.toString('base64url'),
  });
  assert.equal(causeOf(() => verifyRevocationList(legacy, aid)), 'signature_invalid');

  // Non-vacuity: the same body signed the CURRENT way DOES verify, so the
  // rejection above is about the signing input, not a malformed fixture.
  const innerSig = edSign(null, digest(canon(body)), privateKey);
  const current = JSON.stringify({
    revocation_list: body,
    signature: innerSig.toString('base64url'),
  });
  assert.equal(verifyRevocationList(current, aid), undefined);
});

test('revocationSigningBytes are the inner body, not the wrapper', () => {
  const a = issuer();
  const env = a.signRevocationList([{ jti: randomUUID() }], 600);
  const bytes = revocationSigningBytes(env);
  assert.ok(bytes.length > 0);
  assert.equal(bytes[0], '{'.charCodeAt(0));
  assert.ok(
    !bytes.subarray(0, 32).toString().includes('revocation_list'),
    'signing input starts with the transport wrapper — that is the pre-0.5.0 shape',
  );
  // Derived from the envelope, never pasted from output.
  assert.equal(bytes.toString(), canon(JSON.parse(env).revocation_list));
});
