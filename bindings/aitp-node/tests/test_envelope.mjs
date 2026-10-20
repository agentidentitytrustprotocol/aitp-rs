// Envelope signing and verification — Node SDK (issue #256).
//
// Mirrors bindings/aitp-py/tests/test_envelope.py. `verifyEnvelope` runs the
// RFC-AITP-0001 §5.4 check order (version → member set → signature) and
// throws an Error whose `code` is the registered error code. The committed
// spec vectors are verified as committed; the env-008..env-011 cases are
// derived from the env-007 vector (`kat-keypair-001-envelope.json`) exactly
// as the spec fixtures at the pinned spec ref derive them.
//
// Build first:  npm run build:debug
// Then run:     node --test tests/

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { AitpAgent, verifyEnvelope } from '../index.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const KAT_DIR = join(ROOT, 'tests/schemas/known-answer/signed-examples/envelope');

const ED25519_AID = 'aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik'; // kat-keypair-001
const P256_AID = 'aid:pubkey:p256:AweBDql0zqV3PmO4l_N-O-mgnnpf6blxpE0QZawqOpMR'; // kat-keypair-005

const KATS = [
  ['kat-keypair-001-envelope.json', ED25519_AID],
  ['kat-keypair-005-envelope.json', P256_AID],
];

function kat(name) {
  return JSON.parse(readFileSync(join(KAT_DIR, name), 'utf8'));
}

// env-007's envelope: Ed25519, with a vendor `extensions` key.
function env007() {
  return kat('kat-keypair-001-envelope.json').envelope;
}

function codeOf(envelope, sender = ED25519_AID) {
  const text = typeof envelope === 'string' ? envelope : JSON.stringify(envelope);
  try {
    verifyEnvelope(text, sender);
  } catch (err) {
    return err.code;
  }
  assert.fail('verifyEnvelope accepted the envelope');
}

for (const [name, sender] of KATS) {
  test(`committed KAT ${name} verifies`, () => {
    assert.equal(verifyEnvelope(JSON.stringify(kat(name).envelope), sender), undefined);
  });

  test(`retired v1 signature of ${name} does not verify`, () => {
    const k = kat(name);
    const envelope = { ...k.envelope, signature: k._must_not_verify.v1_signature };
    assert.equal(codeOf(envelope, sender), 'INVALID_SIGNATURE');
  });
}

test('P-256 double-hash signature does not verify', () => {
  const k = kat('kat-keypair-005-envelope.json');
  const envelope = { ...k.envelope, signature: k._must_not_verify.double_hash_signature };
  assert.equal(codeOf(envelope, P256_AID), 'INVALID_SIGNATURE');
});

test('env-008: tampered extensions is INVALID_SIGNATURE', () => {
  const envelope = env007();
  envelope.extensions = {
    'com.example.audit_trace': envelope.extensions['com.example.debug_trace'],
  };
  assert.equal(codeOf(envelope), 'INVALID_SIGNATURE');
});

test('env-009: substituted message_type is INVALID_SIGNATURE', () => {
  assert.equal(codeOf({ ...env007(), message_type: 'mutual_hello_ack' }), 'INVALID_SIGNATURE');
});

test('env-010: unknown version beats the bad signature', () => {
  assert.equal(codeOf({ ...env007(), version: 'aitp/9.9' }), 'UNKNOWN_VERSION');
});

test('env-011: well-signed previous revision is UNKNOWN_VERSION', () => {
  // env-011 at the pinned spec ref: env-007 with version `aitp/0.2`, a
  // fresh message_id, and a signature valid for these exact bytes.
  const envelope = {
    ...env007(),
    version: 'aitp/0.2',
    message_id: '770e8400-e29b-41d4-a716-446655441011',
    signature:
      'qXNURAet0h9miBTCFOBSjsj01ptplj_702PekH0hTCLRMmGziQvW-7jLMsTfP4ZyF5--0FNgJKMJ-RmFo3aOBg',
  };
  assert.equal(codeOf(envelope), 'UNKNOWN_VERSION');
});

test('unknown top-level member is UNKNOWN_FIELD', () => {
  // env-006's defect: a sibling member outside `extensions`.
  const envelope = { ...env007(), trace_id: '770e8400-e29b-41d4-a716-446655449999' };
  assert.equal(codeOf(envelope), 'UNKNOWN_FIELD');
});

test('unknown version is checked before the member set', () => {
  assert.equal(codeOf({ ...env007(), version: 'aitp/9.9', trace_id: 'x' }), 'UNKNOWN_VERSION');
});

test('missing version is UNKNOWN_VERSION', () => {
  const envelope = env007();
  delete envelope.version;
  assert.equal(codeOf(envelope), 'UNKNOWN_VERSION');
});

for (const [label, mutate] of [
  ['missing payload', (e) => delete e.payload],
  ['unregistered message_type', (e) => (e.message_type = 'not_registered')],
  ['non-v4 message_id', (e) => (e.message_id = '770e8400-e29b-11d4-a716-446655441007')],
  // Issue #261: the aitp-envelope.schema.json rules for payload, timestamp
  // and signature (and extensions) are structure, checked before the
  // signature.
  ['payload an array', (e) => (e.payload = [1, 2])],
  ['payload a string', (e) => (e.payload = 'text')],
  ['payload null', (e) => (e.payload = null)],
  ['negative timestamp', (e) => (e.timestamp = -1)],
  ['signature too short', (e) => (e.signature = e.signature.slice(1))],
  ['signature with padding', (e) => (e.signature = e.signature.slice(1) + '=')],
  ['signature with an unknown tag', (e) => (e.signature = `rsa.${e.signature}`)],
  ['empty signature', (e) => (e.signature = '')],
  ['extensions null', (e) => (e.extensions = null)],
]) {
  test(`structural defect (${label}) is INVALID_ENVELOPE`, () => {
    const envelope = env007();
    mutate(envelope);
    assert.equal(codeOf(envelope), 'INVALID_ENVELOPE');
  });
}

test('unknown version wins over a schema-rule defect', () => {
  const envelope = { ...env007(), version: 'aitp/9.9', payload: [], timestamp: -1, signature: 'x' };
  assert.equal(codeOf(envelope), 'UNKNOWN_VERSION');
});

test('a tagged signature passes the structure step', () => {
  // The schema pattern allows the optional `ed25519.` tag
  // (RFC-AITP-0001 §5.4.3); the tagged form of a valid signature verifies.
  const envelope = env007();
  envelope.signature = `ed25519.${envelope.signature}`;
  assert.equal(verifyEnvelope(JSON.stringify(envelope), ED25519_AID), undefined);
});

test('duplicate key is INVALID_ENVELOPE', () => {
  const text = JSON.stringify(env007());
  assert.equal(codeOf(text.slice(0, -1) + ',"timestamp":1711900001}'), 'INVALID_ENVELOPE');
});

test('wrong expected sender is INVALID_SIGNATURE', () => {
  assert.equal(codeOf(env007(), AitpAgent.generate().aid), 'INVALID_SIGNATURE');
});

test('bad expectedSenderAid is a caller error with no verification code', () => {
  assert.throws(
    () => verifyEnvelope(JSON.stringify(env007()), 'not-an-aid'),
    (err) => /invalid expectedSenderAid/.test(err.message) && !String(err.code).match(/^[A-Z_]+$/),
  );
});

for (const [seed, suite, name] of [
  [Buffer.alloc(32), 'ed25519', 'kat-keypair-001-envelope.json'],
  [Buffer.alloc(32, 5), 'p256', 'kat-keypair-005-envelope.json'],
]) {
  test(`signEnvelope reproduces the committed KAT ${name}`, () => {
    const expected = kat(name).envelope;
    const agent = AitpAgent.fromSeed(seed, { suite });
    const signed = agent.signEnvelope(expected.message_type, JSON.stringify(expected.payload), {
      extensionsJson: expected.extensions ? JSON.stringify(expected.extensions) : undefined,
      messageId: expected.message_id,
      timestamp: expected.timestamp,
    });
    assert.deepEqual(JSON.parse(signed), expected);
  });
}

test('signEnvelope round-trips and the signature covers extensions', () => {
  const agent = AitpAgent.generate({ suite: 'p256' });
  const signed = agent.signEnvelope('tct', JSON.stringify({ k: 1 }), {
    extensionsJson: JSON.stringify({ 'com.example.x': true }),
  });
  assert.equal(verifyEnvelope(signed, agent.aid), undefined);
  const parsed = JSON.parse(signed);
  assert.equal(parsed.version, 'aitp/0.3');
  assert.equal(parsed.message_id[14], '4');
  parsed.extensions['com.example.x'] = false;
  assert.equal(codeOf(parsed, agent.aid), 'INVALID_SIGNATURE');
});

for (const [label, args] of [
  ['message type', ['not_registered', '{}']],
  ['payload not an object', ['tct', '[]']],
  ['extensions not an object', ['tct', '{}', { extensionsJson: '[]' }]],
  ['non-v4 message id', ['tct', '{}', { messageId: '770e8400-e29b-11d4-a716-446655441007' }]],
  ['negative timestamp', ['tct', '{}', { timestamp: -1 }]],
]) {
  test(`signEnvelope rejects bad input (${label})`, () => {
    assert.throws(() => AitpAgent.generate().signEnvelope(...args));
  });
}
