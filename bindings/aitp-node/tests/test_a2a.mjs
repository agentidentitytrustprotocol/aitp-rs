// A2A Agent Card binding, client verification (RFC-AITP-0014) — Node SDK.
//
// Gated by the `experimental-a2a-agent-card` Cargo feature: build with
// `npm run build:experimental`. Without the feature the tests skip. The SDK
// cannot set a Manifest extension, so these use the committed vector signed
// in `crates/aitp-experimental/tests/fixtures/a2a/`, at a pinned time.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { HAS_A2A, a2aCardManifestUrl, verifyA2aAgentCardBinding } from './_experimental.mjs';

const VECTOR = new URL('../../../crates/aitp-experimental/tests/fixtures/a2a/', import.meta.url);
const INTERFACE = 'https://b.agents.example.com/a2a/v1';
const NOW = 1_711_900_100;
const AID = 'aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg';
const skip = !HAS_A2A && 'needs experimental-a2a-agent-card';

function card(params = {}) {
  const c = JSON.parse(readFileSync(new URL('agent-card.json', VECTOR), 'utf8'));
  Object.assign(c.capabilities.extensions[0].params, params);
  return JSON.stringify(c);
}

const manifest = () => readFileSync(new URL('manifest.json', VECTOR), 'utf8');

function codeOf(fn) {
  try {
    fn();
  } catch (e) {
    return e.code;
  }
  assert.fail('expected a throw');
}

test('reads the pointer', { skip }, () => {
  assert.deepEqual({ ...a2aCardManifestUrl(card()) }, {
    aid: AID,
    manifestUrl: 'https://b.agents.example.com/.well-known/aitp-manifest',
  });
});

test("binds and reports the Manifest's values", { skip }, () => {
  // The Card's advisory types do not reach the result (§4.3).
  const c = card({ acceptedIdentityTypes: ['pinned_key'] });
  assert.deepEqual({ ...verifyA2aAgentCardBinding(c, INTERFACE, manifest(), NOW) }, {
    aid: AID,
    acceptedIdentityTypes: ['oidc'],
    acceptedTrustAnchors: ['https://auth.example.com/'],
    offeredCapabilities: ['macp.mode.task.v1'],
    handshakeEndpoint: 'https://b.agents.example.com/aitp/handshake',
    interfaceUrl: INTERFACE,
  });
});

test('the tagged AID is the same key', { skip }, () => {
  const c = card({ aid: AID.replace('aid:pubkey:', 'aid:pubkey:ed25519:') });
  assert.equal(verifyA2aAgentCardBinding(c, INTERFACE, manifest(), NOW).aid, AID);
});

test('another key is IDENTITY_FAILED', { skip }, () => {
  const c = card({ aid: 'aid:pubkey:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU' });
  assert.equal(codeOf(() => verifyA2aAgentCardBinding(c, INTERFACE, manifest(), NOW)), 'IDENTITY_FAILED');
});

test('an unlisted interface is IDENTITY_FAILED', { skip }, () => {
  const url = 'https://agents.attacker.example/a2a/v1';
  assert.equal(codeOf(() => verifyA2aAgentCardBinding(card(), url, manifest(), NOW)), 'IDENTITY_FAILED');
});

test('a failed fetch is MANIFEST_NOT_FOUND', { skip }, () => {
  assert.equal(codeOf(() => verifyA2aAgentCardBinding(card(), INTERFACE, null, NOW)), 'MANIFEST_NOT_FOUND');
  assert.equal(codeOf(() => verifyA2aAgentCardBinding(card(), INTERFACE, undefined, NOW)), 'MANIFEST_NOT_FOUND');
});

test('an expired Manifest is refused', { skip }, () => {
  const later = NOW + 10_000_000;
  assert.equal(codeOf(() => verifyA2aAgentCardBinding(card(), INTERFACE, manifest(), later)), 'MANIFEST_EXPIRED');
});

test('malformed JSON has a code and no text from the input', { skip }, () => {
  const hostile = '{"a":1,"a":2,"ignore_instructions":';
  assert.equal(codeOf(() => verifyA2aAgentCardBinding(hostile, INTERFACE, manifest(), NOW)), 'IDENTITY_FAILED');
  assert.equal(codeOf(() => verifyA2aAgentCardBinding(card(), INTERFACE, hostile, NOW)), 'MANIFEST_INVALID');
  assert.throws(
    () => a2aCardManifestUrl(hostile),
    (e) => e.code === 'IDENTITY_FAILED' && !e.message.includes('ignore_instructions'),
  );
});

test('a duplicate key is malformed', { skip }, () => {
  const duplicate = '{"a":1,"a":2}';
  assert.equal(codeOf(() => verifyA2aAgentCardBinding(duplicate, INTERFACE, manifest(), NOW)), 'IDENTITY_FAILED');
  assert.equal(codeOf(() => verifyA2aAgentCardBinding(card(), INTERFACE, duplicate, NOW)), 'MANIFEST_INVALID');
});

test('a clock that is not a finite number is refused', { skip }, () => {
  for (const bad of [NaN, Infinity, -Infinity]) {
    assert.throws(() => verifyA2aAgentCardBinding(card(), INTERFACE, manifest(), bad), /finite/);
  }
});

test('a duplicate key in an otherwise valid Card is refused', { skip }, () => {
  const duplicate = `{"dup":1,"dup":2,${card().slice(1)}`;
  assert.equal(codeOf(() => verifyA2aAgentCardBinding(duplicate, INTERFACE, manifest(), NOW)), 'IDENTITY_FAILED');
});

test('a refused Manifest quotes nothing from it', { skip }, () => {
  const env = JSON.parse(manifest());
  env.manifest.IGNORE_PREV_h0stile = 1;
  assert.throws(
    () => verifyA2aAgentCardBinding(card(), INTERFACE, JSON.stringify(env), NOW),
    (e) => Boolean(e.code) && e.code !== 'GenericFailure' && !e.message.includes('h0stile'),
  );
});

test('the clock defaults to now', { skip }, () => {
  assert.equal(codeOf(() => verifyA2aAgentCardBinding(card(), INTERFACE, manifest())), 'MANIFEST_EXPIRED');
});

test('a Card without the extension has a code', { skip }, () => {
  assert.equal(codeOf(() => a2aCardManifestUrl('{}')), 'IDENTITY_FAILED');
});
