// `buildManifest({ revocationListUri })` (RFC-AITP-0005 §11,
// RFC-AITP-0008 §1.4): every TCT issuer advertises its `ListRevoked` URL in
// the signed Manifest.

import test from 'node:test';
import assert from 'node:assert/strict';

import { AitpAgent, REVOCATION_LIST_PATH, verifyManifestJson } from '../index.js';

const EXT = 'rfc-aitp-0008.revocation_list_uri';

const build = (agent, extra = {}) =>
  agent.buildManifest({
    displayName: 'issuer',
    handshakeEndpoint: 'https://issuer.example/aitp/handshake/',
    offeredCaps: ['demo.echo'],
    ...extra,
  });

test('revocationListUri round-trips inside the signed Manifest', () => {
  const uri = `https://issuer.example${REVOCATION_LIST_PATH}`;
  const envelope = build(AitpAgent.generate(), { revocationListUri: uri });
  assert.equal(JSON.parse(envelope).manifest.extensions[EXT], uri);
  verifyManifestJson(envelope);
});

test('revocationListUri is absent by default', () => {
  const { manifest } = JSON.parse(build(AitpAgent.generate()));
  assert.equal((manifest.extensions ?? {})[EXT], undefined);
});

test('an invalid revocationListUri throws', () => {
  assert.throws(() => build(AitpAgent.generate(), { revocationListUri: 'not a url' }), /revocationListUri/);
});

test('REVOCATION_LIST_PATH constant', () => {
  assert.equal(REVOCATION_LIST_PATH, '/.well-known/aitp-revocation-list');
});
