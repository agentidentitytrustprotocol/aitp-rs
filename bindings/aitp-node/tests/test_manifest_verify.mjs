// `verifyManifestJson` free function — Node SDK.
//
// Mirrors bindings/aitp-py/tests/test_manifest_verify.py so the two
// SDKs stay at parity on the control-plane manifest-enrollment path.
//
// Build first:  npm run build:debug
// Then run:     node --test tests/

import test from 'node:test';
import assert from 'node:assert/strict';

import { AitpAgent, verifyManifestJson } from '../index.js';

function signedManifest() {
  const a = AitpAgent.generate();
  return a.buildManifest({
    displayName: 'enrollee',
    handshakeEndpoint: 'http://localhost:9000/aitp/handshake/',
    offeredCaps: ['demo.write'],
  });
}

test('verifyManifestJson accepts a freshly built manifest', () => {
  // Returns void on success; throws on failure.
  verifyManifestJson(signedManifest());
});

test('verifyManifestJson rejects a tampered payload', () => {
  const env = JSON.parse(signedManifest());
  // display_name is part of the signed JCS body — mutating it breaks
  // the signature.
  env.manifest.display_name = 'imposter';
  assert.throws(() => verifyManifestJson(JSON.stringify(env)));
});

test('verifyManifestJson rejects garbage input', () => {
  assert.throws(() => verifyManifestJson('not json'));
});
