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

// ── Typed failure causes ─────────────────────────────────────────────────
//
// Added in 0.6.1. Until then verifyManifestJson threw a generic error while
// verifyRevocationList carried a stable error.code — so a caller wanting to
// tell "this manifest expired" from "this manifest is forged" had to parse
// prose on one side and could branch on a code on the other. Same shape as
// the missing-binding defect this family spent a release on: one artifact has
// the surface, its sibling does not.

function causeOf(fn) {
  try {
    fn();
  } catch (err) {
    // err.code is the contract. Deliberately NOT parsed out of err.message:
    // a caller string-matching a message pins program output as an expected
    // value, which is the bug class this binding exists to remove.
    return err.code;
  }
  throw new Error('expected verification to fail, but it succeeded');
}

test('every manifest failure cause is recoverable without parsing prose', () => {
  const a = AitpAgent.generate();
  const mk = (extra = {}) =>
    a.buildManifest({
      displayName: 'peer',
      handshakeEndpoint: 'http://localhost:9000/aitp/handshake/',
      offeredCaps: ['demo.write'],
      ...extra,
    });

  assert.equal(verifyManifestJson(mk()), undefined);

  const tampered = JSON.parse(mk());
  tampered.manifest.display_name = 'imposter';
  assert.equal(causeOf(() => verifyManifestJson(JSON.stringify(tampered))), 'signature_invalid');

  // A negative TTL back-dates expires_at before published_at, so the manifest
  // is expired the instant it is minted — deterministic, and no sleep.
  assert.equal(causeOf(() => verifyManifestJson(mk({ ttlSecs: -1 }))), 'expired');

  assert.equal(causeOf(() => verifyManifestJson('not json at all')), 'malformed');
});

// ── nowUnixSecs override ─────────────────────────────────────────────────
//
// verifyRevocationList has always accepted a clock override so tests can
// pin "expired" deterministically instead of faking the system clock or
// minting an already-negative TTL. verifyManifestJson lacked the same
// parameter (aitp-rs#102) — a caller could not distinguish "this manifest
// lapsed" from "this manifest is forged" without either faking system time
// or, as the tests above do, minting a manifest that's born expired. This
// exercises the override on an otherwise-valid (positive-TTL) manifest, so
// it proves the parameter actually reaches the verifier rather than just
// being accepted and ignored.

test('nowUnixSecs overrides the verification clock to accept a normally-valid manifest', () => {
  const manifest = signedManifest();
  const soon = Math.floor(Date.now() / 1000) + 60;
  assert.equal(verifyManifestJson(manifest, soon), undefined);
});

test('nowUnixSecs overrides the verification clock to expire a normally-valid manifest', () => {
  const manifest = signedManifest();
  const farFuture = Math.floor(Date.now() / 1000) + 10_000_000;
  assert.equal(causeOf(() => verifyManifestJson(manifest, farFuture)), 'expired');
});

test('expired is distinct from signature_invalid', () => {
  // "That peer's manifest went stale" and "someone tampered with it" send an
  // operator to different places; a caller that cannot separate them cannot
  // alert on the second without drowning in the first.
  const a = AitpAgent.generate();
  const mk = (extra = {}) =>
    a.buildManifest({
      displayName: 'peer',
      handshakeEndpoint: 'http://localhost:9000/aitp/handshake/',
      offeredCaps: ['demo.write'],
      ...extra,
    });
  const forged = JSON.parse(mk());
  forged.manifest.aid = AitpAgent.generate().aid;

  assert.notEqual(
    causeOf(() => verifyManifestJson(mk({ ttlSecs: -1 }))),
    causeOf(() => verifyManifestJson(JSON.stringify(forged))),
  );
});
