// SPKI cert pinning — Node SDK.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';

import forge from 'node-forge';

import {
  AitpAgent as _AitpAgent,
  computeSpkiHash,
  SpkiPinVerifier,
} from '../index.js';

const HAS_PINNING = typeof computeSpkiHash === 'function';

function selfSignedDer() {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  const attrs = [{ name: 'commonName', value: 'pinning-test.example' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  return Buffer.from(derBytes, 'binary');
}

test('computeSpkiHash returns 32 bytes', { skip: !HAS_PINNING }, () => {
  const der = selfSignedDer();
  const h = computeSpkiHash(der);
  assert.equal(h.length, 32);
});

test('computeSpkiHash is deterministic', { skip: !HAS_PINNING }, () => {
  const der = selfSignedDer();
  assert.deepEqual(computeSpkiHash(der), computeSpkiHash(der));
});

test('computeSpkiHash rejects garbage', { skip: !HAS_PINNING }, () => {
  assert.throws(() => computeSpkiHash(Buffer.from('not a cert')));
});

test('SpkiPinVerifier matches pinned cert', { skip: !HAS_PINNING }, () => {
  const der = selfSignedDer();
  const h = computeSpkiHash(der);
  const otherDer = selfSignedDer();

  const verifier = new SpkiPinVerifier([h]);
  assert.equal(verifier.isPinned(der), true);
  assert.equal(verifier.isPinned(otherDer), false);
  assert.equal(verifier.len, 1);
});

test('SpkiPinVerifier rejects wrong-length pin', { skip: !HAS_PINNING }, () => {
  assert.throws(() => new SpkiPinVerifier([Buffer.alloc(31, 0)]));
});
