// Full four-message AITP handshake with OIDC identity proofs (RFC-AITP-0002).
//
// Uses an in-process mock OIDC issuer built directly on node:crypto so the
// SDK's sync `oidcMintJwt` callback can sign the JWT inline. No HTTP I/O —
// the issuer's JWK is pre-loaded into the SDK's `JwksProvider`.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';

import { AitpAgent, JwksProvider } from '../index.js';

const ISSUER_URL = 'https://idp.example.test/';

function b64url(b) {
  return Buffer.from(b).toString('base64url');
}

// Synchronous in-process OIDC issuer. Holds an Ed25519 keypair, signs
// JWTs by hand, exposes the public key as a JWK for the JwksProvider.
function mockIssuer(kid = 'kid-1') {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: b64url(rawPub),
    kid,
    alg: 'EdDSA',
    use: 'sig',
  };
  const mint = ({ sub, aud, nonce, cnfJkt, now }) => {
    const header = { alg: 'EdDSA', typ: 'JWT', kid };
    const payload = {
      iss: ISSUER_URL,
      sub,
      aud,
      iat: now,
      exp: now + 3600,
      nonce,
      cnf: { jkt: cnfJkt },
    };
    const h = b64url(JSON.stringify(header));
    const p = b64url(JSON.stringify(payload));
    const signingInput = Buffer.from(`${h}.${p}`);
    const sig = cryptoSign(null, signingInput, privateKey);
    return `${h}.${p}.${b64url(sig)}`;
  };
  return { kid, jwk, mint };
}

// JWK thumbprint for the Ed25519 pubkey embedded in an AID.
function aidJkt(aid) {
  const prefix = 'aid:pubkey:ed25519:';
  const legacy = 'aid:pubkey:';
  const pkB64 = aid.startsWith(prefix) ? aid.slice(prefix.length) : aid.slice(legacy.length);
  const pk = Buffer.from(pkB64 + '==', 'base64url').subarray(0, 32);
  const canonical = JSON.stringify({
    crv: 'Ed25519',
    kty: 'OKP',
    x: b64url(pk),
  });
  return b64url(createHash('sha256').update(canonical).digest());
}

function setup() {
  const issuer = mockIssuer();
  const provider = new JwksProvider({ [ISSUER_URL]: [issuer.jwk] });

  const alice = AitpAgent.generate();
  const bob = AitpAgent.generate();
  const aManifest = alice.buildManifest({
    displayName: 'alice',
    handshakeEndpoint: 'https://alice.example.test/aitp/handshake/',
    offeredCaps: ['demo.echo'],
    identityType: 'oidc',
    oidcIssuer: ISSUER_URL,
    oidcSubject: 'alice',
  });
  const bManifest = bob.buildManifest({
    displayName: 'bob',
    handshakeEndpoint: 'https://bob.example.test/aitp/handshake/',
    offeredCaps: ['demo.write'],
    identityType: 'oidc',
    oidcIssuer: ISSUER_URL,
    oidcSubject: 'bob',
  });
  return { issuer, provider, alice, bob, aManifest, bManifest };
}

test('full OIDC handshake yields mutual TCTs', () => {
  const { issuer, provider, alice, bob, bManifest } = setup();
  const now = Math.floor(Date.now() / 1000);
  const aJkt = aidJkt(alice.aid);
  const bJkt = aidJkt(bob.aid);

  const aMint = (nonce) =>
    issuer.mint({ sub: 'alice', aud: bob.aid, nonce, cnfJkt: aJkt, now });
  const bMint = (nonce) =>
    issuer.mint({ sub: 'bob', aud: alice.aid, nonce, cnfJkt: bJkt, now });

  const sess = alice.newSession(provider);
  const rsess = bob.newResponder(provider);

  const hello = sess.buildHello(bManifest, ['demo.write'], aMint);
  const { ackJson: helloAck, sessionId } = rsess.processHello(hello, bMint);
  const commit = sess.processHelloAck(helloAck, sessionId);
  const { ackJson: commitAck, tctJson: bobHeld } = rsess.processCommit(commit);
  const aliceHeld = sess.complete(commitAck);

  const aIdent = alice.verifyTct(aliceHeld, 'demo.write');
  assert.equal(aIdent.peerAid, bob.aid);
  const bIdent = bob.verifyTct(bobHeld, 'demo.echo');
  assert.equal(bIdent.peerAid, alice.aid);
});

test('OIDC session requires mintJwt callback', () => {
  const { provider, alice, bManifest } = setup();
  const sess = alice.newSession(provider);
  assert.throws(() => sess.buildHello(bManifest, ['demo.write']));
});

// Regression: napi Ref leak. Previously, passing a mintJwt callback to
// buildHello and then having buildHello error BEFORE the state machine
// invoked the callback would panic napi-rs's Ref drop impl with
// "Ref count is not equal to 0 while dropping". Trigger that path by
// feeding a malformed peer manifest — the JSON parse fails before
// Initiator::start even constructs the descriptor.
test('mintJwt callback Ref unrefs cleanly on early error', () => {
  const { provider, alice } = setup();
  const sess = alice.newSession(provider);
  let called = false;
  const neverInvoked = (_nonce) => {
    called = true;
    return 'irrelevant';
  };
  assert.throws(() =>
    sess.buildHello('not valid manifest json', ['demo.write'], neverInvoked),
  );
  assert.equal(called, false, 'mint callback should not have run');
  // If we reach this line without a panic, the Ref was unref'd cleanly.
});
