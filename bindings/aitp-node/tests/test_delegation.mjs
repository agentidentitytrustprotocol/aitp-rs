// Delegation (RFC-AITP-0006) round-trip — Node SDK.
//
// Three agents: A (issuer/verifier), B (delegator), C (delegatee).
//   1. A issues a TCT to B for ["demo.write"] via the four-message handshake.
//   2. B mints a DelegationEnvelope binding C's pubkey.
//   3. A verifies the envelope, then mints a fresh TCT for C.
//   4. C verifies the fresh TCT under the presented-TCT model.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  AitpAgent,
  verifyDelegation,
  verifyDelegationExperimentalMultihop,
} from '../index.js';

const HAS_MULTIHOP =
  typeof verifyDelegationExperimentalMultihop === 'function';

// Take a valid single-hop envelope and inject a non-empty `chain`. A
// `DelegationStep` shares the wire shape of `grant_proof`, so reusing the
// envelope's own `grant_proof` keeps the JSON deserializable while turning the
// token into a (structurally bogus) multi-hop one — enough to exercise the
// strict-vs-experimental gate, which fires before signature/structure checks.
function injectMultihopChain(delegationEnv) {
  const env = JSON.parse(delegationEnv);
  env.delegation.chain = [env.delegation.grant_proof];
  return JSON.stringify(env);
}

function buildDelegationEnv() {
  const { agent: a, manifest: aManifest } = buildPeer('A', 8301, ['demo.write']);
  const { agent: b } = buildPeer('B', 8302, ['demo.echo']);
  const { agent: c } = buildPeer('C', 8303, ['demo.read']);

  const bHeldTctFromA = fullHandshake(b, a, aManifest, ['demo.write']);
  const cManifestEnv = JSON.parse(c.buildManifest({
    displayName: 'C',
    handshakeEndpoint: 'http://localhost:8303/aitp/handshake/',
    offeredCaps: ['demo.read'],
  }));
  const cPubKey = cManifestEnv.manifest.identity_hint.public_key;
  const delegationEnv = b.buildDelegation(bHeldTctFromA, c.aid, cPubKey, ['demo.write']);
  return { a, delegationEnv };
}

function buildPeer(name, port, offers) {
  const agent = AitpAgent.generate();
  const manifest = agent.buildManifest({
    displayName: name,
    handshakeEndpoint: `http://localhost:${port}/aitp/handshake/`,
    offeredCaps: offers,
  });
  return { agent, manifest };
}

function fullHandshake(initiator, responder, respManifest, requested) {
  const sess = initiator.newSession();
  const rsess = responder.newResponder();
  const hello = sess.buildHello(respManifest, requested);
  const { ackJson: helloAck, sessionId } = rsess.processHello(hello);
  const commit = sess.processHelloAck(helloAck, sessionId);
  const { ackJson: commitAck } = rsess.processCommit(commit);
  return sess.complete(commitAck); // initiator-held TCT (issued by responder)
}

test('delegation round-trip: A → B → C → A re-issues to C', () => {
  // Use ephemeral ports for clarity; manifests are not actually fetched.
  const { agent: a, manifest: aManifest } = buildPeer('A', 8101, ['demo.write']);
  const { agent: b } = buildPeer('B', 8102, ['demo.echo']);
  const { agent: c } = buildPeer('C', 8103, ['demo.read']);

  // B initiates against A and ends up holding A's TCT for demo.write.
  const bHeldTctFromA = fullHandshake(b, a, aManifest, ['demo.write']);

  // C's raw Ed25519 pubkey — pulled from C's manifest identity_hint.
  const cManifestEnv = JSON.parse(c.buildManifest({
    displayName: 'C',
    handshakeEndpoint: 'http://localhost:8103/aitp/handshake/',
    offeredCaps: ['demo.read'],
  }));
  const cPubKey = cManifestEnv.manifest.identity_hint.public_key;

  // B mints a delegation envelope binding C's key, scoped to demo.write.
  const delegationEnv = b.buildDelegation(
    bHeldTctFromA,
    c.aid,
    cPubKey,
    ['demo.write'],
  );

  // A verifies and mints a fresh TCT bound to C.
  const verified = verifyDelegation(delegationEnv, a.aid);
  assert.equal(verified.delegator, a.aid);
  assert.equal(verified.delegatee, c.aid);
  assert.equal(verified.issuedBy, b.aid);
  assert.deepEqual(verified.grants, ['demo.write']);

  const freshTctForC = a.issueTctForDelegatee(verified);

  // C verifies the new TCT under the presented-TCT model (audience = C.aid).
  const ident = c.verifyTct(freshTctForC, 'demo.write', c.aid);
  assert.equal(ident.peerAid, a.aid);
  assert.ok(ident.grants.includes('demo.write'));
});

test('verifyDelegation rejects a wrong verifier AID', () => {
  const { agent: a, manifest: aManifest } = buildPeer('A', 8201, ['demo.write']);
  const { agent: b } = buildPeer('B', 8202, ['demo.echo']);
  const { agent: c } = buildPeer('C', 8203, ['demo.read']);
  const { agent: other } = buildPeer('Other', 8204, ['demo.x']);

  const bHeldTctFromA = fullHandshake(b, a, aManifest, ['demo.write']);

  const cManifestEnv = JSON.parse(c.buildManifest({
    displayName: 'C',
    handshakeEndpoint: 'http://localhost:8203/aitp/handshake/',
    offeredCaps: ['demo.read'],
  }));
  const cPubKey = cManifestEnv.manifest.identity_hint.public_key;

  const delegationEnv = b.buildDelegation(
    bHeldTctFromA,
    c.aid,
    cPubKey,
    ['demo.write'],
  );

  // A different agent's AID should be rejected as the verifier.
  assert.throws(() => verifyDelegation(delegationEnv, other.aid));
});

test('verifyDelegation (strict default) rejects a multi-hop chain', () => {
  // RFC-AITP-0006 §4.4: any non-empty chain is rejected with
  // DELEGATION_MULTIHOP_NOT_SUPPORTED before any per-hop work.
  const { a, delegationEnv } = buildDelegationEnv();
  const tampered = injectMultihopChain(delegationEnv);
  assert.throws(
    () => verifyDelegation(tampered, a.aid),
    /multi-hop delegation is not supported/,
  );
});

test(
  'verifyDelegationExperimentalMultihop opts past the hop gate',
  { skip: !HAS_MULTIHOP ? 'built without experimental-multihop-delegation' : false },
  () => {
    // The opt-in verifier must get PAST the hop gate the strict path rejects
    // at — proven by failing with a *different* error (structure/signature)
    // rather than MULTIHOP_NOT_SUPPORTED.
    const { a, delegationEnv } = buildDelegationEnv();
    const tampered = injectMultihopChain(delegationEnv);
    assert.throws(() => verifyDelegationExperimentalMultihop(tampered, a.aid, 3), (err) => {
      assert.doesNotMatch(String(err.message), /multi-hop delegation is not supported/);
      return true;
    });
  },
);
