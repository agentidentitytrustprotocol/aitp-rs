// Delegation (RFC-AITP-0006, voucher-based v0.2) round-trip — Node SDK.
//
// Three agents: A (issuer/verifier), B (delegator), C (delegatee).
//   1. A issues a TCT + grant voucher to B for ["demo.write"] via the
//      four-message handshake.
//   2. B mints a delegation token from its grant voucher, binding C's AID.
//   3. A verifies the delegation, then mints a fresh TCT for C.
//   4. C verifies the fresh TCT under the presented-TCT model.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  AitpAgent,
  verifyDelegation,
  verifyDelegationMultihop,
} from '../index.js';
import { withClaims } from './_jws.mjs';

const HAS_MULTIHOP =
  typeof verifyDelegationMultihop === 'function';

// Take a valid single-hop delegation token and forge a non-empty `chain`
// claim into its (unverified) payload. The strict vs. multi-hop gate
// fires on the decoded `chain` *before* the signature check, so the stale
// signature is irrelevant to the gate — enough to exercise it.
function injectMultihopChain(delegationToken) {
  return withClaims(delegationToken, { chain: [delegationToken] });
}

// Run the handshake and return B's grant voucher (the delegation root) for
// the requested grants.
function buildVoucher() {
  const { agent: a, manifest: aManifest } = buildPeer('A', 8301, ['demo.write']);
  const { agent: b } = buildPeer('B', 8302, ['demo.echo']);
  const { agent: c } = buildPeer('C', 8303, ['demo.read']);

  const bCompleted = fullHandshake(b, a, aManifest, ['demo.write']);
  const delegationToken = b.buildDelegation(
    bCompleted.grantVoucher,
    c.aid,
    ['demo.write'],
  );
  return { a, delegationToken };
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
  // { tct, claims, grantVoucher } — the voucher is the delegation root.
  return sess.complete(commitAck);
}

test('delegation round-trip: A → B → C → A re-issues to C', () => {
  // Use ephemeral ports for clarity; manifests are not actually fetched.
  const { agent: a, manifest: aManifest } = buildPeer('A', 8101, ['demo.write']);
  const { agent: b } = buildPeer('B', 8102, ['demo.echo']);
  const { agent: c } = buildPeer('C', 8103, ['demo.read']);

  // B initiates against A and ends up holding A's TCT + grant voucher.
  const bCompleted = fullHandshake(b, a, aManifest, ['demo.write']);
  assert.ok(bCompleted.grantVoucher, 'A should issue a delegable grant voucher');

  // B mints a delegation from its voucher, binding C's AID, scoped to
  // demo.write. C's key binding is derived from c.aid itself.
  const delegationToken = b.buildDelegation(
    bCompleted.grantVoucher,
    c.aid,
    ['demo.write'],
  );

  // A verifies and mints a fresh TCT bound to C.
  const verified = verifyDelegation(delegationToken, a.aid);
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

  const bCompleted = fullHandshake(b, a, aManifest, ['demo.write']);
  const delegationToken = b.buildDelegation(
    bCompleted.grantVoucher,
    c.aid,
    ['demo.write'],
  );

  // A different agent's AID should be rejected as the verifier.
  assert.throws(() => verifyDelegation(delegationToken, other.aid));
});

test('verifyDelegation (strict default) rejects a multi-hop chain', () => {
  // RFC-AITP-0006 §4.4: any non-empty chain is rejected with
  // DELEGATION_MULTIHOP_NOT_SUPPORTED before any per-hop work.
  const { a, delegationToken } = buildVoucher();
  const tampered = injectMultihopChain(delegationToken);
  assert.throws(
    () => verifyDelegation(tampered, a.aid),
    /multi-hop delegation is not supported/,
  );
});

test(
  'verifyDelegationMultihop opts past the hop gate',
  { skip: !HAS_MULTIHOP ? 'built without multihop-delegation' : false },
  () => {
    // The opt-in verifier must get PAST the hop gate the strict path rejects
    // at — proven by failing with a *different* error (structure/signature)
    // rather than MULTIHOP_NOT_SUPPORTED.
    const { a, delegationToken } = buildVoucher();
    const tampered = injectMultihopChain(delegationToken);
    assert.throws(() => verifyDelegationMultihop(tampered, a.aid, 3), (err) => {
      assert.doesNotMatch(String(err.message), /multi-hop delegation is not supported/);
      return true;
    });
  },
);
