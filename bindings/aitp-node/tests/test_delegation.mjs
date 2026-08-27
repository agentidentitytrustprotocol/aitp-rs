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
import {
  withClaims,
  decodeJwsPayload,
  tamperJwsSignature,
} from './_jws.mjs';

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

// ── Revocation (RFC-AITP-0006 §4 step 7, RFC-AITP-0011 §6) ───────────────
//
// The Rust core has always had `revocation_check` / `hop_revocation_check`.
// What was missing was any way to reach them from JS: both entry points
// built their context with `VerifyDelegationContext::new`, which hardcodes
// both hooks to `None`, and neither exposed a parameter. Every delegation
// redeemed through this SDK therefore skipped step 7 — a MUST-reject — and a
// revoked source TCT still bought a freshly minted TCT for the delegatee.
//
// These pin the wiring; the semantics are covered in the core's own tests.

/** The `src_jti` of the voucher a delegation is rooted in — what A revokes. */
function srcJti(delegationToken) {
  const claims = decodeJwsPayload(delegationToken);
  return decodeJwsPayload(claims.voucher).src_jti;
}

test('revoking the source TCT rejects the delegation', () => {
  const { a, delegationToken } = buildVoucher();

  // Sanity: verifies while nothing is revoked, so the rejection below is
  // attributable to the deny list and nothing else.
  verifyDelegation(delegationToken, a.aid);

  assert.throws(
    () => verifyDelegation(delegationToken, a.aid, [srcJti(delegationToken)]),
    /revoked/i,
  );
});

test('a revoked source TCT yields no TCT for the delegatee', () => {
  // Step 7 is not bookkeeping: redeeming a delegation mints a *fresh TCT*
  // for the delegatee. Skipping it meant a revoked grant kept minting
  // credentials for a third party the grantor never re-authorized.
  const { a, delegationToken } = buildVoucher();

  assert.throws(() => {
    const verified = verifyDelegation(delegationToken, a.aid, [
      srcJti(delegationToken),
    ]);
    // Unreachable while step 7 holds. If it ever is reached, this is the
    // line that shows what the omission actually costs.
    a.issueTctForDelegatee(verified);
  });
});

test('an unrelated revoked jti does not reject', () => {
  // The lookup is keyed on `src_jti`, not "the list is non-empty" — without
  // this, a blanket-reject bug would pass the test above.
  const { a, delegationToken } = buildVoucher();
  const unrelated = '00000000-0000-4000-8000-000000000000';
  assert.notEqual(unrelated, srcJti(delegationToken));

  const verified = verifyDelegation(delegationToken, a.aid, [unrelated]);
  assert.equal(verified.delegator, a.aid);
});

test('omitting revokedJtis verifies a revoked delegation', () => {
  // Pins the default so it cannot change silently. Omitting the list waives
  // step 7 entirely — the same posture `verifyTct` takes, and the reason
  // both doc comments say verifiers SHOULD supply it. This documents the
  // hazard rather than endorsing it.
  const { a, delegationToken } = buildVoucher();
  const verified = verifyDelegation(delegationToken, a.aid);
  assert.equal(verified.delegator, a.aid);
});

test('malformed jtis in the list are ignored, not treated as matches', () => {
  // `parseRevokedSet` drops anything that is not a UUID. A list of pure
  // garbage must therefore behave exactly like an empty one, rather than
  // rejecting every token that comes near it.
  const { a, delegationToken } = buildVoucher();
  const verified = verifyDelegation(delegationToken, a.aid, [
    'not-a-uuid',
    '',
  ]);
  assert.equal(verified.delegator, a.aid);
});

test('revocation is consulted only after the signature checks', () => {
  // RFC-AITP-0008 §3.3 ordering, and it is not cosmetic: running the one
  // stateful lookup before the signature checks would let an unauthenticated
  // caller probe which jtis are in a verifier's deny list by watching which
  // forged tokens come back "revoked" versus "bad signature".
  const { a, delegationToken } = buildVoucher();
  const tampered = tamperJwsSignature(delegationToken);

  assert.throws(
    () => verifyDelegation(tampered, a.aid, [srcJti(delegationToken)]),
    (err) => !/revoked/i.test(String(err.message)),
    'a token failing signature verification was reported as revoked — the ' +
      'deny-list lookup ran before the signature checks',
  );
});
