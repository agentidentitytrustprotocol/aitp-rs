// UUID inputs to the binding: strict where wire-bound, lenient where a
// lookup key (#272).
//
// Strict (signed or sent as given, so it must already be the wire form,
// lowercase hyphenated v4 per RFC-AITP-0001 §5.2): `signEnvelope`'s
// `messageId` and `SessionBundleBuilder.sessionId`. Every other form
// throws, naming the wire field.
//
// Lenient (a lookup key, never signed or sent): every `revokedJtis` list.
// An entry in any RFC 9562 text form is normalized and matches the
// canonical `jti`; a v1 entry is accepted but never matches a v4 `jti`;
// an entry that is not a UUID at all throws.
//
// Python mirror: `bindings/aitp-py/tests/test_uuid_inputs.py`.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  AitpAgent,
  TctStore,
  verifyDelegation,
} from '../index.js';
import {
  HAS_BUNDLE,
  HAS_MULTIHOP,
  HAS_RENEWAL,
  SessionBundleBuilder,
  verifyDelegationMultihop,
} from './_experimental.mjs';
import { decodeJwsPayload } from './_jws.mjs';

const V4 = '770e8400-e29b-41d4-a716-446655441011';
const V1 = '770e8400-e29b-11d4-a716-446655441007';

function respell(canonical, label) {
  switch (label) {
    case 'lowercase':
      return canonical;
    case 'uppercase':
      return canonical.toUpperCase();
    case 'braced':
      return `{${canonical}}`;
    case 'urn':
      return `urn:uuid:${canonical}`;
    case 'unhyphenated':
      return canonical.replaceAll('-', '');
    default:
      throw new Error(`unknown spelling ${label}`);
  }
}

const SPELLINGS = ['uppercase', 'braced', 'urn', 'unhyphenated'];
const NON_CANONICAL = [...SPELLINGS.map((l) => [l, respell(V4, l)]), ['v1', V1]];

function peer(name, port, offers, extra = {}) {
  const agent = AitpAgent.generate();
  const manifest = agent.buildManifest({
    displayName: name,
    handshakeEndpoint: `http://localhost:${port}/aitp/handshake/`,
    offeredCaps: offers,
    ...extra,
  });
  return { agent, manifest };
}

function handshake(initiator, responder, respManifest, requested) {
  const sess = initiator.newSession(null, { pinnedKeys: [responder.aid] });
  const rsess = responder.newResponder(null, { pinnedKeys: [initiator.aid] });
  const hello = sess.buildHello(respManifest, requested);
  const { ackJson: helloAck, sessionId } = rsess.processHello(hello);
  const commit = sess.processHelloAck(helloAck, sessionId);
  const { ackJson: commitAck } = rsess.processCommit(commit, []);
  return sess.complete(commitAck, []);
}

// ── Strict: envelope messageId ─────────────────────────────────────────

test('messageId: lowercase v4 is signed verbatim', () => {
  const signed = JSON.parse(AitpAgent.generate().signEnvelope('tct', '{}', { messageId: V4 }));
  assert.equal(signed.message_id, V4);
});

for (const [label, value] of NON_CANONICAL) {
  test(`messageId: ${label} is rejected`, () => {
    assert.throws(
      () => AitpAgent.generate().signEnvelope('tct', '{}', { messageId: value }),
      /message_id is not a lowercase UUID v4/,
    );
  });
}

// ── Strict: session bundle sessionId ───────────────────────────────────


test('sessionId: lowercase v4 is signed verbatim', { skip: !HAS_BUNDLE }, () => {
  const { agent: coord, manifest: coordManifest } = peer('coordinator', 9801, ['session.member'], {
    ttlSecs: 24 * 3600,
  });
  const { agent: member } = peer('member', 9802, ['x']);
  const tct = handshake(member, coord, coordManifest, ['session.member']).tct;
  const envelope = JSON.parse(
    new SessionBundleBuilder(coord).sessionId(V4).participant(member.aid, tct).build(),
  );
  assert.equal(envelope.session_bundle.session_id, V4);
});

for (const [label, value] of NON_CANONICAL) {
  test(`sessionId: ${label} is rejected`, { skip: !HAS_BUNDLE }, () => {
    const builder = new SessionBundleBuilder(AitpAgent.generate());
    assert.throws(() => builder.sessionId(value), /session_id is not a lowercase UUID v4/);
  });
}

// ── Lenient: revokedJtis on verifyTct / verifyTctCached ────────────────

const GRANT = 'demo.write';

function heldTct() {
  const { agent: initiator } = peer('initiator', 9811, ['demo.echo']);
  const { agent: responder, manifest } = peer('responder', 9812, [GRANT]);
  const { tct } = handshake(initiator, responder, manifest, [GRANT]);
  return { initiator, responder, tct, jti: decodeJwsPayload(tct).jti };
}

const held = heldTct();

for (const label of ['lowercase', ...SPELLINGS]) {
  test(`verifyTct: ${label} revoked jti matches`, () => {
    const { initiator, tct, jti } = held;
    assert.throws(
      () => initiator.verifyTct(tct, GRANT, null, [respell(jti, label)]),
      /revoked/,
    );
  });

  test(`verifyTctCached: ${label} revoked jti matches on a cache hit`, () => {
    const { initiator, tct, jti } = held;
    const store = new TctStore(4);
    assert.equal(initiator.verifyTctCached(tct, GRANT, store, undefined, []).jti, jti);
    assert.equal(store.len(), 1);
    assert.throws(
      () => initiator.verifyTctCached(tct, GRANT, store, null, [respell(jti, label)]),
      /revoked/,
    );
  });
}

test('verifyTct: v1 revoked jti is accepted but never matches', () => {
  const { initiator, tct, jti } = held;
  assert.equal(initiator.verifyTct(tct, GRANT, null, [V1]).jti, jti);
});

test('verifyTct: malformed revoked jti is rejected', () => {
  const { initiator, tct } = held;
  assert.throws(
    () => initiator.verifyTct(tct, GRANT, null, ['not-a-uuid']),
    /revoked_jtis entry is not a UUID/,
  );
});

test('verifyTctCached: malformed revoked jti is rejected', () => {
  const { initiator, tct } = held;
  const store = new TctStore(4);
  initiator.verifyTctCached(tct, GRANT, store, undefined, []);
  assert.throws(
    () => initiator.verifyTctCached(tct, GRANT, store, null, ['not-a-uuid']),
    /revoked_jtis entry is not a UUID/,
  );
});

// ── Lenient: revokedJtis on processRenewalRequest ──────────────────────


function renew(revoked) {
  const { initiator, responder, tct } = held;
  const req = initiator.buildRenewalRequest(tct);
  return responder.processRenewalRequest(req, Math.floor(Date.now() / 1000) + 86_400, 3600, revoked);
}

for (const label of ['lowercase', ...SPELLINGS]) {
  test(`processRenewalRequest: ${label} revoked jti matches`, { skip: !HAS_RENEWAL }, () => {
    assert.throws(() => renew([respell(held.jti, label)]), /revoked/);
  });
}

test('processRenewalRequest: v1 revoked jti is accepted but never matches', { skip: !HAS_RENEWAL }, () => {
  assert.equal(renew([V1]).tct.split('.').length, 3);
});

test('processRenewalRequest: malformed revoked jti is rejected', { skip: !HAS_RENEWAL }, () => {
  assert.throws(() => renew(['not-a-uuid']), /revoked_jtis entry is not a UUID/);
});

// ── Lenient: revokedJtis on verifyDelegation(Multihop, undefined, undefined, []) ─────────────────

function buildDelegation() {
  const { agent: a, manifest: aManifest } = peer('A', 9821, [GRANT]);
  const { agent: b, manifest: bManifest } = peer('B', 9822, ['demo.echo']);
  const { agent: c } = peer('C', 9823, ['demo.read']);
  const { grantVoucher } = handshake(b, a, aManifest, [GRANT]);
  const token = b.buildDelegation(grantVoucher, c.aid, [GRANT]);
  const srcJti = decodeJwsPayload(decodeJwsPayload(token).voucher).src_jti;
  return { a, bManifest, token, srcJti };
}

const delegation = buildDelegation();

const VERIFIERS = [['verifyDelegation', (t, aid, m, r) => verifyDelegation(t, aid, m, r)]];
if (HAS_MULTIHOP) {
  VERIFIERS.push([
    'verifyDelegationMultihop',
    (t, aid, m, r) => verifyDelegationMultihop(t, aid, m, null, r),
  ]);
}

for (const [name, verify] of VERIFIERS) {
  for (const label of ['lowercase', ...SPELLINGS]) {
    test(`${name}: ${label} revoked jti matches`, () => {
      const { a, bManifest, token, srcJti } = delegation;
      assert.throws(() => verify(token, a.aid, [bManifest], [respell(srcJti, label)]), /revoked/);
    });
  }

  test(`${name}: v1 revoked jti is accepted but never matches`, () => {
    const { a, bManifest, token } = delegation;
    assert.equal(verify(token, a.aid, [bManifest], [V1]).delegator, a.aid);
  });

  test(`${name}: malformed revoked jti is rejected`, () => {
    const { a, bManifest, token } = delegation;
    assert.throws(
      () => verify(token, a.aid, [bManifest], ['not-a-uuid']),
      /revoked_jtis entry is not a UUID/,
    );
  });
}
