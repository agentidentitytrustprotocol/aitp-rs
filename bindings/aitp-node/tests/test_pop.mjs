// Downstream proof of possession (RFC-AITP-0005 §6) — Node SDK.
//
// The consumer challenges the presenter of a TCT (`newPopChallenge`), the
// holder signs it (`signPopResponse`), and the consumer verifies the TCT and
// the response together (`verifyTct(..., pop)`) or the response alone
// (`verifyPopResponse`). The happy path mirrors the `tct-006` fixture; the
// wrong-key refusal mirrors `tct-007` (no valid response, no capability).

import test from 'node:test';
import assert from 'node:assert/strict';

import { AitpAgent, TctStore, verifyPopResponse } from '../index.js';

const GRANT = 'demo.write';
const OTHER_JTI = '00000000-0000-4000-8000-000000000000';

const coded = (code) => (err) => err.code === code;

// `{ holder, consumer, tct }`: the consumer issued `tct` to the holder in a
// handshake, and the holder now presents it back.
function presented() {
  const holder = AitpAgent.generate();
  const consumer = AitpAgent.generate();
  holder.buildManifest({
    displayName: 'holder',
    handshakeEndpoint: 'http://localhost:8100/aitp/handshake/',
    offeredCaps: ['demo.echo'],
  });
  const consumerManifest = consumer.buildManifest({
    displayName: 'consumer',
    handshakeEndpoint: 'http://localhost:8200/aitp/handshake/',
    offeredCaps: [GRANT],
  });
  const sess = holder.newSession(null, { pinnedKeys: [consumer.aid] });
  const rsess = consumer.newResponder(null, { pinnedKeys: [holder.aid] });
  const { ackJson: helloAck, sessionId } = rsess.processHello(
    sess.buildHello(consumerManifest, [GRANT]),
  );
  const { ackJson } = rsess.processCommit(sess.processHelloAck(helloAck, sessionId), []);
  return { holder, consumer, tct: sess.complete(ackJson, []).tct };
}

function exchange() {
  const p = presented();
  const challenge = p.consumer.newPopChallenge(p.tct);
  return { ...p, challenge, response: p.holder.signPopResponse(challenge) };
}

const edit = (json, fields) => JSON.stringify({ ...JSON.parse(json), ...fields });
const b64 = (n) => Buffer.alloc(n).toString('base64url');
const nowSecs = () => Math.floor(Date.now() / 1000);

// ── tct-006: the exchange end to end ────────────────────────────────────

test('verifyTct with pop accepts the holder', () => {
  const { consumer, tct, challenge, response } = exchange();
  const ident = consumer.verifyTct(tct, GRANT, null, [], undefined, { challenge, response });
  assert.equal(ident.peerAid, consumer.aid);
  assert.ok(ident.grants.includes(GRANT));
});

test('verifyPopResponse returns the proven holder', () => {
  const { holder, tct, challenge, response } = exchange();
  assert.equal(verifyPopResponse(challenge, response, tct), holder.aid);
});

test('challenge shape', () => {
  const { holder, consumer, tct } = presented();
  const { jti } = holder.verifyTct(tct, GRANT, null, []);
  const before = nowSecs();
  const challenge = JSON.parse(consumer.newPopChallenge(tct, 30));
  assert.deepEqual(Object.keys(challenge).sort(), ['expires_at', 'nonce', 'tct_jti']);
  assert.equal(challenge.tct_jti, jti);
  assert.doesNotMatch(challenge.nonce, /=/);
  assert.equal(Buffer.from(challenge.nonce, 'base64url').length, 16);
  assert.ok(challenge.expires_at >= before + 30 && challenge.expires_at <= nowSecs() + 30);
  assert.notEqual(JSON.parse(consumer.newPopChallenge(tct)).nonce, challenge.nonce);
});

test('the holder signs the wire payload (no expires_at)', () => {
  const { holder, consumer, tct, challenge } = exchange();
  const { expires_at: _, ...wire } = JSON.parse(challenge);
  const response = holder.signPopResponse(JSON.stringify(wire));
  const body = JSON.parse(response);
  assert.deepEqual(Object.keys(body).sort(), ['nonce_echo', 'pop_signature', 'tct_jti']);
  assert.equal(body.tct_jti, wire.tct_jti);
  assert.equal(body.nonce_echo, wire.nonce);
  consumer.verifyTct(tct, GRANT, null, [], undefined, { challenge, response });
});

test('cached verify checks pop on every call', () => {
  const { consumer, tct, challenge, response } = exchange();
  const store = new TctStore(8);
  consumer.verifyTctCached(tct, GRANT, store, null, [], undefined, { challenge, response });
  assert.equal(store.len(), 1);
  const forged = AitpAgent.generate().signPopResponse(challenge);
  assert.throws(
    () =>
      consumer.verifyTctCached(tct, GRANT, store, null, [], undefined, {
        challenge,
        response: forged,
      }),
    coded('POP_RESPONSE_INVALID'),
  );
});

// ── tct-007 and the other §6.2 refusals ─────────────────────────────────

function refused(code, consumer, tct, challenge, response) {
  assert.throws(
    () => consumer.verifyTct(tct, GRANT, null, [], undefined, { challenge, response }),
    coded(code),
  );
  assert.throws(() => verifyPopResponse(challenge, response, tct), coded(code));
}

test('wrong key is refused', () => {
  const { consumer, tct, challenge } = exchange();
  const forged = AitpAgent.generate().signPopResponse(challenge);
  refused('POP_RESPONSE_INVALID', consumer, tct, challenge, forged);
});

test('wrong nonce is refused', () => {
  const { consumer, tct, challenge, response } = exchange();
  refused('POP_RESPONSE_INVALID', consumer, tct, challenge, edit(response, { nonce_echo: b64(16) }));
});

test('a response to another challenge is refused', () => {
  const { holder, consumer, tct, challenge } = exchange();
  const other = holder.signPopResponse(consumer.newPopChallenge(tct));
  refused('POP_RESPONSE_INVALID', consumer, tct, challenge, other);
});

test('jti mismatch is refused', () => {
  const { holder, consumer, tct, challenge } = exchange();
  const elsewhere = edit(challenge, { tct_jti: OTHER_JTI });
  refused('POP_RESPONSE_INVALID', consumer, tct, elsewhere, holder.signPopResponse(elsewhere));
});

test('an expired challenge is refused', () => {
  const { consumer, tct, challenge, response } = exchange();
  const stale = edit(challenge, { expires_at: nowSecs() - 5 });
  refused('POP_CHALLENGE_INVALID', consumer, tct, stale, response);
});

test('the holder refuses an expired challenge', () => {
  const { holder, consumer, tct } = presented();
  const stale = edit(consumer.newPopChallenge(tct), { expires_at: nowSecs() - 5 });
  assert.throws(() => holder.signPopResponse(stale), coded('POP_CHALLENGE_INVALID'));
});

test('a malformed challenge is refused', () => {
  const holder = AitpAgent.generate();
  for (const challenge of [
    'not json',
    JSON.stringify({ tct_jti: OTHER_JTI }),
    JSON.stringify({ tct_jti: OTHER_JTI, nonce: b64(8) }),
    JSON.stringify({ tct_jti: OTHER_JTI, nonce: '!!', extra: 1 }),
  ]) {
    assert.throws(() => holder.signPopResponse(challenge), coded('POP_CHALLENGE_INVALID'));
  }
});

test('a malformed response is refused', () => {
  const { consumer, tct, challenge } = exchange();
  refused('POP_RESPONSE_INVALID', consumer, tct, challenge, '{}');
});

test('a TCT failure still wins: revocation applies with pop', () => {
  const { consumer, tct, challenge, response } = exchange();
  assert.throws(
    () => consumer.verifyTct(tct, GRANT, null, undefined, undefined, { challenge, response }),
    coded('TCT_REVOKED'),
  );
});

// ── Argument errors ─────────────────────────────────────────────────────

test('pop excludes expectedAudience', () => {
  const { holder, consumer, tct, challenge, response } = exchange();
  assert.throws(
    () => consumer.verifyTct(tct, GRANT, holder.aid, [], undefined, { challenge, response }),
    /not both/,
  );
});

test('ttlSecs must be positive', () => {
  const { consumer, tct } = presented();
  assert.throws(() => consumer.newPopChallenge(tct, 0), /ttlSecs/);
});
