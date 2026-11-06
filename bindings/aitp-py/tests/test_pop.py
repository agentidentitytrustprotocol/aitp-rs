"""Downstream proof of possession (RFC-AITP-0005 §6) — Python SDK.

The consumer challenges the presenter of a TCT (`new_pop_challenge`), the
holder signs it (`sign_pop_response`), and the consumer verifies the TCT and
the response together (`verify_tct(..., pop=...)`) or the response alone
(`verify_pop_response`). The happy path mirrors the `tct-006` fixture; the
wrong-key refusal mirrors `tct-007` (no valid response, no capability). Run
with `maturin develop` then `pytest` from `bindings/aitp-py/`.
"""

import base64
import json
import time

import pytest

import aitp

GRANT = "demo.write"
OTHER_JTI = "00000000-0000-4000-8000-000000000000"


def _presented():
    """`(holder, consumer, tct)`: the consumer issued `tct` to the holder in a
    handshake, and the holder now presents it back."""
    holder = aitp.AitpAgent.generate()
    consumer = aitp.AitpAgent.generate()
    holder.build_manifest(
        display_name="holder",
        handshake_endpoint="https://localhost:8100/aitp/handshake/",
        offered_caps=["demo.echo"],
    )
    consumer_manifest = consumer.build_manifest(
        display_name="consumer",
        handshake_endpoint="https://localhost:8200/aitp/handshake/",
        offered_caps=[GRANT],
    )
    sess = holder.new_session(pinned_keys=[consumer.aid])
    rsess = consumer.new_responder(pinned_keys=[holder.aid])
    hello_ack, sid = rsess.process_hello(sess.build_hello(consumer_manifest, [GRANT]))
    commit_ack, _ = rsess.process_commit(sess.process_hello_ack(hello_ack, sid), revoked_jtis=set())
    held = json.loads(sess.complete(commit_ack, revoked_jtis=set()))
    return holder, consumer, held["tct"]


def _exchange():
    holder, consumer, tct = _presented()
    challenge = consumer.new_pop_challenge(tct)
    return holder, consumer, tct, challenge, holder.sign_pop_response(challenge)


def _edit(doc_json, **fields):
    doc = json.loads(doc_json)
    doc.update(fields)
    return json.dumps(doc)


def _b64(n):
    return base64.urlsafe_b64encode(bytes(n)).rstrip(b"=").decode()


# ── tct-006: the exchange end to end ────────────────────────────────────


def test_verify_tct_with_pop_accepts_the_holder():
    holder, consumer, tct, challenge, response = _exchange()
    ident = consumer.verify_tct(tct, GRANT, revoked_jtis=set(), pop=(challenge, response))
    assert ident.peer_aid == consumer.aid
    assert GRANT in ident.grants


def test_verify_pop_response_returns_the_proven_holder():
    holder, _, tct, challenge, response = _exchange()
    assert aitp.verify_pop_response(challenge, response, tct) == holder.aid


def test_challenge_shape():
    holder, consumer, tct = _presented()
    ident = holder.verify_tct(tct, GRANT, revoked_jtis=set())
    before = int(time.time())
    challenge = json.loads(consumer.new_pop_challenge(tct, ttl_secs=30))
    assert set(challenge) == {"tct_jti", "nonce", "expires_at"}
    assert challenge["tct_jti"] == ident.jti
    nonce = challenge["nonce"]
    assert "=" not in nonce
    assert len(base64.urlsafe_b64decode(nonce + "==")) == 16
    assert before + 30 <= challenge["expires_at"] <= int(time.time()) + 30
    assert json.loads(consumer.new_pop_challenge(tct))["nonce"] != nonce


def test_response_shape_and_wire_payload_challenge():
    """The holder may receive only the wire payload (`tct_jti`, `nonce`)."""
    holder, consumer, tct, challenge, _ = _exchange()
    wire = json.loads(challenge)
    del wire["expires_at"]
    response = holder.sign_pop_response(json.dumps(wire))
    body = json.loads(response)
    assert set(body) == {"tct_jti", "nonce_echo", "pop_signature"}
    assert body["tct_jti"] == wire["tct_jti"]
    assert body["nonce_echo"] == wire["nonce"]
    consumer.verify_tct(tct, GRANT, revoked_jtis=set(), pop=(challenge, response))


def test_cached_verify_checks_pop_on_every_call():
    holder, consumer, tct, challenge, response = _exchange()
    store = aitp.TctStore(max_entries=8)
    consumer.verify_tct_cached(tct, GRANT, store, revoked_jtis=set(), pop=(challenge, response))
    assert store.len() == 1
    forged = aitp.AitpAgent.generate().sign_pop_response(challenge)
    with pytest.raises(RuntimeError) as exc:
        consumer.verify_tct_cached(tct, GRANT, store, revoked_jtis=set(), pop=(challenge, forged))
    assert exc.value.code == "POP_RESPONSE_INVALID"


# ── tct-007 and the other §6.2 refusals ─────────────────────────────────


def _refused(code, consumer, tct, challenge, response):
    with pytest.raises(RuntimeError) as exc:
        consumer.verify_tct(tct, GRANT, revoked_jtis=set(), pop=(challenge, response))
    assert exc.value.code == code
    with pytest.raises(RuntimeError) as exc:
        aitp.verify_pop_response(challenge, response, tct)
    assert exc.value.code == code


def test_wrong_key_is_refused():
    _, consumer, tct, challenge, _ = _exchange()
    forged = aitp.AitpAgent.generate().sign_pop_response(challenge)
    _refused("POP_RESPONSE_INVALID", consumer, tct, challenge, forged)


def test_wrong_nonce_is_refused():
    _, consumer, tct, challenge, response = _exchange()
    _refused("POP_RESPONSE_INVALID", consumer, tct, challenge, _edit(response, nonce_echo=_b64(16)))


def test_response_to_another_challenge_is_refused():
    holder, consumer, tct, challenge, _ = _exchange()
    other = holder.sign_pop_response(consumer.new_pop_challenge(tct))
    _refused("POP_RESPONSE_INVALID", consumer, tct, challenge, other)


def test_jti_mismatch_is_refused():
    holder, consumer, tct, challenge, _ = _exchange()
    elsewhere = _edit(challenge, tct_jti=OTHER_JTI)
    _refused("POP_RESPONSE_INVALID", consumer, tct, elsewhere, holder.sign_pop_response(elsewhere))


def test_expired_challenge_is_refused():
    _, consumer, tct, challenge, response = _exchange()
    stale = _edit(challenge, expires_at=int(time.time()) - 5)
    _refused("POP_CHALLENGE_INVALID", consumer, tct, stale, response)


def test_holder_refuses_an_expired_challenge():
    holder, consumer, tct = _presented()
    stale = _edit(consumer.new_pop_challenge(tct), expires_at=int(time.time()) - 5)
    with pytest.raises(RuntimeError) as exc:
        holder.sign_pop_response(stale)
    assert exc.value.code == "POP_CHALLENGE_INVALID"


@pytest.mark.parametrize(
    "challenge",
    [
        "not json",
        json.dumps({"tct_jti": OTHER_JTI}),
        json.dumps({"tct_jti": OTHER_JTI, "nonce": _b64(8)}),
        json.dumps({"tct_jti": OTHER_JTI, "nonce": "!!", "extra": 1}),
    ],
)
def test_malformed_challenge_is_refused(challenge):
    holder = aitp.AitpAgent.generate()
    with pytest.raises(RuntimeError) as exc:
        holder.sign_pop_response(challenge)
    assert exc.value.code == "POP_CHALLENGE_INVALID"


def test_malformed_response_is_refused():
    _, consumer, tct, challenge, _ = _exchange()
    _refused("POP_RESPONSE_INVALID", consumer, tct, challenge, "{}")


def test_tct_failure_still_wins():
    """PoP does not stand in for the TCT checks: revocation still applies."""
    _, consumer, tct, challenge, response = _exchange()
    with pytest.raises(RuntimeError) as exc:
        consumer.verify_tct(tct, GRANT, pop=(challenge, response))
    assert exc.value.code == "TCT_REVOKED"


# ── Argument errors ─────────────────────────────────────────────────────


def test_pop_excludes_expected_audience():
    holder, consumer, tct, challenge, response = _exchange()
    with pytest.raises(ValueError, match="not both"):
        consumer.verify_tct(
            tct, GRANT, expected_audience=holder.aid, revoked_jtis=set(), pop=(challenge, response)
        )


def test_ttl_must_be_positive():
    _, consumer, tct = _presented()
    with pytest.raises(ValueError, match="ttl_secs"):
        consumer.new_pop_challenge(tct, ttl_secs=0)
