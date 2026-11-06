"""UUID inputs to the binding: strict where wire-bound, lenient where a
lookup key (#272).

Strict (signed or sent as given, so it must already be the wire form,
lowercase hyphenated v4 per RFC-AITP-0001 §5.2): `sign_envelope`'s
`message_id` and `SessionBundleBuilder.session_id`. Every other form
raises `ValueError` naming the field.

Lenient (a lookup key, never signed or sent): every `revoked_jtis` set.
An entry in any RFC 9562 text form is normalized and matches the
canonical `jti`; a v1 entry is accepted but never matches a v4 `jti`;
an entry that is not a UUID at all raises `ValueError`.

Node mirror: `bindings/aitp-node/tests/test_uuid_inputs.mjs`.
"""

import base64
import json
import time

import pytest

import aitp
from _experimental import HAS_BUNDLE, HAS_MULTIHOP, HAS_RENEWAL

V4 = "770e8400-e29b-41d4-a716-446655441011"
V1 = "770e8400-e29b-11d4-a716-446655441007"


def _forms(canonical):
    """The non-canonical spellings of `canonical`, keyed by label."""
    return {
        "uppercase": canonical.upper(),
        "braced": "{" + canonical + "}",
        "urn": "urn:uuid:" + canonical,
        "unhyphenated": canonical.replace("-", ""),
    }


NON_CANONICAL = list(_forms(V4).items()) + [("v1", V1)]
NON_CANONICAL_IDS = [label for label, _ in NON_CANONICAL]
SPELLINGS = list(_forms(V4))


def _claims(token):
    seg = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def _respell(canonical, label):
    return _forms(canonical)[label]


# ── Strict: envelope message_id ────────────────────────────────────────


def test_message_id_lowercase_v4_is_signed_verbatim():
    agent = aitp.AitpAgent.generate()
    signed = json.loads(agent.sign_envelope("tct", "{}", message_id=V4))
    assert signed["message_id"] == V4


@pytest.mark.parametrize("label, value", NON_CANONICAL, ids=NON_CANONICAL_IDS)
def test_message_id_non_canonical_is_rejected(label, value):
    agent = aitp.AitpAgent.generate()
    with pytest.raises(ValueError, match="message_id is not a lowercase UUID v4"):
        agent.sign_envelope("tct", "{}", message_id=value)


# ── Strict: session bundle session_id ──────────────────────────────────



def _bundle_builder():
    coord = aitp.AitpAgent.generate()
    member = aitp.AitpAgent.generate()
    coord_manifest = coord.build_manifest(
        display_name="coordinator",
        handshake_endpoint="https://localhost:9701/aitp/handshake/",
        offered_caps=["session.member"],
        ttl_secs=24 * 3600,
    )
    member.build_manifest(
        display_name="member",
        handshake_endpoint="https://localhost:9702/aitp/handshake/",
        offered_caps=["x"],
    )
    sess = member.new_session(pinned_keys=[coord.aid])
    rsess = coord.new_responder(pinned_keys=[member.aid])
    hello = sess.build_hello(coord_manifest, ["session.member"])
    hello_ack, sid = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = rsess.process_commit(commit, revoked_jtis=set())
    tct = json.loads(sess.complete(commit_ack, revoked_jtis=set()))["tct"]
    return aitp.SessionBundleBuilder(coord).participant(member.aid, tct)


@pytest.mark.skipif(not HAS_BUNDLE, reason="built without experimental-session-bundle")
def test_session_id_lowercase_v4_is_signed_verbatim():
    envelope = json.loads(_bundle_builder().session_id(V4).build())
    assert envelope["session_bundle"]["session_id"] == V4


@pytest.mark.skipif(not HAS_BUNDLE, reason="built without experimental-session-bundle")
@pytest.mark.parametrize("label, value", NON_CANONICAL, ids=NON_CANONICAL_IDS)
def test_session_id_non_canonical_is_rejected(label, value):
    builder = aitp.SessionBundleBuilder(aitp.AitpAgent.generate())
    with pytest.raises(ValueError, match="session_id is not a lowercase UUID v4"):
        builder.session_id(value)


# ── Lenient: revoked_jtis on verify_tct / verify_tct_cached ────────────

GRANT = "demo.write"


def _held_tct():
    initiator = aitp.AitpAgent.generate()
    responder = aitp.AitpAgent.generate()
    initiator.build_manifest(
        display_name="initiator",
        handshake_endpoint="https://localhost:9711/aitp/handshake/",
        offered_caps=["demo.echo"],
    )
    responder_manifest = responder.build_manifest(
        display_name="responder",
        handshake_endpoint="https://localhost:9712/aitp/handshake/",
        offered_caps=[GRANT],
    )
    sess = initiator.new_session(pinned_keys=[responder.aid])
    rsess = responder.new_responder(pinned_keys=[initiator.aid])
    hello = sess.build_hello(responder_manifest, [GRANT])
    hello_ack, sid = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = rsess.process_commit(commit, revoked_jtis=set())
    completed = json.loads(sess.complete(commit_ack, revoked_jtis=set()))
    return responder, initiator, completed["tct"], completed.get("grant_voucher")


@pytest.fixture(scope="module")
def held():
    _responder, initiator, tct, _voucher = _held_tct()
    return initiator, tct, _claims(tct)["jti"]


def test_verify_tct_lowercase_revoked_jti_matches(held):
    initiator, tct, jti = held
    with pytest.raises(RuntimeError, match="revoked"):
        initiator.verify_tct(tct, GRANT, revoked_jtis={jti})


@pytest.mark.parametrize("label", SPELLINGS)
def test_verify_tct_revoked_jti_is_normalized(held, label):
    initiator, tct, jti = held
    with pytest.raises(RuntimeError, match="revoked"):
        initiator.verify_tct(tct, GRANT, revoked_jtis={_respell(jti, label)})


def test_verify_tct_v1_revoked_jti_is_accepted_but_never_matches(held):
    initiator, tct, jti = held
    assert initiator.verify_tct(tct, GRANT, revoked_jtis={V1}).jti == jti


def test_verify_tct_malformed_revoked_jti_is_rejected(held):
    initiator, tct, _jti = held
    with pytest.raises(ValueError, match="revoked_jtis entry is not a UUID"):
        initiator.verify_tct(tct, GRANT, revoked_jtis={"not-a-uuid"})


@pytest.mark.parametrize("label", SPELLINGS)
def test_verify_tct_cached_revoked_jti_is_normalized_on_a_hit(held, label):
    initiator, tct, jti = held
    store = aitp.TctStore(4)
    assert initiator.verify_tct_cached(tct, GRANT, store, revoked_jtis=set()).jti == jti
    assert store.len() == 1
    with pytest.raises(RuntimeError, match="revoked"):
        initiator.verify_tct_cached(
            tct, GRANT, store, revoked_jtis={_respell(jti, label)}
        )


def test_verify_tct_cached_malformed_revoked_jti_is_rejected(held):
    initiator, tct, _jti = held
    store = aitp.TctStore(4)
    initiator.verify_tct_cached(tct, GRANT, store, revoked_jtis=set())
    with pytest.raises(ValueError, match="revoked_jtis entry is not a UUID"):
        initiator.verify_tct_cached(tct, GRANT, store, revoked_jtis={"not-a-uuid"})


# ── Lenient: revoked_jtis on process_renewal_request ───────────────────



def _renew(responder, initiator, tct, revoked):
    req = initiator.build_renewal_request(tct)
    return responder.process_renewal_request(
        req, int(time.time()) + 86_400, 3600, revoked_jtis=revoked
    )


@pytest.fixture(scope="module")
def renewal_pair():
    responder, initiator, tct, _voucher = _held_tct()
    return responder, initiator, tct, _claims(tct)["jti"]


@pytest.mark.skipif(not HAS_RENEWAL, reason="built without experimental-renewal")
@pytest.mark.parametrize("label", ["lowercase"] + SPELLINGS)
def test_renewal_revoked_jti_is_normalized(renewal_pair, label):
    responder, initiator, tct, jti = renewal_pair
    entry = jti if label == "lowercase" else _respell(jti, label)
    with pytest.raises(RuntimeError, match="revoked"):
        _renew(responder, initiator, tct, {entry})


@pytest.mark.skipif(not HAS_RENEWAL, reason="built without experimental-renewal")
def test_renewal_v1_revoked_jti_is_accepted_but_never_matches(renewal_pair):
    responder, initiator, tct, _jti = renewal_pair
    fresh = json.loads(_renew(responder, initiator, tct, {V1}))
    assert fresh["tct"].count(".") == 2


@pytest.mark.skipif(not HAS_RENEWAL, reason="built without experimental-renewal")
def test_renewal_malformed_revoked_jti_is_rejected(renewal_pair):
    responder, initiator, tct, _jti = renewal_pair
    with pytest.raises(ValueError, match="revoked_jtis entry is not a UUID"):
        _renew(responder, initiator, tct, {"not-a-uuid"})


# ── Lenient: revoked_jtis on verify_delegation(_multihop) ──────────────

PING_CAP = "demo.ping"


@pytest.fixture(scope="module")
def delegation():
    a = aitp.AitpAgent.generate()
    b = aitp.AitpAgent.generate()
    c = aitp.AitpAgent.generate()
    a_manifest = a.build_manifest(
        display_name="A",
        handshake_endpoint="https://localhost:9721/aitp/handshake/",
        offered_caps=[PING_CAP],
    )
    b_manifest = b.build_manifest(
        display_name="B",
        handshake_endpoint="https://localhost:9722/aitp/handshake/",
        offered_caps=[PING_CAP],
    )
    c.build_manifest(
        display_name="C",
        handshake_endpoint="https://localhost:9723/aitp/handshake/",
        offered_caps=[PING_CAP],
    )
    bsess = b.new_session(pinned_keys=[a.aid])
    arsess = a.new_responder(pinned_keys=[b.aid])
    hello = bsess.build_hello(a_manifest, [PING_CAP])
    hello_ack, sid = arsess.process_hello(hello)
    commit = bsess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = arsess.process_commit(commit, revoked_jtis=set())
    voucher = json.loads(bsess.complete(commit_ack, revoked_jtis=set()))["grant_voucher"]
    token = b.build_delegation(voucher, c.aid, [PING_CAP])
    src_jti = _claims(_claims(token)["voucher"])["src_jti"]
    return a, token, b_manifest, src_jti


VERIFIERS = [("strict", getattr(aitp, "verify_delegation"))]
if HAS_MULTIHOP:
    VERIFIERS.append(
        (
            "multihop",
            lambda tok, aid, mans, revoked: aitp.verify_delegation_multihop(
                tok, aid, mans, revoked_jtis=revoked
            ),
        )
    )


@pytest.mark.parametrize("verify", [v for _, v in VERIFIERS], ids=[n for n, _ in VERIFIERS])
@pytest.mark.parametrize("label", ["lowercase"] + SPELLINGS)
def test_delegation_revoked_jti_is_normalized(delegation, verify, label):
    a, token, b_manifest, src_jti = delegation
    entry = src_jti if label == "lowercase" else _respell(src_jti, label)
    with pytest.raises(RuntimeError, match="revoked"):
        verify(token, a.aid, [b_manifest], {entry})


@pytest.mark.parametrize("verify", [v for _, v in VERIFIERS], ids=[n for n, _ in VERIFIERS])
def test_delegation_v1_revoked_jti_is_accepted_but_never_matches(delegation, verify):
    a, token, b_manifest, _src_jti = delegation
    assert verify(token, a.aid, [b_manifest], {V1}).delegator == a.aid


@pytest.mark.parametrize("verify", [v for _, v in VERIFIERS], ids=[n for n, _ in VERIFIERS])
def test_delegation_malformed_revoked_jti_is_rejected(delegation, verify):
    a, token, b_manifest, _src_jti = delegation
    with pytest.raises(ValueError, match="revoked_jtis entry is not a UUID"):
        verify(token, a.aid, [b_manifest], {"not-a-uuid"})
