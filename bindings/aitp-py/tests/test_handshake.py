"""In-process exercise of the full four-message AITP handshake.

Run with `maturin develop` then `pytest` from `bindings/aitp-py/`.
No HTTP — the JSON each step produces is fed straight into the peer.
"""

import json

import pytest

import aitp


def _agents():
    initiator = aitp.AitpAgent.generate()
    responder = aitp.AitpAgent.generate()
    init_manifest = initiator.build_manifest(
        display_name="initiator",
        handshake_endpoint="http://localhost:8100/aitp/handshake/",
        offered_caps=["demo.echo"],
    )
    resp_manifest = responder.build_manifest(
        display_name="responder",
        handshake_endpoint="http://localhost:8200/aitp/handshake/",
        offered_caps=["demo.write"],
    )
    return initiator, responder, init_manifest, resp_manifest


def test_full_handshake_yields_mutual_tcts():
    initiator, responder, _init_manifest, resp_manifest = _agents()

    sess = initiator.new_session()
    rsess = responder.new_responder()

    hello = sess.build_hello(resp_manifest, ["demo.write"])
    hello_ack, session_id = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, session_id)
    commit_ack, responder_completed = rsess.process_commit(commit)
    initiator_completed = sess.complete(commit_ack)

    # v0.2: completion returns {"tct": <compact JWS>, "grant_voucher": ...}.
    init_done = json.loads(initiator_completed)
    resp_done = json.loads(responder_completed)
    assert isinstance(init_done["tct"], str)
    # A mutual handshake mints a grant voucher alongside each TCT.
    assert init_done["grant_voucher"] is not None
    assert resp_done["grant_voucher"] is not None

    # The initiator holds a TCT issued by the responder for demo.write.
    ident = initiator.verify_tct(init_done["tct"], "demo.write")
    assert ident.peer_aid == responder.aid
    assert "demo.write" in ident.grants

    # The responder holds a TCT issued by the initiator for demo.echo.
    resp_ident = responder.verify_tct(resp_done["tct"], "demo.echo")
    assert resp_ident.peer_aid == initiator.aid
    assert "demo.echo" in resp_ident.grants


def test_verify_tct_rejects_missing_grant():
    initiator, responder, _init_manifest, resp_manifest = _agents()
    sess = initiator.new_session()
    rsess = responder.new_responder()

    hello = sess.build_hello(resp_manifest, ["demo.write"])
    hello_ack, session_id = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, session_id)
    commit_ack, _ = rsess.process_commit(commit)
    completed = json.loads(sess.complete(commit_ack))

    with pytest.raises(Exception):
        initiator.verify_tct(completed["tct"], "demo.not-granted")


def test_initiator_rejects_peer_substitution():
    """RFC-AITP-0004 peer-AID binding: the initiator authenticates the
    peer it targeted. A HELLO_ACK from a different (well-signed) peer must
    be rejected — the session must not silently bind to the wrong AID.
    """
    initiator = aitp.AitpAgent.generate()
    real = aitp.AitpAgent.generate()
    mallory = aitp.AitpAgent.generate()
    # The initiator needs its own manifest before it can open a session.
    initiator.build_manifest(
        display_name="initiator",
        handshake_endpoint="http://localhost:8100/aitp/handshake/",
        offered_caps=["demo.write"],
    )
    real_manifest = real.build_manifest(
        display_name="real",
        handshake_endpoint="http://localhost:8200/aitp/handshake/",
        offered_caps=["demo.write"],
    )
    mallory_manifest = mallory.build_manifest(
        display_name="mallory",
        handshake_endpoint="http://localhost:8300/aitp/handshake/",
        offered_caps=["demo.write"],
    )

    # Session S1 targets `real`.
    s1 = initiator.new_session()
    s1.build_hello(real_manifest, ["demo.write"])

    # Mallory legitimately answers a DIFFERENT session that targeted her,
    # producing a fully-valid HELLO_ACK signed under her own AID.
    s2 = initiator.new_session()
    hello_for_mallory = s2.build_hello(mallory_manifest, ["demo.write"])
    mallory_resp = mallory.new_responder()
    mallory_ack, mallory_session = mallory_resp.process_hello(hello_for_mallory)

    # Feeding Mallory's HELLO_ACK into S1 (which targeted `real`) must be
    # rejected: the signed sender AID is not the intended peer.
    with pytest.raises(Exception):
        s1.process_hello_ack(mallory_ack, mallory_session)


def _jws_jti(tct_token):
    """Decode a TCT compact-JWS payload and return its `jti` claim."""
    import base64

    payload_seg = tct_token.split(".")[1]
    raw = base64.urlsafe_b64decode(payload_seg + "=" * (-len(payload_seg) % 4))
    return json.loads(raw)["jti"]


def test_verify_tct_honors_revoked_jtis():
    """F-1: a verifier that supplies `revoked_jtis` must reject an otherwise
    valid (signed, unexpired, in-scope) TCT whose jti is in the set — and
    still accept it when the set omits that jti."""
    initiator, responder, _init_manifest, resp_manifest = _agents()
    sess = initiator.new_session()
    rsess = responder.new_responder()

    hello = sess.build_hello(resp_manifest, ["demo.write"])
    hello_ack, sid = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = rsess.process_commit(commit)
    tct = json.loads(sess.complete(commit_ack))["tct"]
    jti = _jws_jti(tct)

    # Empty / unrelated revocation set: still verifies.
    ident = initiator.verify_tct(tct, "demo.write", revoked_jtis={"some-other-jti"})
    assert ident.jti == jti

    # The TCT's own jti in the set: rejected.
    with pytest.raises(Exception):
        initiator.verify_tct(tct, "demo.write", revoked_jtis={jti})


def test_verify_tct_cached_honors_revoked_jtis_on_hits():
    """F-1: revocation is re-checked on every call, including cache hits, so a
    freshly-revoked TCT stops verifying even after its signature was cached."""
    initiator, responder, _init_manifest, resp_manifest = _agents()
    sess = initiator.new_session()
    rsess = responder.new_responder()

    hello = sess.build_hello(resp_manifest, ["demo.write"])
    hello_ack, sid = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = rsess.process_commit(commit)
    tct = json.loads(sess.complete(commit_ack))["tct"]
    jti = _jws_jti(tct)

    store = aitp.TctStore(8)
    # Warm the cache (no revocation).
    initiator.verify_tct_cached(tct, "demo.write", store)
    # Now revoke: even though the signature is cached, the cache hit must
    # honor the revocation set.
    with pytest.raises(Exception):
        initiator.verify_tct_cached(tct, "demo.write", store, revoked_jtis={jti})


def test_from_seed_is_deterministic():
    a = aitp.AitpAgent.from_seed(bytes([7] * 32))
    b = aitp.AitpAgent.from_seed(bytes([7] * 32))
    assert a.aid == b.aid


def test_from_seed_rejects_wrong_length():
    with pytest.raises(Exception):
        aitp.AitpAgent.from_seed(bytes([0] * 31))


def test_session_before_manifest_raises():
    agent = aitp.AitpAgent.generate()
    with pytest.raises(Exception):
        agent.new_session()
