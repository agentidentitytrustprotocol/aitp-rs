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

    sess = initiator.new_session(pinned_keys=[responder.aid])
    rsess = responder.new_responder(pinned_keys=[initiator.aid])

    hello = sess.build_hello(resp_manifest, ["demo.write"])
    hello_ack, session_id = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, session_id)
    commit_ack, responder_completed = rsess.process_commit(commit, revoked_jtis=set())
    initiator_completed = sess.complete(commit_ack, revoked_jtis=set())

    # v0.2: completion returns {"tct": <compact JWS>, "grant_voucher": ...}.
    init_done = json.loads(initiator_completed)
    resp_done = json.loads(responder_completed)
    assert isinstance(init_done["tct"], str)
    # A mutual handshake mints a grant voucher alongside each TCT.
    assert init_done["grant_voucher"] is not None
    assert resp_done["grant_voucher"] is not None

    # The initiator holds a TCT issued by the responder for demo.write.
    ident = initiator.verify_tct(init_done["tct"], "demo.write", revoked_jtis=set())
    assert ident.peer_aid == responder.aid
    assert "demo.write" in ident.grants

    # The responder holds a TCT issued by the initiator for demo.echo.
    resp_ident = responder.verify_tct(resp_done["tct"], "demo.echo", revoked_jtis=set())
    assert resp_ident.peer_aid == initiator.aid
    assert "demo.echo" in resp_ident.grants


def test_verify_tct_rejects_missing_grant():
    initiator, responder, _init_manifest, resp_manifest = _agents()
    sess = initiator.new_session(pinned_keys=[responder.aid])
    rsess = responder.new_responder(pinned_keys=[initiator.aid])

    hello = sess.build_hello(resp_manifest, ["demo.write"])
    hello_ack, session_id = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, session_id)
    commit_ack, _ = rsess.process_commit(commit, revoked_jtis=set())
    completed = json.loads(sess.complete(commit_ack, revoked_jtis=set()))

    with pytest.raises(Exception):
        initiator.verify_tct(completed["tct"], "demo.not-granted", revoked_jtis=set())


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

    # Session S1 targets `real`. It trusts both pinned keys, so the
    # rejection below is the peer-AID binding, not the trust store.
    s1 = initiator.new_session(pinned_keys=[real.aid, mallory.aid])
    s1.build_hello(real_manifest, ["demo.write"])

    # Mallory legitimately answers a DIFFERENT session that targeted her,
    # producing a fully-valid HELLO_ACK signed under her own AID.
    s2 = initiator.new_session(pinned_keys=[mallory.aid])
    hello_for_mallory = s2.build_hello(mallory_manifest, ["demo.write"])
    mallory_resp = mallory.new_responder(pinned_keys=[initiator.aid])
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
    sess = initiator.new_session(pinned_keys=[responder.aid])
    rsess = responder.new_responder(pinned_keys=[initiator.aid])

    hello = sess.build_hello(resp_manifest, ["demo.write"])
    hello_ack, sid = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = rsess.process_commit(commit, revoked_jtis=set())
    tct = json.loads(sess.complete(commit_ack, revoked_jtis=set()))["tct"]
    jti = _jws_jti(tct)

    # Empty / unrelated revocation set: still verifies.
    ident = initiator.verify_tct(tct, "demo.write", revoked_jtis={"00000000-0000-4000-8000-000000000000"})
    assert ident.jti == jti

    # The TCT's own jti in the set: rejected.
    with pytest.raises(Exception):
        initiator.verify_tct(tct, "demo.write", revoked_jtis={jti})


def test_verify_tct_cached_honors_revoked_jtis_on_hits():
    """F-1: revocation is re-checked on every call, including cache hits, so a
    freshly-revoked TCT stops verifying even after its signature was cached."""
    initiator, responder, _init_manifest, resp_manifest = _agents()
    sess = initiator.new_session(pinned_keys=[responder.aid])
    rsess = responder.new_responder(pinned_keys=[initiator.aid])

    hello = sess.build_hello(resp_manifest, ["demo.write"])
    hello_ack, sid = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = rsess.process_commit(commit, revoked_jtis=set())
    tct = json.loads(sess.complete(commit_ack, revoked_jtis=set()))["tct"]
    jti = _jws_jti(tct)

    store = aitp.TctStore(8)
    # Warm the cache (no revocation).
    initiator.verify_tct_cached(tct, "demo.write", store, revoked_jtis=set())
    # Now revoke: even though the signature is cached, the cache hit must
    # honor the revocation set.
    with pytest.raises(Exception):
        initiator.verify_tct_cached(tct, "demo.write", store, revoked_jtis={jti})


def test_hello_envelope_check_order_is_version_then_members():
    """RFC-AITP-0001 §5.4 check order: an `aitp/0.2` envelope (strict
    cutover) is refused on its version before its unknown member; under
    the known version the unknown member is reported."""
    initiator, responder, _init_manifest, resp_manifest = _agents()
    sess = initiator.new_session(pinned_keys=[responder.aid])
    hello = json.loads(sess.build_hello(resp_manifest, ["demo.write"]))
    assert hello["version"] == "aitp/0.3"
    hello["trace_id"] = "rogue"
    rsess = responder.new_responder(pinned_keys=[initiator.aid])
    with pytest.raises(ValueError, match="unknown field `trace_id`"):
        rsess.process_hello(json.dumps(hello))
    hello["version"] = "aitp/0.2"
    with pytest.raises(ValueError, match='unknown protocol version "aitp/0.2"'):
        rsess.process_hello(json.dumps(hello))


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


# ── Pinned-key trust store (RFC-AITP-0002 §3.2) ─────────────────────────


def test_responder_without_pinned_keys_rejects_pinned_initiator():
    """0.14: no possession-only mode. A responder whose trust store is
    empty (no `pinned_keys`) rejects every pinned_key initiator, even one
    whose proof is valid."""
    initiator, responder, _init_manifest, resp_manifest = _agents()
    sess = initiator.new_session(pinned_keys=[responder.aid])
    hello = sess.build_hello(resp_manifest, ["demo.write"])

    for rsess in (responder.new_responder(), responder.new_responder(pinned_keys=[])):
        with pytest.raises(RuntimeError, match="trust store"):
            rsess.process_hello(hello)


def test_responder_rejects_pinned_initiator_not_in_store():
    initiator, responder, _init_manifest, resp_manifest = _agents()
    stranger = aitp.AitpAgent.generate()
    sess = initiator.new_session(pinned_keys=[responder.aid])
    hello = sess.build_hello(resp_manifest, ["demo.write"])
    rsess = responder.new_responder(pinned_keys=[stranger.aid])
    with pytest.raises(RuntimeError, match="trust store"):
        rsess.process_hello(hello)


def test_initiator_without_pinned_keys_rejects_pinned_responder():
    initiator, responder, _init_manifest, resp_manifest = _agents()
    sess = initiator.new_session()
    hello = sess.build_hello(resp_manifest, ["demo.write"])
    rsess = responder.new_responder(pinned_keys=[initiator.aid])
    hello_ack, sid = rsess.process_hello(hello)
    with pytest.raises(RuntimeError, match="trust store"):
        sess.process_hello_ack(hello_ack, sid)


@pytest.mark.parametrize(
    "bad", ["not-an-aid", "aid:pubkey:ed25519:AAAA", "aid:pubkey:p256:" + "A" * 44]
)
def test_invalid_pinned_keys_entry_raises_value_error(bad):
    agent = aitp.AitpAgent.generate()
    agent.build_manifest(
        display_name="a",
        handshake_endpoint="http://localhost:8100/aitp/handshake/",
        offered_caps=["demo.echo"],
    )
    good = aitp.AitpAgent.generate().aid
    with pytest.raises(ValueError, match="pinned_keys"):
        agent.new_session(pinned_keys=[good, bad])
    with pytest.raises(ValueError, match="pinned_keys"):
        agent.new_responder(pinned_keys=[bad])
