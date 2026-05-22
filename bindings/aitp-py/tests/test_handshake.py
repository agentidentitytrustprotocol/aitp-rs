"""In-process exercise of the full four-message AITP handshake.

Run with `maturin develop` then `pytest` from `bindings/aitp-py/`.
No HTTP — the JSON each step produces is fed straight into the peer.
"""

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
    commit_ack, responder_held_tct = rsess.process_commit(commit)
    initiator_held_tct = sess.complete(commit_ack)

    # The initiator holds a TCT issued by the responder for demo.write.
    ident = initiator.verify_tct(initiator_held_tct, "demo.write")
    assert ident.peer_aid == responder.aid
    assert "demo.write" in ident.grants

    # The responder holds a TCT issued by the initiator for demo.echo.
    resp_ident = responder.verify_tct(responder_held_tct, "demo.echo")
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
    tct = sess.complete(commit_ack)

    with pytest.raises(Exception):
        initiator.verify_tct(tct, "demo.not-granted")


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
