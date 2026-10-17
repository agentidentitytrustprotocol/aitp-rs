"""P-256 signing suite (RFC-AITP-0001 §5.4.3) — Python SDK.

Validates that an agent generated with `suite="p256"` produces p256.* AIDs
and drives the four-message handshake to mutual TCTs with a `pinned_key`
identity, both P-256 ↔ P-256 and cross-suite (Ed25519 ↔ P-256): the
verifier is algorithm-agile, and since 0.14 a P-256 pinned_key manifest
carries the 33-byte SEC1 compressed point as `identity_hint.public_key`.
"""

import json

import pytest

import aitp


def _build(suite, name, port, offers):
    agent = aitp.AitpAgent.generate(suite=suite)
    manifest = agent.build_manifest(
        display_name=name,
        handshake_endpoint=f"http://localhost:{port}/aitp/handshake/",
        offered_caps=offers,
    )
    return agent, manifest


def _handshake(init_suite, resp_suite):
    initiator, _ = _build(init_suite, "initiator", 8100, ["demo.echo"])
    responder, resp_manifest = _build(resp_suite, "responder", 8200, ["demo.write"])
    sess = initiator.new_session(pinned_keys=[responder.aid])
    rsess = responder.new_responder(pinned_keys=[initiator.aid])
    hello = sess.build_hello(resp_manifest, ["demo.write"])
    hello_ack, sid = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, sid)
    commit_ack, resp_done = rsess.process_commit(commit)
    init_done = sess.complete(commit_ack)
    return initiator, responder, json.loads(init_done), json.loads(resp_done)


def test_p256_pinned_key_manifest_carries_compressed_point():
    agent, manifest = _build("p256", "erin", 8300, ["demo.echo"])
    hint = json.loads(manifest)["manifest"]["identity_hint"]
    assert hint["type"] == "pinned_key"
    # 33-byte SEC1 compressed point → 44 base64url chars, equal to the
    # AID's identifier.
    assert len(hint["public_key"]) == 44
    assert agent.aid == "aid:pubkey:p256:" + hint["public_key"]
    aitp.verify_manifest_json(manifest)


@pytest.mark.parametrize(
    "init_suite,resp_suite",
    [("p256", "p256"), ("ed25519", "p256"), ("p256", "ed25519")],
)
def test_p256_pinned_key_handshake(init_suite, resp_suite):
    initiator, responder, init_done, resp_done = _handshake(init_suite, resp_suite)
    assert initiator.verify_tct(init_done["tct"], "demo.write").peer_aid == responder.aid
    assert responder.verify_tct(resp_done["tct"], "demo.echo").peer_aid == initiator.aid


def test_p256_pinned_initiator_rejected_without_pinned_keys():
    initiator, _ = _build("p256", "initiator", 8100, ["demo.echo"])
    responder, resp_manifest = _build("p256", "responder", 8200, ["demo.write"])
    hello = initiator.new_session(pinned_keys=[responder.aid]).build_hello(
        resp_manifest, ["demo.write"]
    )
    with pytest.raises(RuntimeError, match="trust store"):
        responder.new_responder().process_hello(hello)


def test_p256_agent_generates_p256_aid():
    agent = aitp.AitpAgent.generate(suite="p256")
    assert agent.aid.startswith("aid:pubkey:p256:"), agent.aid


def test_p256_from_seed_is_deterministic():
    seed = bytes(range(32))
    a = aitp.AitpAgent.from_seed(seed, suite="p256")
    b = aitp.AitpAgent.from_seed(seed, suite="p256")
    assert a.aid == b.aid


def test_ed25519_remains_default():
    a = aitp.AitpAgent.generate()
    assert a.aid.startswith("aid:pubkey:")
    assert "p256:" not in a.aid


def test_unknown_suite_rejected():
    with pytest.raises(ValueError, match="unknown suite"):
        aitp.AitpAgent.generate(suite="rsa")
