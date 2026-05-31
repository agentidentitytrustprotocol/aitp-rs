"""Delegation (RFC-AITP-0006) — Python SDK.

Covers the v0.1 single-hop round-trip and the strict-by-default posture:
the default `verify_delegation` rejects any draft RFC-AITP-0011 multi-hop
chain, and the opt-in `verify_delegation_experimental_multihop` (only present
when the binding is built with `--features experimental-multihop-delegation`)
is the sole way to accept one.

Run with `maturin develop --features experimental` then `pytest` from
`bindings/aitp-py/`.
"""

import json

import pytest

import aitp

PING_CAP = "demo.write"


def _build_delegation_env():
    """A issues a TCT to B via an in-process handshake; B mints a
    DelegationEnvelope binding C's pubkey. Returns (a, b, c, delegation_env)."""
    a = aitp.AitpAgent.generate()
    b = aitp.AitpAgent.generate()
    c = aitp.AitpAgent.generate()

    a_manifest = a.build_manifest(
        display_name="A",
        handshake_endpoint="http://localhost:8100/aitp/handshake/",
        offered_caps=[PING_CAP],
    )
    b.build_manifest(
        display_name="B",
        handshake_endpoint="http://localhost:8101/aitp/handshake/",
        offered_caps=[PING_CAP],
    )
    c_manifest = c.build_manifest(
        display_name="C",
        handshake_endpoint="http://localhost:8102/aitp/handshake/",
        offered_caps=[PING_CAP],
    )
    c_pubkey = json.loads(c_manifest)["manifest"]["identity_hint"]["public_key"]

    # B handshakes against A → B holds A's TCT for PING_CAP.
    bsess = b.new_session()
    arsess = a.new_responder()
    hello = bsess.build_hello(a_manifest, [PING_CAP])
    hello_ack, sid = arsess.process_hello(hello)
    commit = bsess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = arsess.process_commit(commit)
    b_held_from_a = bsess.complete(commit_ack)

    # B mints a delegation envelope binding C, scoped to PING_CAP.
    delegation_env = b.build_delegation(b_held_from_a, c.aid, c_pubkey, [PING_CAP])
    return a, b, c, delegation_env


def test_delegation_round_trip_strict():
    """RFC-AITP-0006 single-hop: A verifies B's delegation under the strict
    default verifier and mints a fresh TCT for C, which C can verify."""
    a, b, c, delegation_env = _build_delegation_env()

    verified = aitp.verify_delegation(delegation_env, a.aid)
    assert verified.delegator == a.aid
    assert verified.delegatee == c.aid
    assert verified.issued_by == b.aid
    assert verified.grants == [PING_CAP]

    fresh_tct_for_c = a.issue_tct_for_delegatee(verified)
    ident = c.verify_tct(fresh_tct_for_c, PING_CAP, c.aid)
    assert ident.peer_aid == a.aid
    assert PING_CAP in ident.grants


def test_verify_delegation_rejects_wrong_verifier():
    a, _b, _c, delegation_env = _build_delegation_env()
    other = aitp.AitpAgent.generate()
    with pytest.raises(Exception):
        aitp.verify_delegation(delegation_env, other.aid)


def _inject_multihop_chain(delegation_env):
    """Take a valid single-hop envelope and inject a non-empty `chain`.

    `DelegationStep` has the same wire shape as `grant_proof`, so reusing the
    envelope's own `grant_proof` keeps the JSON deserializable while making the
    token a (structurally bogus) multi-hop one — enough to exercise the
    strict-vs-experimental gate, which fires before signature/structure checks.
    """
    env = json.loads(delegation_env)
    env["delegation"]["chain"] = [env["delegation"]["grant_proof"]]
    return json.dumps(env)


def test_strict_verify_rejects_multihop_chain():
    """The default `verify_delegation` is strict v0.1: any non-empty chain is
    rejected with DELEGATION_MULTIHOP_NOT_SUPPORTED before any per-hop work
    (RFC-AITP-0006 §4.4)."""
    a, _b, _c, delegation_env = _build_delegation_env()
    tampered = _inject_multihop_chain(delegation_env)

    with pytest.raises(Exception) as exc:
        aitp.verify_delegation(tampered, a.aid)
    assert "multi-hop delegation is not supported" in str(exc.value)


def test_experimental_multihop_opts_past_the_hop_gate():
    """The opt-in verifier (built under `experimental-multihop-delegation`)
    must get PAST the hop gate the strict path rejects at — proven by it
    failing with a *different* error (structure/signature) rather than
    MULTIHOP_NOT_SUPPORTED."""
    if not hasattr(aitp, "verify_delegation_experimental_multihop"):
        pytest.skip("binding built without --features experimental-multihop-delegation")

    a, _b, _c, delegation_env = _build_delegation_env()
    tampered = _inject_multihop_chain(delegation_env)

    with pytest.raises(Exception) as exc:
        aitp.verify_delegation_experimental_multihop(tampered, a.aid, 3)
    assert "multi-hop delegation is not supported" not in str(exc.value)
