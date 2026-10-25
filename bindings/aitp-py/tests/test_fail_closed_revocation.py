"""Fail-closed revocation (RFC-AITP-0008 §3.1) — Python SDK.

Revocation defaults to `fail_closed`: a verifier with no `revoked_jtis` has
no revocation status, and an unknown status counts as revoked. The failure
carries the same `.code` as a listed jti, and its message says "revocation
source unavailable" so the two stay distinguishable. `revocation="fail_open"`
is the explicit opt-out. Run with `maturin develop` then `pytest` from
`bindings/aitp-py/`.
"""

import json

import pytest

import aitp

GRANT = "demo.write"
UNAVAILABLE = "revocation source unavailable"


def _agents():
    initiator = aitp.AitpAgent.generate()
    responder = aitp.AitpAgent.generate()
    initiator.build_manifest(
        display_name="initiator",
        handshake_endpoint="http://localhost:8100/aitp/handshake/",
        offered_caps=["demo.echo"],
    )
    responder_manifest = responder.build_manifest(
        display_name="responder",
        handshake_endpoint="http://localhost:8200/aitp/handshake/",
        offered_caps=[GRANT],
    )
    sess = initiator.new_session(pinned_keys=[responder.aid])
    rsess = responder.new_responder(pinned_keys=[initiator.aid])
    hello = sess.build_hello(responder_manifest, [GRANT])
    hello_ack, sid = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, sid)
    return initiator, responder, sess, rsess, commit


def _held_tct():
    initiator, _, sess, rsess, commit = _agents()
    commit_ack, _ = rsess.process_commit(commit, revoked_jtis=set())
    return initiator, json.loads(sess.complete(commit_ack, revoked_jtis=set()))


# ── TCT verification ─────────────────────────────────────────────────────


def test_verify_tct_without_list_fails_closed():
    initiator, held = _held_tct()
    with pytest.raises(RuntimeError, match=UNAVAILABLE) as exc:
        initiator.verify_tct(held["tct"], GRANT)
    assert exc.value.code == "TCT_REVOKED"


def test_verify_tct_explicit_fail_closed_matches_default():
    initiator, held = _held_tct()
    with pytest.raises(RuntimeError, match=UNAVAILABLE) as exc:
        initiator.verify_tct(held["tct"], GRANT, revocation="fail_closed")
    assert exc.value.code == "TCT_REVOKED"


def test_verify_tct_listed_jti_has_same_code_different_message():
    initiator, held = _held_tct()
    jti = initiator.verify_tct(held["tct"], GRANT, revoked_jtis=set()).jti
    with pytest.raises(RuntimeError) as exc:
        initiator.verify_tct(held["tct"], GRANT, revoked_jtis={jti})
    assert exc.value.code == "TCT_REVOKED"
    assert UNAVAILABLE not in str(exc.value)


def test_verify_tct_fail_open_opt_out_accepts():
    initiator, held = _held_tct()
    ident = initiator.verify_tct(held["tct"], GRANT, revocation="fail_open")
    assert GRANT in ident.grants


def test_supplied_list_wins_over_fail_open():
    """A deny list is always consulted, even under `fail_open`."""
    initiator, held = _held_tct()
    jti = initiator.verify_tct(held["tct"], GRANT, revoked_jtis=set()).jti
    with pytest.raises(RuntimeError) as exc:
        initiator.verify_tct(held["tct"], GRANT, revoked_jtis={jti}, revocation="fail_open")
    assert exc.value.code == "TCT_REVOKED"


def test_unknown_revocation_mode_raises_value_error():
    initiator, held = _held_tct()
    with pytest.raises(ValueError, match="fail_open"):
        initiator.verify_tct(held["tct"], GRANT, revocation="maybe")


def test_non_revocation_failure_has_no_code():
    initiator, held = _held_tct()
    with pytest.raises(RuntimeError) as exc:
        initiator.verify_tct(held["tct"], "demo.not-granted", revoked_jtis=set())
    assert not hasattr(exc.value, "code")


def test_cached_hit_without_list_still_fails_closed():
    """A warm cache entry must not bypass the revocation policy."""
    initiator, held = _held_tct()
    store = aitp.TctStore(16)
    initiator.verify_tct_cached(held["tct"], GRANT, store, revoked_jtis=set())
    assert store.len() == 1
    with pytest.raises(RuntimeError, match=UNAVAILABLE) as exc:
        initiator.verify_tct_cached(held["tct"], GRANT, store)
    assert exc.value.code == "TCT_REVOKED"
    ident = initiator.verify_tct_cached(held["tct"], GRANT, store, revocation="fail_open")
    assert GRANT in ident.grants


# ── Handshake completion ─────────────────────────────────────────────────


def test_process_commit_without_list_fails_closed():
    _, _, _, rsess, commit = _agents()
    with pytest.raises(RuntimeError, match=UNAVAILABLE) as exc:
        rsess.process_commit(commit)
    assert exc.value.code == "TCT_REVOKED"


def test_complete_without_list_fails_closed():
    _, _, sess, rsess, commit = _agents()
    commit_ack, _ = rsess.process_commit(commit, revoked_jtis=set())
    with pytest.raises(RuntimeError, match=UNAVAILABLE) as exc:
        sess.complete(commit_ack)
    assert exc.value.code == "TCT_REVOKED"


def test_handshake_fail_open_opt_out_completes():
    _, _, sess, rsess, commit = _agents()
    commit_ack, _ = rsess.process_commit(commit, revocation="fail_open")
    held = json.loads(sess.complete(commit_ack, revocation="fail_open"))
    assert held["tct"].count(".") == 2


# ── Delegation ───────────────────────────────────────────────────────────


def _delegation():
    a, b, c = (aitp.AitpAgent.generate() for _ in range(3))
    a_manifest = a.build_manifest(
        display_name="A",
        handshake_endpoint="http://localhost:8100/aitp/handshake/",
        offered_caps=[GRANT],
    )
    b_manifest = b.build_manifest(
        display_name="B",
        handshake_endpoint="http://localhost:8101/aitp/handshake/",
        offered_caps=[GRANT],
    )
    bsess = b.new_session(pinned_keys=[a.aid])
    arsess = a.new_responder(pinned_keys=[b.aid])
    hello_ack, sid = arsess.process_hello(bsess.build_hello(a_manifest, [GRANT]))
    commit = bsess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = arsess.process_commit(commit, revoked_jtis=set())
    voucher = json.loads(bsess.complete(commit_ack, revoked_jtis=set()))["grant_voucher"]
    return a, b_manifest, b.build_delegation(voucher, c.aid, [GRANT])


def test_verify_delegation_without_list_fails_closed():
    a, b_manifest, token = _delegation()
    with pytest.raises(RuntimeError, match=UNAVAILABLE) as exc:
        aitp.verify_delegation(token, a.aid, [b_manifest])
    assert exc.value.code == "DELEGATION_SOURCE_TCT_REVOKED"


def test_verify_delegation_fail_open_opt_out_accepts():
    a, b_manifest, token = _delegation()
    verified = aitp.verify_delegation(token, a.aid, [b_manifest], revocation="fail_open")
    assert verified.delegator == a.aid


@pytest.mark.skipif(
    not hasattr(aitp, "verify_delegation_multihop"),
    reason="multihop-delegation feature absent",
)
def test_verify_delegation_multihop_without_list_fails_closed():
    a, b_manifest, token = _delegation()
    with pytest.raises(RuntimeError, match=UNAVAILABLE) as exc:
        aitp.verify_delegation_multihop(token, a.aid, [b_manifest])
    assert exc.value.code == "DELEGATION_SOURCE_TCT_REVOKED"
    verified = aitp.verify_delegation_multihop(
        token, a.aid, [b_manifest], revocation="fail_open"
    )
    assert verified.delegator == a.aid
