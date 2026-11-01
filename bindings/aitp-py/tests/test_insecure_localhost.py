"""The loopback opt-in on `verify_manifest_json`, sessions and delegation.

`handshake_endpoint` must be HTTPS (RFC-AITP-0003 §5 step 2). A plain-HTTP
loopback endpoint verifies only under `insecure_localhost_dangerous`, and
any other plain-HTTP endpoint never does.
"""

import json

import pytest

import aitp
from _experimental import HAS_MULTIHOP

LOOPBACK = ["http://localhost:8100/aitp/handshake/", "http://127.0.0.1:8100/aitp/handshake/"]
NOT_LOOPBACK = [
    "http://example.com/aitp/handshake/",
    "http://playground:8000/aitp/handshake/",
    "http://localhost.example.com/aitp/handshake/",
    "http://192.168.1.10:8100/aitp/handshake/",
    "ftp://localhost/aitp/handshake/",
]
CAP = "demo.write"


def _manifest(agent, endpoint):
    return agent.build_manifest(
        display_name="peer", handshake_endpoint=endpoint, offered_caps=[CAP]
    )


@pytest.mark.parametrize("endpoint", LOOPBACK)
def test_verify_manifest_json_needs_the_opt_in_for_loopback(endpoint):
    manifest = _manifest(aitp.AitpAgent.generate(), endpoint)
    with pytest.raises(aitp.ManifestVerificationError) as err:
        aitp.verify_manifest_json(manifest)
    assert err.value.code == "malformed"
    aitp.verify_manifest_json(manifest, insecure_localhost_dangerous=True)


@pytest.mark.parametrize("endpoint", NOT_LOOPBACK)
def test_verify_manifest_json_opt_in_admits_only_loopback(endpoint):
    manifest = _manifest(aitp.AitpAgent.generate(), endpoint)
    with pytest.raises(aitp.ManifestVerificationError) as err:
        aitp.verify_manifest_json(manifest, insecure_localhost_dangerous=True)
    assert err.value.code == "malformed"


def test_an_unknown_manifest_version_keeps_its_code():
    env = json.loads(_manifest(aitp.AitpAgent.generate(), "https://a.example/h"))
    env["manifest"]["version"] = "aitp/9.9"
    bad = json.dumps(env)
    with pytest.raises(aitp.ManifestVerificationError) as err:
        aitp.verify_manifest_json(bad)
    assert err.value.code == "version_unknown"

    a, b = aitp.AitpAgent.generate(), aitp.AitpAgent.generate()
    _manifest(a, "https://a.example/h")
    with pytest.raises(RuntimeError) as err:
        a.new_session(pinned_keys=[b.aid]).build_hello(bad, [CAP])
    assert err.value.code == "MANIFEST_VERSION_UNKNOWN"


def test_the_opt_in_is_keyword_only():
    manifest = _manifest(aitp.AitpAgent.generate(), LOOPBACK[0])
    with pytest.raises(TypeError):
        aitp.verify_manifest_json(manifest, None, True)


def _handshake(a, b, endpoint, opt_in_a, opt_in_b):
    """`a` initiates against `b`, each side with its own opt-in."""
    _manifest(a, endpoint)
    b_manifest = _manifest(b, endpoint)
    sess = a.new_session(pinned_keys=[b.aid], insecure_localhost_dangerous=opt_in_a)
    rsess = b.new_responder(pinned_keys=[a.aid], insecure_localhost_dangerous=opt_in_b)
    hello = sess.build_hello(b_manifest, [CAP])
    hello_ack, sid = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = rsess.process_commit(commit, revoked_jtis=set())
    return json.loads(sess.complete(commit_ack, revoked_jtis=set()))


def test_a_handshake_over_loopback_completes_with_the_opt_in_on_both_sides():
    a, b = aitp.AitpAgent.generate(), aitp.AitpAgent.generate()
    assert _handshake(a, b, LOOPBACK[0], True, True)["tct"]


def test_an_initiator_without_the_opt_in_refuses_a_loopback_peer():
    a, b = aitp.AitpAgent.generate(), aitp.AitpAgent.generate()
    with pytest.raises(RuntimeError) as err:
        _handshake(a, b, LOOPBACK[0], False, True)
    assert err.value.code == "MANIFEST_INVALID"


@pytest.mark.parametrize(
    "mutate,code",
    [
        (lambda m: m.update(display_name="tampered"), "MANIFEST_SIGNATURE_INVALID"),
        (lambda m: m.update(expires_at=0), "MANIFEST_INVALID"),
        (lambda m: m.update(version="aitp/99.0"), "MANIFEST_VERSION_UNKNOWN"),
    ],
)
def test_build_hello_refuses_an_unverifiable_peer_manifest(mutate, code):
    a, b = aitp.AitpAgent.generate(), aitp.AitpAgent.generate()
    _manifest(a, "https://a.example/h")
    env = json.loads(_manifest(b, "https://b.example/h"))
    mutate(env["manifest"])
    with pytest.raises(RuntimeError) as err:
        a.new_session(pinned_keys=[b.aid]).build_hello(json.dumps(env), [CAP])
    assert err.value.code == code


def test_build_hello_codes_a_peer_manifest_outside_the_wire_grammar():
    a, b = aitp.AitpAgent.generate(), aitp.AitpAgent.generate()
    _manifest(a, "https://a.example/h")
    env = json.loads(_manifest(b, "https://b.example/h"))
    sess = a.new_session(pinned_keys=[b.aid])
    for mutate, code in [
        (lambda m: m.update(display_name=None), "MANIFEST_INVALID"),
        (lambda m: m.update(brandnew=1), "UNKNOWN_FIELD"),
    ]:
        bad = json.loads(json.dumps(env))
        mutate(bad["manifest"])
        with pytest.raises(RuntimeError) as err:
            sess.build_hello(json.dumps(bad), [CAP])
        assert err.value.code == code
    with pytest.raises(RuntimeError) as err:
        sess.build_hello("not json", [CAP])
    assert err.value.code == "MANIFEST_INVALID"


def test_build_hello_refuses_a_peer_that_does_not_accept_this_identity_type():
    a, b = aitp.AitpAgent.generate(), aitp.AitpAgent.generate()
    _manifest(a, "https://a.example/h")
    peer = b.build_manifest(
        display_name="b",
        handshake_endpoint="https://b.example/h",
        offered_caps=[CAP],
        accepted_identity_types=["oidc"],
    )
    with pytest.raises(RuntimeError) as err:
        a.new_session(pinned_keys=[b.aid]).build_hello(peer, [CAP])
    assert err.value.code == "INCOMPATIBLE_IDENTITY_TYPE"


def test_build_hello_checks_the_identity_type_before_minting():
    a, b = aitp.AitpAgent.generate(), aitp.AitpAgent.generate()
    a.build_manifest(
        display_name="a",
        handshake_endpoint="https://a.example/h",
        offered_caps=[CAP],
        identity_type="oidc",
        oidc_issuer="https://idp.example/",
        oidc_subject="a",
    )
    peer = _manifest(b, "https://b.example/h")
    minted = []
    sess = a.new_session(jwks=aitp.JwksProvider({}), pinned_keys=[b.aid])
    with pytest.raises(RuntimeError) as err:
        sess.build_hello(peer, [CAP], oidc_mint_jwt=lambda n: minted.append(n) or "x")
    assert err.value.code == "INCOMPATIBLE_IDENTITY_TYPE"
    assert minted == []


def test_a_session_works_after_a_refused_build_hello():
    a, b = aitp.AitpAgent.generate(), aitp.AitpAgent.generate()
    _manifest(a, "https://a.example/h")
    good = _manifest(b, "https://b.example/h")
    env = json.loads(good)
    env["manifest"]["display_name"] = "tampered"
    sess = a.new_session(pinned_keys=[b.aid])
    with pytest.raises(RuntimeError):
        sess.build_hello(json.dumps(env), [CAP])
    rsess = b.new_responder(pinned_keys=[a.aid])
    ack, sid = rsess.process_hello(sess.build_hello(good, [CAP]))
    assert sess.process_hello_ack(ack, sid)


def test_build_hello_refuses_a_loopback_peer_before_anything_is_sent():
    a, b = aitp.AitpAgent.generate(), aitp.AitpAgent.generate()
    _manifest(a, LOOPBACK[0])
    peer = _manifest(b, LOOPBACK[0])
    with pytest.raises(RuntimeError) as err:
        a.new_session(pinned_keys=[b.aid]).build_hello(peer, [CAP])
    assert err.value.code == "MANIFEST_INVALID"
    assert a.new_session(pinned_keys=[b.aid], insecure_localhost_dangerous=True).build_hello(
        peer, [CAP]
    )


def test_build_hello_verifies_before_minting_an_oidc_token():
    a, b = aitp.AitpAgent.generate(), aitp.AitpAgent.generate()
    a.build_manifest(
        display_name="a",
        handshake_endpoint="https://a.example/h",
        offered_caps=[CAP],
        identity_type="oidc",
        oidc_issuer="https://idp.example/",
        oidc_subject="a",
    )
    env = json.loads(_manifest(b, "https://b.example/h"))
    env["manifest"]["display_name"] = "tampered"
    minted = []
    sess = a.new_session(jwks=aitp.JwksProvider({}), pinned_keys=[b.aid])
    with pytest.raises(RuntimeError):
        sess.build_hello(json.dumps(env), [CAP], oidc_mint_jwt=lambda n: minted.append(n) or "x")
    assert minted == []


def test_a_responder_without_the_opt_in_refuses_a_loopback_peer():
    a, b = aitp.AitpAgent.generate(), aitp.AitpAgent.generate()
    with pytest.raises(RuntimeError) as err:
        _handshake(a, b, LOOPBACK[0], True, False)
    assert err.value.code == "MANIFEST_INVALID"


@pytest.mark.parametrize("endpoint", NOT_LOOPBACK)
def test_the_session_opt_in_admits_only_loopback(endpoint):
    a, b = aitp.AitpAgent.generate(), aitp.AitpAgent.generate()
    with pytest.raises(RuntimeError) as err:
        _handshake(a, b, endpoint, True, True)
    assert err.value.code == "MANIFEST_INVALID"


def _delegation(endpoint):
    """B holds A's voucher and delegates to C; B's Manifest has `endpoint`."""
    a, b, c = (aitp.AitpAgent.generate() for _ in range(3))
    b_manifest = _manifest(b, endpoint)
    a_manifest = _manifest(a, "https://a.example/aitp/handshake/")
    sess = b.new_session(pinned_keys=[a.aid])
    rsess = a.new_responder(pinned_keys=[b.aid], insecure_localhost_dangerous=True)
    hello = sess.build_hello(a_manifest, [CAP])
    hello_ack, sid = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = rsess.process_commit(commit, revoked_jtis=set())
    voucher = json.loads(sess.complete(commit_ack, revoked_jtis=set()))["grant_voucher"]
    return a, b.build_delegation(voucher, c.aid, [CAP]), b_manifest


def test_verify_delegation_needs_the_opt_in_for_a_loopback_issuer():
    a, token, manifest = _delegation(LOOPBACK[0])
    with pytest.raises(RuntimeError):
        aitp.verify_delegation(token, a.aid, [manifest], revoked_jtis=set())
    verified = aitp.verify_delegation(
        token, a.aid, [manifest], revoked_jtis=set(), insecure_localhost_dangerous=True
    )
    assert verified.grants == [CAP]


def test_an_unknown_version_manifest_does_not_fail_the_other_issuers():
    a, token, manifest = _delegation(LOOPBACK[0])
    other = json.loads(_manifest(aitp.AitpAgent.generate(), "https://o.example/h"))
    other["manifest"]["version"] = "aitp/99.0"
    verified = aitp.verify_delegation(
        token,
        a.aid,
        [json.dumps(other), manifest],
        revoked_jtis=set(),
        insecure_localhost_dangerous=True,
    )
    assert verified.grants == [CAP]


def test_an_unknown_version_issuer_is_unresolved():
    a, token, manifest = _delegation(LOOPBACK[0])
    env = json.loads(manifest)
    env["manifest"]["version"] = "aitp/99.0"
    with pytest.raises(RuntimeError):
        aitp.verify_delegation(token, a.aid, [json.dumps(env)], revoked_jtis=set())


@pytest.mark.skipif(not HAS_MULTIHOP, reason="needs experimental-multihop-delegation")
def test_multihop_verification_takes_the_opt_in():
    a, token, manifest = _delegation(LOOPBACK[0])
    with pytest.raises(RuntimeError):
        aitp.verify_delegation_multihop(token, a.aid, [manifest], revoked_jtis=set())
    verified = aitp.verify_delegation_multihop(
        token, a.aid, [manifest], revoked_jtis=set(), insecure_localhost_dangerous=True
    )
    assert verified.grants == [CAP]


def test_the_delegation_opt_in_admits_only_loopback():
    a, b, c = (aitp.AitpAgent.generate() for _ in range(3))
    a_manifest = _manifest(a, "https://a.example/aitp/handshake/")
    _manifest(b, "https://b.example/aitp/handshake/")
    sess = b.new_session(pinned_keys=[a.aid])
    rsess = a.new_responder(pinned_keys=[b.aid])
    hello = sess.build_hello(a_manifest, [CAP])
    hello_ack, sid = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = rsess.process_commit(commit, revoked_jtis=set())
    voucher = json.loads(sess.complete(commit_ack, revoked_jtis=set()))["grant_voucher"]
    token = b.build_delegation(voucher, c.aid, [CAP])
    # The same key, re-published with a plain-HTTP endpoint off loopback.
    plain = _manifest(b, NOT_LOOPBACK[0])
    with pytest.raises(RuntimeError):
        aitp.verify_delegation(
            token, a.aid, [plain], revoked_jtis=set(), insecure_localhost_dangerous=True
        )
