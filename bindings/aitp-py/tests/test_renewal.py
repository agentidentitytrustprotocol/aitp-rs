"""TCT renewal (RFC-AITP-0005 §10) — Python SDK.

Gated by the `renewal` Cargo feature on the binding. Build
the dev wheel with `maturin develop --features renewal`.
The test exits gracefully if the binding doesn't have the methods.
"""

import base64
import json
import time

import pytest

import aitp


def _jws_claims(tct_token):
    """Decode a TCT compact-JWS payload into its claims dict."""
    payload_seg = tct_token.split(".")[1]
    raw = base64.urlsafe_b64decode(payload_seg + "=" * (-len(payload_seg) % 4))
    return json.loads(raw)

ed = aitp.AitpAgent
HAS_RENEWAL = hasattr(ed.generate(), "build_renewal_request")
pytestmark = pytest.mark.skipif(
    not HAS_RENEWAL, reason="binding built without --features renewal"
)


def _issued_pair():
    """Issuer A mints a TCT for holder B via the full handshake."""
    a = aitp.AitpAgent.generate()
    b = aitp.AitpAgent.generate()
    a.build_manifest(
        display_name="A",
        handshake_endpoint="http://localhost:9201/aitp/handshake/",
        offered_caps=["demo.write"],
    )
    b_manifest = b.build_manifest(
        display_name="B",
        handshake_endpoint="http://localhost:9202/aitp/handshake/",
        offered_caps=["demo.echo"],
    )
    # B is the initiator → at the end of the handshake, B holds a TCT
    # issued by A for demo.echo. Actually we want the opposite — let
    # A initiate so A becomes the issuer of B's TCT. Re-orient:
    a_manifest = json.loads(a.build_manifest(
        display_name="A",
        handshake_endpoint="http://localhost:9201/aitp/handshake/",
        offered_caps=["demo.write"],
    ))
    # Run handshake B-initiates-against-A: B → A. B will end up holding
    # A's TCT (since A is the responder, A issues a TCT to B).
    sess = b.new_session()
    rsess = a.new_responder()
    hello = sess.build_hello(json.dumps(a_manifest), ["demo.write"])
    hello_ack, sid = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = rsess.process_commit(commit)
    b_held = json.loads(sess.complete(commit_ack))["tct"]
    return a, b, b_held


def test_renewal_round_trip():
    a, b, b_held = _issued_pair()
    # B asks A to renew (b_held is the held TCT compact JWS).
    renewal_req = b.build_renewal_request(b_held)
    # A processes the renewal — manifest expiry comfortably in the future.
    now = int(time.time())
    fresh = json.loads(
        a.process_renewal_request(
            renewal_req, manifest_exp_unix_secs=now + 86_400, new_ttl_secs=3600
        )
    )
    old = _jws_claims(b_held)
    new = _jws_claims(fresh["tct"])
    assert new["jti"] != old["jti"]
    assert new["sub"] == old["sub"]
    assert new["grants"] == old["grants"]


def test_renewal_with_wrong_holder_key_rejected():
    a, b, b_held = _issued_pair()
    # An attacker agent tries to renew B's TCT using its own key — the
    # POP signature won't match B's cnf.
    attacker = aitp.AitpAgent.generate()
    bad_req = attacker.build_renewal_request(b_held)
    now = int(time.time())
    with pytest.raises(RuntimeError, match="renewal request rejected"):
        a.process_renewal_request(
            bad_req, manifest_exp_unix_secs=now + 86_400, new_ttl_secs=3600
        )
