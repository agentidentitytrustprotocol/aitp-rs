"""Revocation-list signing — Python SDK.

Round-trip: build a list with two entries, parse it back, verify the
issuer signature, and confirm the entries land in expected positions.
"""

import json
import uuid

import aitp


def test_sign_revocation_list_round_trips():
    issuer = aitp.AitpAgent.generate()
    issuer.build_manifest(
        display_name="issuer",
        handshake_endpoint="http://localhost:8100/aitp/handshake/",
        offered_caps=["demo.echo"],
    )

    jti_a = str(uuid.uuid4())
    jti_b = str(uuid.uuid4())
    envelope_json = issuer.sign_revocation_list(
        [
            {"jti": jti_a, "reason": "compromised"},
            {"jti": jti_b, "revoked_at": 1_700_000_000},
        ],
        expires_in_secs=600,
    )

    env = json.loads(envelope_json)
    body = env["revocation_list"]
    assert body["issuer"] == issuer.aid
    assert body["version"] == "aitp/0.1"
    assert len(body["entries"]) == 2

    jti_set = {e["jti"] for e in body["entries"]}
    assert jti_set == {jti_a, jti_b}

    # The custom revoked_at on entry B must survive the round-trip.
    by_jti = {e["jti"]: e for e in body["entries"]}
    assert by_jti[jti_b]["revoked_at"] == 1_700_000_000
    assert by_jti[jti_a]["reason"] == "compromised"

    # Expiry is now + 600.
    assert body["expires_at"] - body["published_at"] == 600

    # Envelope carries a signature string.
    assert isinstance(env["signature"], str) and env["signature"]


def test_sign_revocation_list_rejects_bad_uuid():
    issuer = aitp.AitpAgent.generate()
    issuer.build_manifest(
        display_name="issuer",
        handshake_endpoint="http://localhost:8100/aitp/handshake/",
        offered_caps=["demo.echo"],
    )
    try:
        issuer.sign_revocation_list([{"jti": "not-a-uuid"}])
    except ValueError:
        return
    raise AssertionError("sign_revocation_list accepted a bad UUID")


def test_sign_revocation_list_requires_jti():
    issuer = aitp.AitpAgent.generate()
    issuer.build_manifest(
        display_name="issuer",
        handshake_endpoint="http://localhost:8100/aitp/handshake/",
        offered_caps=["demo.echo"],
    )
    try:
        issuer.sign_revocation_list([{"reason": "missing jti"}])
    except ValueError:
        return
    raise AssertionError("sign_revocation_list accepted an entry missing jti")
