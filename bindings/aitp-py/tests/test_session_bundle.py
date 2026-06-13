"""Session Trust Bundle (RFC-AITP-0010) — Python SDK.

Gated by the `experimental-bundle` feature. Build with
`maturin develop --features experimental`.
"""

import base64
import json

import pytest

import aitp

HAS_BUNDLE = hasattr(aitp, "SessionBundleBuilder")
pytestmark = pytest.mark.skipif(
    not HAS_BUNDLE, reason="binding built without --features experimental-bundle"
)


def _jws_jti(tct_token):
    """Decode a TCT compact-JWS payload and return its `jti` claim."""
    payload_seg = tct_token.split(".")[1]
    raw = base64.urlsafe_b64decode(payload_seg + "=" * (-len(payload_seg) % 4))
    return json.loads(raw)["jti"]


def _handshake_to_coordinator(participant, coordinator, coord_manifest_json):
    """Run a four-message handshake with `coordinator` as the responder.
    Returns the coordinator-issued TCT (compact JWS) for the participant."""
    sess = participant.new_session()
    rsess = coordinator.new_responder()
    hello = sess.build_hello(coord_manifest_json, ["session.member"])
    hello_ack, sid = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = rsess.process_commit(commit)
    return json.loads(sess.complete(commit_ack))["tct"]


def test_session_bundle_round_trip():
    coord = aitp.AitpAgent.generate()
    alice = aitp.AitpAgent.generate()
    bob = aitp.AitpAgent.generate()

    coord_manifest = coord.build_manifest(
        display_name="coordinator",
        handshake_endpoint="http://localhost:9401/aitp/handshake/",
        offered_caps=["session.member"],
    )
    alice.build_manifest(
        display_name="alice",
        handshake_endpoint="http://localhost:9402/aitp/handshake/",
        offered_caps=["x"],
    )
    bob.build_manifest(
        display_name="bob",
        handshake_endpoint="http://localhost:9403/aitp/handshake/",
        offered_caps=["x"],
    )

    alice_tct = _handshake_to_coordinator(alice, coord, coord_manifest)
    bob_tct = _handshake_to_coordinator(bob, coord, coord_manifest)

    # Coordinator builds a bundle binding Alice + Bob.
    builder = aitp.SessionBundleBuilder(coord)
    builder = builder.participant(alice.aid, alice_tct)
    builder = builder.participant(bob.aid, bob_tct)
    envelope = builder.build()

    parsed = json.loads(envelope)
    assert "session_bundle" in parsed
    assert parsed["session_bundle"]["coordinator"] == coord.aid

    # Alice verifies her own membership.
    outcome = aitp.verify_session_bundle(envelope, alice.aid)
    assert outcome["kind"] == "clear"
    assert alice.aid in outcome["active_aids"]
    assert bob.aid in outcome["active_aids"]
    assert outcome["dropped_aids"] == []

    # Non-member rejected.
    outsider = aitp.AitpAgent.generate()
    with pytest.raises(RuntimeError, match="bundle verification failed"):
        aitp.verify_session_bundle(envelope, outsider.aid)


def test_session_bundle_revocation_drops_participant():
    coord = aitp.AitpAgent.generate()
    alice = aitp.AitpAgent.generate()
    bob = aitp.AitpAgent.generate()

    coord_manifest = coord.build_manifest(
        display_name="coordinator",
        handshake_endpoint="http://localhost:9501/aitp/handshake/",
        offered_caps=["session.member"],
    )
    alice.build_manifest(
        display_name="alice",
        handshake_endpoint="http://localhost:9502/aitp/handshake/",
        offered_caps=["x"],
    )
    bob.build_manifest(
        display_name="bob",
        handshake_endpoint="http://localhost:9503/aitp/handshake/",
        offered_caps=["x"],
    )

    alice_tct = _handshake_to_coordinator(alice, coord, coord_manifest)
    bob_tct = _handshake_to_coordinator(bob, coord, coord_manifest)

    envelope = (
        aitp.SessionBundleBuilder(coord)
        .participant(alice.aid, alice_tct)
        .participant(bob.aid, bob_tct)
        .build()
    )

    revoked_jti = _jws_jti(bob_tct)
    outcome = aitp.verify_session_bundle(
        envelope,
        alice.aid,
        revocation_check=lambda jti: jti == revoked_jti,
    )
    assert outcome["kind"] == "degraded"
    assert alice.aid in outcome["active_aids"]
    assert bob.aid in outcome["dropped_aids"]
