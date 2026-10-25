"""`build_manifest(revocation_list_uri=...)` (RFC-AITP-0005 §11,
RFC-AITP-0008 §1.4): every TCT issuer advertises its `ListRevoked` URL in
the signed Manifest. Run with `maturin develop` then `pytest` from
`bindings/aitp-py/`.
"""

import json

import pytest

import aitp

EXT = "rfc-aitp-0008.revocation_list_uri"


def _build(agent, **kw):
    return agent.build_manifest(
        display_name="issuer",
        handshake_endpoint="https://issuer.example/aitp/handshake/",
        offered_caps=["demo.echo"],
        **kw,
    )


def test_revocation_list_uri_round_trips_and_is_signed():
    agent = aitp.AitpAgent.generate()
    uri = "https://issuer.example" + aitp.REVOCATION_LIST_PATH
    envelope = _build(agent, revocation_list_uri=uri)
    assert json.loads(envelope)["manifest"]["extensions"][EXT] == uri
    # The extension sits inside the signed body: the envelope verifies.
    aitp.verify_manifest_json(envelope)


def test_revocation_list_uri_is_absent_by_default():
    envelope = _build(aitp.AitpAgent.generate())
    assert EXT not in (json.loads(envelope)["manifest"].get("extensions") or {})


def test_invalid_revocation_list_uri_raises_value_error():
    with pytest.raises(ValueError, match="revocation_list_uri"):
        _build(aitp.AitpAgent.generate(), revocation_list_uri="not a url")


def test_revocation_list_path_constant():
    assert aitp.REVOCATION_LIST_PATH == "/.well-known/aitp-revocation-list"
