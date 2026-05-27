"""`verify_manifest_json` free function — Python SDK."""

import json

import pytest

import aitp


def _signed_manifest():
    a = aitp.AitpAgent.generate()
    return a.build_manifest(
        display_name="enrollee",
        handshake_endpoint="http://localhost:9000/aitp/handshake/",
        offered_caps=["demo.write"],
    )


def test_verify_manifest_accepts_freshly_built():
    aitp.verify_manifest_json(_signed_manifest())


def test_verify_manifest_rejects_tampered_payload():
    env = json.loads(_signed_manifest())
    # Mutate a load-bearing field — display_name is part of the JCS body.
    env["manifest"]["display_name"] = "imposter"
    tampered = json.dumps(env)
    with pytest.raises(RuntimeError, match="manifest verification failed"):
        aitp.verify_manifest_json(tampered)


def test_verify_manifest_rejects_garbage():
    with pytest.raises(ValueError, match="invalid manifest JSON"):
        aitp.verify_manifest_json("not json")
