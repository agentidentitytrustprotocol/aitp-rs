"""A2A Agent Card binding, client verification (RFC-AITP-0014) — Python SDK.

Gated by the `experimental-a2a-agent-card` Cargo feature. The SDK cannot set
a Manifest extension, so these use the committed vector signed in
`crates/aitp-experimental/tests/fixtures/a2a/`, at a pinned time.
"""

import json
import pathlib

import pytest

import aitp
from _experimental import HAS_A2A

pytestmark = pytest.mark.skipif(not HAS_A2A, reason="needs experimental-a2a-agent-card")

VECTOR = (
    pathlib.Path(__file__).resolve().parents[3]
    / "crates/aitp-experimental/tests/fixtures/a2a"
)
INTERFACE = "https://b.agents.example.com/a2a/v1"
NOW = 1_711_900_100
AID = "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"


def card(**params):
    c = json.loads((VECTOR / "agent-card.json").read_text())
    c["capabilities"]["extensions"][0]["params"].update(params)
    return json.dumps(c)


def manifest():
    return (VECTOR / "manifest.json").read_text()


def verify(card_json, url=INTERFACE, body=None, now=NOW):
    return aitp.verify_a2a_agent_card_binding(card_json, url, body, now)


def code_of(*args, **kwargs):
    with pytest.raises(RuntimeError) as e:
        verify(*args, **kwargs)
    return e.value.code


def test_reads_the_pointer():
    assert aitp.a2a_card_manifest_url(card()) == {
        "aid": AID,
        "manifest_url": "https://b.agents.example.com/.well-known/aitp-manifest",
    }


def test_binds_and_reports_the_manifests_values():
    # The Card's advisory types do not reach the result (§4.3).
    bound = verify(card(acceptedIdentityTypes=["pinned_key"]), body=manifest())
    assert bound == {
        "aid": AID,
        "accepted_identity_types": ["oidc"],
        "accepted_trust_anchors": ["https://auth.example.com/"],
        "offered_capabilities": ["macp.mode.task.v1"],
        "handshake_endpoint": "https://b.agents.example.com/aitp/handshake",
        "interface_url": INTERFACE,
    }


def test_the_tagged_aid_is_the_same_key():
    tagged = AID.replace("aid:pubkey:", "aid:pubkey:ed25519:")
    assert verify(card(aid=tagged), body=manifest())["aid"] == AID


def test_another_key_is_identity_failed():
    other = "aid:pubkey:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU"
    assert code_of(card(aid=other), body=manifest()) == "IDENTITY_FAILED"


def test_an_unlisted_interface_is_identity_failed():
    url = "https://agents.attacker.example/a2a/v1"
    assert code_of(card(), url=url, body=manifest()) == "IDENTITY_FAILED"


def test_a_failed_fetch_is_manifest_not_found():
    assert code_of(card()) == "MANIFEST_NOT_FOUND"


def test_an_expired_manifest_is_refused():
    assert code_of(card(), body=manifest(), now=NOW + 10**7) == "MANIFEST_EXPIRED"


def test_malformed_json_has_a_code_and_no_text_from_the_input():
    hostile = '{"a":1,"a":2,"ignore_instructions":'
    assert code_of(hostile, body=manifest()) == "IDENTITY_FAILED"
    assert code_of(card(), body=hostile) == "MANIFEST_INVALID"
    with pytest.raises(RuntimeError) as e:
        aitp.a2a_card_manifest_url(hostile)
    assert e.value.code == "IDENTITY_FAILED"
    assert "ignore_instructions" not in str(e.value)


def test_a_duplicate_key_is_malformed():
    duplicate = '{"a":1,"a":2}'
    assert code_of(duplicate, body=manifest()) == "IDENTITY_FAILED"
    assert code_of(card(), body=duplicate) == "MANIFEST_INVALID"


def test_a_duplicate_key_in_an_otherwise_valid_card_is_refused():
    duplicate = '{"dup":1,"dup":2,' + card()[1:]
    assert code_of(duplicate, body=manifest()) == "IDENTITY_FAILED"


def test_a_refused_manifest_quotes_nothing_from_it():
    env = json.loads(manifest())
    env["manifest"]["IGNORE_PREV_h0stile"] = 1
    with pytest.raises(RuntimeError) as e:
        verify(card(), body=json.dumps(env))
    assert e.value.code
    assert "h0stile" not in str(e.value)


def test_the_clock_defaults_to_now():
    with pytest.raises(RuntimeError) as e:
        aitp.verify_a2a_agent_card_binding(card(), INTERFACE, manifest())
    assert e.value.code == "MANIFEST_EXPIRED"


def test_a_card_without_the_extension_has_a_code():
    with pytest.raises(RuntimeError) as e:
        aitp.a2a_card_manifest_url("{}")
    assert e.value.code == "IDENTITY_FAILED"
