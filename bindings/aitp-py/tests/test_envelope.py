"""Envelope signing and verification — Python SDK (issue #256).

`verify_envelope` runs the RFC-AITP-0001 §5.4 check order (version →
member set → signature) and raises `EnvelopeVerificationError` with the
registered error code. The committed spec vectors are verified as committed;
the env-008..env-011 cases are derived from the env-007 vector
(`kat-keypair-001-envelope.json`) exactly as the spec fixtures at the pinned
spec ref (`tests/schemas/SPEC_VERSION`) derive them.
"""

import copy
import json
import pathlib
import uuid

import pytest

import aitp

ROOT = pathlib.Path(__file__).resolve().parents[3]
KAT_DIR = ROOT / "tests/schemas/known-answer/signed-examples/envelope"

ED25519_AID = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"  # kat-keypair-001
P256_AID = "aid:pubkey:p256:AweBDql0zqV3PmO4l_N-O-mgnnpf6blxpE0QZawqOpMR"  # kat-keypair-005


def _kat(name):
    return json.loads((KAT_DIR / name).read_text())


def _env007():
    """env-007's envelope: Ed25519, with a vendor `extensions` key."""
    return _kat("kat-keypair-001-envelope.json")["envelope"]


def _code(envelope, sender=ED25519_AID):
    with pytest.raises(aitp.EnvelopeVerificationError) as info:
        aitp.verify_envelope(json.dumps(envelope), sender)
    return info.value.code


@pytest.mark.parametrize(
    "name, sender",
    [
        ("kat-keypair-001-envelope.json", ED25519_AID),
        ("kat-keypair-005-envelope.json", P256_AID),
    ],
)
def test_committed_kat_envelopes_verify(name, sender):
    envelope = _kat(name)["envelope"]
    assert aitp.verify_envelope(json.dumps(envelope), sender) is None


@pytest.mark.parametrize(
    "name, sender",
    [
        ("kat-keypair-001-envelope.json", ED25519_AID),
        ("kat-keypair-005-envelope.json", P256_AID),
    ],
)
def test_retired_v1_signatures_do_not_verify(name, sender):
    kat = _kat(name)
    envelope = dict(kat["envelope"], signature=kat["_must_not_verify"]["v1_signature"])
    assert _code(envelope, sender) == "INVALID_SIGNATURE"


def test_p256_double_hash_signature_does_not_verify():
    kat = _kat("kat-keypair-005-envelope.json")
    envelope = dict(
        kat["envelope"], signature=kat["_must_not_verify"]["double_hash_signature"]
    )
    assert _code(envelope, P256_AID) == "INVALID_SIGNATURE"


def test_env008_tampered_extensions_is_invalid_signature():
    envelope = _env007()
    envelope["extensions"] = {
        "com.example.audit_trace": envelope["extensions"]["com.example.debug_trace"]
    }
    assert _code(envelope) == "INVALID_SIGNATURE"


def test_env009_substituted_message_type_is_invalid_signature():
    envelope = dict(_env007(), message_type="mutual_hello_ack")
    assert _code(envelope) == "INVALID_SIGNATURE"


def test_env010_unknown_version_beats_the_bad_signature():
    envelope = dict(_env007(), version="aitp/9.9")
    assert _code(envelope) == "UNKNOWN_VERSION"


def test_env011_well_signed_previous_revision_is_unknown_version():
    # env-011 at the pinned spec ref: env-007 with version `aitp/0.2`, a
    # fresh message_id, and a signature valid for these exact bytes.
    envelope = dict(
        _env007(),
        version="aitp/0.2",
        message_id="770e8400-e29b-41d4-a716-446655441011",
        signature="qXNURAet0h9miBTCFOBSjsj01ptplj_702PekH0hTCLRMmGziQvW-7jLMsTfP4ZyF5--0FNgJKMJ-RmFo3aOBg",
    )
    assert _code(envelope) == "UNKNOWN_VERSION"


def test_unknown_top_level_member_is_unknown_field():
    # env-006's defect: a sibling member outside `extensions`.
    envelope = dict(_env007(), trace_id="770e8400-e29b-41d4-a716-446655449999")
    assert _code(envelope) == "UNKNOWN_FIELD"


def test_unknown_version_is_checked_before_the_member_set():
    envelope = dict(_env007(), version="aitp/9.9", trace_id="x")
    assert _code(envelope) == "UNKNOWN_VERSION"


def test_missing_version_is_unknown_version():
    envelope = _env007()
    del envelope["version"]
    assert _code(envelope) == "UNKNOWN_VERSION"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.pop("payload"),
        lambda e: e.update(message_type="not_registered"),
        lambda e: e.update(message_id="770e8400-e29b-11d4-a716-446655441007"),
        # Issue #261: the aitp-envelope.schema.json rules for payload,
        # timestamp and signature (and extensions) are structure, checked
        # before the signature.
        lambda e: e.update(payload=[1, 2]),
        lambda e: e.update(payload="text"),
        lambda e: e.update(payload=None),
        lambda e: e.update(timestamp=-1),
        lambda e: e.update(signature=e["signature"][1:]),
        lambda e: e.update(signature=e["signature"][1:] + "="),
        lambda e: e.update(signature="rsa." + e["signature"]),
        lambda e: e.update(signature=""),
        lambda e: e.update(extensions=None),
    ],
    ids=[
        "missing-payload",
        "unregistered-message-type",
        "non-v4-message-id",
        "payload-array",
        "payload-string",
        "payload-null",
        "negative-timestamp",
        "signature-too-short",
        "signature-padded",
        "signature-unknown-tag",
        "signature-empty",
        "extensions-null",
    ],
)
def test_structural_defects_are_invalid_envelope(mutate):
    envelope = _env007()
    mutate(envelope)
    assert _code(envelope) == "INVALID_ENVELOPE"


def test_unknown_version_wins_over_a_schema_rule_defect():
    envelope = dict(
        _env007(), version="aitp/9.9", payload=[], timestamp=-1, signature="x"
    )
    assert _code(envelope) == "UNKNOWN_VERSION"


def test_tagged_signature_passes_the_structure_step():
    # The schema pattern allows the optional `ed25519.` tag
    # (RFC-AITP-0001 §5.4.3); the tagged form of a valid signature verifies.
    envelope = _env007()
    envelope["signature"] = "ed25519." + envelope["signature"]
    assert aitp.verify_envelope(json.dumps(envelope), ED25519_AID) is None


def test_duplicate_key_is_invalid_envelope():
    text = json.dumps(_env007())
    duplicated = text[:-1] + ', "timestamp": 1711900001}'
    with pytest.raises(aitp.EnvelopeVerificationError) as info:
        aitp.verify_envelope(duplicated, ED25519_AID)
    assert info.value.code == "INVALID_ENVELOPE"


def test_wrong_expected_sender_is_invalid_signature():
    other = aitp.AitpAgent.generate().aid
    assert _code(_env007(), other) == "INVALID_SIGNATURE"


def test_bad_expected_sender_aid_is_a_caller_error():
    with pytest.raises(ValueError):
        aitp.verify_envelope(json.dumps(_env007()), "not-an-aid")


def test_verification_error_is_a_runtime_error():
    assert issubclass(aitp.EnvelopeVerificationError, RuntimeError)


@pytest.mark.parametrize(
    "seed, suite, name",
    [
        (bytes(32), "ed25519", "kat-keypair-001-envelope.json"),
        (bytes([5]) * 32, "p256", "kat-keypair-005-envelope.json"),
    ],
)
def test_sign_envelope_reproduces_the_committed_kat(seed, suite, name):
    expected = _kat(name)["envelope"]
    agent = aitp.AitpAgent.from_seed(seed, suite)
    extensions = expected.get("extensions")
    signed = json.loads(
        agent.sign_envelope(
            expected["message_type"],
            json.dumps(expected["payload"]),
            extensions_json=json.dumps(extensions) if extensions is not None else None,
            message_id=expected["message_id"],
            timestamp=expected["timestamp"],
        )
    )
    assert signed == expected


def test_sign_envelope_round_trips_and_covers_extensions():
    agent = aitp.AitpAgent.generate("p256")
    signed = agent.sign_envelope(
        "tct", json.dumps({"k": 1}), extensions_json=json.dumps({"com.example.x": True})
    )
    assert aitp.verify_envelope(signed, agent.aid) is None
    parsed = json.loads(signed)
    assert parsed["version"] == "aitp/0.3"
    assert uuid.UUID(parsed["message_id"]).version == 4
    tampered = copy.deepcopy(parsed)
    tampered["extensions"]["com.example.x"] = False
    assert _code(tampered, agent.aid) == "INVALID_SIGNATURE"


@pytest.mark.parametrize(
    "args, kwargs",
    [
        (("not_registered", "{}"), {}),
        (("tct", "[]"), {}),
        (("tct", "{}"), {"extensions_json": "[]"}),
        (("tct", "{}"), {"message_id": "770e8400-e29b-11d4-a716-446655441007"}),
        (("tct", "{}"), {"timestamp": -1}),
    ],
    ids=[
        "message-type",
        "payload-not-object",
        "extensions-not-object",
        "non-v4-id",
        "negative-timestamp",
    ],
)
def test_sign_envelope_rejects_bad_input(args, kwargs):
    with pytest.raises(ValueError):
        aitp.AitpAgent.generate().sign_envelope(*args, **kwargs)
