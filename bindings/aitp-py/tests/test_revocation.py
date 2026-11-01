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
        handshake_endpoint="https://localhost:8100/aitp/handshake/",
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
    assert body["version"] == "aitp/0.3"
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
        handshake_endpoint="https://localhost:8100/aitp/handshake/",
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
        handshake_endpoint="https://localhost:8100/aitp/handshake/",
        offered_caps=["demo.echo"],
    )
    try:
        issuer.sign_revocation_list([{"reason": "missing jti"}])
    except ValueError:
        return
    raise AssertionError("sign_revocation_list accepted an entry missing jti")


# ── Verification ─────────────────────────────────────────────────────────
#
# The verify half was missing until 0.6.0: both the Python and Node bindings
# exposed `sign_revocation_list` and neither exposed `verify_revocation_list`,
# even though `verify_revocation_snapshot` is a Tier C conformance operation
# the Rust adapter implements. Three downstream repos then hand-rolled,
# skipped, or faked verification, and the 0.5.0 signing-input change crossed a
# whole release family with one accidental interlock in its way.


def _kat_issuer_aid() -> str:
    """The KAT keypair's AID, read from `keypairs.json` — NOT from the
    snapshot being verified.

    Taking it from the envelope would make the issuer-binding half of
    verification tautological: a snapshot whose `issuer` had been swapped
    (with a matching signature) would still pass.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[3]
    keypairs = json.loads(
        (root / "tests/schemas/known-answer/keypairs.json").read_text()
    )

    def find(node):
        if isinstance(node, dict):
            if node.get("id") == "kat-keypair-001" and "aid" in node:
                return node["aid"]
            for value in node.values():
                found = find(value)
                if found:
                    return found
        elif isinstance(node, list):
            for value in node:
                found = find(value)
                if found:
                    return found
        return None

    aid = find(keypairs)
    assert aid, "kat-keypair-001 not found in keypairs.json"
    return aid


def _committed_snapshot() -> str:
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[3]
    doc = json.loads(
        (
            root
            / "tests/schemas/known-answer/signed-examples/revocation"
            / "kat-keypair-001-snapshot.json"
        ).read_text()
    )
    # `_kat_input` and `signing_input` are vector companions, never part of
    # the wire object.
    doc.pop("_kat_input", None)
    doc.pop("signing_input", None)
    return json.dumps(doc)


def test_verify_revocation_list_accepts_a_freshly_signed_snapshot():
    issuer = aitp.AitpAgent.generate()
    envelope = issuer.sign_revocation_list([{"jti": str(uuid.uuid4())}], 600)
    assert aitp.verify_revocation_list(envelope, issuer.aid) is None


def test_verify_revocation_list_verifies_the_committed_spec_vector_as_committed():
    """Cross-implementation check — the one that would have caught 0.5.0.

    The vector is verified **as committed**, without re-minting. A suite where
    the same code signs and verifies passes under any self-consistent
    convention, including a wrong one; that self-consistency is precisely what
    let an aitp-rs issuer and an aitp-verifier-py consumer disagree on the wire
    while both suites stayed green.
    """
    assert (
        aitp.verify_revocation_list(
            _committed_snapshot(), _kat_issuer_aid(), 1_711_900_100
        )
        is None
    )


def _code_for(envelope_json: str, issuer_aid: str, now=None) -> str:
    try:
        aitp.verify_revocation_list(envelope_json, issuer_aid, now)
    except aitp.RevocationVerificationError as exc:
        return exc.code
    raise AssertionError("expected verification to fail, but it succeeded")


def test_every_failure_cause_is_recoverable_without_parsing_a_message():
    """`.code` is the contract; the message wording is not.

    A caller forced to string-match an exception message is pinning program
    output as an expected value — the bug class this whole effort exists to
    remove. Before this binding existed, that was the only option available.
    """
    issuer = aitp.AitpAgent.generate()
    other = aitp.AitpAgent.generate()
    envelope = issuer.sign_revocation_list([{"jti": str(uuid.uuid4())}], 600)

    assert _code_for(envelope, other.aid) == "issuer_mismatch"

    tampered = json.loads(envelope)
    tampered["revocation_list"]["entries"] = []
    assert _code_for(json.dumps(tampered), issuer.aid) == "signature_invalid"

    bad_version = json.loads(envelope)
    bad_version["revocation_list"]["version"] = "aitp/9.9"
    assert _code_for(json.dumps(bad_version), issuer.aid) == "version_unknown"

    assert _code_for(envelope, issuer.aid, 99_999_999_999) == "expired"
    assert _code_for("not json at all", issuer.aid) == "malformed"


def test_issuer_mismatch_is_distinct_from_malformed():
    """These were the same cause until 0.6.0 (both `CnfMalformed`).

    An attacker serving their own correctly-signed list and a corrupt fetch
    are different events; a caller that cannot separate them cannot alert on
    the first without drowning in the second.
    """
    issuer = aitp.AitpAgent.generate()
    other = aitp.AitpAgent.generate()
    envelope = issuer.sign_revocation_list([{"jti": str(uuid.uuid4())}], 600)

    # Internally valid — it verifies against its own issuer.
    assert aitp.verify_revocation_list(envelope, issuer.aid) is None
    assert _code_for(envelope, other.aid) == "issuer_mismatch"
    assert _code_for("{}", issuer.aid) == "malformed"


def test_a_bad_expected_issuer_is_the_callers_error_not_a_verification_cause():
    issuer = aitp.AitpAgent.generate()
    envelope = issuer.sign_revocation_list([{"jti": str(uuid.uuid4())}], 600)
    try:
        aitp.verify_revocation_list(envelope, "not-an-aid")
    except aitp.RevocationVerificationError:  # pragma: no cover
        raise AssertionError(
            "a malformed expected_issuer_aid is the caller's mistake; "
            "reporting it as a snapshot verification cause would blame the "
            "wrong party"
        )
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected a ValueError")


def test_revocation_signing_bytes_are_the_inner_body_not_the_wrapper():
    """The 0.5.0 convention, exposed so callers stop reconstructing it.

    Reconstructing the shape at the call site is exactly how signer, verifier
    and conformance fixture drifted apart before 0.5.0.
    """
    issuer = aitp.AitpAgent.generate()
    envelope = issuer.sign_revocation_list([{"jti": str(uuid.uuid4())}], 600)
    body = json.loads(envelope)["revocation_list"]

    signing_bytes = aitp.revocation_signing_bytes(envelope)

    assert signing_bytes.startswith(b"{"), signing_bytes[:20]
    assert b'"revocation_list"' not in signing_bytes[:32], (
        "the signing input starts with the transport wrapper — this is the "
        "pre-0.5.0 shape"
    )
    # Derived from the envelope, never pasted from output.
    assert signing_bytes == json.dumps(
        body, separators=(",", ":"), sort_keys=True
    ).encode()


def test_a_wrapped_form_signature_is_rejected():
    """The 0.5.0 break, asserted from the verifier's side.

    Up to 0.4.x the signing input was `JCS({"revocation_list": body})` — the
    transport wrapper. From 0.5.0 it is the inner body alone, and there is no
    dual-accept in either direction. This mints a snapshot the *old* way, with
    a local key rather than the SDK, and requires that it fail: an SDK that
    accepted it would silently re-open the wire incompatibility.

    The signer here is deliberately independent of the code under test — a
    test where the SDK both signs and verifies passes under any
    self-consistent convention, including a wrong one.
    """
    import base64
    import hashlib
    import time

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    raw_pub = private.public_key().public_bytes_raw()
    aid = "aid:pubkey:" + base64.urlsafe_b64encode(raw_pub).decode().rstrip("=")

    now = int(time.time())
    body = {
        "version": "aitp/0.3",
        "issuer": aid,
        "published_at": now,
        "expires_at": now + 600,
        "entries": [{"jti": str(uuid.uuid4()), "revoked_at": now}],
    }
    wrapped_input = json.dumps(
        {"revocation_list": body}, separators=(",", ":"), sort_keys=True
    ).encode()
    signature = private.sign(hashlib.sha256(wrapped_input).digest())

    legacy = json.dumps(
        {
            "revocation_list": body,
            "signature": base64.urlsafe_b64encode(signature).decode().rstrip("="),
        }
    )

    assert _code_for(legacy, aid) == "signature_invalid"

    # Non-vacuity: the same body signed the CURRENT way does verify, so the
    # rejection above is about the signing input and not about the fixture
    # being malformed in some unrelated way.
    inner_input = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    good_signature = private.sign(hashlib.sha256(inner_input).digest())
    current = json.dumps(
        {
            "revocation_list": body,
            "signature": base64.urlsafe_b64encode(good_signature).decode().rstrip("="),
        }
    )
    assert aitp.verify_revocation_list(current, aid) is None


# ── Hardened wire parsing (aitp-rs#152) ──────────────────────────────────
#
# A duplicate key (RFC-AITP-0001 §5.4.5) and a member outside the schema
# (RFC-AITP-0001 §7) are each rejected before any signature check runs.


def _fresh_snapshot():
    issuer = aitp.AitpAgent.generate()
    issuer.build_manifest(
        display_name="issuer",
        handshake_endpoint="https://localhost:8100/aitp/handshake/",
        offered_caps=["demo.echo"],
    )
    return issuer, issuer.sign_revocation_list([{"jti": str(uuid.uuid4())}], 600)


def test_verify_revocation_list_rejects_a_duplicate_json_key_as_malformed():
    issuer, text = _fresh_snapshot()
    assert '"revocation_list":{' in text
    dup = text.replace(
        '"revocation_list":{', '"revocation_list":{"version":"aitp/0.3",', 1
    )
    assert dup != text
    assert _code_for(dup, issuer.aid) == "malformed"


def test_verify_revocation_list_rejects_an_unknown_member_as_unknown_field():
    issuer, text = _fresh_snapshot()
    env = json.loads(text)
    env["revocation_list"]["deployment_region"] = "eu-west-1"
    assert _code_for(json.dumps(env), issuer.aid) == "unknown_field"


# #268: signing takes the strict wire form. Before, `Uuid::parse_str`
# accepted an uppercase jti (and signed it lowercased) and any UUID
# version, so a v1/v7 jti produced a list verify_revocation_list rejects.
NON_V4_OR_NON_CANONICAL = [
    "550E8400-E29B-41D4-A716-446655440000",  # uppercase v4
    "{550e8400-e29b-41d4-a716-446655440000}",  # braced
    "550e8400e29b41d4a716446655440000",  # simple
    "550e8400-e29b-11d4-a716-446655440000",  # v1
    "0190f8a8-5b7e-7a3c-8d2e-1f4a5b6c7d8e",  # v7
    "550e8400-e29b-41d4-c716-446655440000",  # v4 nibble, wrong variant
]


def test_sign_revocation_list_refuses_non_v4_or_non_canonical_jti():
    issuer = aitp.AitpAgent.generate()
    for jti in NON_V4_OR_NON_CANONICAL:
        try:
            issuer.sign_revocation_list([{"jti": jti}])
        except ValueError as exc:
            assert "lowercase UUID v4" in str(exc), jti
            continue
        raise AssertionError(f"sign_revocation_list accepted {jti}")
    # A canonical v4 still signs and verifies.
    envelope = issuer.sign_revocation_list([{"jti": str(uuid.uuid4())}], 600)
    assert aitp.verify_revocation_list(envelope, issuer.aid) is None


def test_verify_revocation_list_rejects_non_v4_or_non_canonical_jti_as_malformed():
    issuer, text = _fresh_snapshot()
    for jti in NON_V4_OR_NON_CANONICAL:
        env = json.loads(text)
        env["revocation_list"]["entries"][0]["jti"] = jti
        assert _code_for(json.dumps(env), issuer.aid) == "malformed", jti
