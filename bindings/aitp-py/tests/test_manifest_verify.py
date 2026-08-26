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


# ── Typed failure causes ─────────────────────────────────────────────────
#
# Added in 0.6.1. Until then `verify_manifest_json` raised a bare RuntimeError
# while `verify_revocation_list` carried a stable `.code` — so a caller who
# wanted to tell "this manifest expired" from "this manifest is forged" had to
# substring-match prose on one side and could branch on a code on the other.
# That asymmetry is the same shape as the missing-binding defect this family
# spent a release on: one artifact has the surface, its sibling does not.


def _code_for(envelope_json: str) -> str:
    try:
        aitp.verify_manifest_json(envelope_json)
    except aitp.ManifestVerificationError as exc:
        return exc.code
    raise AssertionError("expected verification to fail, but it succeeded")


def test_every_failure_cause_is_recoverable_without_parsing_a_message():
    """`.code` is the contract; the message wording is not."""
    import json

    agent = aitp.AitpAgent.generate()
    good = agent.build_manifest(
        display_name="peer",
        handshake_endpoint="http://localhost:9/aitp/handshake/",
        offered_caps=["demo.x"],
    )
    assert aitp.verify_manifest_json(good) is None

    tampered = json.loads(good)
    tampered["manifest"]["display_name"] = "evil"
    assert _code_for(json.dumps(tampered)) == "signature_invalid"

    # A negative TTL back-dates expires_at before published_at, so the
    # manifest is expired the instant it is minted — deterministic, no sleep.
    expired = agent.build_manifest(
        display_name="peer",
        handshake_endpoint="http://localhost:9/aitp/handshake/",
        offered_caps=["demo.x"],
        ttl_secs=-1,
    )
    assert _code_for(expired) == "expired"


def test_expired_is_distinct_from_signature_invalid():
    """The distinction the playground previously had to get by substring match.

    "That peer's manifest went stale" and "someone tampered with it" send an
    operator to different places; a caller that cannot separate them cannot
    alert on the second without drowning in the first.
    """
    import json

    agent = aitp.AitpAgent.generate()
    stale = agent.build_manifest(
        display_name="peer",
        handshake_endpoint="http://localhost:9/aitp/handshake/",
        offered_caps=["demo.x"],
        ttl_secs=-1,
    )
    forged = json.loads(
        agent.build_manifest(
            display_name="peer",
            handshake_endpoint="http://localhost:9/aitp/handshake/",
            offered_caps=["demo.x"],
        )
    )
    forged["manifest"]["aid"] = aitp.AitpAgent.generate().aid

    assert _code_for(stale) == "expired"
    assert _code_for(json.dumps(forged)) == "signature_invalid"
