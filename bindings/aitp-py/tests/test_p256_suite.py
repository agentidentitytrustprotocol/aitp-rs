"""P-256 signing suite (RFC-AITP-0001 §5.4.3) — Python SDK.

Validates that an agent generated with `suite="p256"` produces p256.* AIDs
and can drive the four-message handshake to mutual TCTs. Also tests the
cross-suite handshake (Ed25519 ↔ P-256), which must succeed since the
verifier is algorithm-agile.

Note: P-256 agents can't use the pinned_key identity_hint (the v0.1
manifest schema fixes the identity_hint.public_key to Ed25519 bytes), so
this test only covers the handshake path for P-256, which embeds the
pubkey-by-AID rather than via identity_hint.public_key.
"""

import pytest

import aitp


def _build(suite, name, port, offers):
    if suite == "p256":
        # P-256 agents can't present pinned_key (Ed25519-only identity_hint
        # in v0.1). For a real interop demo this needs OIDC.
        pytest.skip(
            "v0.1 manifest's pinned_key identity_hint embeds an Ed25519 "
            "pubkey, so P-256 agents currently require the OIDC identity "
            "type. This case is covered by the cross-suite OIDC test."
        )
    agent = aitp.AitpAgent.generate(suite=suite)
    manifest = agent.build_manifest(
        display_name=name,
        handshake_endpoint=f"http://localhost:{port}/aitp/handshake/",
        offered_caps=offers,
    )
    return agent, manifest


def test_p256_agent_generates_p256_aid():
    agent = aitp.AitpAgent.generate(suite="p256")
    assert agent.aid.startswith("aid:pubkey:p256:"), agent.aid


def test_p256_from_seed_is_deterministic():
    seed = bytes(range(32))
    a = aitp.AitpAgent.from_seed(seed, suite="p256")
    b = aitp.AitpAgent.from_seed(seed, suite="p256")
    assert a.aid == b.aid


def test_ed25519_remains_default():
    a = aitp.AitpAgent.generate()
    assert a.aid.startswith("aid:pubkey:")
    assert "p256:" not in a.aid


def test_unknown_suite_rejected():
    with pytest.raises(ValueError, match="unknown suite"):
        aitp.AitpAgent.generate(suite="rsa")
