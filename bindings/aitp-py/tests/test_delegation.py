"""Delegation (RFC-AITP-0006) — Python SDK.

Covers the v0.2 single-hop round-trip and the strict-by-default posture:
the default `verify_delegation` rejects any draft RFC-AITP-0011 multi-hop
chain, and the opt-in `verify_delegation_multihop` (only present
when the binding is built with `--features multihop-delegation`)
is the sole way to accept one.

v0.2 wire shape: TCTs, grant vouchers, and delegation tokens are all opaque
**compact JWS strings**. B delegates from the *grant voucher* it received
alongside its TCT in the handshake commit — not from the TCT itself.

Run with `maturin develop` then `pytest` from
`bindings/aitp-py/`.
"""

import base64
import json

import pytest

import aitp

PING_CAP = "demo.write"


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _build_delegation_token():
    """A issues a TCT (+ grant voucher) to B via an in-process handshake; B
    mints a single-hop delegation token (compact JWS) authorizing C. Returns
    (a, b, c, delegation_token)."""
    a = aitp.AitpAgent.generate()
    b = aitp.AitpAgent.generate()
    c = aitp.AitpAgent.generate()

    a_manifest = a.build_manifest(
        display_name="A",
        handshake_endpoint="http://localhost:8100/aitp/handshake/",
        offered_caps=[PING_CAP],
    )
    b.build_manifest(
        display_name="B",
        handshake_endpoint="http://localhost:8101/aitp/handshake/",
        offered_caps=[PING_CAP],
    )
    c.build_manifest(
        display_name="C",
        handshake_endpoint="http://localhost:8102/aitp/handshake/",
        offered_caps=[PING_CAP],
    )

    # B handshakes against A → B holds A's TCT + grant voucher for PING_CAP.
    bsess = b.new_session()
    arsess = a.new_responder()
    hello = bsess.build_hello(a_manifest, [PING_CAP])
    hello_ack, sid = arsess.process_hello(hello)
    commit = bsess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = arsess.process_commit(commit)
    b_completed = json.loads(bsess.complete(commit_ack))
    b_voucher = b_completed["grant_voucher"]
    assert b_voucher is not None

    # B mints a delegation token rooted in A's voucher, binding C, scoped to
    # PING_CAP. C's key binding is derived from its AID — no pubkey arg.
    delegation_token = b.build_delegation(b_voucher, c.aid, [PING_CAP])
    return a, b, c, delegation_token


def test_delegation_round_trip_strict():
    """RFC-AITP-0006 single-hop: A verifies B's delegation under the strict
    default verifier and mints a fresh TCT for C, which C can verify."""
    a, b, c, delegation_token = _build_delegation_token()

    verified = aitp.verify_delegation(delegation_token, a.aid)
    assert verified.delegator == a.aid
    assert verified.delegatee == c.aid
    assert verified.issued_by == b.aid
    assert verified.grants == [PING_CAP]

    # A mints a fresh TCT for C; completion shape is {"tct", "grant_voucher"}.
    fresh = json.loads(a.issue_tct_for_delegatee(verified))
    ident = c.verify_tct(fresh["tct"], PING_CAP, c.aid)
    assert ident.peer_aid == a.aid
    assert PING_CAP in ident.grants


def test_verify_delegation_rejects_wrong_verifier():
    a, _b, _c, delegation_token = _build_delegation_token()
    other = aitp.AitpAgent.generate()
    with pytest.raises(Exception):
        aitp.verify_delegation(delegation_token, other.aid)


def _inject_multihop_chain(delegation_token):
    """Take a valid single-hop compact JWS and inject a non-empty `chain`
    claim into its (unsigned) payload, re-encoding the segment.

    The signature no longer matches, but the strict-vs-multihop hop gate
    fires on the structural `chain` presence *before* any signature work
    (RFC-AITP-0006 §4.4), so this is enough to exercise that gate. We reuse
    the token itself as a bogus chain entry to keep `chain` a non-empty list.
    """
    header_seg, payload_seg, sig_seg = delegation_token.split(".")
    payload = json.loads(_b64url_decode(payload_seg))
    payload["chain"] = [delegation_token]
    new_payload_seg = _b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    return f"{header_seg}.{new_payload_seg}.{sig_seg}"


def test_strict_verify_rejects_multihop_chain():
    """The default `verify_delegation` is strict v0.2: any non-empty chain is
    rejected with DELEGATION_MULTIHOP_NOT_SUPPORTED before any per-hop work
    (RFC-AITP-0006 §4.4)."""
    a, _b, _c, delegation_token = _build_delegation_token()
    tampered = _inject_multihop_chain(delegation_token)

    with pytest.raises(Exception) as exc:
        aitp.verify_delegation(tampered, a.aid)
    assert "multi-hop delegation is not supported" in str(exc.value)


def test_multihop_opts_past_the_hop_gate():
    """The opt-in verifier (built under `multihop-delegation`)
    must get PAST the hop gate the strict path rejects at — proven by it
    failing with a *different* error (structure/signature) rather than
    MULTIHOP_NOT_SUPPORTED."""
    if not hasattr(aitp, "verify_delegation_multihop"):
        pytest.skip("binding built without --features multihop-delegation")

    a, _b, _c, delegation_token = _build_delegation_token()
    tampered = _inject_multihop_chain(delegation_token)

    with pytest.raises(Exception) as exc:
        aitp.verify_delegation_multihop(tampered, a.aid, 3)
    assert "multi-hop delegation is not supported" not in str(exc.value)
