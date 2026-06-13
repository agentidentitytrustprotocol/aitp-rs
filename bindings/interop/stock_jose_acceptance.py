#!/usr/bin/env python3
"""Stock-JOSE acceptance check — the headline property of the v0.2
compact-JWS migration.

A v0.2 TCT (and grant voucher, and delegation token) is an RFC 7515
compact JWS. The migration's whole point is that *any* off-the-shelf
JOSE library can verify one given only the issuer's public key — no
AITP stack, no JCS canonicalization, no byte reconstruction
(RFC-AITP-0001 §5.4.5).

This test proves exactly that, end to end, against **third-party**
libraries — `pyjwt` here, and `jose` (Node) via
`stock_jose_acceptance.mjs` — using the spec's pinned signed-example
KAT vectors. It deliberately does NOT import the `aitp` bindings: it is
the independent corroboration that our tokens are real JWS, not the
in-house verifier checking its own output.

The issuer AID's identifier component is the unpadded-base64url raw
Ed25519 public key (RFC-AITP-0001 §5.3), so the verifying key is
derived from the token's `iss` claim alone — same as any AITP verifier
would, but here through a generic JOSE path.

Runs standalone (no native bindings, no maturin): `python3
stock_jose_acceptance.py`. Also collected by pytest.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import jwt  # pyjwt — a third-party JOSE implementation, NOT aitp
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# signed-examples vendored from the spec repo into the aitp-rs tree.
# parents[2] of bindings/interop/<file> is the repo root.
SIGNED_EXAMPLES = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "schemas"
    / "known-answer"
    / "signed-examples"
)

# Token kind -> (vector path, token field, expected `typ`).
VECTORS = {
    "tct": ("tct/kat-keypair-001-issues-002.json", "tct_token", "aitp-tct+jwt"),
    "voucher": ("grant-voucher/kat-voucher-001.json", "voucher_token", "aitp-grant+jwt"),
    "delegation": (
        "delegation/single-hop-001-002-003.json",
        "delegation_token",
        "aitp-delegation+jwt",
    ),
}


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _issuer_pubkey(iss_aid: str) -> Ed25519PublicKey:
    """Derive the Ed25519 verifying key from an `aid:pubkey:<b64url>` AID.

    The legacy/untagged AID form encodes the 32-byte raw public key
    directly (RFC-AITP-0001 §5.3); a JOSE-generic verifier needs only
    this, exactly as it would for any EdDSA JWT.
    """
    prefix = "aid:pubkey:"
    assert iss_aid.startswith(prefix), f"unexpected AID form: {iss_aid}"
    raw = _b64url_decode(iss_aid[len(prefix):])
    assert len(raw) == 32, f"Ed25519 pubkey must be 32 bytes, got {len(raw)}"
    return Ed25519PublicKey.from_public_bytes(raw)


def _load(kind: str) -> tuple[str, dict, str]:
    rel, field, typ = VECTORS[kind]
    vec = json.loads((SIGNED_EXAMPLES / rel).read_text())
    return vec[field], vec["decoded_claims"], typ


def verify_with_pyjwt(kind: str) -> dict:
    """Verify a v0.2 token with stock pyjwt and return the decoded claims.

    Asserts: the protected header `typ` is the expected AITP type, the
    EdDSA signature verifies under the issuer key, and the decoded
    claims match the vector byte-equivalently.
    """
    token, expected_claims, expected_typ = _load(kind)

    header = json.loads(_b64url_decode(token.split(".")[0]))
    assert header == {"alg": "EdDSA", "typ": expected_typ}, header

    key = _issuer_pubkey(expected_claims["iss"])
    # pyjwt is a real third-party JOSE library: it does the base64url
    # split, header parse, and Ed25519 verify over the transmitted
    # bytes. We disable claim-level policy (aud/exp) — that's the AITP
    # verifier's job; here we are proving the *signature/JOSE* contract.
    claims = jwt.decode(
        token,
        key=key,
        algorithms=["EdDSA"],
        options={"verify_aud": False, "verify_exp": False},
    )
    assert claims == expected_claims, f"{kind}: pyjwt claims diverge from vector"
    return claims


def alg_none_is_rejected() -> None:
    """A token whose header claims `alg: none` MUST be rejected by stock
    pyjwt too (corroborating the AITP alg-pin defense)."""
    token, claims, typ = _load("tct")
    rest = token.split(".", 1)[1]
    evil_header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": typ}, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    evil = f"{evil_header}.{rest}"
    key = _issuer_pubkey(claims["iss"])
    try:
        jwt.decode(evil, key=key, algorithms=["EdDSA"],
                   options={"verify_aud": False, "verify_exp": False})
    except jwt.InvalidTokenError:
        return
    raise AssertionError("stock pyjwt accepted an alg:none token")


# ── pytest entry points ──────────────────────────────────────────────

def test_pyjwt_verifies_tct():
    verify_with_pyjwt("tct")


def test_pyjwt_verifies_voucher():
    verify_with_pyjwt("voucher")


def test_pyjwt_verifies_delegation():
    verify_with_pyjwt("delegation")


def test_pyjwt_rejects_alg_none():
    alg_none_is_rejected()


if __name__ == "__main__":
    for kind in VECTORS:
        claims = verify_with_pyjwt(kind)
        print(f"  pyjwt verified {kind:11s} iss={claims['iss']}")
    alg_none_is_rejected()
    print("  pyjwt rejected alg:none")
    print("stock-JOSE (pyjwt) acceptance: OK")
