#!/usr/bin/env python3
"""Generate the candidate KAT vectors for spec proposal
`p256-pinned-key-and-signing-input-2026-10` (agentidentitytrustprotocol#72).

The proposal's spec PRs A-D have not landed, so there is no spec commit
to vendor yet. Until they do, aitp-rs pins the proposal's vectors in
`tests/proposal-kats/p256-pinned-key-2026-10.json`. This script is the
*independent* half of the recomputation: it derives every value with
pyca/cryptography (OpenSSL), sharing no code with the Rust crates. The
Rust tests then reproduce every value byte-for-byte with RustCrypto. Two
implementations that agree on every byte are the RFC-PROCESS KAT bar.

Run: python3 scripts/gen-proposal-kats.py   (needs cryptography >= 44
for deterministic ECDSA; checked with 50.0.1).

When the spec PRs land, this file and its output are deleted in favour
of the vendored `tests/schemas/known-answer/` set (plan Phase 0).
"""

import base64
import hashlib
import json
import pathlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

OUT = pathlib.Path(__file__).resolve().parent.parent / "tests/proposal-kats/p256-pinned-key-2026-10.json"

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jcs(obj) -> bytes:
    # Sufficient for these vectors: ASCII strings, integers, no floats.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# kat-keypair-005-p256: scalar 0x05 * 32.
P256_SK = ec.derive_private_key(int("05" * 32, 16), ec.SECP256R1())
P256_PK = P256_SK.public_key()
P256_PK_COMPRESSED = P256_PK.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
P256_AID = "aid:pubkey:p256:" + b64u(P256_PK_COMPRESSED)
assert P256_AID == "aid:pubkey:p256:AweBDql0zqV3PmO4l_N-O-mgnnpf6blxpE0QZawqOpMR"


def ed_key(seed_hex: str):
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, raw


ED1_SK, ED1_PK = ed_key("00" * 32)
ED3_SK, ED3_PK = ed_key("ff" * 32)
ED1_AID = "aid:pubkey:" + b64u(ED1_PK)
ED3_AID = "aid:pubkey:" + b64u(ED3_PK)
ED1_AID_TAGGED = "aid:pubkey:ed25519:" + b64u(ED1_PK)
ED3_AID_TAGGED = "aid:pubkey:ed25519:" + b64u(ED3_PK)


def p256_low_s(r: int, s: int):
    return (r, s) if s <= P256_N // 2 else (r, P256_N - s)


def p256_sign_prehash(d: bytes) -> bytes:
    """§5.4.6: ECDSA with e = d (single hash), RFC 6979, low-S, r||s."""
    der = P256_SK.sign(d, ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
    r, s = p256_low_s(*utils.decode_dss_signature(der))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def p256_sign_es256(msg: bytes) -> bytes:
    """JOSE ES256 over `msg` (hash once inside ECDSA), RFC 6979, low-S."""
    der = P256_SK.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = p256_low_s(*utils.decode_dss_signature(der))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def p256_verify_prehash(d: bytes, rs: bytes) -> bool:
    der = utils.encode_dss_signature(int.from_bytes(rs[:32], "big"), int.from_bytes(rs[32:], "big"))
    try:
        P256_PK.verify(der, d, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except Exception:
        return False


def high_s_sibling(rs: bytes) -> bytes:
    r, s = int.from_bytes(rs[:32], "big"), int.from_bytes(rs[32:], "big")
    return r.to_bytes(32, "big") + (P256_N - s).to_bytes(32, "big")


def pinned_proof_input(sender: str, receiver: str, mid: str, ts: int, nonce: str) -> bytes:
    return (
        b"aitp-pinned-key-v1\0"
        + sender.encode() + b"\0"
        + receiver.encode() + b"\0"
        + mid.encode() + b"\0"
        + str(ts).encode() + b"\0"
        + b64u_dec(nonce)
    )


def derived_v4(tag: str, data: bytes):
    assert all(0x21 <= ord(c) <= 0x7E for c in tag)
    preimage = tag.encode() + b"\0" + data
    h = bytearray(sha256(preimage))
    u = h[:16]
    u[6] = (u[6] & 0x0F) | 0x40
    u[8] = (u[8] & 0x3F) | 0x80
    x = u.hex()
    return preimage, bytes(h), f"{x[:8]}-{x[8:12]}-{x[12:16]}-{x[16:20]}-{x[20:]}"


def jwk_thumbprint_ed(pk: bytes) -> str:
    return b64u(sha256(jcs({"crv": "Ed25519", "kty": "OKP", "x": b64u(pk)})))


def jwk_thumbprint_p256() -> str:
    nums = P256_PK.public_numbers()
    return b64u(sha256(jcs({"crv": "P-256", "kty": "EC", "x": b64u(nums.x.to_bytes(32, "big")), "y": b64u(nums.y.to_bytes(32, "big"))})))


def compact_jws(alg: str, typ: str, claims: dict, sign) -> str:
    header = '{"alg":"%s","typ":"%s"}' % (alg, typ)
    si = b64u(header.encode()) + "." + b64u(jcs(claims))
    return si + "." + b64u(sign(si.encode()))


vectors = []

# --- Item 1: generic §5.4.6 vector -------------------------------------
preimage = jcs({"kat": "kat-p256-jcs-sign-001", "rule": "RFC-AITP-0001 §5.4.6", "single_hash": True})
d = sha256(preimage)
sig = p256_sign_prehash(d)
double = p256_sign_prehash(sha256(d))
assert p256_verify_prehash(d, sig) and not p256_verify_prehash(d, double)
# "Equivalently ES256 over the pre-hash input" (§5.4.6).
assert p256_sign_es256(preimage) == sig
vectors.append({
    "id": "kat-p256-jcs-sign-001",
    "rfc_refs": ["RFC-AITP-0001 §5.4.6"],
    "signing_keypair_id": "kat-keypair-005-p256",
    "signer_aid": P256_AID,
    "preimage_hex": preimage.hex(),
    "sha256_hex": d.hex(),
    "signature": "p256." + b64u(sig),
    "double_hash_signature_MUST_NOT_verify": "p256." + b64u(double),
    "high_s_sibling_MUST_NOT_verify": "p256." + b64u(high_s_sibling(sig)),
})

# --- Item 1/2: pinned-key proof, P-256 sender (proposal candidate) -----
pk2 = dict(sender_aid=P256_AID, receiver_aid=ED1_AID, message_id="770e8400-e29b-41d4-a716-446655440702", timestamp=1711900000, pop_nonce="AAAAAAAAAAAAAAAAAAAAAA")
pi = pinned_proof_input(pk2["sender_aid"], pk2["receiver_aid"], pk2["message_id"], pk2["timestamp"], pk2["pop_nonce"])
d = sha256(pi)
sig = p256_sign_prehash(d)
proposal_proof = "p256.X9FVRk-1kawJ_rKSXlW3ySlC2A0WfSCArxzswSPWtSRQol3VSaNYx9u-Q3kdL0SKbd51HSYlJZ_IzjU0E-wr1Q"
proposal_double = "p256.xDGuosZC63lLwIMmOad0wD8kaK163ugpr3O2ZEP4W3NgWXFqNe_Fq_Ig74Wl6ubMVQp_mMr0ym9CB7i3rqeBgw"
assert "p256." + b64u(sig) == proposal_proof, "proposal candidate value not reproduced"
assert "p256." + b64u(p256_sign_prehash(sha256(d))) == proposal_double
vectors.append({
    "id": "kat-pinned-key-proof-002-p256",
    "rfc_refs": ["RFC-AITP-0002 §3.1", "RFC-AITP-0001 §5.4.6"],
    **pk2,
    "proof_input_hex": pi.hex(),
    "proof_input_len_bytes": len(pi),
    "sha256_hex": d.hex(),
    "signing_keypair_id": "kat-keypair-005-p256",
    "proof": proposal_proof,
    "double_hash_proof_MUST_NOT_verify": proposal_double,
})

# --- pinned-key proof, tagged Ed25519 sender AID ------------------------
pk3 = dict(sender_aid=ED3_AID_TAGGED, receiver_aid=ED1_AID, message_id="770e8400-e29b-41d4-a716-446655440701", timestamp=1711900000, pop_nonce="AAAAAAAAAAAAAAAAAAAAAA")
pi = pinned_proof_input(pk3["sender_aid"], pk3["receiver_aid"], pk3["message_id"], pk3["timestamp"], pk3["pop_nonce"])
d = sha256(pi)
vectors.append({
    "id": "kat-pinned-key-proof-003-tagged-ed25519",
    "rfc_refs": ["RFC-AITP-0002 §3.1"],
    "$comment": "Same tuple as kat-pinned-key-proof-001 but the sender uses the tagged aid:pubkey:ed25519: AID. The AID string bytes, not the key, enter proof_input, so the proof differs from -001's.",
    **pk3,
    "proof_input_hex": pi.hex(),
    "proof_input_len_bytes": len(pi),
    "sha256_hex": d.hex(),
    "signing_keypair_id": "kat-keypair-003",
    "proof": b64u(ED3_SK.sign(d)),
})

vectors.append({
    "id": "kat-keypair-001-tagged",
    "rfc_refs": ["RFC-AITP-0001 §5.3"],
    "seed_hex": "00" * 32,
    "pubkey_b64url": b64u(ED1_PK),
    "aid": ED1_AID_TAGGED,
    "untagged_aid": ED1_AID,
})

# --- §5.4.2 PoP with P-256 ----------------------------------------------
challenge = "AAECAwQFBgcICQoLDA0ODw"
d = sha256(b64u_dec(challenge))
sig = p256_sign_prehash(d)
vectors.append({
    "id": "kat-manifest-pop-002-p256",
    "rfc_refs": ["RFC-AITP-0001 §5.4.2", "RFC-AITP-0001 §5.4.6"],
    "challenge": challenge,
    "decoded_hex": b64u_dec(challenge).hex(),
    "sha256_hex": d.hex(),
    "signing_keypair_id": "kat-keypair-005-p256",
    "signer_aid": P256_AID,
    "signature": "p256." + b64u(sig),
    "double_hash_signature_MUST_NOT_verify": "p256." + b64u(p256_sign_prehash(sha256(d))),
})

# --- Item 6b: derived v4 identifier -------------------------------------
tag, data = "aitp-kat-derived-uuid-v1", b"kat-derived-uuid-001/input"
preimage, h, uuid_str = derived_v4(tag, data)
vectors.append({
    "id": "kat-derived-uuid-001",
    "rfc_refs": ["RFC-AITP-0005 §2"],
    "domain_tag": tag,
    "input_hex": data.hex(),
    "preimage_hex": preimage.hex(),
    "sha256_hex": h.hex(),
    "uuid": uuid_str,
})

# --- Item 4: strictness negatives ---------------------------------------
# sig-001: the identity point as an Ed25519 key, signature R = identity, S = 0.
identity = (1).to_bytes(32, "little")
vectors.append({
    "id": "sig-001-ed25519-small-order-key-rejected",
    "rfc_refs": ["RFC-AITP-0001 §5.4.7"],
    "public_key_b64url": b64u(identity),
    "message_hex": "00" * 32,
    "signature_b64url": b64u(identity + bytes(32)),
    "expected": "reject",
})
# sig-002: kat-keypair-001 signature with S + L (non-canonical S).
L = 2**252 + 27742317777372353535851937790883648493
msg = sha256(b"sig-002")
good = ED1_SK.sign(msg)
s = int.from_bytes(good[32:], "little") + L
assert s < 2**256
vectors.append({
    "id": "sig-002-ed25519-noncanonical-s-rejected",
    "rfc_refs": ["RFC-AITP-0001 §5.4.7"],
    "signer_aid": ED1_AID,
    "message_hex": msg.hex(),
    "valid_signature_b64url": b64u(good),
    "signature_b64url": b64u(good[:32] + s.to_bytes(32, "little")),
    "expected": "reject",
})
# sig-003: high-S sibling of kat-p256-jcs-sign-001.
v1 = vectors[0]
vectors.append({
    "id": "sig-003-p256-high-s-rejected",
    "rfc_refs": ["RFC-AITP-0001 §5.4.7"],
    "signer_aid": P256_AID,
    "sha256_hex": v1["sha256_hex"],
    "low_s_signature": v1["signature"],
    "signature": v1["high_s_sibling_MUST_NOT_verify"],
    "expected": "reject",
})

# --- Item 5: self-attestation TCTs --------------------------------------
HUNDRED_YEARS = 3155760000
IAT = 1711900000


def attestation(kat_id, aid, jkt, alg, sign):
    _, _, jti = derived_v4("aitp-kat-attestation-v1", kat_id.encode())
    claims = {
        "ver": "aitp/0.2", "jti": jti, "iss": aid, "sub": aid, "aud": aid,
        "iat": IAT, "exp": IAT + HUNDRED_YEARS, "grants": ["aitp.attestation"],
        "cnf": {"jkt": jkt},
        "ext": {"org.aitp.kat": {"statement": kat_id + " archival attestation"}},
    }
    return {
        "id": kat_id,
        "rfc_refs": ["RFC-AITP-0005 §5.3", "RFC-AITP-0005 §2"],
        "jti_derivation": {"domain_tag": "aitp-kat-attestation-v1", "input_utf8": kat_id},
        "ttl_secs": HUNDRED_YEARS,
        "claims": claims,
        "token": compact_jws(alg, "aitp-tct+jwt", claims, sign),
    }


vectors.append(attestation("kat-tct-002-self-attestation", ED1_AID, jwk_thumbprint_ed(ED1_PK), "EdDSA", ED1_SK.sign))
vectors.append(attestation("kat-tct-003-p256-self-attestation", P256_AID, jwk_thumbprint_p256(), "ES256", p256_sign_es256))

doc = {
    "$comment": "Candidate KAT vectors for spec proposal p256-pinned-key-and-signing-input-2026-10 (agentidentitytrustprotocol#72). NOT a vendored spec artifact: generated by scripts/gen-proposal-kats.py with pyca/cryptography (OpenSSL) and reproduced byte-for-byte by the Rust tests with RustCrypto. kat-pinned-key-proof-002-p256 is the proposal's own candidate value. Replace with the vendored tests/schemas/known-answer/ set once spec PRs A-D land.",
    "proposal": "rfcs/proposals/p256-pinned-key-and-signing-input-2026-10.md",
    "generator": "scripts/gen-proposal-kats.py (pyca/cryptography " + __import__("cryptography").__version__ + ")",
    "vectors": vectors,
}
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(f"wrote {len(vectors)} vectors to {OUT}")
