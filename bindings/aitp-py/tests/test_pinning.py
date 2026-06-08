"""SPKI cert pinning — Python SDK.

Gated by `experimental-pinning`. Generates a fresh self-signed cert
in-test so we don't need a fixture file on disk.
"""

import datetime

import pytest

import aitp

HAS_PINNING = hasattr(aitp, "SpkiPinVerifier")
pytestmark = pytest.mark.skipif(
    not HAS_PINNING, reason="binding built without --features experimental-pinning"
)


def _self_signed_der():
    """Mint a fresh self-signed cert; return its DER bytes."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "pinning-test.example")]
    )
    # datetime.timezone.utc, not datetime.UTC — the latter is 3.11+ only
    # and the package supports Python 3.9.
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_compute_spki_hash_is_32_bytes():
    der = _self_signed_der()
    h = aitp.compute_spki_hash(der)
    assert isinstance(h, bytes)
    assert len(h) == 32


def test_compute_spki_hash_is_deterministic():
    der = _self_signed_der()
    assert aitp.compute_spki_hash(der) == aitp.compute_spki_hash(der)


def test_compute_spki_hash_rejects_garbage():
    with pytest.raises(ValueError, match="invalid X.509 certificate"):
        aitp.compute_spki_hash(b"not a cert")


def test_pin_verifier_matches_pinned_cert():
    der = _self_signed_der()
    h = aitp.compute_spki_hash(der)
    other_der = _self_signed_der()  # different keypair → different SPKI

    verifier = aitp.SpkiPinVerifier([h])
    assert verifier.is_pinned(der) is True
    assert verifier.is_pinned(other_der) is False


def test_pin_verifier_rejects_wrong_length_pin():
    with pytest.raises(ValueError, match="must be exactly 32 bytes"):
        aitp.SpkiPinVerifier([b"\x00" * 31])
