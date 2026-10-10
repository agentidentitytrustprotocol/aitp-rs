"""Executable documentation samples — Python SDK.

Every ```python block in `docs/sdk-python.md` and in the "Usage" section of
`bindings/aitp-py/README.md` is pasted below VERBATIM (indented one level),
inside a function whose header comment names the doc section it comes from.
The blocks form one connected flow, so each section function receives the
names defined by the earlier sections.

Two guards keep docs and binding in step:

* running the sections exercises every documented call against the built
  binding, so an API change breaks this file;
* `test_every_doc_block_is_executed_here` re-reads the docs and asserts each
  block appears in this file unchanged, so a doc edit breaks this file until
  the copy here is updated (and thereby executed).

A doc block whose first line is `# not executed: <reason>` is exempt from the
second guard. Everything here is hermetic: the OIDC IdP is an in-process
mock and the certificates are generated in-test. No network.

Run with `maturin develop` then `pytest` from `bindings/aitp-py/`.
"""

import base64
import datetime
import json
import pathlib
import re
import textwrap
import time
import types
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aitp

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
DOC = REPO_ROOT / "docs" / "sdk-python.md"
README = REPO_ROOT / "bindings" / "aitp-py" / "README.md"

HAS_RENEWAL = hasattr(aitp.AitpAgent.generate(), "build_renewal_request")
HAS_MULTIHOP = hasattr(aitp, "verify_delegation_multihop")
HAS_BUNDLE = hasattr(aitp, "SessionBundleBuilder")
HAS_PINNING = hasattr(aitp, "SpkiPinVerifier")


def _ns(*scopes):
    """Merge the names from earlier sections with a section's locals()."""
    merged = {}
    for scope in filter(None, scopes):
        merged.update(vars(scope) if isinstance(scope, types.SimpleNamespace) else scope)
    return types.SimpleNamespace(**merged)


# ── Test doubles the doc blocks assume (`my_idp`, `idp_jwk`, certs) ─────────


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class _MockIdp:
    """In-process OIDC issuer for https://idp.example/ (Ed25519, EdDSA)."""

    issuer = "https://idp.example/"

    def __init__(self):
        self._key = Ed25519PrivateKey.generate()
        raw = self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.jwk = {
            "kty": "OKP", "crv": "Ed25519", "x": _b64url(raw),
            "kid": "k1", "alg": "EdDSA", "use": "sig",
        }

    def mint_jwt(self, *, sub, aud, nonce, cnf_jkt):
        now = int(time.time())
        header = {"alg": "EdDSA", "typ": "JWT", "kid": "k1"}
        claims = {
            "iss": self.issuer, "sub": sub, "aud": aud, "iat": now,
            "exp": now + 600, "nonce": nonce, "cnf": {"jkt": cnf_jkt},
        }
        signing_input = ".".join(
            _b64url(json.dumps(part, separators=(",", ":")).encode())
            for part in (header, claims)
        )
        return f"{signing_input}.{_b64url(self._key.sign(signing_input.encode()))}"


def _self_signed_der():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "docs.example")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


# ── docs/sdk-python.md sections, in page order ──────────────────────────────


def _mutual_handshake():
    # docs/sdk-python.md § Mutual handshake (RFC-AITP-0004)
    import json

    import aitp

    alice = aitp.AitpAgent.generate()
    bob   = aitp.AitpAgent.generate()
    bob_manifest = bob.build_manifest(
        display_name="bob",
        handshake_endpoint="https://bob.example/aitp/handshake/",
        offered_caps=["demo.echo"],
    )
    alice.build_manifest(
        display_name="alice",
        handshake_endpoint="https://alice.example/aitp/handshake/",
        offered_caps=["demo.write"],
    )
    # 4 messages — each call's output is the next peer's input.
    s, r = alice.new_session(), bob.new_responder()
    hello = s.build_hello(bob_manifest, ["demo.echo"])
    ack, sid = r.process_hello(hello)
    commit   = s.process_hello_ack(ack, sid)
    cack, bob_side_json = r.process_commit(commit)  # bob_side_json: what alice issued to bob
    held = json.loads(s.complete(cack))             # complete() returns a JSON string
    tct_jws     = held["tct"]            # compact JWS issued by bob — store / present this
    voucher_jws = held["grant_voucher"]  # compact JWS, or None if bob disallowed delegation
    return _ns(locals())


def _tct_verification(ns):
    # docs/sdk-python.md § TCT verification (RFC-AITP-0005 §7.2)
    alice, bob, tct_jws = ns.alice, ns.bob, ns.tct_jws
    # Holder-receipt model — the verifier's AID is the agent's own AID (default).
    ident = alice.verify_tct(tct_jws, "demo.echo")
    print(ident.peer_aid == bob.aid, ident.grants)   # True ['demo.echo']

    # Presented-TCT model — a resource server checking a TCT a peer presented
    # (e.g. in `X-AITP-TCT`). The expected audience is the TCT's subject (aud == sub).
    ident = bob.verify_tct(tct_jws, "demo.echo", expected_audience=alice.aid)

    # Revocation gate: pass the set of revoked TCT `jti`s. Verifiers SHOULD supply
    # it — omitting it accepts a revoked-but-unexpired TCT.
    try:
        alice.verify_tct(tct_jws, "demo.echo", revoked_jtis={ident.jti})
    except RuntimeError as err:
        print(err)   # TCT verification failed: TCT jti is revoked
        caught = err
    return _ns(ns, locals())


def _cached_verification(ns):
    # docs/sdk-python.md § TCT verification › Cached verification (`TctStore`)
    alice, tct_jws = ns.alice, ns.tct_jws
    store = aitp.TctStore(max_entries=1024)
    ident = alice.verify_tct_cached(tct_jws, "demo.echo", store)
    ident = alice.verify_tct_cached(tct_jws, "demo.echo", store)  # signature check skipped
    print(store.len())   # 1
    return _ns(ns, locals())


def _delegation(ns):
    # docs/sdk-python.md § Delegation (RFC-AITP-0006)
    alice, bob, voucher_jws = ns.alice, ns.bob, ns.voucher_jws
    carol = aitp.AitpAgent.generate()
    # alice delegates part of what bob granted her to carol.
    delegation_jws = alice.build_delegation(voucher_jws, carol.aid, ["demo.echo"])

    # bob (the original grantor) verifies and mints carol a TCT of her own.
    revoked = set()   # bob's deny list, e.g. jtis from verified revocation snapshots
    verified = aitp.verify_delegation(delegation_jws, bob.aid, revoked_jtis=revoked)
    issued = json.loads(bob.issue_tct_for_delegatee(verified))  # JSON string
    carol_tct = issued["tct"]
    print(carol.verify_tct(carol_tct, "demo.echo").peer_aid == bob.aid)   # True
    return _ns(ns, locals())


def _manifest_verification(ns):
    # docs/sdk-python.md § Manifest verification
    bob_manifest = ns.bob_manifest
    aitp.verify_manifest_json(bob_manifest)   # returns None on success

    try:
        aitp.verify_manifest_json(bob_manifest, now_unix_secs=4_102_444_800)  # year 2100
    except aitp.ManifestVerificationError as err:
        print(err.code)   # expired
        caught = err
    return _ns(ns, locals())


def _revocation_lists(ns):
    # docs/sdk-python.md § Revocation lists (RFC-AITP-0008)
    alice, bob, revoked = ns.alice, ns.bob, ns.revoked
    import uuid

    snapshot = bob.sign_revocation_list(
        [{"jti": str(uuid.uuid4()), "reason": "compromised"}],   # jti must be a UUID
        expires_in_secs=600,
    )
    aitp.verify_revocation_list(snapshot, bob.aid)   # pin the expected issuer
    try:
        aitp.verify_revocation_list(snapshot, alice.aid)
    except aitp.RevocationVerificationError as err:
        print(err.code)   # issuer_mismatch

    revoked |= {e["jti"] for e in json.loads(snapshot)["revocation_list"]["entries"]}
    signed_bytes = aitp.revocation_signing_bytes(snapshot)   # JCS of the inner body
    return _ns(ns, locals())


def _oidc_identity(ns):
    # docs/sdk-python.md § OIDC identity (RFC-AITP-0002)
    bob, bob_manifest = ns.bob, ns.bob_manifest
    my_idp = _MockIdp()
    idp_jwk = my_idp.jwk
    # You fetch the IdP's JWKS yourself; the SDK does no HTTP.
    jwks = aitp.JwksProvider({"https://idp.example/": [idp_jwk]})
    dave = aitp.AitpAgent.generate()
    dave.build_manifest(
        display_name="dave",
        handshake_endpoint="https://dave.example/aitp/handshake/",
        offered_caps=["demo.write"],
        identity_type="oidc", oidc_issuer="https://idp.example/", oidc_subject="dave",
    )

    def mint(pop_nonce: str) -> str:
        # Return a fresh JWT from your IdP, bound to this handshake and to dave's key.
        return my_idp.mint_jwt(sub="dave", aud=bob.aid, nonce=pop_nonce,
                               cnf_jkt=aitp.compute_aid_jkt(dave.aid))

    sess = dave.new_session(jwks=jwks)
    oidc_hello = sess.build_hello(bob_manifest, ["demo.echo"], oidc_mint_jwt=mint)

    # bob's manifest accepts no OIDC issuer by default, so his responder must
    # trust the IdP explicitly.
    responder = bob.new_responder(jwks=jwks, trust_anchors=["https://idp.example/"])
    oidc_ack, oidc_sid = responder.process_hello(oidc_hello)
    return _ns(ns, locals())


def _p256_suite(ns):
    # docs/sdk-python.md § P-256 signing suite (RFC-AITP-0001 §5.4.3)
    erin = aitp.AitpAgent.generate(suite="p256")                  # aid:pubkey:p256:…
    erin_again = aitp.AitpAgent.from_seed(bytes(range(32)), suite="p256")   # deterministic

    try:
        erin.build_manifest(display_name="erin",
                            handshake_endpoint="https://erin.example/aitp/handshake/",
                            offered_caps=["demo.echo"])   # pinned_key is the default
    except RuntimeError as err:
        print(err)   # pinned_key identity_hint with a P-256 agent key is not supported; …
        caught = err
    return _ns(ns, locals())


def _tct_renewal(ns):
    # docs/sdk-python.md § Additional capabilities › TCT renewal (feature `renewal`)
    alice, bob, tct_jws = ns.alice, ns.bob, ns.tct_jws
    import time

    req = alice.build_renewal_request(tct_jws)   # pass the held TCT positionally
    renewed = json.loads(bob.process_renewal_request(
        req, manifest_exp_unix_secs=int(time.time()) + 86_400, new_ttl_secs=3600,
    ))
    fresh_tct, fresh_voucher = renewed["tct"], renewed["grant_voucher"]
    return _ns(ns, locals())


def _multihop(ns):
    # docs/sdk-python.md § Additional capabilities › Multi-hop delegation
    bob, delegation_jws, revoked = ns.bob, ns.delegation_jws, ns.revoked
    verified = aitp.verify_delegation_multihop(
        delegation_jws, bob.aid, max_delegation_hops=3, revoked_jtis=revoked,
    )
    return _ns(ns, locals())


def _session_bundle(ns):
    # docs/sdk-python.md § Additional capabilities › Session Trust Bundle
    alice, bob, carol = ns.alice, ns.bob, ns.carol
    tct_jws, carol_tct, revoked = ns.tct_jws, ns.carol_tct, ns.revoked
    bundle = (
        aitp.SessionBundleBuilder(bob)              # bob coordinates
            .session_id(str(uuid.uuid4()))          # optional; defaults to a fresh UUID
            .issued_at(int(time.time()))            # optional; defaults to now
            .participant(alice.aid, tct_jws)        # TCTs bob issued to each member
            .participant(carol.aid, carol_tct)
            .build()
    )
    outcome = aitp.verify_session_bundle(bundle, alice.aid)
    print(outcome["kind"])   # clear  (keys: kind, active_aids, dropped_aids)

    outcome = aitp.verify_session_bundle(
        bundle, alice.aid, revocation_check=lambda jti: jti in revoked,
    )
    return _ns(ns, locals())


def _spki_pinning(ns):
    # docs/sdk-python.md § Additional capabilities › SPKI cert pinning
    cert_der_bytes, other_cert_der = _self_signed_der(), _self_signed_der()
    pin = aitp.compute_spki_hash(cert_der_bytes)    # 32 bytes
    verifier = aitp.SpkiPinVerifier([pin])
    print(verifier.is_pinned(cert_der_bytes), verifier.is_pinned(other_cert_der))   # True False
    return _ns(ns, locals())


def _readme_usage():
    # bindings/aitp-py/README.md § Usage
    import json

    import aitp

    initiator = aitp.AitpAgent.generate()
    responder = aitp.AitpAgent.generate()

    initiator.build_manifest(
        display_name="initiator",
        handshake_endpoint="http://localhost:8100/aitp/handshake/",
        offered_caps=["demo.echo"],
    )
    resp_manifest = responder.build_manifest(
        display_name="responder",
        handshake_endpoint="http://localhost:8200/aitp/handshake/",
        offered_caps=["demo.write"],
    )

    # Four-message mutual handshake — each call's output is the next peer's input.
    sess  = initiator.new_session()
    rsess = responder.new_responder()

    hello                 = sess.build_hello(resp_manifest, ["demo.write"])
    hello_ack, session_id = rsess.process_hello(hello)
    commit                = sess.process_hello_ack(hello_ack, session_id)
    commit_ack, responder_held = rsess.process_commit(commit)  # JSON: TCT the initiator issued the responder
    held = json.loads(sess.complete(commit_ack))  # JSON string: {"tct": ..., "grant_voucher": ...}

    # Each peer now holds a TCT the other issued it.
    ident = initiator.verify_tct(held["tct"], "demo.write")
    print(ident.peer_aid, ident.grants)
    return _ns(locals())


def _through_delegation():
    return _delegation(_mutual_handshake())


# ── Tests ───────────────────────────────────────────────────────────────────


def test_mutual_handshake():
    ns = _mutual_handshake()
    assert set(ns.held) == {"tct", "grant_voucher"}
    assert ns.tct_jws.count(".") == 2
    assert ns.voucher_jws is not None and ns.voucher_jws.count(".") == 2
    assert set(json.loads(ns.bob_side_json)) == {"tct", "grant_voucher"}


def test_tct_verification(capsys):
    ns = _tct_verification(_mutual_handshake())
    out = capsys.readouterr().out
    assert "True ['demo.echo']" in out
    assert "TCT verification failed" in out
    assert not hasattr(ns.caught, "code")  # documented: no `.code` on TCT failures
    assert ns.ident.peer_aid == ns.bob.aid


def test_cached_verification(capsys):
    _cached_verification(_mutual_handshake())
    assert capsys.readouterr().out.strip() == "1"


def test_delegation(capsys):
    ns = _through_delegation()
    assert "True" in capsys.readouterr().out
    assert set(ns.issued) == {"tct", "grant_voucher"}
    assert ns.verified.delegatee == ns.carol.aid


def test_manifest_verification(capsys):
    ns = _manifest_verification(_mutual_handshake())
    assert capsys.readouterr().out.strip() == "expired"
    assert isinstance(ns.caught, RuntimeError)


def test_manifest_verification_rejects_non_manifest_with_value_error():
    # Documented in the same section: non-manifest input raises ValueError.
    with pytest.raises(ValueError):
        aitp.verify_manifest_json("{}")


def test_revocation_lists(capsys):
    ns = _revocation_lists(_through_delegation())
    assert capsys.readouterr().out.splitlines()[-1] == "issuer_mismatch"
    assert len(ns.revoked) == 1
    assert isinstance(ns.signed_bytes, bytes)


def test_oidc_identity():
    ns = _oidc_identity(_mutual_handshake())
    commit = ns.sess.process_hello_ack(ns.oidc_ack, ns.oidc_sid)
    commit_ack, _ = ns.responder.process_commit(commit)
    assert json.loads(ns.sess.complete(commit_ack))["tct"].count(".") == 2


def test_p256_suite(capsys):
    ns = _p256_suite(_mutual_handshake())
    assert ns.erin.aid.startswith("aid:pubkey:p256:")
    assert ns.erin_again.aid == aitp.AitpAgent.from_seed(bytes(range(32)), suite="p256").aid
    assert "not supported" in capsys.readouterr().out
    assert isinstance(ns.caught, RuntimeError)


@pytest.mark.skipif(not HAS_RENEWAL, reason="binding built without the renewal feature")
def test_tct_renewal():
    ns = _tct_renewal(_mutual_handshake())
    assert ns.fresh_tct.count(".") == 2 and ns.fresh_tct != ns.tct_jws
    assert ns.fresh_voucher is not None


@pytest.mark.skipif(not HAS_MULTIHOP, reason="binding built without multihop-delegation")
def test_multihop_delegation():
    ns = _multihop(_through_delegation())
    assert ns.verified.delegatee == ns.carol.aid


@pytest.mark.skipif(not HAS_BUNDLE, reason="binding built without session-bundle")
def test_session_bundle(capsys):
    ns = _delegation(_mutual_handshake())
    ns = _revocation_lists(ns)
    ns = _session_bundle(ns)
    assert "clear" in capsys.readouterr().out.splitlines()
    assert ns.outcome["kind"] == "clear"  # nothing in `revoked` names a member TCT


@pytest.mark.skipif(not HAS_PINNING, reason="binding built without spki-pinning")
def test_spki_pinning(capsys):
    _spki_pinning(None)
    assert capsys.readouterr().out.strip() == "True False"


def test_readme_usage(capsys):
    ns = _readme_usage()
    assert ns.ident.peer_aid == ns.responder.aid
    assert "demo.write" in capsys.readouterr().out


# ── Drift guard: every doc block must be pasted (and so executed) above ─────
# Substring match: catches changed arguments and new blocks; deleting only the
# first/last line of a block is not detected.

_FENCE = re.compile(r"^```python\n(.*?)^```", re.S | re.M)


def _doc_blocks(path):
    text = path.read_text(encoding="utf-8")
    if path == README:  # only the Usage section of the README is mirrored
        text = text.split("## Usage", 1)[1].split("\n## ", 1)[0]
    return [b for b in _FENCE.findall(text) if not b.startswith("# not executed:")]


@pytest.mark.parametrize("path", [DOC, README], ids=lambda p: p.name)
def test_every_doc_block_is_executed_here(path):
    if not path.exists():
        pytest.skip(f"{path} not present (running outside the repo checkout)")
    source = pathlib.Path(__file__).read_text(encoding="utf-8")
    blocks = _doc_blocks(path)
    assert blocks, f"no python blocks found in {path}"
    for block in blocks:
        indented = textwrap.indent(block, "    ")
        assert indented in source, (
            f"a python block in {path.relative_to(REPO_ROOT)} is not mirrored verbatim "
            f"in {pathlib.Path(__file__).name}; copy it into the matching section "
            f"function:\n{block}"
        )
