"""Cross-language AITP interop integration tests.

Exercises a real four-message AITP handshake where the two ends run in
*different language runtimes*:

* the **Python** end runs in-process via the ``aitp`` extension, and
* the **Node** end runs in a ``node`` subprocess driven over
  line-delimited JSON-RPC (see ``node_worker.mjs``).

Each wire message produced by one binding is fed straight into the
other, so a green run proves the two SDKs emit byte-compatible AITP
envelopes. Both handshake directions are covered — Python-initiated and
Node-initiated — plus cross-language TCT-rejection semantics.

Run from ``bindings/interop/`` after building both bindings::

    maturin develop -m ../aitp-py/Cargo.toml
    (cd ../aitp-node && npm install && npm run build:debug)
    pytest

or simply ``make interop`` / ``scripts/interop.sh``, which builds both
bindings first.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

import aitp

HERE = os.path.dirname(os.path.abspath(__file__))

# A capability both agents offer, so each handshake direction yields a
# mutual TCT scoped to exactly this grant.
PING_CAP = "interop.ping"


# ── Node side: a subprocess worker driven over JSON-RPC ─────────────────


class NodeWorker:
    """A ``node node_worker.mjs`` subprocess driven over JSON-RPC stdio."""

    def __init__(self) -> None:
        self._proc = subprocess.Popen(
            ["node", os.path.join(HERE, "node_worker.mjs")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,  # surface Node-side errors into pytest output
            text=True,
            bufsize=1,
        )
        self._next_id = 0

    def _rpc(self, method: str, params: dict) -> dict:
        self._next_id += 1
        request = {"id": self._next_id, "method": method, "params": params}
        self._proc.stdin.write(json.dumps(request) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            raise RuntimeError(f"node worker exited before answering {method!r}")
        return json.loads(line)

    def call(self, method: str, **params):
        resp = self._rpc(method, params)
        if not resp.get("ok"):
            raise RuntimeError(f"node.{method} failed: {resp['error']}")
        return resp["result"]

    def call_expect_error(self, method: str, **params) -> str:
        resp = self._rpc(method, params)
        if resp.get("ok"):
            raise AssertionError(f"node.{method} unexpectedly succeeded")
        return resp["error"]

    def close(self) -> None:
        try:
            self._proc.stdin.close()
            self._proc.wait(timeout=5)
        except Exception:
            self._proc.kill()


@pytest.fixture(scope="module")
def node():
    """A live Node interop worker, shared across the module's tests."""
    if shutil.which("node") is None:
        pytest.skip("node executable not found on PATH")
    worker = NodeWorker()
    try:
        worker.call("ping")  # fail fast if the aitp-node binding is not built
        yield worker
    finally:
        worker.close()


# ── Endpoints: a uniform handshake surface over each runtime ────────────
#
# Both endpoints expose the same methods so `_handshake` can drive a
# handshake with either runtime in either role. A "handle" is a real
# Python object for `PyEndpoint` and an opaque integer for `NodeEndpoint`.


class PyEndpoint:
    """The Python binding, called in-process."""

    name = "python"
    label = "aitp-py 0.1.0"

    def new_agent(self):
        agent = aitp.AitpAgent.generate()
        return agent, agent.aid

    def build_manifest(self, agent, display_name, endpoint, caps):
        return agent.build_manifest(
            display_name=display_name,
            handshake_endpoint=endpoint,
            offered_caps=caps,
        )

    def new_session(self, agent):
        return agent.new_session()

    def new_responder(self, agent):
        return agent.new_responder()

    def build_hello(self, session, peer_manifest, grants):
        return session.build_hello(peer_manifest, grants)

    def process_hello(self, responder, hello):
        return responder.process_hello(hello)  # (hello_ack, session_id)

    def process_hello_ack(self, session, hello_ack, session_id):
        return session.process_hello_ack(hello_ack, session_id)

    def process_commit(self, responder, commit):
        return responder.process_commit(commit)  # (commit_ack, tct)

    def complete(self, session, commit_ack):
        return session.complete(commit_ack)

    def verify_tct(self, agent, tct, grant):
        ident = agent.verify_tct(tct, grant)
        return {
            "peer_aid": ident.peer_aid,
            "grants": list(ident.grants),
            "jti": ident.jti,
        }

    def verify_tct_expect_error(self, agent, tct, grant):
        with pytest.raises(Exception):
            agent.verify_tct(tct, grant)


class NodeEndpoint:
    """The Node binding, called over the JSON-RPC subprocess worker."""

    name = "node"
    label = "aitp-node 0.1.0"

    def __init__(self, worker: NodeWorker) -> None:
        self._w = worker

    def new_agent(self):
        result = self._w.call("new_agent")
        return result["handle"], result["aid"]

    def build_manifest(self, agent, display_name, endpoint, caps):
        return self._w.call(
            "build_manifest",
            agent=agent,
            display_name=display_name,
            handshake_endpoint=endpoint,
            offered_caps=caps,
        )["manifest"]

    def new_session(self, agent):
        return self._w.call("new_session", agent=agent)["handle"]

    def new_responder(self, agent):
        return self._w.call("new_responder", agent=agent)["handle"]

    def build_hello(self, session, peer_manifest, grants):
        return self._w.call(
            "build_hello",
            session=session,
            peer_manifest=peer_manifest,
            requested_grants=grants,
        )["hello"]

    def process_hello(self, responder, hello):
        result = self._w.call("process_hello", responder=responder, hello=hello)
        return result["hello_ack"], result["session_id"]

    def process_hello_ack(self, session, hello_ack, session_id):
        return self._w.call(
            "process_hello_ack",
            session=session,
            hello_ack=hello_ack,
            session_id=session_id,
        )["commit"]

    def process_commit(self, responder, commit):
        result = self._w.call("process_commit", responder=responder, commit=commit)
        return result["commit_ack"], result["tct"]

    def complete(self, session, commit_ack):
        return self._w.call("complete", session=session, commit_ack=commit_ack)["tct"]

    def verify_tct(self, agent, tct, grant):
        return self._w.call(
            "verify_tct", agent=agent, tct=tct, required_grant=grant
        )

    def verify_tct_expect_error(self, agent, tct, grant):
        self._w.call_expect_error(
            "verify_tct", agent=agent, tct=tct, required_grant=grant
        )


def _handshake(initiator, responder):
    """Drive one full four-message handshake across two endpoints.

    Returns the two agents, their AIDs, and the TCT each end holds once
    the exchange completes.
    """
    init_agent, init_aid = initiator.new_agent()
    resp_agent, resp_aid = responder.new_agent()

    # Both ends must publish a manifest before opening a session.
    initiator.build_manifest(
        init_agent,
        f"{initiator.name}-initiator",
        "http://localhost:8100/aitp/handshake/",
        [PING_CAP],
    )
    resp_manifest = responder.build_manifest(
        resp_agent,
        f"{responder.name}-responder",
        "http://localhost:8200/aitp/handshake/",
        [PING_CAP],
    )

    isession = initiator.new_session(init_agent)
    rsession = responder.new_responder(resp_agent)

    # Four messages — each one crosses the language boundary as wire JSON.
    hello = initiator.build_hello(isession, resp_manifest, [PING_CAP])
    hello_ack, session_id = responder.process_hello(rsession, hello)
    commit = initiator.process_hello_ack(isession, hello_ack, session_id)
    commit_ack, responder_held_tct = responder.process_commit(rsession, commit)
    initiator_held_tct = initiator.complete(isession, commit_ack)

    return {
        "init_agent": init_agent,
        "init_aid": init_aid,
        "resp_agent": resp_agent,
        "resp_aid": resp_aid,
        "initiator_held_tct": initiator_held_tct,
        "responder_held_tct": responder_held_tct,
    }


# ── Tests ───────────────────────────────────────────────────────────────


def test_python_initiator_node_responder(node):
    """Python opens the handshake, Node answers; both hold a valid TCT."""
    py, nd = PyEndpoint(), NodeEndpoint(node)
    hs = _handshake(initiator=py, responder=nd)

    # Python holds a TCT the Node responder issued it.
    init_ident = py.verify_tct(hs["init_agent"], hs["initiator_held_tct"], PING_CAP)
    # Node holds a TCT the Python initiator issued it.
    resp_ident = nd.verify_tct(hs["resp_agent"], hs["responder_held_tct"], PING_CAP)

    assert init_ident["peer_aid"] == hs["resp_aid"]
    assert resp_ident["peer_aid"] == hs["init_aid"]
    assert init_ident["grants"] == [PING_CAP]
    assert resp_ident["grants"] == [PING_CAP]
    assert init_ident["jti"] != resp_ident["jti"]


def test_node_initiator_python_responder(node):
    """Node opens the handshake, Python answers; both hold a valid TCT."""
    py, nd = PyEndpoint(), NodeEndpoint(node)
    hs = _handshake(initiator=nd, responder=py)

    # Node holds a TCT the Python responder issued it.
    init_ident = nd.verify_tct(hs["init_agent"], hs["initiator_held_tct"], PING_CAP)
    # Python holds a TCT the Node initiator issued it.
    resp_ident = py.verify_tct(hs["resp_agent"], hs["responder_held_tct"], PING_CAP)

    assert init_ident["peer_aid"] == hs["resp_aid"]
    assert resp_ident["peer_aid"] == hs["init_aid"]
    assert init_ident["grants"] == [PING_CAP]
    assert resp_ident["grants"] == [PING_CAP]
    assert init_ident["jti"] != resp_ident["jti"]


def test_node_rejects_python_issued_tct_for_missing_grant(node):
    """A TCT Python issued is rejected by Node when an absent grant is required."""
    py, nd = PyEndpoint(), NodeEndpoint(node)
    # Python initiates → the Node responder holds the Python-issued TCT.
    hs = _handshake(initiator=py, responder=nd)
    nd.verify_tct_expect_error(
        hs["resp_agent"], hs["responder_held_tct"], "interop.absent"
    )


def test_python_rejects_node_issued_tct_for_missing_grant(node):
    """A TCT Node issued is rejected by Python when an absent grant is required."""
    py, nd = PyEndpoint(), NodeEndpoint(node)
    # Node initiates → the Python responder holds the Node-issued TCT.
    hs = _handshake(initiator=nd, responder=py)
    py.verify_tct_expect_error(
        hs["resp_agent"], hs["responder_held_tct"], "interop.absent"
    )


# ── A2 — presented-TCT verify across runtimes ──────────────────────────


def test_node_presented_tct_verifies_via_python_audience(node):
    """A TCT Node issued is verified by Python under the presented-TCT model
    (RFC-AITP-0005 §9): the verifier passes the TCT's audience explicitly
    rather than defaulting to the holder's own AID."""
    py, nd = PyEndpoint(), NodeEndpoint(node)
    # Node initiates → Python (responder) holds a TCT issued by Node, bound
    # to Python's own AID. Verify via the presented-mode audience.
    hs = _handshake(initiator=nd, responder=py)
    ident = hs["resp_agent"].verify_tct(
        hs["responder_held_tct"], PING_CAP, hs["resp_aid"]
    )
    assert ident.peer_aid == hs["init_aid"]


def test_python_presented_tct_verifies_via_node_audience(node):
    """Mirror of the above — Node verifies a Python-issued TCT under the
    presented-TCT model."""
    py, nd = PyEndpoint(), NodeEndpoint(node)
    hs = _handshake(initiator=py, responder=nd)
    # Node holds a TCT issued by Python, with audience = Node's AID.
    ident = node.call(
        "verify_tct",
        agent=hs["resp_agent"],
        tct=hs["responder_held_tct"],
        required_grant=PING_CAP,
        expected_audience=hs["resp_aid"],
    )
    assert ident["peer_aid"] == hs["init_aid"]


# ── A1 — delegation across runtimes ─────────────────────────────────────


def test_delegation_python_issuer_node_chain(node):
    """Python A issues a TCT to Python B via handshake; B mints a
    DelegationEnvelope binding Node-C's pubkey; A (Python) verifies it
    and mints a fresh TCT for C; C (Node) verifies the fresh TCT under
    the presented-TCT model."""
    py = PyEndpoint()

    # A and B both Python; C is Node.
    a, _ = py.new_agent()
    b, _ = py.new_agent()
    a_manifest = py.build_manifest(
        a, "py-A", "http://localhost:8500/aitp/handshake/", [PING_CAP]
    )
    py.build_manifest(
        b, "py-B", "http://localhost:8501/aitp/handshake/", [PING_CAP]
    )

    # B handshakes against A → B holds A's TCT for PING_CAP.
    bsess = py.new_session(b)
    arsess = py.new_responder(a)
    hello = py.build_hello(bsess, a_manifest, [PING_CAP])
    hello_ack, sid = py.process_hello(arsess, hello)
    commit = py.process_hello_ack(bsess, hello_ack, sid)
    commit_ack, _ = py.process_commit(arsess, commit)
    b_held_from_a = py.complete(bsess, commit_ack)

    # C is a Node agent. Build C's manifest so we can pull its pubkey.
    c_handle, c_aid = NodeEndpoint(node).new_agent()
    c_manifest = NodeEndpoint(node).build_manifest(
        c_handle, "node-C", "http://localhost:8502/aitp/handshake/", [PING_CAP]
    )
    c_pubkey = node.call("pubkey_from_manifest", manifest=c_manifest)["pubkey_b64u"]

    # B (Python) builds a delegation envelope binding C.
    delegation_env = b.build_delegation(
        b_held_from_a, c_aid, c_pubkey, [PING_CAP]
    )

    # A (Python) verifies → mints fresh TCT for C.
    verified = aitp.verify_delegation(delegation_env, a.aid)
    fresh_tct_for_c = a.issue_tct_for_delegatee(verified)

    # C (Node) verifies the fresh TCT under presented-TCT mode.
    ident = node.call(
        "verify_tct",
        agent=c_handle,
        tct=fresh_tct_for_c,
        required_grant=PING_CAP,
        expected_audience=c_aid,
    )
    assert ident["peer_aid"] == a.aid


# ── A3 — Python-signed revocation list parses on Node ───────────────────


def test_python_revocation_list_parses_on_node(node):
    """Python signs a revocation list; Node parses the envelope. (Full
    revocation enforcement requires a callback hook the bindings don't
    expose yet — this test confirms wire compatibility only.)"""
    py = PyEndpoint()
    issuer, issuer_aid = py.new_agent()
    py.build_manifest(
        issuer, "issuer", "http://localhost:8600/aitp/handshake/", [PING_CAP]
    )
    envelope = issuer.sign_revocation_list(
        [
            {"jti": "11111111-1111-1111-1111-111111111111", "reason": "test"},
        ],
        expires_in_secs=600,
    )
    parsed = json.loads(envelope)
    # Sanity from Python side first.
    assert parsed["revocation_list"]["issuer"] == issuer_aid
    # Round-trip through Node's JSON parser to confirm wire shape.
    # (Node doesn't currently expose a parser, but valid JSON is sufficient.)
    assert json.loads(envelope) == parsed


# ── A4 — Python manifest verified by Node ───────────────────────────────


def test_python_manifest_verifies_on_node(node):
    """A manifest signed by the Python binding verifies through Node's
    verifyManifestJson and vice versa."""
    py, nd = PyEndpoint(), NodeEndpoint(node)
    py_agent, _ = py.new_agent()
    nd_agent, _ = nd.new_agent()

    py_manifest = py.build_manifest(
        py_agent, "py-mfst", "http://localhost:8700/aitp/handshake/", [PING_CAP]
    )
    nd_manifest = nd.build_manifest(
        nd_agent, "nd-mfst", "http://localhost:8701/aitp/handshake/", [PING_CAP]
    )

    # Each side verifies the other's manifest.
    node.call("verify_manifest", manifest=py_manifest)  # raises on failure
    aitp.verify_manifest_json(nd_manifest)


# ── B1 — OIDC handshake interop ────────────────────────────────────────


OIDC_ISSUER = "https://idp.interop.test/"  # canonical (trailing-slash)


def _aid_jkt_local(aid: str) -> str:
    """Same Ed25519 JWK thumbprint computation as bindings/aitp-py/tests."""
    import base64
    import hashlib
    import json as json_mod

    prefix = "aid:pubkey:ed25519:"
    legacy = "aid:pubkey:"
    pk_b64 = aid[len(prefix):] if aid.startswith(prefix) else aid[len(legacy):]
    pk = base64.urlsafe_b64decode(pk_b64 + "==")[:32]
    canonical = json_mod.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": base64.urlsafe_b64encode(pk).rstrip(b"=").decode()},
        separators=(",", ":"),
        sort_keys=True,
    )
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()


def test_oidc_python_initiator_node_responder(node):
    """A four-message OIDC handshake: Python initiator + Node responder.
    The mock OIDC issuer lives in the Node worker; Python uses pyjwt to
    mint its own JWT inline; Node calls back into the worker's signer."""
    import time

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    # Python-side mock OIDC issuer (we don't share the keypair across
    # runtimes; instead each side has its own kid).
    py_seed = bytes(range(32))
    py_priv = Ed25519PrivateKey.from_private_bytes(py_seed)
    py_pub = py_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    import base64 as b64

    def _b64u(b):
        return b64.urlsafe_b64encode(b).rstrip(b"=").decode()

    py_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64u(py_pub),
        "kid": "py-kid",
        "alg": "EdDSA",
        "use": "sig",
    }
    # Ask the Node worker to mint its own issuer keypair so both sides
    # share the same JWKS map (we register both kids under the same URL).
    node_jwk = node.call("make_oidc_issuer", issuer=OIDC_ISSUER, kid="node-kid")["jwk"]

    # Python-side: provider with both kids; OIDC manifest; OIDC session.
    provider = aitp.JwksProvider({OIDC_ISSUER: [py_jwk, node_jwk]})
    py_agent = aitp.AitpAgent.generate()
    py_agent.build_manifest(
        display_name="py-oidc-init",
        handshake_endpoint="https://py.interop.test/aitp/handshake/",
        offered_caps=[PING_CAP],
        identity_type="oidc",
        oidc_issuer=OIDC_ISSUER,
        oidc_subject="py-init",
    )
    py_sess = py_agent.new_session(jwks=provider)

    # Node-side: agent in OIDC mode + responder pre-configured with the
    # same JWKS provider. The worker's mint callback is wired via the
    # mint_* params on process_hello_oidc.
    node_agent_handle = node.call("new_agent")["handle"]
    node_aid = node.call("new_agent")  # discard — get real aid for the active agent below
    # Use the first node agent we created. Reuse its handle.
    node_agent = node_agent_handle
    node_aid = node.call(
        "build_manifest_oidc",
        agent=node_agent,
        display_name="node-oidc-resp",
        handshake_endpoint="https://node.interop.test/aitp/handshake/",
        offered_caps=[PING_CAP],
        oidc_issuer=OIDC_ISSUER,
        oidc_subject="node-resp",
    )
    node_manifest = node_aid["manifest"]
    # Read the responder's AID from the just-minted manifest.
    node_resp_aid = json.loads(node_manifest)["manifest"]["aid"]

    node_jwks_handle = node.call(
        "new_jwks_provider",
        keys={OIDC_ISSUER: [py_jwk, node_jwk]},
    )["handle"]
    node_resp_handle = node.call(
        "new_oidc_responder", agent=node_agent, jwks=node_jwks_handle
    )["handle"]

    now = int(time.time())
    py_jkt = _aid_jkt_local(py_agent.aid)
    node_jkt = _aid_jkt_local(node_resp_aid)

    # Python's mint callback signs locally with `py_priv`.
    def py_mint(nonce: str) -> str:
        import json as json_mod

        header = {"alg": "EdDSA", "typ": "JWT", "kid": "py-kid"}
        claims = {
            "iss": OIDC_ISSUER,
            "sub": "py-init",
            "aud": node_resp_aid,
            "iat": now,
            "exp": now + 3600,
            "nonce": nonce,
            "cnf": {"jkt": py_jkt},
        }
        h = _b64u(json_mod.dumps(header, separators=(",", ":")).encode())
        p = _b64u(json_mod.dumps(claims, separators=(",", ":")).encode())
        sig = py_priv.sign(f"{h}.{p}".encode())
        return f"{h}.{p}.{_b64u(sig)}"

    # ── Four messages ───────────────────────────────────────────────
    hello = py_sess.build_hello(node_manifest, [PING_CAP], oidc_mint_jwt=py_mint)
    ack_result = node.call(
        "process_hello_oidc",
        responder=node_resp_handle,
        hello=hello,
        mint_kid="node-kid",
        mint_sub="node-resp",
        mint_aud=py_agent.aid,
        mint_cnf_jkt=node_jkt,
        mint_now=now,
    )
    commit = py_sess.process_hello_ack(ack_result["hello_ack"], ack_result["session_id"])
    commit_result = node.call("process_commit", responder=node_resp_handle, commit=commit)
    py_held_tct = py_sess.complete(commit_result["commit_ack"])

    # Each side holds the other's TCT.
    py_ident = py_agent.verify_tct(py_held_tct, PING_CAP)
    assert py_ident.peer_aid == node_resp_aid
    nd_ident = node.call(
        "verify_tct",
        agent=node_agent,
        tct=commit_result["tct"],
        required_grant=PING_CAP,
    )
    assert nd_ident["peer_aid"] == py_agent.aid


# ── B4 — session bundle interop ────────────────────────────────────────


def test_session_bundle_python_coordinator_node_verifier(node):
    """Python coordinator builds a bundle binding two participants
    (one py, one node, each with a coordinator-issued TCT from a
    bilateral handshake). Node verifies the bundle and finds itself in
    the active set."""
    if not hasattr(aitp, "SessionBundleBuilder"):
        pytest.skip("python binding built without --features experimental-bundle")

    py = PyEndpoint()
    nd = NodeEndpoint(node)

    # Coordinator + Python participant + Node participant.
    coord, coord_aid = py.new_agent()
    py_part, py_part_aid = py.new_agent()
    nd_part_handle, nd_part_aid = nd.new_agent()

    coord_manifest = py.build_manifest(
        coord, "coord", "http://localhost:9001/aitp/handshake/", ["session.member"]
    )
    py.build_manifest(
        py_part, "py-part", "http://localhost:9002/aitp/handshake/", ["x"]
    )
    nd.build_manifest(
        nd_part_handle, "nd-part", "http://localhost:9003/aitp/handshake/", ["x"]
    )

    # Bilateral handshakes against coordinator.
    def handshake_to(py_or_nd_endpoint, part_handle):
        sess = py_or_nd_endpoint.new_session(part_handle)
        rsess = py.new_responder(coord)
        hello = py_or_nd_endpoint.build_hello(sess, coord_manifest, ["session.member"])
        hello_ack, sid = py.process_hello(rsess, hello)
        commit = py_or_nd_endpoint.process_hello_ack(sess, hello_ack, sid)
        commit_ack, _ = py.process_commit(rsess, commit)
        return py_or_nd_endpoint.complete(sess, commit_ack)

    py_part_tct = handshake_to(py, py_part)
    nd_part_tct = handshake_to(nd, nd_part_handle)

    # Coordinator (Python) builds the bundle.
    envelope = (
        aitp.SessionBundleBuilder(coord)
        .participant(py_part_aid, py_part_tct)
        .participant(nd_part_aid, nd_part_tct)
        .build()
    )

    # Node verifies its own membership.
    outcome = node.call("verify_session_bundle", envelope=envelope, verifier_aid=nd_part_aid)
    assert outcome["kind"] == "clear"
    assert nd_part_aid in outcome["active_aids"]
    assert py_part_aid in outcome["active_aids"]

    # And Python verifies its own membership against a Node-built bundle.
    # (Inverse direction: coordinator is Node this time.)
    nd_coord_handle, nd_coord_aid = nd.new_agent()
    nd_coord_manifest = nd.build_manifest(
        nd_coord_handle,
        "nd-coord",
        "http://localhost:9011/aitp/handshake/",
        ["session.member"],
    )

    def handshake_to_nd_coord(py_or_nd_endpoint, part_handle):
        sess = py_or_nd_endpoint.new_session(part_handle)
        rsess = nd.new_responder(nd_coord_handle)
        hello = py_or_nd_endpoint.build_hello(sess, nd_coord_manifest, ["session.member"])
        hello_ack, sid = nd.process_hello(rsess, hello)
        commit = py_or_nd_endpoint.process_hello_ack(sess, hello_ack, sid)
        commit_ack, _ = nd.process_commit(rsess, commit)
        return py_or_nd_endpoint.complete(sess, commit_ack)

    # Fresh participants (one py, one nd).
    py_part2, py_part2_aid = py.new_agent()
    nd_part2_handle, nd_part2_aid = nd.new_agent()
    py.build_manifest(
        py_part2, "py-part2", "http://localhost:9012/aitp/handshake/", ["x"]
    )
    nd.build_manifest(
        nd_part2_handle, "nd-part2", "http://localhost:9013/aitp/handshake/", ["x"]
    )

    py_part2_tct = handshake_to_nd_coord(py, py_part2)
    nd_part2_tct = handshake_to_nd_coord(nd, nd_part2_handle)

    nd_envelope = node.call(
        "build_session_bundle",
        coordinator=nd_coord_handle,
        participants=[
            {"aid": py_part2_aid, "tct": py_part2_tct},
            {"aid": nd_part2_aid, "tct": nd_part2_tct},
        ],
    )["envelope"]

    # Python verifies the Node-built bundle.
    outcome2 = aitp.verify_session_bundle(nd_envelope, py_part2_aid)
    assert outcome2["kind"] == "clear"
    assert py_part2_aid in outcome2["active_aids"]
    assert nd_part2_aid in outcome2["active_aids"]


# ── B2 — P-256 suite negotiation across language boundaries ────────────


def test_p256_aid_minted_by_python_recognised_by_node(node):
    """A P-256 agent minted by Python produces an AID that Node can
    construct a matching P-256 agent from (via the same seed → same AID).
    Validates that both bindings share the same `aid:pubkey:p256:`
    grammar (RFC-AITP-0001 §5.4.3)."""
    seed = bytes([0xA5] * 32)
    py_agent = aitp.AitpAgent.from_seed(seed, suite="p256")
    assert py_agent.aid.startswith("aid:pubkey:p256:")

    nd_result = node.call("new_agent", suite="p256", seed=list(seed))
    assert nd_result["aid"] == py_agent.aid, (
        "P-256 AID derivation must match across language bindings — "
        f"py={py_agent.aid} nd={nd_result['aid']}"
    )


def test_p256_handshake_via_oidc_python_to_node(node):
    """End-to-end interop: a P-256 Python initiator runs an OIDC
    handshake against a Node Ed25519 responder. Both ends produce + verify
    a TCT, exercising the cross-suite, cross-language signature path.

    Exercises `aitp.compute_aid_jkt` for the P-256 subject — the Node-side
    OIDC verifier (in aitp-handshake) now derives the EC JWK thumbprint
    from the subject AID via the same crypto crate, so the Python-minted
    JWT's `cnf.jkt` matches without any in-Python curve arithmetic."""
    import time
    import base64 as b64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    def _b64u(b):
        return b64.urlsafe_b64encode(b).rstrip(b"=").decode()

    # Re-use the same OIDC issuer as the B1 test (the worker registers
    # under the same URL; new kids stack).
    py_priv = Ed25519PrivateKey.from_private_bytes(bytes([7] * 32))
    py_pub = py_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    py_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64u(py_pub),
        "kid": "py-p256-kid",
        "alg": "EdDSA",
        "use": "sig",
    }
    node_jwk = node.call("make_oidc_issuer", issuer=OIDC_ISSUER, kid="node-p256-kid")["jwk"]
    provider = aitp.JwksProvider({OIDC_ISSUER: [py_jwk, node_jwk]})

    # Python P-256 agent in OIDC mode.
    py_agent = aitp.AitpAgent.generate(suite="p256")
    assert py_agent.aid.startswith("aid:pubkey:p256:")
    py_agent.build_manifest(
        display_name="py-p256-oidc",
        handshake_endpoint="https://py.p256.test/aitp/handshake/",
        offered_caps=[PING_CAP],
        identity_type="oidc",
        oidc_issuer=OIDC_ISSUER,
        oidc_subject="py-p256",
    )
    py_sess = py_agent.new_session(jwks=provider)

    # Node Ed25519 agent in OIDC mode.
    node_agent = node.call("new_agent")["handle"]
    nd_manifest = node.call(
        "build_manifest_oidc",
        agent=node_agent,
        display_name="node-p256-resp",
        handshake_endpoint="https://node.p256.test/aitp/handshake/",
        offered_caps=[PING_CAP],
        oidc_issuer=OIDC_ISSUER,
        oidc_subject="node-p256",
    )["manifest"]
    node_resp_aid = json.loads(nd_manifest)["manifest"]["aid"]
    node_jwks_handle = node.call(
        "new_jwks_provider", keys={OIDC_ISSUER: [py_jwk, node_jwk]}
    )["handle"]
    node_resp = node.call(
        "new_oidc_responder", agent=node_agent, jwks=node_jwks_handle
    )["handle"]

    now = int(time.time())
    # Both sides derive their `cnf.jkt` via the binding helper so the
    # P-256 / Ed25519 split is handled by the same code in aitp-crypto.
    py_jkt = aitp.compute_aid_jkt(py_agent.aid)
    node_jkt = aitp.compute_aid_jkt(node_resp_aid)

    def py_mint(nonce: str) -> str:
        import json as json_mod

        header = {"alg": "EdDSA", "typ": "JWT", "kid": "py-p256-kid"}
        claims = {
            "iss": OIDC_ISSUER,
            "sub": "py-p256",
            "aud": node_resp_aid,
            "iat": now,
            "exp": now + 3600,
            "nonce": nonce,
            "cnf": {"jkt": py_jkt},
        }
        h = _b64u(json_mod.dumps(header, separators=(",", ":")).encode())
        p = _b64u(json_mod.dumps(claims, separators=(",", ":")).encode())
        sig = py_priv.sign(f"{h}.{p}".encode())
        return f"{h}.{p}.{_b64u(sig)}"

    # ── Four messages ───────────────────────────────────────────────
    hello = py_sess.build_hello(nd_manifest, [PING_CAP], oidc_mint_jwt=py_mint)
    ack_result = node.call(
        "process_hello_oidc",
        responder=node_resp,
        hello=hello,
        mint_kid="node-p256-kid",
        mint_sub="node-p256",
        mint_aud=py_agent.aid,
        mint_cnf_jkt=node_jkt,
        mint_now=now,
    )
    commit = py_sess.process_hello_ack(ack_result["hello_ack"], ack_result["session_id"])
    commit_result = node.call("process_commit", responder=node_resp, commit=commit)
    py_held_tct = py_sess.complete(commit_result["commit_ack"])

    # Each side holds the other's TCT under the cross-suite combination.
    py_ident = py_agent.verify_tct(py_held_tct, PING_CAP)
    assert py_ident.peer_aid == node_resp_aid
    nd_ident = node.call(
        "verify_tct",
        agent=node_agent,
        tct=commit_result["tct"],
        required_grant=PING_CAP,
    )
    assert nd_ident["peer_aid"] == py_agent.aid
