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
