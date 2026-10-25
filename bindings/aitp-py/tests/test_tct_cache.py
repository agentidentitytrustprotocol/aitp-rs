"""TctStore — cached TCT verification (Python SDK).

Exercises the verification-result cache: a byte-identical, already-verified,
still-valid TCT skips the signature check, while tampered bytes miss the cache
and are fully (re-)verified. Run with `maturin develop` then `pytest` from
`bindings/aitp-py/`.
"""

import json

import pytest

import aitp

GRANT = "demo.write"


def _held_tct():
    """Run a handshake so the initiator holds a responder-issued TCT for
    GRANT. Returns (initiator, tct_token) where tct_token is the compact
    JWS string."""
    initiator = aitp.AitpAgent.generate()
    responder = aitp.AitpAgent.generate()
    initiator.build_manifest(
        display_name="initiator",
        handshake_endpoint="http://localhost:8100/aitp/handshake/",
        offered_caps=["demo.echo"],
    )
    responder_manifest = responder.build_manifest(
        display_name="responder",
        handshake_endpoint="http://localhost:8200/aitp/handshake/",
        offered_caps=[GRANT],
    )
    sess = initiator.new_session(pinned_keys=[responder.aid])
    rsess = responder.new_responder(pinned_keys=[initiator.aid])
    hello = sess.build_hello(responder_manifest, [GRANT])
    hello_ack, sid = rsess.process_hello(hello)
    commit = sess.process_hello_ack(hello_ack, sid)
    commit_ack, _ = rsess.process_commit(commit, revoked_jtis=set())
    completed = json.loads(sess.complete(commit_ack, revoked_jtis=set()))
    return initiator, completed["tct"]


def test_cached_verify_matches_cold_verify_and_populates():
    initiator, tct = _held_tct()
    store = aitp.TctStore(128)
    assert store.len() == 0

    cold = initiator.verify_tct(tct, GRANT, revoked_jtis=set())
    warm = initiator.verify_tct_cached(tct, GRANT, store, revoked_jtis=set())
    assert (warm.peer_aid, warm.grants, warm.jti) == (
        cold.peer_aid,
        cold.grants,
        cold.jti,
    )
    assert store.len() == 1

    # Second cached call (a cache hit) returns the same identity.
    again = initiator.verify_tct_cached(tct, GRANT, store, revoked_jtis=set())
    assert again.jti == cold.jti
    assert store.len() == 1


def test_tampered_bytes_miss_cache_and_are_rejected():
    """Security: a tampered token hashes differently, so it cannot be
    served from a cache populated by the genuine token — it is fully
    re-verified and fails."""
    initiator, tct = _held_tct()
    store = aitp.TctStore(128)

    # Populate the cache with the genuine TCT.
    initiator.verify_tct_cached(tct, GRANT, store, revoked_jtis=set())

    # Flip a character in the compact-JWS signature segment → different
    # bytes → different hash → cache miss → full (failing) verification.
    header, payload, sig = tct.split(".")
    sig = ("A" if sig[0] != "A" else "B") + sig[1:]
    tampered = f"{header}.{payload}.{sig}"

    with pytest.raises(Exception):
        initiator.verify_tct_cached(tampered, GRANT, store, revoked_jtis=set())


def test_same_signing_input_with_different_signature_gets_no_cached_result():
    """RFC-AITP-0001 §5.4.3 review (#266): the key is SHA-256 of the whole
    compact JWS, i.e. of the signing input (header.payload) AND the
    signature. A token with the same signing input but other signature
    bytes never gets the cached result: it misses, is fully verified, and
    is not cached on failure."""
    initiator, tct = _held_tct()
    store = aitp.TctStore(128)
    initiator.verify_tct_cached(tct, GRANT, store, revoked_jtis=set())
    assert store.len() == 1

    header, payload, sig = tct.split(".")
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    for other_sig in (flipped, sig + "A", "", "AAAA"):
        other = f"{header}.{payload}.{other_sig}"
        assert other != tct
        with pytest.raises(Exception):
            initiator.verify_tct_cached(other, GRANT, store, revoked_jtis=set())
        assert store.len() == 1, "a failed verification must not be cached"

    # The genuine token still hits.
    assert initiator.verify_tct_cached(tct, GRANT, store, revoked_jtis=set()).jti == (
        initiator.verify_tct(tct, GRANT, revoked_jtis=set()).jti
    )
    assert store.len() == 1


def test_revocation_is_checked_on_a_cache_hit():
    initiator, tct = _held_tct()
    store = aitp.TctStore(8)
    jti = initiator.verify_tct_cached(tct, GRANT, store, revoked_jtis=set()).jti
    assert store.len() == 1
    with pytest.raises(Exception):
        initiator.verify_tct_cached(tct, GRANT, store, revoked_jtis={jti})
    # Without the revocation set the cached entry still serves.
    assert initiator.verify_tct_cached(tct, GRANT, store, revoked_jtis=set()).jti == jti


def test_missing_grant_rejected():
    initiator, tct = _held_tct()
    store = aitp.TctStore(128)
    initiator.verify_tct_cached(tct, GRANT, store, revoked_jtis=set())  # cache the good TCT
    # A grant the TCT does not carry must be rejected even with a warm cache.
    with pytest.raises(Exception):
        initiator.verify_tct_cached(tct, "demo.not-granted", store, revoked_jtis=set())


def test_eviction_respects_max_entries():
    store = aitp.TctStore(1)
    a, tct_a = _held_tct()
    b, tct_b = _held_tct()
    a.verify_tct_cached(tct_a, GRANT, store, revoked_jtis=set())
    assert store.len() == 1
    b.verify_tct_cached(tct_b, GRANT, store, revoked_jtis=set())
    # FIFO eviction keeps the cache bounded at max_entries.
    assert store.len() == 1


def test_max_entries_zero_raises():
    with pytest.raises(Exception):
        aitp.TctStore(0)


def test_clear_empties_the_cache():
    initiator, tct = _held_tct()
    store = aitp.TctStore(128)
    initiator.verify_tct_cached(tct, GRANT, store, revoked_jtis=set())
    assert store.len() == 1
    store.clear()
    assert store.len() == 0
