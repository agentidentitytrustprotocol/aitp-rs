# Python SDK — feature guide

This page is a feature-by-feature pointer into [`bindings/aitp-py`](../bindings/aitp-py).
Each section names the RFC, the Cargo feature flag (if any), and a
~5-line example. For full method signatures see [`aitp.pyi`](../bindings/aitp-py/aitp.pyi).

The Node SDK has a symmetric surface; see [`sdk-node.md`](sdk-node.md).

## Build

```bash
maturin develop                       # default surface
maturin develop                       # full surface (all capabilities)
```

## Default surface

### Mutual handshake (RFC-AITP-0004)

```python
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
cack, _  = r.process_commit(commit)
held = s.complete(cack)
# v0.2: completion exposes the peer-issued TCT (opaque compact JWS), its
# decoded claims, and the optional companion grant voucher.
tct_jws      = held.tct.token          # compact JWS string — store / present this
claims       = held.tct.claims         # decoded {ver, jti, iss, sub, aud, iat, exp, grants, cnf}
voucher_jws  = held.grant_voucher      # compact JWS string, or None if the issuer disallowed delegation
```

### TCT verification (RFC-AITP-0005 §9)

A TCT is an opaque compact JWS string. `verify_tct` parses it strictly
(enforcing `typ == aitp-tct+jwt`, the AID-pinned `alg`, and the signature over
the transmitted bytes) and returns the verified identity.

```python
# Holder-receipt model — verifier's AID = own AID (default).
ident = agent.verify_tct(tct_jws, "demo.echo")

# Presented-TCT model — for a resource server checking a TCT a peer
# presented in `X-AITP-TCT`. The audience is the TCT's own subject (== sub).
ident = agent.verify_tct(tct_jws, "demo.echo", expected_audience=peer_aid)

# Optional revocation gate (F-1): pass the set of revoked TCT `jti`s; a TCT
# whose jti is in the set is rejected with TCT_REVOKED.
ident = agent.verify_tct(tct_jws, "demo.echo", revoked_jtis={"<revoked-uuid>"})
```

You can also verify a TCT with any stock JOSE library (`pyjwt`, etc.) given
only the issuer's public key — no AITP stack required. See
[architecture.md](architecture.md#debugging-a-tct).

### Delegation (RFC-AITP-0006)

Delegation embeds the **grant voucher** A minted alongside B's TCT; nothing is
reconstructed. `build_delegation` takes the voucher string B holds.

```python
delegation_jws = b.build_delegation(
    grant_voucher=voucher_b_holds_from_a,   # compact JWS string from the handshake
    delegatee_aid=c.aid,
    delegatee_pubkey_b64u=c_pubkey,
    scope=["demo.write"],
)
verified = aitp.verify_delegation(delegation_jws, a.aid)
fresh_tct_for_c = a.issue_tct_for_delegatee(verified)   # compact JWS string
```

### Manifest verification

```python
aitp.verify_manifest_json(manifest_envelope_json)  # raises on failure
```

### Revocation-list signing

```python
envelope = issuer.sign_revocation_list(
    [{"jti": "uuid-here", "reason": "compromised"}],
    expires_in_secs=600,
)
```

### OIDC identity (RFC-AITP-0002)

```python
jwks = aitp.JwksProvider({"https://idp.example/": [my_jwk_dict]})
agent.build_manifest(
    ..., identity_type="oidc", oidc_issuer="https://idp.example/", oidc_subject="alice",
)
sess = agent.new_session(jwks=jwks)
hello = sess.build_hello(peer_manifest, grants, oidc_mint_jwt=mint_callback)
```

The `oidc_mint_jwt` callback receives the handshake-generated `pop_nonce`
(str) and must return a freshly-minted compact JWT whose `nonce` claim
equals that nonce.

### P-256 signing suite (RFC-AITP-0001 §5.4.3)

```python
agent = aitp.AitpAgent.generate(suite="p256")           # aid:pubkey:p256:<44>
agent = aitp.AitpAgent.from_seed(seed_bytes, suite="p256")
```

P-256 produces `p256.<86-char-b64url>` signatures; an algorithm-agile
verifier on the other side accepts them. **Caveat:** the manifest's
`pinned_key` identity_hint embeds an Ed25519 public key only, so P-256
agents must use `identity_type="oidc"`.

## Additional capabilities (on by default)

These ship in the default wheel; a `--no-default-features` build can omit
any of them via its named Cargo feature.

### TCT renewal (RFC-AITP-0013 / RFC-AITP-0004 §8.1, feature `renewal`)

```python
# current_tct is the holder's TCT compact JWS string.
req = holder.build_renewal_request(current_tct)
result = issuer.process_renewal_request(req, manifest_exp_unix_secs, new_ttl_secs)
fresh_tct, fresh_voucher = result["tct"], result.get("grant_voucher")
```

### Session Trust Bundle (RFC-AITP-0010, feature `session-bundle`)

```python
envelope = (
    aitp.SessionBundleBuilder(coordinator)
        .participant(alice.aid, alice_tct)   # alice_tct: compact JWS string
        .participant(bob.aid, bob_tct)       # bob_tct:   compact JWS string
        .build()
)
outcome = aitp.verify_session_bundle(envelope, alice.aid)
# {"kind": "clear" | "degraded", "active_aids": [...], "dropped_aids": [...]}
```

### SPKI cert pinning (HPKP-style, feature `spki-pinning`)

```python
pin = aitp.compute_spki_hash(cert_der_bytes)    # 32 bytes
verifier = aitp.SpkiPinVerifier([pin])
verifier.is_pinned(other_cert_der)              # True / False
```

Wire `verifier.is_pinned()` into your HTTP client's
`checkServerIdentity`-equivalent hook (e.g. an `httpx` transport-level
verify callback). The SDK does no HTTP itself.

## Tests + interop

```bash
maturin develop
pytest -v                      # 27 binding tests
cd ../interop && pytest -v     # 12 cross-language interop tests (1 deliberately skipped)
```
