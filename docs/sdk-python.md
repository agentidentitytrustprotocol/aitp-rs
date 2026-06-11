# Python SDK — feature guide

This page is a feature-by-feature pointer into [`bindings/aitp-py`](../bindings/aitp-py).
Each section names the RFC, the Cargo feature flag (if any), and a
~5-line example. For full method signatures see [`aitp.pyi`](../bindings/aitp-py/aitp.pyi).

The Node SDK has a symmetric surface; see [`sdk-node.md`](sdk-node.md).

## Build

```bash
maturin develop                       # default surface
maturin develop --features experimental   # adds post-v0.1 features
```

## Default surface (v0.1)

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
alice_held = s.complete(cack)
```

### TCT verification (RFC-AITP-0005 §9)

```python
# Holder-receipt model — verifier's AID = own AID (default).
ident = agent.verify_tct(tct_json, "demo.echo")

# Presented-TCT model — for a resource server checking a TCT a peer
# presented in `X-AITP-TCT`. The audience is the TCT's own subject.
ident = agent.verify_tct(tct_json, "demo.echo", expected_audience=peer_aid)
```

### Delegation (RFC-AITP-0006)

```python
delegation_env = b.build_delegation(
    held_tct_envelope_json=tct_b_holds_from_a,
    delegatee_aid=c.aid,
    delegatee_pubkey_b64u=c_pubkey,
    scope=["demo.write"],
)
verified = aitp.verify_delegation(delegation_env, a.aid)
fresh_tct_for_c = a.issue_tct_for_delegatee(verified)
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
verifier on the other side accepts them. **Caveat:** the v0.1 manifest's
`pinned_key` identity_hint embeds an Ed25519 public key only, so P-256
agents must use `identity_type="oidc"`.

## Experimental surface (Cargo `--features experimental`)

### TCT renewal (RFC-AITP-0013 / RFC-AITP-0004 §8.1, feature `experimental-renewal`)

```python
req = holder.build_renewal_request(current_tct_envelope_json)
fresh = issuer.process_renewal_request(req, manifest_exp_unix_secs, new_ttl_secs)
```

### Session Trust Bundle (RFC-AITP-0010, feature `experimental-bundle`)

```python
envelope = (
    aitp.SessionBundleBuilder(coordinator)
        .participant(alice.aid, alice_tct)
        .participant(bob.aid, bob_tct)
        .build()
)
outcome = aitp.verify_session_bundle(envelope, alice.aid)
# {"kind": "clear" | "degraded", "active_aids": [...], "dropped_aids": [...]}
```

### SPKI cert pinning (HPKP-style, feature `experimental-pinning`)

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
maturin develop --features experimental
pytest -v                      # 27 binding tests
cd ../interop && pytest -v     # 12 cross-language interop tests (1 deliberately skipped)
```
