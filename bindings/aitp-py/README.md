# aitp — Python SDK

Python bindings for the **Agent Identity & Trust Protocol (AITP)**, built on
the pure-Rust `aitp-rs` protocol crates via [PyO3](https://pyo3.rs).

A thin SDK: an `AitpAgent` plus initiator/responder session objects whose
methods take and return JSON strings — the HTTP request/response bodies — so
agent code never handles a Rust type across the FFI boundary.

## Build

This crate is **not** part of the `aitp-rs` Cargo workspace. Build it with
[maturin](https://github.com/PyO3/maturin):

```bash
pip install maturin
maturin develop                          # full wheel (all capabilities)
maturin develop --no-default-features    # minimal wheel (core surface only)
```

### Cargo features

The published wheel ships the **full** capability surface by default —
handshake, TCT, delegation, manifest verify, revocation-list signing, OIDC
identity, **plus** TCT renewal, session bundles, SPKI pinning, and multi-hop
delegation. Each capability is a named feature (all on by default) so a
minimal wheel can opt out with `--no-default-features`:

| Feature               | Enables                                                            | RFC                  |
|-----------------------|--------------------------------------------------------------------|----------------------|
| `renewal`             | `AitpAgent.build_renewal_request` / `process_renewal_request`      | RFC-AITP-0005 §10    |
| `session-bundle`      | `SessionBundleBuilder`, `verify_session_bundle`                    | RFC-AITP-0010        |
| `spki-pinning`        | `compute_spki_hash`, `SpkiPinVerifier`                             | HPKP (RFC 7469)      |
| `multihop-delegation` | `verify_delegation_multihop`                                       | RFC-AITP-0011        |

Capabilities whose underlying RFC has not yet graduated do not promise wire
stability across binding versions — pin a specific version if you depend on
them.

## Usage

```python
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
commit_ack, held_tct  = rsess.process_commit(commit)
initiator_held_tct    = sess.complete(commit_ack)

# Each peer now holds a TCT the other issued it.
ident = initiator.verify_tct(initiator_held_tct, "demo.write")
print(ident.peer_aid, ident.grants)
```

In a real deployment each message moves over HTTP: `build_hello` returns the
`POST /aitp/handshake/hello` body, `process_hello` returns the response body
plus the value for the `X-Aitp-Session-Id` header, and so on.

## API

The full public surface is described in [`aitp.pyi`](aitp.pyi); below is a
summary. All `*_json` parameters and return values are JSON strings (the
on-wire HTTP request/response bodies).

| Type                  | Default? | Notes                                                                                   |
|-----------------------|:--------:|-----------------------------------------------------------------------------------------|
| `AitpAgent`           |    ✅    | `generate(suite=...)`, `from_seed(bytes, suite=...)`, `aid`, `build_manifest(...)`, `new_session(...)`, `new_responder(...)`, `verify_tct(...)`, `build_delegation(...)`, `issue_tct_for_delegatee(...)`, `sign_revocation_list(...)` |
| `InitiatorSession`    |    ✅    | `build_hello(peer_manifest, grants, oidc_mint_jwt=None)`, `process_hello_ack(...)`, `complete(...)` |
| `ResponderSession`    |    ✅    | `process_hello(hello, oidc_mint_jwt=None)`, `process_commit(...)`                       |
| `TctIdentity`         |    ✅    | `peer_aid`, `grants`, `expires_at`, `jti`                                               |
| `DelegationVerified`  |    ✅    | `delegator`, `delegatee`, `issued_by`, `grants`, `expires_at`, `cnf`                    |
| `JwksProvider`        |    ✅    | OIDC JWKS map. `upsert(issuer, keys)`, `remove(issuer)`, `issuers()`                    |
| `TctStore` / `verify_tct_cached()` | ✅ | Hot-path verify cache: skips the signature check for a byte-identical, still-valid TCT (keyed by SHA-256 of the envelope) |
| `verify_delegation()` |    ✅    | RFC-AITP-0006 — strict v0.1 single-hop; rejects any multi-hop `chain`                   |
| `verify_manifest_json()` | ✅    | Control-plane manifest enrollment                                                       |
| `AitpAgent.build_renewal_request()` / `process_renewal_request()` | `renewal` | RFC-AITP-0005 §10 |
| `SessionBundleBuilder`, `verify_session_bundle()`                 | `session-bundle`  | RFC-AITP-0010 |
| `compute_spki_hash()`, `SpkiPinVerifier`                          | `spki-pinning` | HPKP-style outbound pinning |
| `verify_delegation_multihop()`                       | `multihop-delegation` | RFC-AITP-0011 (draft) multi-hop opt-in |

### OIDC identity (RFC-AITP-0002)

```python
import aitp

jwks = aitp.JwksProvider({"https://idp.example/": [{"kty": "OKP", ...}]})

agent = aitp.AitpAgent.generate()
agent.build_manifest(
    display_name="alice",
    handshake_endpoint="https://alice.example/aitp/handshake/",
    offered_caps=["demo.echo"],
    identity_type="oidc",
    oidc_issuer="https://idp.example/",
    oidc_subject="alice",
)
sess = agent.new_session(jwks=jwks)

def mint(nonce: str) -> str:
    return my_idp.mint_jwt(nonce=nonce, sub="alice", aud=peer_aid, ...)

hello = sess.build_hello(peer_manifest, ["demo.echo"], oidc_mint_jwt=mint)
```

### P-256 signing (RFC-AITP-0001 §5.4.3)

```python
agent = aitp.AitpAgent.generate(suite="p256")  # aid:pubkey:p256:<44>
# All other methods identical; signatures are emitted as `p256.<86b64u>`.
```

> **Note.** In v0.1 the `pinned_key` identity_hint embeds an Ed25519 raw
> public key. P-256 agents must therefore use `identity_type="oidc"` until
> the manifest's identity_hint shape is extended.

## Tests

```bash
maturin develop
pip install pytest
pytest
```

The cross-language interop suite (Python ↔ Node) lives in
[`../interop`](../interop) — run it with `make interop` from the repo root.
