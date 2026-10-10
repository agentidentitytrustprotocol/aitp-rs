# aitp — Python SDK

Python bindings for the **Agent Identity & Trust Protocol (AITP)**, built on
the pure-Rust `aitp-rs` protocol crates via [PyO3](https://pyo3.rs).

A thin SDK: an `AitpAgent` plus initiator/responder session objects. Their
methods take and return strings: JSON for the HTTP request/response bodies,
and compact-JWS strings for TCTs, grant vouchers and delegation tokens. Agent
code never handles a Rust type across the FFI boundary.

The feature-by-feature guide, with an example for every capability, is
[`docs/sdk-python.md`](../../docs/sdk-python.md).

## Install

```bash
pip install aitp-sdk      # PyPI distribution name; the import name is `aitp`
```

## Build from source

This crate is **not** part of the `aitp-rs` Cargo workspace. Build it with
[maturin](https://github.com/PyO3/maturin) and a Rust toolchain:

```bash
pip install maturin
maturin develop                          # full wheel (all capabilities)
maturin develop --no-default-features    # minimal wheel (core surface only)
```

### Cargo features

By default the published wheel ships the **full** capability surface:

- handshake, TCT, delegation, manifest verification and OIDC identity
- revocation-list signing and verification
- TCT renewal, session bundles, SPKI pinning and multi-hop delegation

Each capability below is a named feature, all on by default. A minimal wheel
can opt out with `--no-default-features`:

| Feature               | Enables                                                            | RFC                  |
|-----------------------|--------------------------------------------------------------------|----------------------|
| `renewal`             | `AitpAgent.build_renewal_request` / `process_renewal_request`      | RFC-AITP-0013 (Planned) |
| `session-bundle`      | `SessionBundleBuilder`, `verify_session_bundle`                    | RFC-AITP-0010 (Draft) |
| `spki-pinning`        | `compute_spki_hash`, `SpkiPinVerifier`                             | HPKP (RFC 7469)      |
| `multihop-delegation` | `verify_delegation_multihop`                                       | RFC-AITP-0011 (Draft) |

Capabilities whose RFC has not graduated make no wire-stability promise
across binding versions. If you depend on them, pin a specific version.

## Usage

```python
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
```

In a real deployment each message moves over HTTP. `build_hello` returns the
body for `POST /aitp/handshake/hello`. `process_hello` returns the response
body plus the value for the `X-Aitp-Session-Id` header, and so on.

## API

[`aitp.pyi`](aitp.pyi) describes the full public surface; the table below
summarizes it. All `*_json` parameters and return values are JSON strings.

| Type / function       | Feature | Notes |
|-----------------------|:-------:|-------|
| `AitpAgent`           | default | `generate(suite=...)`, `from_seed(bytes, suite=...)`, `aid`, `build_manifest(...)`, `new_session(jwks=None, trust_anchors=None)`, `new_responder(jwks=None, trust_anchors=None)`, `verify_tct(...)`, `verify_tct_cached(...)`, `build_delegation(voucher_token, delegatee_aid, scope, ttl_secs=None)`, `issue_tct_for_delegatee(...)` (returns JSON), `sign_revocation_list(...)` |
| `InitiatorSession`    | default | `build_hello(peer_manifest, grants, oidc_mint_jwt=None)`, `process_hello_ack(...)`, `complete(...)` → JSON `{"tct", "grant_voucher"}` |
| `ResponderSession`    | default | `process_hello(hello, oidc_mint_jwt=None)` → `(ack_json, session_id)`, `process_commit(...)` → `(ack_json, completed_json)` |
| `TctIdentity`         | default | `peer_aid`, `grants`, `expires_at`, `jti` |
| `DelegationVerified`  | default | `delegator`, `delegatee`, `issued_by`, `grants`, `expires_at`, `cnf` |
| `JwksProvider`        | default | OIDC JWKS map. `upsert(issuer, keys)`, `remove(issuer)`, `issuers()` |
| `TctStore`            | default | Cache for `AitpAgent.verify_tct_cached()`. A byte-identical, still-valid TCT skips the signature check; the key is the SHA-256 of the token bytes |
| `verify_delegation()` | default | RFC-AITP-0006, strict single-hop; rejects any multi-hop `chain`. Takes `revoked_jtis` |
| `verify_manifest_json()` / `ManifestVerificationError` | default | Raises `ManifestVerificationError` with `.code`; non-manifest input raises `ValueError` |
| `verify_revocation_list()` / `RevocationVerificationError` | default | Verifies a revocation snapshot against a pinned issuer. Raises with `.code` |
| `revocation_signing_bytes()` | default | The exact bytes a revocation snapshot's signature covers |
| `compute_aid_jkt()`   | default | RFC 7638 thumbprint of an AID's key, for an OIDC JWT's `cnf.jkt` |
| `AitpAgent.build_renewal_request()` / `process_renewal_request()` | `renewal` | RFC-AITP-0013 (Planned). `process_renewal_request` returns JSON |
| `SessionBundleBuilder`, `verify_session_bundle()` | `session-bundle` | RFC-AITP-0010 |
| `compute_spki_hash()`, `SpkiPinVerifier` | `spki-pinning` | HPKP-style outbound pinning |
| `verify_delegation_multihop()` | `multihop-delegation` | RFC-AITP-0011 multi-hop opt-in |

The Python and Node bindings differ in some return shapes and argument
names; see
[Python vs Node differences](../../docs/sdk-python.md#python-vs-node-differences).

### OIDC identity and P-256

See [OIDC identity](../../docs/sdk-python.md#oidc-identity-rfc-aitp-0002) and
[P-256 signing suite](../../docs/sdk-python.md#p-256-signing-suite-rfc-aitp-0001-543).

`pinned_key` identities are Ed25519-only **in this SDK**. The v0.2 manifest
schema itself accepts a P-256 `public_key`, but `build_manifest` cannot emit
one. P-256 agents must therefore use `identity_type="oidc"`.

## Tests

```bash
pip install maturin pytest httpx 'pyjwt[crypto]' cryptography
maturin develop
pytest tests/
```

`tests/test_docs_samples.py` runs every Python block in
[`docs/sdk-python.md`](../../docs/sdk-python.md) and the Usage block above.

The cross-language interop suite (Python ↔ Node) lives in
[`../interop`](../interop). Run it with `make interop` from the repo root.
